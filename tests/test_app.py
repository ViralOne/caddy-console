"""End-to-end tests through the Flask test client, with caddy and its admin API faked.

Run with:  python3 -m unittest discover -s tests -t . -v
No caddy binary or network required.
"""
import json
import os
import re
import shutil
import time
import unittest
from unittest import mock

import tests._env as env  # noqa: F401  (sets env before src is imported)

import requests
from authlib.jose import JsonWebKey, JsonWebToken

from src import audit, auth, create_app
from src.routes import editor as editor_mod
from src.routes import ops as ops_mod

AUTH = {"Cf-Access-Authenticated-User-Email": "admin@example.com"}


class FakeResponse:
    def __init__(self, status_code=200, text="", payload=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload

    def json(self):
        return self._payload


def write_caddyfile(content):
    with open(env.CADDYFILE, "w") as f:
        f.write(content)


def reset_backup_dir():
    for name in os.listdir(env.BACKUP_DIR):
        p = os.path.join(env.BACKUP_DIR, name)
        if name.startswith("Caddyfile.") or name in ("audit.log", "audit.log.1"):
            os.remove(p)


class AppTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.testing = True

    def setUp(self):
        reset_backup_dir()
        write_caddyfile(":80 {\n\trespond 200\n}\n")
        self.client = self.app.test_client()
        html = self.client.get("/", headers=AUTH).get_data(as_text=True)
        self.csrf = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
        # Nothing here should ever shell out to caddy.
        self.patches = [
            mock.patch.object(editor_mod, "caddy_fmt", lambda c: c),
            mock.patch.object(editor_mod, "caddy_validate", lambda c: (True, "Config is valid")),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def post(self, url, payload=None, **kw):
        headers = {**AUTH, "X-CSRF-Token": self.csrf, **kw.pop("headers", {})}
        return self.client.post(url, json=payload, headers=headers, **kw)

    def delete(self, url):
        return self.client.delete(url, headers={**AUTH, "X-CSRF-Token": self.csrf})


class BackupsApiTest(AppTestCase):
    def test_only_real_backups_are_addressable(self):
        # These files live in BACKUP_DIR but must never be served or deleted.
        audit.log_action("save_reload", "someone@example.com")
        with open(os.path.join(env.BACKUP_DIR, ".secret_key"), "w") as f:
            f.write("x" * 64)
        for name in (".secret_key", "audit.log", ".lock", "Caddyfile.", "..%2F..%2Fetc%2Fpasswd"):
            with self.subTest(name=name):
                self.assertEqual(self.client.get(f"/api/backups/{name}", headers=AUTH).status_code, 404)
                self.assertEqual(self.delete(f"/api/backups/{name}").status_code, 404)
                self.assertEqual(self.post(f"/api/backups/{name}/restore").status_code, 404)
        self.assertTrue(os.path.exists(env.AUDIT_LOG), "audit log must survive")
        self.assertTrue(os.path.exists(os.path.join(env.BACKUP_DIR, ".secret_key")))

    def test_real_backup_round_trip(self):
        path = os.path.join(env.BACKUP_DIR, "Caddyfile.20260101-000000")
        with open(path, "w") as f:
            f.write("backup content\n")
        r = self.client.get("/api/backups/Caddyfile.20260101-000000", headers=AUTH)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["content"], "backup content\n")
        self.assertEqual(self.delete("/api/backups/Caddyfile.20260101-000000").status_code, 200)
        self.assertFalse(os.path.exists(path))


class CsrfTest(AppTestCase):
    def test_non_ascii_token_is_a_403_not_a_500(self):
        r = self.client.post("/api/fmt", json={"content": ""}, headers={**AUTH, "X-CSRF-Token": "\u00e9\u00e9"})
        self.assertEqual(r.status_code, 403)

    def test_missing_token_is_rejected(self):
        self.assertEqual(self.client.post("/api/fmt", json={"content": ""}, headers=AUTH).status_code, 403)

    def test_valid_token_is_accepted(self):
        self.assertEqual(self.post("/api/fmt", {"content": "a"}).status_code, 200)

    def test_oversized_body_is_rejected(self):
        r = self.post("/api/fmt", {"content": "x" * (9 * 1024 * 1024)})
        self.assertEqual(r.status_code, 413)


class SavePathTest(AppTestCase):
    def _save(self, content, version=None, post=None):
        post = post or (lambda *a, **k: FakeResponse(200))
        with mock.patch.object(editor_mod.http_client, "post", post):
            payload = {"content": content}
            if version is not None:
                payload["version"] = version
            return self.post("/api/save", payload)

    def test_save_writes_file_and_creates_backup(self):
        r = self._save("new {\n}\n")
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertTrue(r.get_json()["ok"])
        with open(env.CADDYFILE) as f:
            self.assertEqual(f.read(), "new {\n}\n")
        self.assertEqual(len(editor_mod.list_backup_names()), 1)

    def test_stale_version_is_a_conflict(self):
        r = self._save("new\n", version="0000000000000000")
        self.assertEqual(r.status_code, 409)
        self.assertTrue(r.get_json()["conflict"])
        with open(env.CADDYFILE) as f:
            self.assertEqual(f.read(), ":80 {\n\trespond 200\n}\n", "file must be untouched")

    def test_conflict_is_detected_even_if_file_changes_during_validation(self):
        # The early check passes, then someone else writes before we take the lock.
        current = self.client.get("/api/caddyfile", headers=AUTH).get_json()["version"]
        real_fmt = editor_mod.caddy_fmt

        def racing_fmt(content):
            write_caddyfile("someone else was here\n")
            return real_fmt(content)

        with mock.patch.object(editor_mod, "caddy_fmt", racing_fmt):
            r = self._save("mine\n", version=current)
        self.assertEqual(r.status_code, 409)
        with open(env.CADDYFILE) as f:
            self.assertEqual(f.read(), "someone else was here\n")

    def test_rejected_reload_rolls_the_file_back(self):
        before = ":80 {\n\trespond 200\n}\n"
        r = self._save("bad\n", post=lambda *a, **k: FakeResponse(400, text="port in use"))
        self.assertEqual(r.status_code, 500)
        data = r.get_json()
        self.assertFalse(data["ok"])
        self.assertIn("restored", data["message"])
        with open(env.CADDYFILE) as f:
            self.assertEqual(f.read(), before, "disk must match what Caddy is still running")
        self.assertEqual(data["version"], editor_mod._version(before))

    def test_reload_timeout_keeps_the_file_and_says_so(self):
        def timeout(*a, **k):
            raise requests.ReadTimeout("slow")

        r = self._save("slow\n", post=timeout)
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data["ok"])
        self.assertIn("did not confirm", data["message"])
        with open(env.CADDYFILE) as f:
            self.assertEqual(f.read(), "slow\n")

    def test_unreachable_caddy_still_saves(self):
        def down(*a, **k):
            raise requests.ConnectionError("down")

        r = self._save("x\n", post=down)
        self.assertTrue(r.get_json()["ok"])
        self.assertIn("reload skipped", r.get_json()["message"])

    def test_backups_are_pruned_and_names_never_collide(self):
        for i in range(6):  # BACKUP_KEEP=3 in the test env; all within one second
            self.assertEqual(self._save(f"v{i}\n").status_code, 200)
        names = editor_mod.list_backup_names()
        self.assertEqual(len(names), 3, names)
        self.assertEqual(len(set(names)), 3)
        # Newest survive: the last three saves backed up v2, v3, v4.
        contents = sorted(open(os.path.join(env.BACKUP_DIR, n)).read() for n in names)
        self.assertEqual(contents, ["v2\n", "v3\n", "v4\n"])

    def test_save_with_missing_caddyfile_does_not_crash(self):
        os.remove(env.CADDYFILE)
        r = self._save("fresh\n")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(editor_mod.list_backup_names(), [], "nothing to back up")

    def test_restore_logs_a_single_audit_entry(self):
        path = os.path.join(env.BACKUP_DIR, "Caddyfile.20260101-000000")
        with open(path, "w") as f:
            f.write("old {\n}\n")
        with mock.patch.object(editor_mod.http_client, "post", lambda *a, **k: FakeResponse(200)):
            r = self.post("/api/backups/Caddyfile.20260101-000000/restore")
        self.assertEqual(r.status_code, 200)
        entries = [e for e in audit.iter_entries() if e["action"].startswith("restore")]
        self.assertEqual(len(entries), 1)
        self.assertIn("from=Caddyfile.20260101-000000", entries[0]["detail"])


class LogsTailTest(AppTestCase):
    def tearDown(self):
        super().tearDown()
        if os.path.exists(env.LOG_FILE):
            os.remove(env.LOG_FILE)

    def _logs(self, pos=None):
        url = "/api/logs" if pos is None else f"/api/logs?pos={pos}"
        return self.client.get(url, headers=AUTH).get_json()

    def test_partial_last_line_waits_for_the_next_poll(self):
        with open(env.LOG_FILE, "wb") as f:
            f.write(b'{"a":1}\n{"b":2}\n{"c":')
        d = self._logs()
        self.assertEqual(d["lines"], ['{"a":1}', '{"b":2}'])
        self.assertEqual(d["pos"], len(b'{"a":1}\n{"b":2}\n'))
        with open(env.LOG_FILE, "ab") as f:
            f.write(b'3}\n')
        d2 = self._logs(d["pos"])
        self.assertEqual(d2["lines"], ['{"c":3}'])

    def test_initial_read_drops_the_partial_first_line(self):
        with open(env.LOG_FILE, "wb") as f:
            f.write(b"x" * 9000 + b"\nfull line\n")
        d = self._logs()
        self.assertEqual(d["lines"], ["full line"])

    def test_rotation_resets_to_the_tail(self):
        with open(env.LOG_FILE, "wb") as f:
            f.write(b"one\ntwo\n")
        d = self._logs(pos=10_000)  # client pos is beyond the (new, smaller) file
        self.assertEqual(d["lines"], ["one", "two"])


class AuditLogTest(unittest.TestCase):
    def setUp(self):
        reset_backup_dir()

    def test_tail_lines_returns_last_n_without_reading_everything(self):
        with open(env.AUDIT_LOG, "w") as f:
            for i in range(500):
                f.write(json.dumps({"i": i}) + "\n")
        tail = audit.tail_lines(env.AUDIT_LOG, 50, block=64)
        self.assertEqual(len(tail), 50)
        self.assertEqual(json.loads(tail[0])["i"], 450)
        self.assertEqual(json.loads(tail[-1])["i"], 499)

    def test_rotation_keeps_the_log_bounded_and_recent_history_readable(self):
        # AUDIT_LOG_MAX_BYTES=400 in the test env; each entry is ~100 bytes, so
        # the log rotates every 4-5 entries and one rotated file is kept.
        for i in range(12):
            audit.log_action("save_reload", "u@example.com", f"n={i}")
        self.assertTrue(os.path.exists(audit.rotated_path()))
        self.assertLess(os.path.getsize(env.AUDIT_LOG), 400 + 200)
        self.assertLess(os.path.getsize(audit.rotated_path()), 400 + 200)
        details = [e["detail"] for e in audit.iter_entries()]
        # Oldest first, contiguous, and ending with the newest entry.
        self.assertEqual(details[-1], "n=11")
        self.assertEqual(details, [f"n={i}" for i in range(12 - len(details), 12)])
        self.assertGreaterEqual(len(details), 5, "current file plus the rotated one")


class MetricsParserTest(unittest.TestCase):
    SCRAPE = "\n".join([
        "# HELP caddy_http_requests_total Counter of HTTP(S) requests made.",
        # One request through a 3-handler chain shows up three times.
        'caddy_http_requests_total{server="srv0",handler="subroute"} 100',
        'caddy_http_requests_total{server="srv0",handler="headers"} 100',
        'caddy_http_requests_total{server="srv0",handler="reverse_proxy"} 90',
        'caddy_http_requests_in_flight{server="srv0",handler="subroute"} 2',
        'caddy_http_requests_in_flight{server="srv0",handler="reverse_proxy"} 2',
        'caddy_http_request_duration_seconds_sum{server="srv0",handler="subroute",code="200",method="GET"} 4.5',
        'caddy_http_request_duration_seconds_count{server="srv0",handler="subroute",code="200",method="GET"} 90',
        'caddy_http_request_duration_seconds_sum{server="srv0",handler="subroute",code="502",method="GET"} 0.5',
        'caddy_http_request_duration_seconds_count{server="srv0",handler="subroute",code="502",method="GET"} 10',
        'caddy_http_request_duration_seconds_count{server="srv0",handler="reverse_proxy",code="502",method="GET"} 10',
        'caddy_http_request_duration_seconds_bucket{server="srv0",handler="subroute",code="200",method="GET",le="0.1"} 50',
        'caddy_http_request_size_bytes_sum{server="srv0",handler="subroute",code="200",method="GET"} 1000',
        'caddy_http_request_size_bytes_sum{server="srv0",handler="reverse_proxy",code="200",method="GET"} 1000',
        'caddy_http_response_size_bytes_sum{server="srv0",handler="subroute",code="200",method="GET"} 5000',
        'caddy_http_requests_total{server="srv1",handler="static_response"} 7',
        'caddy_reverse_proxy_upstreams_healthy{upstream="10.0.0.1:8080"} 1',
        "",
    ])

    def test_requests_are_not_multiplied_by_handler_count(self):
        result = ops_mod.parse_prometheus_metrics(self.SCRAPE)
        self.assertEqual(result["sites"]["srv0"]["requests"], 100)
        self.assertEqual(result["sites"]["srv1"]["requests"], 7)
        self.assertEqual(result["totals"]["requests"], 107)
        self.assertEqual(result["totals"]["in_flight"], 2)
        self.assertEqual(result["sites"]["srv0"]["bytes_in"], 1000)
        self.assertEqual(result["sites"]["srv0"]["bytes_out"], 5000)

    def test_5xx_errors_come_from_the_duration_histogram(self):
        result = ops_mod.parse_prometheus_metrics(self.SCRAPE)
        self.assertEqual(result["sites"]["srv0"]["errors"], 10)
        self.assertEqual(result["sites"]["srv0"]["error_rate"], 10.0)
        self.assertEqual(result["totals"]["errors"], 10)
        self.assertAlmostEqual(result["sites"]["srv0"]["avg_latency_ms"], 50.0)

    def test_upstream_health_is_passed_through(self):
        result = ops_mod.parse_prometheus_metrics(self.SCRAPE)
        self.assertEqual(result["upstreams_healthy"], {"10.0.0.1:8080": 1})


class CloudflareJwtTest(unittest.TestCase):
    ISS = "https://team.cloudflareaccess.com"

    def setUp(self):
        self.key = JsonWebKey.generate_key("RSA", 2048, is_private=True, options={"kid": "k1"})
        self.jwks = JsonWebKey.import_key_set({"keys": [self.key.as_dict(is_private=False)]})
        self.patches = [
            mock.patch.object(auth, "CF_ACCESS_TEAM_DOMAIN", "team"),
            mock.patch.object(auth, "CF_ACCESS_AUD", "aud-tag"),
            mock.patch.object(auth, "_jwks", lambda force=False: self.jwks),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def token(self, **claims):
        payload = {"email": "Admin@Example.com", "aud": ["aud-tag"], "iss": self.ISS,
                   "exp": int(time.time()) + 300, "iat": int(time.time())}
        payload.update(claims)
        return JsonWebToken(["RS256"]).encode({"alg": "RS256", "kid": "k1"}, payload, self.key).decode()

    def test_team_domain_shorthand_is_expanded(self):
        self.assertEqual(auth._cf_team_host(), "team.cloudflareaccess.com")
        self.assertTrue(auth.cf_jwt_enabled())

    def test_valid_token_yields_normalised_email(self):
        self.assertEqual(auth.verify_cf_token(self.token()), "admin@example.com")

    def test_wrong_audience_expired_or_forged_tokens_are_rejected(self):
        self.assertIsNone(auth.verify_cf_token(self.token(aud=["other-app"])))
        self.assertIsNone(auth.verify_cf_token(self.token(exp=int(time.time()) - 600)))
        self.assertIsNone(auth.verify_cf_token(self.token(iss="https://evil.example.com")))
        other = JsonWebKey.generate_key("RSA", 2048, is_private=True, options={"kid": "k1"})
        forged = JsonWebToken(["RS256"]).encode({"alg": "RS256", "kid": "k1"},
                                                {"email": "x@example.com", "aud": ["aud-tag"], "iss": self.ISS,
                                                 "exp": int(time.time()) + 300}, other).decode()
        self.assertIsNone(auth.verify_cf_token(forged))
        self.assertIsNone(auth.verify_cf_token(""))
        self.assertIsNone(auth.verify_cf_token("not.a.jwt"))

    def test_header_alone_is_not_enough_when_jwt_is_enabled(self):
        app = create_app()
        app.testing = True
        c = app.test_client()
        self.assertEqual(c.get("/api/me", headers=AUTH).status_code, 401)
        r = c.get("/api/me", headers={"Cf-Access-Jwt-Assertion": self.token()})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["email"], "admin@example.com")


class SecretKeyAtomicityTest(unittest.TestCase):
    def test_never_observes_a_partial_key(self):
        import src

        tmp = os.path.join(env.ROOT, "keys")
        shutil.rmtree(tmp, ignore_errors=True)
        os.makedirs(tmp)
        with mock.patch.object(src, "BACKUP_DIR", tmp):
            keys = {src._persisted_secret_key() for _ in range(5)}
        self.assertEqual(len(keys), 1)
        self.assertEqual(len(keys.pop()), 64)
        self.assertEqual(os.listdir(tmp), [".secret_key"], "no temp files left behind")


if __name__ == "__main__":
    unittest.main()
