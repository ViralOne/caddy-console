"""End-to-end tests through the Flask test client, with caddy and its admin API faked.

Run with:  python3 -m unittest discover -s tests -t . -v
No caddy binary or network required.
"""
import base64
import hashlib
import json
import os
import re
import shutil
import tempfile
import threading
import time
import unittest
from unittest import mock

import tests._env as env  # noqa: F401  (sets env before src is imported)

import flask
import requests
from authlib.jose import JsonWebKey, JsonWebToken

import src
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
            mock.patch.object(editor_mod, "caddy_validate", lambda c: (True, "Config passed local Caddy validation")),
            mock.patch.object(editor_mod, "caddy_check", lambda c: (True, "Config passed local Caddy validation", "validated")),
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

    def test_failed_rollback_returns_the_content_left_on_disk(self):
        real_write = editor_mod._write_caddyfile
        calls = 0

        def fail_second_write(content):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("rollback failed")
            return real_write(content)

        with mock.patch.object(editor_mod, "_write_caddyfile", fail_second_write):
            r = self._save("formatted-on-disk\n", post=lambda *a, **k: FakeResponse(400, text="rejected"))
        data = r.get_json()
        self.assertEqual(r.status_code, 500)
        self.assertTrue(data["saved"])
        self.assertEqual(data["content"], "formatted-on-disk\n")
        with open(env.CADDYFILE) as f:
            self.assertEqual(f.read(), data["content"])

    def test_reload_timeout_keeps_the_file_and_reports_unknown(self):
        def timeout(*a, **k):
            raise requests.ReadTimeout("slow")

        r = self._save("slow\n", post=timeout)
        self.assertEqual(r.status_code, 504)
        data = r.get_json()
        self.assertFalse(data["ok"])
        self.assertTrue(data["saved"])
        self.assertEqual(data["reload_status"], "unknown")
        self.assertIn("did not confirm", data["message"])
        with open(env.CADDYFILE) as f:
            self.assertEqual(f.read(), "slow\n")

    def test_connection_reset_saves_but_reports_unknown(self):
        def down(*a, **k):
            raise requests.ConnectionError("connection reset")

        r = self._save("x\n", post=down)
        self.assertEqual(r.status_code, 504)
        data = r.get_json()
        self.assertFalse(data["ok"])
        self.assertTrue(data["saved"])
        self.assertEqual(data["reload_status"], "unknown")
        self.assertIn("did not confirm", data["message"])

    def test_connect_timeout_reports_reload_not_applied(self):
        def down(*a, **k):
            raise requests.ConnectTimeout("not connected")

        r = self._save("x\n", post=down)
        self.assertEqual(r.status_code, 503)
        data = r.get_json()
        self.assertFalse(data["ok"])
        self.assertTrue(data["saved"])
        self.assertEqual(data["reload_status"], "failed")
        self.assertIn("could not be established", data["message"])

    def test_backups_are_pruned_and_names_never_collide(self):
        for i in range(6):  # BACKUP_KEEP=3 in the test env; all within one second
            self.assertEqual(self._save(f"v{i}\n").status_code, 200)
        names = editor_mod.list_backup_names()
        self.assertEqual(len(names), 3, names)
        self.assertEqual(len(set(names)), 3)
        # Newest survive: the last three saves backed up v2, v3, v4.
        contents = []
        for name in names:
            with open(os.path.join(env.BACKUP_DIR, name)) as f:
                contents.append(f.read())
        contents.sort()
        self.assertEqual(contents, ["v2\n", "v3\n", "v4\n"])

    def test_save_with_missing_caddyfile_does_not_crash(self):
        os.remove(env.CADDYFILE)
        r = self._save("fresh\n")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(editor_mod.list_backup_names(), [], "nothing to back up")

    def test_runtime_lock_failure_is_a_structured_503(self):
        with mock.patch.object(editor_mod.os, "open", side_effect=PermissionError("denied")):
            r = self._save("blocked\n")
        self.assertEqual(r.status_code, 503)
        self.assertIn("lock", r.get_json()["error"].lower())

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


    def test_reload_is_inside_the_cross_process_lock(self):
        first_in_reload = threading.Event()
        allow_first_to_finish = threading.Event()
        reload_order = []
        results = []

        def blocking_post(url, data, **kwargs):
            content = data.decode("utf-8")
            if content == "first\n":
                first_in_reload.set()
                self.assertTrue(allow_first_to_finish.wait(2))
            reload_order.append(content)
            return FakeResponse(200)

        def apply(content):
            with self.app.app_context():
                results.append(editor_mod._apply_config(content, "u@example.com", "save"))

        with mock.patch.object(editor_mod.http_client, "post", blocking_post):
            first = threading.Thread(target=apply, args=("first\n",))
            second = threading.Thread(target=apply, args=("second\n",))
            first.start()
            self.assertTrue(first_in_reload.wait(2))
            second.start()
            time.sleep(0.05)
            self.assertTrue(second.is_alive(), "second save must wait while the first reload is in flight")
            allow_first_to_finish.set()
            first.join(2)
            second.join(2)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(reload_order, ["first\n", "second\n"])
        self.assertEqual(len(results), 2)
        with open(env.CADDYFILE) as f:
            self.assertEqual(f.read(), "second\n")


    def test_save_replaces_the_file_atomically(self):
        before_inode = os.stat(env.CADDYFILE).st_ino
        r = self._save("atomic\n")
        self.assertEqual(r.status_code, 200)
        self.assertNotEqual(os.stat(env.CADDYFILE).st_ino, before_inode)

    def test_restore_rejects_a_stale_live_version(self):
        path = os.path.join(env.BACKUP_DIR, "Caddyfile.20260101-000000")
        with open(path, "w") as f:
            f.write("old {\n}\n")
        version = self.client.get("/api/caddyfile", headers=AUTH).get_json()["version"]
        write_caddyfile("someone else changed it\n")
        with mock.patch.object(editor_mod.http_client, "post") as post:
            r = self.post(
                "/api/backups/Caddyfile.20260101-000000/restore",
                {"version": version},
            )
        self.assertEqual(r.status_code, 409)
        self.assertTrue(r.get_json()["conflict"])
        post.assert_not_called()
        with open(env.CADDYFILE) as f:
            self.assertEqual(f.read(), "someone else changed it\n")

    def test_rejected_reload_restores_crlf_bytes_exactly(self):
        original = b":80 {\r\n\trespond 200\r\n}\r\n"
        with open(env.CADDYFILE, "wb") as f:
            f.write(original)
        r = self._save("bad\n", post=lambda *a, **k: FakeResponse(400, text="rejected"))
        self.assertEqual(r.status_code, 500)
        with open(env.CADDYFILE, "rb") as f:
            self.assertEqual(f.read(), original)


class ExploreIpApiTest(AppTestCase):
    def test_public_ip_with_no_database(self):
        r = self.client.get("/api/explore/ip?ip=172.126.2.72&range=24h", headers=AUTH)
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body["kind"], "public")
        self.assertIsNone(body["location"])
        self.assertFalse(body["source"]["available"])
        self.assertIn("requests", body["seen"])

    def test_rejects_non_ip(self):
        r = self.client.get("/api/explore/ip?ip=example.com", headers=AUTH)
        self.assertEqual(r.status_code, 400)

    def test_requires_login(self):
        r = self.client.get("/api/explore/ip?ip=1.1.1.1")
        self.assertIn(r.status_code, (302, 401, 403))


class ExploreRawApiTest(AppTestCase):
    def test_path_like_file_tokens_are_rejected(self):
        for bad in ("../../etc/passwd", "/etc/passwd", "..", "sub\\x.log"):
            r = self.client.get("/api/explore/raw", query_string={"file": bad, "offset": 0}, headers=AUTH)
            self.assertEqual(r.status_code, 400, bad)

    def test_unknown_file_is_a_structured_error(self):
        r = self.client.get("/api/explore/raw?file=not-a-log.log&offset=0", headers=AUTH)
        self.assertEqual(r.status_code, 200)
        self.assertIn("error", r.get_json())
        self.assertNotIn("line", r.get_json())

    def test_missing_offset_or_file_is_a_400(self):
        self.assertEqual(self.client.get("/api/explore/raw?file=x.log", headers=AUTH).status_code, 400)
        self.assertEqual(self.client.get("/api/explore/raw?offset=0", headers=AUTH).status_code, 400)
        self.assertEqual(self.client.get(
            "/api/explore/raw?file=x.log&offset=999999999999999999999999",
            headers=AUTH,
        ).status_code, 400)


class StatusApiTest(AppTestCase):
    def test_status_uses_running_caddy_check_semantics(self):
        ops_mod._status_cache.update(file_key=None, config_check=None, version=None)
        with (
            mock.patch.object(ops_mod, "caddy_check", return_value=(
                True,
                "Caddyfile syntax and modules were accepted by the running Caddy",
                "adapted",
            )),
            mock.patch.object(ops_mod, "_caddy_version", return_value="v2.test"),
        ):
            r = self.client.get("/api/status", headers=AUTH)
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertTrue(body["config_valid"])
        self.assertEqual(body["config_check_level"], "adapted")
        self.assertIn("running Caddy", body["config_check_message"])

    def test_failed_local_fallback_status_is_not_cached(self):
        ops_mod._status_cache.update(file_key=None, config_check=None, version=None)
        checks = [
            (False, "module not registered", "validated"),
            (True, "accepted by running Caddy", "adapted"),
        ]
        with (
            mock.patch.object(ops_mod, "caddy_check", side_effect=checks) as check,
            mock.patch.object(ops_mod, "_caddy_version", return_value="v2.test"),
        ):
            first = self.client.get("/api/status", headers=AUTH).get_json()
            second = self.client.get("/api/status", headers=AUTH).get_json()
        self.assertFalse(first["config_valid"])
        self.assertTrue(second["config_valid"])
        self.assertEqual(check.call_count, 2)


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


class GoogleStartupValidationTest(unittest.TestCase):
    def test_non_https_server_url_is_rejected_outside_localhost(self):
        with (
            mock.patch.object(src, "AUTH_MODE", "google"),
            mock.patch.object(src, "SERVER_URL", "http://console.example.com"),
            mock.patch.dict(os.environ, {
                "GOOGLE_CLIENT_ID": "client.apps.googleusercontent.com",
                "GOOGLE_CLIENT_SECRET": "secret",
                "SECRET_KEY": "x" * 64,
            }),
        ):
            with self.assertRaisesRegex(RuntimeError, "must use https"):
                create_app()


class CloudflareFailClosedTest(unittest.TestCase):
    def test_missing_jwt_configuration_refuses_to_start(self):
        with (
            mock.patch.object(src, "UNSAFE_ALLOW_UNVERIFIED_CF_HEADER", False),
            mock.patch.object(src, "cf_jwt_enabled", return_value=False),
        ):
            with self.assertRaisesRegex(RuntimeError, "requires CF_ACCESS_TEAM_DOMAIN"):
                create_app()

    def test_unsigned_header_is_ignored_without_explicit_opt_in(self):
        app = create_app()
        with (
            app.test_request_context("/", headers=AUTH),
            mock.patch.object(auth, "UNSAFE_ALLOW_UNVERIFIED_CF_HEADER", False),
            mock.patch.object(auth, "CF_ACCESS_TEAM_DOMAIN", ""),
            mock.patch.object(auth, "CF_ACCESS_AUD", ""),
        ):
            self.assertEqual(auth.cloudflare_identity(), "")


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


class SitesApiTest(AppTestCase):
    def test_previous_total_is_always_present(self):
        body = self.client.get("/api/sites?range=1h", headers=AUTH).get_json()
        self.assertIn("previous_total", body)


class UpstreamsApiTest(AppTestCase):
    METRICS = "\n".join([
        'caddy_reverse_proxy_upstreams_healthy{upstream="127.0.0.1:2283"} 0',
        'caddy_reverse_proxy_upstreams_healthy{upstream="127.0.0.1:8096"} 1',
    ])
    SERVERS = {"srv0": {"routes": [
        {"match": [{"host": ["photos.example.com"]}],
         "handle": [{"handler": "subroute", "routes": [{"handle": [
             {"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:2283"}]}]}]}]},
        {"match": [{"host": ["watch.example.com"]}],
         "handle": [{"handler": "subroute", "routes": [{"handle": [
             {"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:8096"}]}]}]}]},
        {"match": [{"host": ["hello.example.com"]}], "handle": [{"handler": "static_response"}]},
    ]}}

    def setUp(self):
        super().setUp()
        from src import upstream_health
        state_dir = tempfile.mkdtemp(prefix="ups-")
        self.patches += [
            mock.patch.object(upstream_health, "STATE_PATH", os.path.join(state_dir, "s.json")),
            mock.patch.object(upstream_health, "LOCK_PATH", os.path.join(state_dir, ".lock")),
        ]
        for p in self.patches[-2:]:
            p.start()

    def fake_get(self, url, timeout=None, **kw):
        if url.endswith("/reverse_proxy/upstreams"):
            return FakeResponse(200, payload=[
                {"address": "127.0.0.1:2283", "num_requests": 0, "fails": 3},
                {"address": "127.0.0.1:8096", "num_requests": 1, "fails": 0},
            ])
        if url.endswith("/metrics"):
            return FakeResponse(200, text=self.METRICS)
        raise AssertionError(url)

    def get(self, servers):
        with mock.patch.object(ops_mod.http_client, "get", self.fake_get), \
             mock.patch.object(ops_mod, "get_servers", return_value=servers):
            return self.client.get("/api/upstreams", headers=AUTH).get_json()

    def test_unhealthy_since_and_configured_sites(self):
        before = time.time()
        body = self.get(self.SERVERS)
        rows = {u["address"]: u for u in body["upstreams"]}
        self.assertGreaterEqual(rows["127.0.0.1:2283"]["unhealthy_since"], before - 1)
        self.assertIsNone(rows["127.0.0.1:8096"]["unhealthy_since"])
        self.assertEqual(rows["127.0.0.1:2283"]["domains"], ["photos.example.com"])  # existing field kept
        self.assertEqual(rows["127.0.0.1:2283"]["fails"], 3)                         # existing field kept
        self.assertEqual(body["configured_sites"], 3)

    def test_configured_sites_is_null_without_a_config(self):
        self.assertIsNone(self.get({})["configured_sites"])


class LastChangeTest(AppTestCase):
    def status(self):
        with mock.patch.object(ops_mod, "_caddy_version", return_value="v2.test"):
            return self.client.get("/api/status", headers=AUTH).get_json()

    def test_null_without_any_change(self):
        audit.log_action("login", "admin@example.com")
        self.assertIsNone(self.status()["last_change"])

    def test_newest_save_or_restore_wins_and_logins_are_ignored(self):
        audit.log_action("save_reload", "a@example.com", "backup=Caddyfile.20261120-100000")
        audit.log_action("restore_reload", "b@example.com", "backup=x, from=Caddyfile.20261119-081000")
        audit.log_action("login", "c@example.com")
        change = self.status()["last_change"]
        self.assertEqual(change["action"], "restore")
        self.assertEqual(change["user"], "b@example.com")
        self.assertAlmostEqual(change["ts"], time.time(), delta=60)

    def test_rejected_reload_counts_only_when_the_file_was_left_changed(self):
        audit.log_action("save_reload_failed", "a@example.com", "rolled_back=True, nope")
        self.assertIsNone(self.status()["last_change"])
        audit.log_action("save_reload_failed", "a@example.com", "rolled_back=False, nope")
        self.assertEqual(self.status()["last_change"]["action"], "save")

    def test_found_in_the_rotated_file(self):
        audit.log_action("save_reload", "a@example.com")
        os.replace(env.AUDIT_LOG, audit.rotated_path())
        audit.log_action("login", "b@example.com")
        self.assertEqual(self.status()["last_change"]["user"], "a@example.com")


class ValidateWarningsApiTest(AppTestCase):
    def test_unformatted_content_gets_a_line_linked_warning_first(self):
        with mock.patch.object(editor_mod, "caddy_fmt", lambda c: c.replace("    ", "\t")):
            body = self.post("/api/validate", {"content": ":80 {\n    respond 200\n}\n"}).get_json()
        self.assertTrue(body["valid"])
        self.assertEqual(body["warnings"][0], "Line 2: not formatted — Check will fix whitespace on 1 line")
        self.assertEqual(body["formatted"], ":80 {\n\trespond 200\n}\n")

    def test_formatted_content_has_no_format_warning(self):
        body = self.post("/api/validate", {"content": ":80 {\n\trespond 200\n}\n"}).get_json()
        self.assertEqual(body["warnings"], [])


class ValidateResolveApiTest(AppTestCase):
    def test_validate_reports_unresolvable_upstreams(self):
        with mock.patch.object(editor_mod, "upstream_resolve_warnings",
                               return_value=["Line 2: upstream nope:80 could not be resolved from the console container"]):
            body = self.post("/api/validate", {"content": "a.example.com {\n\treverse_proxy nope:80\n}\n"}).get_json()
        self.assertIn("Line 2: upstream nope:80 could not be resolved from the console container", body["warnings"])

    def test_save_never_resolves(self):
        with mock.patch.object(editor_mod, "upstream_resolve_warnings", side_effect=AssertionError("save resolved")), \
             mock.patch.object(editor_mod.http_client, "post", lambda *a, **k: FakeResponse(200)):
            r = self.post("/api/save", {"content": "a.example.com {\n\treverse_proxy nope:80\n}\n"})
        self.assertEqual(r.status_code, 200)


def assert_inline_script_allowed(test, response):
    """Exactly one inline <script>, allowed by its sha256 and nothing looser."""
    html = response.get_data(as_text=True)
    inline = re.findall(r"<script>(.*?)</script>", html, re.S)
    test.assertEqual(len(inline), 1, "exactly one inline script")
    digest = "sha256-" + base64.b64encode(hashlib.sha256(inline[0].encode()).digest()).decode()
    script_src = re.search(r"script-src ([^;]+)", response.headers["Content-Security-Policy"]).group(1)
    test.assertIn(f"'{digest}'", script_src)
    test.assertNotIn("unsafe-inline", script_src)


class ThemeBootCspTest(AppTestCase):
    def test_app_page_theme_script_is_allowed_by_hash(self):
        assert_inline_script_allowed(self, self.client.get("/", headers=AUTH))

    def test_script_uses_the_shared_storage_key(self):
        from src import theme_boot
        self.assertIn(f"'{theme_boot.THEME_STORAGE_KEY}'", theme_boot.THEME_BOOT_JS)


class SignInPageTest(AppTestCase):
    def test_cloudflare_page_without_identity(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 403)
        html = r.get_data(as_text=True)
        self.assertIn("Protected by Cloudflare Access", html)
        self.assertIn("Manage the Caddy server at", html)
        self.assertIn(">localhost<", html)
        self.assertIn("allowed list", html)
        assert_inline_script_allowed(self, r)

    def test_api_still_answers_json(self):
        r = self.client.get("/api/me")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.get_json(), {"error": "unauthorized"})

    def test_server_url_wins_when_configured(self):
        with mock.patch.object(auth, "SERVER_URL_CONFIGURED", True), \
             mock.patch.object(auth, "SERVER_URL", "https://console.example.com"):
            html = self.client.get("/").get_data(as_text=True)
        self.assertIn(">console.example.com<", html)

    def test_no_host_reads_as_this_server(self):
        with self.app.test_request_context("/welcome"):
            html = flask.render_template("welcome.html", auth_mode="google", server_host="")
        self.assertIn("Manage this Caddy server:", html)
        self.assertNotIn("at this Caddy server", html)

    def test_google_variant(self):
        with self.app.test_request_context("/welcome"):
            html = flask.render_template("welcome.html", auth_mode="google",
                                         server_host="console.example.com")
        self.assertIn('href="/login"', html)
        self.assertIn("Sign in with Google", html)
        self.assertNotIn("Cloudflare Access", html)


if __name__ == "__main__":
    unittest.main()
