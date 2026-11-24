"""Manual file mode against stock caddy:2.11.9-alpine (spec "Caddy integration tests").

  docker compose -f docker-compose.dev.yaml exec -T caddy-console \
    /app/.venv/bin/python -m unittest tests.integration.bans_caddy_it -v
"""
import tests.integration._env as itenv  # noqa: I001  (must precede src imports)

import contextlib
import json
import os
import re
import shutil
import unittest
from datetime import timedelta
from unittest import mock

import requests

from src import create_app
from src.bans import addr, caddy as caddy_admin, detect, fsio, render, service, store, txn
from src.routes.editor import caddyfile_lock

D = itenv.BANS_DIR
SITE_LOG = "/var/log/caddy/itest-access.log"
BANNED, ALLOWED = "203.0.113.7", "203.0.113.8"
AUTH = {"Cf-Access-Authenticated-User-Email": "it@example.com"}
IMP = f"import {D}/bans-manual*.caddy"
HASH = "$2a$14$Zkx19XLiW6VYouLHR5NmfOFU0z2GTNmpkT/5qqR7hx4IjWJPDhjvG"
CADDYFILE = f"""{{
\tadmin 0.0.0.0:2019
\tservers {{
\t\ttrusted_proxies static private_ranges
\t\tclient_ip_headers X-Forwarded-For
\t}}
}}

&(named) {{
\trespond "named" 200
}}

http://proxy.it.example.com {{
\t{IMP}
\tlog {{
\t\toutput file {SITE_LOG} {{
\t\t\tmode 0644
\t\t}}
\t\tformat json
\t}}
\treverse_proxy 127.0.0.1:80 {{
\t\theader_up Host plain.it.example.com
\t}}
}}

http://plain.it.example.com {{
\trespond "plain" 200
}}

http://handle.it.example.com {{
\t{IMP}
\thandle /api/* {{
\t\trespond "api" 200
\t}}
\thandle {{
\t\trespond "app" 200
\t}}
}}

http://path.it.example.com {{
\t{IMP}
\thandle_path /static/* {{
\t\trespond "static" 200
\t}}
\thandle {{
\t\trespond "app" 200
\t}}
}}

http://route.it.example.com {{
\t{IMP}
\troute {{
\t\trespond "app" 200
\t}}
}}

http://strict.it.example.com {{
\troute {{
\t\t{IMP}
\t\tredir /old /new
\t\trespond "app" 200
\t}}
}}

http://redir.it.example.com {{
\t{IMP}
\tredir /old /new
\trespond "app" 200
}}

http://rewrite.it.example.com {{
\t{IMP}
\trewrite /old /new
\trespond "app" 200
}}

http://basicauth.it.example.com {{
\t{IMP}
\tbasic_auth {{
\t\tBob {HASH}
\t}}
\trespond "app" 200
}}

http://fwdauth.it.example.com {{
\t{IMP}
\tforward_auth 127.0.0.1:80 {{
\t\turi /verify
\t\theader_up Host auth.it.example.com
\t}}
\trespond "app" 200
}}

http://auth.it.example.com {{
\trespond 200
}}

http://invoke.it.example.com {{
\t{IMP}
\tinvoke named
}}

http://console.it.example.com {{
\treverse_proxy caddy-console:9090
}}
"""
BROKEN = CADDYFILE + "\nhttp://bad.it.example.com {\n\tlog {\n\t\toutput file /nonexistent-dir/x.log\n\t}\n\trespond 200\n}\n"


def write_caddyfile(text):
    with open(f"{itenv.ROOT}/Caddyfile", "w", encoding="utf-8") as f:
        f.write(text)


def reset_itest(load=True):
    for name in os.listdir(itenv.BACKUP_DIR):
        if name.startswith(("bans", ".bans", ".policy-transactions", "audit.log", "allowlist")):
            path = os.path.join(itenv.BACKUP_DIR, name)
            shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)
    shutil.rmtree(D, ignore_errors=True)
    os.makedirs(D)
    write_caddyfile(CADDYFILE)
    service.reset_caches()
    if load:
        assert caddy_admin.load(CADDYFILE).status == "applied"


def get(host, path="/", ip=ALLOWED):
    return requests.get(itenv.DATA_URL + path, headers={"Host": host, "X-Forwarded-For": ip},
                        allow_redirects=False, timeout=5)


@contextlib.contextmanager
def crash_at(point):
    class Crash(BaseException):
        pass

    def boom(name):
        if name == point:
            raise Crash(name)
    with mock.patch.object(txn, "_checkpoint", boom):
        try:
            yield
        except Crash:
            pass


class StockCaddyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open("/etc/caddy/Caddyfile", encoding="utf-8") as f:
            cls.dev_caddyfile = f.read()
        cls.app = create_app()
        cls.app.testing = True

    @classmethod
    def tearDownClass(cls):
        caddy_admin.load(cls.dev_caddyfile)

    def setUp(self):
        reset_itest()
        self.client = self.app.test_client()
        page = self.client.get("/", headers=AUTH).get_data(as_text=True)
        self.h = {**AUTH, "X-CSRF-Token": re.search(r'name="csrf-token" content="([^"]+)"', page).group(1)}

    def ban(self, value=BANNED, duration="4h"):
        r = self.client.post("/api/bans", json={"value": value, "duration": duration, "reason": ""}, headers=self.h)
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        return r.get_json()

    def sites(self):
        return {s["label"]: s for s in self.client.get("/api/security", headers=AUTH).get_json()["sites"]}

    def test_ban_and_unban_on_a_reverse_proxy_site(self):
        self.assertEqual(get("proxy.it.example.com", ip=BANNED).status_code, 200)
        body = self.ban()
        self.assertEqual(body["enforcement"], "enforced")
        self.assertEqual(get("proxy.it.example.com", ip=BANNED).status_code, 403)
        self.assertEqual(get("proxy.it.example.com").text, "plain")
        r = self.client.delete(f"/api/bans/{body['record']['id']}", headers=self.h)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(get("proxy.it.example.com", ip=BANNED).status_code, 200)

    def test_enforced_before_handle_handle_path_and_route(self):
        self.ban()
        for host, paths in (("handle.it.example.com", ("/", "/api/x")),
                            ("path.it.example.com", ("/", "/static/x")),
                            ("route.it.example.com", ("/",))):
            for p in paths:
                with self.subTest(host=host, path=p):
                    self.assertEqual(get(host, p, BANNED).status_code, 403)
                    self.assertEqual(get(host, p).status_code, 200)

    def test_path_specific_handle_does_not_bypass(self):
        self.ban()
        self.assertEqual(get("handle.it.example.com", "/api/x", BANNED).status_code, 403)
        self.assertEqual(get("handle.it.example.com", "/api/x").text, "api")

    def test_pre_handlers_are_reported_and_strict_route_enforces_first(self):
        self.ban()
        sites = self.sites()
        expect = {"proxy.it.example.com": ("enforced", []), "strict.it.example.com": ("enforced", []),
                  "redir.it.example.com": ("enforced_pre_handler", ["redir"]),
                  "rewrite.it.example.com": ("enforced_pre_handler", ["rewrite"]),
                  "basicauth.it.example.com": ("enforced_pre_handler", ["basic_auth"]),
                  "fwdauth.it.example.com": ("enforced_pre_handler", ["forward_auth"]),
                  "invoke.it.example.com": ("unknown", ["invoke"]),
                  "plain.it.example.com": ("not_imported", []),
                  "console.it.example.com": ("management", [])}
        for host, (status, pre) in expect.items():
            with self.subTest(host=host):
                self.assertEqual((sites[host]["status"], sites[host]["pre_handlers"]), (status, pre))
        self.assertEqual(get("strict.it.example.com", "/old", BANNED).status_code, 403)
        self.assertIn(get("redir.it.example.com", "/old", BANNED).status_code, (301, 302, 307, 308))
        self.assertEqual(get("redir.it.example.com", "/", BANNED).status_code, 403)
        self.assertEqual(get("rewrite.it.example.com", "/old", BANNED).status_code, 403)
        self.assertEqual(get("fwdauth.it.example.com", "/", BANNED).status_code, 403)
        self.assertEqual(get("fwdauth.it.example.com").status_code, 200)
        self.assertNotEqual(get("basicauth.it.example.com", "/", BANNED).status_code, 200)
        # Reported as not verified because the named route answers before the ban check:
        self.assertEqual(get("invoke.it.example.com", "/", BANNED).text, "named")

    def test_expiry_regenerates_and_reloads(self):
        self.ban(duration="4h")
        self.assertEqual(service.expire_tick(now=store.utc_now() + timedelta(hours=5)), "applied")
        self.assertEqual(get("proxy.it.example.com", ip=BANNED).status_code, 200)

    def test_crash_between_policy_and_state_replacement_recovers(self):
        self.ban("203.0.113.9", "permanent")
        before = fsio.read_bytes(store.STATE_PATH)
        with crash_at("replaced:bans-manual.caddy"):
            service.add_ban({"value": BANNED, "duration": "4h"}, "it@example.com", None)
        with caddyfile_lock():
            self.assertIsNone(txn.resolve_pending())
        self.assertEqual(fsio.read_bytes(store.STATE_PATH), before)
        self.assertEqual(get("proxy.it.example.com", ip=BANNED).status_code, 200)
        with crash_at("loaded"):
            service.add_ban({"value": BANNED, "duration": "4h"}, "it@example.com", None)
        with caddyfile_lock():
            self.assertIsNone(txn.resolve_pending())
        self.assertIn(BANNED, [r.value for r in store.load().records])
        self.assertEqual(get("proxy.it.example.com", ip=BANNED).status_code, 403)

    def test_protected_addresses_bypass_at_runtime(self):
        self.ban()
        state = store.load()
        state.records.append(store.new_manual_record(addr.canonical("10.0.0.0/16"), "permanent", "", "it", store.utc_now()))
        fsio.atomic_write(store.STATE_PATH, store.dumps(state), 0o600)
        r = self.client.post("/api/security/reapply", json={"source": "manual"}, headers=self.h)
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertIn(b"client_ip 10.0.0.0/16 203.0.113.7", fsio.read_bytes(render.SOURCES["manual"].path))
        self.assertEqual(get("proxy.it.example.com", ip="10.0.0.5").status_code, 200)
        self.assertEqual(get("proxy.it.example.com", ip=BANNED).status_code, 403)

    def test_allowlisted_ip_is_not_blocked_under_a_banned_range(self):
        self.ban("203.0.113.0/24")
        self.assertEqual(get("proxy.it.example.com", ip=ALLOWED).status_code, 403)
        r = self.client.post("/api/security/allowlist", json={"value": ALLOWED, "note": "it"}, headers=self.h)
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        self.assertEqual(r.get_json()["reload_status"], "applied")
        self.assertEqual(get("proxy.it.example.com", ip=ALLOWED).status_code, 200)
        self.assertEqual(get("proxy.it.example.com", ip=BANNED).status_code, 403)
        records = self.client.get("/api/bans", headers=AUTH).get_json()["records"]
        self.assertEqual(records[0]["protected"], "allowlist")
        r = self.client.delete(f"/api/security/allowlist/{r.get_json()['entry']['id']}", headers=self.h)
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertEqual(get("proxy.it.example.com", ip=ALLOWED).status_code, 403)

    def test_exact_file_absence_fails_but_glob_absence_does_not(self):
        self.assertFalse(os.path.exists(render.SOURCES["manual"].path))
        self.assertEqual(get("proxy.it.example.com", ip=BANNED).status_code, 200)   # setUp loaded the glob
        exact = CADDYFILE.replace(f"{D}/bans-manual*.caddy", f"{D}/bans-manual.caddy", 1)
        self.assertFalse(caddy_admin.adapt(exact).ok)

    def test_empty_policy_keeps_its_marker_without_a_matcher(self):
        body = self.ban()
        self.client.delete(f"/api/bans/{body['record']['id']}", headers=self.h)
        live = caddy_admin.live_config()
        self.assertTrue(detect.marker_present(live, render.SOURCES["manual"].marker))
        self.assertNotIn('"client_ip":{"ranges"', caddy_admin.normalize(live).decode())
        self.assertEqual(self.sites()["proxy.it.example.com"]["status"], "imported_empty")

    def test_rejected_then_accepted_reload(self):
        write_caddyfile(BROKEN)                         # adapts, but cannot provision the log file
        policy_before = fsio.read_bytes(render.SOURCES["manual"].path)
        r = self.client.post("/api/bans", json={"value": BANNED, "duration": "4h"}, headers=self.h)
        self.assertEqual((r.status_code, r.get_json()["code"]), (502, "reload_rejected"))
        self.assertEqual(fsio.read_bytes(render.SOURCES["manual"].path), policy_before)
        self.assertEqual(get("proxy.it.example.com", ip=BANNED).status_code, 200)
        write_caddyfile(CADDYFILE)
        self.ban()
        self.assertEqual(get("proxy.it.example.com", ip=BANNED).status_code, 403)

    def test_403_appears_in_the_access_log(self):
        self.ban()
        self.assertEqual(get("proxy.it.example.com", "/probe-403", BANNED).status_code, 403)
        with open(SITE_LOG, encoding="utf-8") as f:
            last = [json.loads(line) for line in f if "/probe-403" in line][-1]
        self.assertEqual((last["status"], last["request"]["client_ip"]), (403, BANNED))

    def test_console_site_stays_reachable_and_is_never_offered_the_import(self):
        self.ban()
        self.assertEqual(get("console.it.example.com", "/health", BANNED).status_code, 200)
        self.assertEqual(self.sites()["console.it.example.com"]["status"], "management")
        context = self.client.get("/api/snippets", headers=AUTH).get_json()["context"]
        self.assertIn("console.it.example.com", context["management_hosts"])

    def test_shipped_site_snippet_adapts(self):
        snippets = self.client.get("/api/snippets", headers=AUTH).get_json()["snippets"]
        code = next(s["code"] for s in snippets if s.get("id") == "manual-bans-site")
        text = "{\n\tadmin 0.0.0.0:2019\n}\nhttp://snippet.it.example.com {\n\t" + code.strip() + "\n\trespond 200\n}\n"
        self.assertTrue(caddy_admin.adapt(text).ok)


if __name__ == "__main__":
    unittest.main()
