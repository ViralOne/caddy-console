"""Security API: auth, CSRF, contracts and the BANS_ENABLED gate.

Run with:  uv run --frozen python -m unittest tests.test_bans_api -v
"""
import re
import tempfile
import unittest
from unittest import mock

import tests._env as env
from tests import _bans, _crowdsec

from src import config, create_app
from src.bans import service, store

AUTH = _bans.AUTH
MUTATIONS = (("post", "/api/bans"), ("delete", "/api/bans/some-id"), ("post", "/api/security/reapply"),
             ("post", "/api/security/reset"), ("post", "/api/security/recovery"))


class SecurityApiTest(_bans.ApiCase):
    def setUp(self):
        super().setUp()
        service.reset_caches()

    def test_reads_need_login(self):
        for url in ("/api/security", "/api/security/recovery", "/api/bans"):
            self.assertEqual(self.client.get(url).status_code, 401, url)
        self.assertEqual(self.client.get("/security").status_code, 403)

    def test_mutations_need_login_and_csrf(self):
        for method, url in MUTATIONS:
            with self.subTest(url=url):
                call = getattr(self.client, method)
                self.assertEqual(call(url, json={}, headers=AUTH).status_code, 403)          # no CSRF token
                self.assertEqual(call(url, json={}, headers={"X-CSRF-Token": self.csrf}).status_code, 401)

    def test_ban_round_trip_over_http(self):
        r = self.post("/api/bans", {"value": "203.0.113.7", "duration": "4h", "reason": "<b>probe</b>"})
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        record = r.get_json()["record"]
        self.assertEqual(record["reason"], "<b>probe</b>")             # stored as plain data
        listed = self.get("/api/bans").get_json()["records"]
        self.assertEqual([x["id"] for x in listed], [record["id"]])
        self.assertEqual(self.get("/api/bans?covering=203.0.113.7").get_json()["exact_ids"], [record["id"]])
        self.assertEqual(self.delete(f"/api/bans/{record['id']}").status_code, 200)
        self.assertEqual(self.get("/api/bans").get_json()["records"], [])

    def test_payload_validation_codes(self):
        cases = ((["x"], "invalid_request"),
                 ({"value": "203.0.113.7", "duration": "1h"}, "invalid_duration"),
                 ({"value": "203.0.113.7", "duration": "4h", "reason": "x" * 501}, "invalid_reason"),
                 ({"value": "127.0.0.1", "duration": "4h"}, "protected_overlap"),
                 ({"value": "203.0.113.0/33", "duration": "4h"}, "invalid_range"))
        for payload, code in cases:
            with self.subTest(code=code):
                r = self.post("/api/bans", payload)
                self.assertEqual((r.status_code, r.get_json()["code"]), (400, code))

    def test_recovery_contract(self):
        r = self.post("/api/security/recovery", {"recovery_id": "x", "action": "drop_tables"})
        self.assertEqual(r.get_json()["code"], "invalid_action")
        r = self.post("/api/security/recovery", {"recovery_id": "x", "action": "use_previous"})
        self.assertEqual((r.status_code, r.get_json()["code"]), (409, "recovery_stale"))
        self.post("/api/bans", {"value": "203.0.113.7", "duration": "4h"})
        self.post("/api/bans", {"value": "192.0.2.1", "duration": "4h"})
        with open(store.STATE_PATH, "wb") as f:
            f.write(b"{broken")
        info = self.get("/api/security/recovery").get_json()
        self.assertEqual(info["kind"], "state_corrupt")
        for backup_id in ("../../etc/passwd", store.STATE_PATH, ""):
            r = self.post("/api/security/recovery", {"recovery_id": info["recovery_id"],
                                                     "action": "restore_backup", "backup_id": backup_id})
            self.assertEqual(r.get_json()["code"], "invalid_backup")

    def test_status_shape(self):
        body = self.get("/api/security").get_json()
        self.assertTrue({"enabled", "available", "degraded", "recovery", "sources", "protected",
                         "sites", "caddy", "limits", "last_apply", "state_version"} <= set(body))
        self.assertEqual(body["sources"]["manual"]["import_line"], f"import {env.BANS_DIR}/bans-manual*.caddy")

    def test_page_has_the_security_tab(self):
        html = self.get("/").get_data(as_text=True)
        self.assertIn('data-view="security"', html)
        self.assertIn('data-bans="on"', html)
        self.assertEqual(self.get("/security").status_code, 200)

    def test_snippets_carry_context_and_bans_dir(self):
        body = self.get("/api/snippets").get_json()
        site = next(s for s in body["snippets"] if s.get("id") == "manual-bans-site")
        self.assertEqual(site["code"], f"import {env.BANS_DIR}/bans-manual*.caddy\n")
        self.assertEqual((site["scope"], site["insert"]), ("site", "site-first"))
        self.assertEqual(body["context"]["bans_dir"], env.BANS_DIR)
        self.assertIsInstance(body["context"]["management_hosts"], list)

    def test_validate_reports_ban_import_problems(self):
        text = f"a.example.com {{\n\trespond 200\n\timport {env.BANS_DIR}/bans-manual*.caddy\n}}\n"
        warnings = self.post("/api/validate", {"content": text}).get_json()["warnings"]
        self.assertTrue(any("put the ban import first" in w for w in warnings), warnings)

    def test_editor_still_saves_while_bans_are_unavailable(self):
        with mock.patch.object(config, "BANS_DIR", tempfile.mkdtemp()):
            service.reset_caches()
            self.assertFalse(self.get("/api/security").get_json()["available"])
            r = self.post("/api/save", {"content": "example.com {\n\trespond 200\n}\n"})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))

    def test_crowdsec_snippets_only_when_configured(self):
        ids = [s.get("id") for s in self.get("/api/snippets").get_json()["snippets"]]
        self.assertNotIn("crowdsec-bans-site", ids)
        self.assertNotIn("crowdsec-log-fields", ids)
        _crowdsec.enable(self)
        body = self.get("/api/snippets").get_json()
        by_id = {s.get("id"): s for s in body["snippets"]}
        self.assertEqual(by_id["crowdsec-bans-site"]["code"], f"import {env.BANS_DIR}/bans-crowdsec*.caddy\n")
        self.assertIn("crowdsec-log-fields", by_id)
        self.assertTrue(body["context"]["crowdsec"])

    def test_validate_reports_crowdsec_import_problems(self):
        text = f"a.example.com {{\n\trespond 200\n\timport {env.BANS_DIR}/bans-crowdsec*.caddy\n}}\n"
        self.assertFalse(any("CrowdSec" in w for w in self.post("/api/validate", {"content": text}).get_json()["warnings"]))
        _crowdsec.enable(self)
        warnings = self.post("/api/validate", {"content": text}).get_json()["warnings"]
        self.assertTrue(any("put the CrowdSec import first" in w for w in warnings), warnings)
        ok = (f"a.example.com {{\n\timport {env.BANS_DIR}/bans-manual*.caddy\n"
              f"\timport {env.BANS_DIR}/bans-crowdsec*.caddy\n\trespond 200\n}}\n")
        self.assertEqual([w for w in self.post("/api/validate", {"content": ok}).get_json()["warnings"]
                          if "import" in w], [])


class DisabledTest(unittest.TestCase):
    def test_everything_is_absent_and_nothing_is_checked(self):
        with mock.patch.object(config, "BANS_ENABLED", False), \
                mock.patch.object(config, "BANS_NEVER", "not-an-ip"), \
                mock.patch.object(service, "availability", side_effect=AssertionError("must not run")):
            app = create_app()
            app.testing = True
            client = app.test_client()
            html = client.get("/", headers=AUTH).get_data(as_text=True)
            csrf = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
            self.assertNotIn('data-view="security"', html)
            self.assertIn('data-bans="off"', html)
            for url in ("/security", "/api/security", "/api/security/recovery", "/api/bans"):
                self.assertEqual(client.get(url, headers=AUTH).status_code, 404, url)
            for method, url in MUTATIONS:
                r = getattr(client, method)(url, json={}, headers={**AUTH, "X-CSRF-Token": csrf})
                self.assertEqual(r.status_code, 404, url)
            body = client.get("/api/snippets", headers=AUTH).get_json()
            ids = [s.get("id") for s in body["snippets"]]
            self.assertNotIn("manual-bans-site", ids)
            self.assertNotIn("manual-bans-recovery", ids)
            self.assertEqual(body["context"], {})
            from src.bans import jobs
            self.assertIsNone(jobs.start_background())

    def test_invalid_bans_never_refuses_startup_when_enabled(self):
        with mock.patch.object(config, "BANS_NEVER", "203.0.113.7, nope"):
            service.reset_caches()
            with self.assertRaisesRegex(RuntimeError, "BANS_NEVER"):
                create_app()
        service.reset_caches()


if __name__ == "__main__":
    unittest.main()
