"""DELETE /api/security/crowdsec/decisions/<id>: delete one CrowdSec decision
in LAPI with the optional machine login, then drop the stored record.

Run with:  uv run --frozen python -m unittest tests.test_crowdsec_unban -v
"""
import logging
import os
import tempfile
import unittest
from unittest import mock

import tests._env as env
from tests import _bans, _crowdsec

from src import config
from src.bans import fsio, lapimachine, render, service, store

CS = render.SOURCES["crowdsec"]
BOTH = ("example.com {{\n\timport {d}/bans-manual*.caddy\n\timport {d}/bans-crowdsec*.caddy\n"
        "\trespond 200\n}}\n").format(d=env.BANS_DIR)
CREDS = {"CROWDSEC_MACHINE_ID": _crowdsec.MACHINE_ID, "CROWDSEC_MACHINE_PASSWORD": _crowdsec.MACHINE_PASSWORD,
         "CROWDSEC_MACHINE_ID_FILE": "", "CROWDSEC_MACHINE_PASSWORD_FILE": ""}
NO_CREDS = dict.fromkeys(CREDS, "")
URL = "/api/security/crowdsec/decisions/"


class UnbanTest(_bans.ApiCase):
    def setUp(self):
        super().setUp()
        _bans.write_caddyfile(BOTH)
        service.reset_caches()
        lapimachine.reset_cache()
        self.addCleanup(lapimachine.reset_cache)
        _crowdsec.enable(self, **CREDS)
        self.lapi = _crowdsec.FakeLapi().install(self)
        self.did = self.lapi.add("203.0.113.9")
        other = self.lapi.add("198.51.100.4")
        r = service.apply_crowdsec([_crowdsec.accepted("203.0.113.9", self.did),
                                    _crowdsec.accepted("198.51.100.4", other)], snapshot=True)
        self.assertEqual(r.code, "applied")

    def stored(self):
        return [r.source_id for r in store.load().records if r.source == "crowdsec"]

    def audit_text(self):
        with open(env.AUDIT_LOG, encoding="utf-8") as f:
            return f.read()

    def test_success_deletes_in_lapi_and_rerenders(self):
        with self.assertLogs(level=logging.DEBUG) as logs:
            logging.getLogger("probe").debug("start")
            r = self.delete(URL + self.did)
        self.assertEqual(r.status_code, 200, r.get_json())
        body = r.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["deleted"], self.did)
        self.assertNotIn(self.did, self.lapi.current)
        self.assertNotIn(self.did, self.stored())
        self.assertNotIn(b"203.0.113.9", fsio.read_bytes(CS.path))
        login, delete = self.lapi.writes
        self.assertEqual((login["method"], login["path"]), ("POST", "/v1/watchers/login"))
        self.assertEqual(login["json"], {"machine_id": _crowdsec.MACHINE_ID, "password": _crowdsec.MACHINE_PASSWORD})
        self.assertEqual((delete["method"], delete["path"]), ("DELETE", f"/v1/decisions/{self.did}"))
        self.assertTrue(delete["headers"]["Authorization"].startswith("Bearer jwt-"))
        self.assertEqual(delete["headers"]["User-Agent"], f"caddy-console/{config.APP_VERSION}")
        self.assertFalse(delete["allow_redirects"])
        audit = self.audit_text()
        self.assertIn("crowdsec_decision_deleted", audit)
        self.assertIn(f"id={self.did}", audit)
        for secret in (_crowdsec.MACHINE_PASSWORD, _crowdsec.KEY, "jwt-"):
            self.assertNotIn(secret, audit)
            self.assertNotIn(secret, r.get_data(as_text=True))
            self.assertNotIn(secret, "\n".join(logs.output))

    def test_token_is_cached(self):
        other = self.stored()[0] if self.stored()[0] != self.did else self.stored()[1]
        self.assertEqual(self.delete(URL + self.did).status_code, 200)
        self.assertEqual(self.delete(URL + other).status_code, 200)
        self.assertEqual([w["method"] for w in self.lapi.writes], ["POST", "DELETE", "DELETE"])

    def test_401_logs_in_again(self):
        other = [x for x in self.stored() if x != self.did][0]
        self.assertEqual(self.delete(URL + self.did).status_code, 200)
        self.lapi.revoke_tokens()                       # an expired or revoked JWT
        r = self.delete(URL + other)
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual([w["method"] for w in self.lapi.writes], ["POST", "DELETE", "DELETE", "POST", "DELETE"])
        self.assertEqual(self.stored(), [])

    def test_wrong_password_is_auth_failed(self):
        self.lapi.machines = {_crowdsec.MACHINE_ID: "something-else"}
        r = self.delete(URL + self.did)
        self.assertEqual((r.status_code, r.get_json()["code"]), (502, "crowdsec_auth_failed"))
        self.assertIn(self.did, self.stored())
        self.assertNotIn(_crowdsec.MACHINE_PASSWORD, r.get_data(as_text=True))

    def test_unreachable(self):
        self.lapi.write_mode = "down"
        r = self.delete(URL + self.did)
        self.assertEqual((r.status_code, r.get_json()["code"]), (503, "crowdsec_unreachable"))
        self.assertIn(self.did, self.stored())

    def test_unknown_or_invalid_id_is_refused_before_lapi(self):
        for raw, status, code in (("999", 404, "decision_not_found"), ("0", 400, "invalid_decision_id"),
                                  ("-1", 400, "invalid_decision_id"), ("01", 400, "invalid_decision_id"),
                                  ("203.0.113.9", 400, "invalid_decision_id")):
            r = self.delete(URL + raw)
            self.assertEqual((r.status_code, r.get_json()["code"]), (status, code), raw)
        self.assertEqual(self.lapi.writes, [])

    def test_manual_record_id_is_not_a_decision(self):
        rid = self.post("/api/bans", {"value": "203.0.113.77", "duration": "24h"}).get_json()["record"]["id"]
        r = self.delete(URL + rid)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.lapi.writes, [])

    def test_already_gone_in_lapi_still_drops_local(self):
        self.lapi.current.pop(self.did)
        r = self.delete(URL + self.did)
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertTrue(r.get_json()["already_gone"])
        self.assertNotIn(self.did, self.stored())

    def test_credentials_missing(self):
        for name, value in NO_CREDS.items():
            p = mock.patch.object(config, name, value)
            p.start()
            self.addCleanup(p.stop)
        r = self.delete(URL + self.did)
        self.assertEqual((r.status_code, r.get_json()["code"]), (409, "crowdsec_write_not_configured"))
        self.assertEqual(self.lapi.writes, [])
        self.assertFalse(self.get("/api/security").get_json()["sources"]["crowdsec"]["write_configured"])

    def test_status_reports_write_access_without_secrets(self):
        r = self.get("/api/security")
        self.assertTrue(r.get_json()["sources"]["crowdsec"]["write_configured"])
        self.assertNotIn(_crowdsec.MACHINE_PASSWORD, r.get_data(as_text=True))

    def test_password_equal_to_bouncer_key_is_refused(self):
        p = mock.patch.object(config, "CROWDSEC_MACHINE_PASSWORD", _crowdsec.KEY)
        p.start()
        self.addCleanup(p.stop)
        r = self.delete(URL + self.did)
        self.assertEqual(r.status_code, 409)
        self.assertIn("differ from the bouncer key", r.get_json()["message"])
        self.assertNotIn(_crowdsec.KEY, r.get_data(as_text=True))

    def test_password_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(_crowdsec.MACHINE_PASSWORD + "\n")
        self.addCleanup(os.remove, f.name)
        for name, value in (("CROWDSEC_MACHINE_PASSWORD", ""), ("CROWDSEC_MACHINE_PASSWORD_FILE", f.name)):
            p = mock.patch.object(config, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.assertEqual(self.delete(URL + self.did).status_code, 200)

    def test_csrf_required(self):
        r = self.client.delete(URL + self.did, headers=_bans.AUTH)
        self.assertIn(r.status_code, (400, 403))
        self.assertEqual(self.lapi.writes, [])


if __name__ == "__main__":
    unittest.main()
