"""Per-source site detection and the CrowdSec part of GET /api/security
(spec "Mode detection and health", 2.7).

Run with:  uv run --frozen python -m unittest tests.test_crowdsec_status -v
"""
import json
import os
import unittest
from datetime import timedelta
from unittest import mock

import tests._env as env
from tests import _bans, _crowdsec

from src import config
from src.bans import addr, detect, fsio, protected, render, scan, service, store, syncstate

CS, MANUAL = render.SOURCES["crowdsec"], render.SOURCES["manual"]
with open(os.path.join(os.path.dirname(__file__), "fixtures", "bans", "adapted-layouts.json"), encoding="utf-8") as f:
    FIXTURES = json.load(f)
D = env.BANS_DIR


def write_state(manual=(), crowdsec=()):
    now = store.utc_now()
    state = store.State()
    for v in manual:
        state.records.append(store.new_manual_record(addr.canonical(v), "24h", "", "a@example.com", now))
    for i, v in enumerate(crowdsec, 1):
        state.records.append(store.new_crowdsec_record(str(i), addr.canonical(v), "crowdsec", "s", now,
                                                       now + timedelta(hours=4)))
    fsio.atomic_write(store.STATE_PATH, store.dumps(state), 0o600)


def sync_doc(**extra):
    return {"version": syncstate.VERSION, "updated_at": store.iso(store.utc_now()), "lapi_state": "ok",
            "apply_state": "ok", "decisions": 3, "leader_pid": os.getpid(), **extra}


class DetectTest(unittest.TestCase):
    def test_a_manual_ban_route_before_the_crowdsec_one_is_not_a_pre_handler(self):
        live = FIXTURES["manual_and_crowdsec"]
        m = detect.site_statuses(live, MANUAL, True, expected_ranges=["198.51.100.0/24", "203.0.113.7"])[0]
        c = detect.site_statuses(live, CS, True, expected_ranges=["192.0.2.0/24", "203.0.113.9"])[0]
        self.assertEqual((m.status, c.status, c.pre_handlers), ("enforced", "enforced", []))
        only = detect.site_statuses(FIXTURES["crowdsec_only"], CS, True)[0]
        self.assertEqual(only.status, "enforced")
        self.assertEqual(detect.site_statuses(FIXTURES["crowdsec_only"], MANUAL, False)[0].status, "not_imported")

    def test_import_position_after_the_manual_import(self):
        text = (f"a.example.com {{\n\timport {D}/bans-manual*.caddy\n\timport {D}/bans-crowdsec*.caddy\n\trespond 200\n}}\n"
                f"b.example.com {{\n\trespond 200\n\timport {D}/bans-crowdsec*.caddy\n}}\n"
                f"c.example.com {{\n\troute {{\n\t\timport {D}/bans-manual*.caddy\n\t\timport {D}/bans-crowdsec*.caddy\n"
                "\t\trespond 200\n\t}\n}\n")
        a, b, c = scan.site_blocks(text)
        after = (MANUAL.path,)
        self.assertTrue(scan.block_import_state(text, a, CS.path, after=after)["first_child"])
        self.assertFalse(scan.block_import_state(text, a, CS.path)["first_child"])     # Phase 1 rule unchanged
        self.assertFalse(scan.block_import_state(text, b, CS.path, after=after)["first_child"])
        self.assertEqual(scan.block_import_state(text, c, CS.path, after=after)["layout"], "strict")

    def test_crowdsec_import_after_manual_uses_render_after(self):
        text = (f"a.example.com {{\n\timport {D}/bans-manual*.caddy\n\timport {D}/bans-crowdsec*.caddy\n\trespond 200\n}}\n")
        block = scan.site_blocks(text)[0]
        after = tuple(render.SOURCES[n].path for n in render.AFTER["crowdsec"])
        self.assertTrue(scan.block_import_state(text, block, CS.path, after=after)["first_child"])


class StatusCase(unittest.TestCase):
    def setUp(self):
        _bans.reset(f"a.example.com {{\n\timport {D}/bans-manual*.caddy\n\timport {D}/bans-crowdsec*.caddy\n"
                    "\treverse_proxy 127.0.0.1:9\n}\n")
        _bans.fresh_audit(self)
        service.reset_caches()
        docker = mock.patch.object(protected, "read_docker_networks", lambda: [])
        docker.start()
        self.addCleanup(docker.stop)
        self.caddy = _bans.FakeCaddy().install(self)

    def tearDown(self):
        service.reset_caches()


class StatusTest(StatusCase):
    def test_crowdsec_source_appears_only_when_active(self):
        self.assertEqual(list(service.status(None)["sources"]), ["manual"])
        _crowdsec.enable(self)
        status = service.status(None)
        self.assertEqual(list(status["sources"]), ["manual", "crowdsec"])
        cs = status["sources"]["crowdsec"]
        self.assertEqual((cs["enabled"], cs["origins"], cs["list_origins"], cs["sync"], cs["stale"]),
                         (True, ["crowdsec", "cscli"], [], None, True))
        self.assertEqual(cs["import_line"], f"import {D}/bans-crowdsec*.caddy")

    def test_sync_report_and_staleness(self):
        _crowdsec.enable(self, CROWDSEC_ORIGINS="crowdsec,capi")
        doc = sync_doc()
        syncstate.write(doc)
        cs = service.status(None)["sources"]["crowdsec"]
        self.assertEqual((cs["sync"]["decisions"], cs["stale"], cs["list_origins"]), (3, False, ["capi"]))
        syncstate.write({**doc, "updated_at": store.iso(store.utc_now() - timedelta(minutes=5))})
        self.assertTrue(service.status(None)["sources"]["crowdsec"]["stale"])

    def test_a_dead_leader_pid_is_stale_even_when_the_report_is_fresh(self):
        _crowdsec.enable(self)
        syncstate.write(sync_doc(leader_pid=2 ** 22 + 12345))
        with mock.patch("os.kill", side_effect=ProcessLookupError):
            self.assertTrue(service.status(None)["sources"]["crowdsec"]["stale"])
        syncstate.write(sync_doc())
        self.assertFalse(service.status(None)["sources"]["crowdsec"]["stale"])

    def test_a_report_left_behind_is_hidden_once_crowdsec_is_not_enabled(self):
        _crowdsec.enable(self)
        write_state(crowdsec=("203.0.113.9",))              # records keep the source active after disabling
        syncstate.write(sync_doc())
        with mock.patch.object(config, "CROWDSEC_URL", ""):
            cs = service.status(None)["sources"]["crowdsec"]
        self.assertEqual((cs["enabled"], cs["sync"], cs["origins"]), (False, None, []))

    def test_sites_report_each_source(self):
        _crowdsec.enable(self)
        write_state(manual=("198.51.100.0/24", "203.0.113.7"), crowdsec=("192.0.2.0/24", "203.0.113.9"))
        self.caddy.live = FIXTURES["manual_and_crowdsec"]
        status = service.status(None)
        row = status["sites"][0]
        self.assertEqual((row["status"], row["policies"]["manual"]["status"], row["policies"]["crowdsec"]["status"]),
                         ("enforced", "enforced", "enforced"))
        self.assertTrue(row["policies"]["crowdsec"]["import"]["first_child"])
        self.assertEqual(status["limits"], {"max_prefixes": config.BANS_MAX, "used": 4,
                                            "by_source": {"manual": 2, "crowdsec": 2}})

    def test_console_site_importing_crowdsec_is_a_lockout_risk(self):
        _crowdsec.enable(self)
        _bans.write_caddyfile(f"a.example.com {{ # caddy-console: management\n\timport {D}/bans-crowdsec*.caddy\n"
                              "\treverse_proxy 127.0.0.1:9\n}\n")
        row = service.status(None)["sites"][0]
        self.assertEqual((row["status"], row["policies"]["crowdsec"]["status"]), ("management", "management_imported"))

    def test_unreachable_caddy_marks_every_policy_unknown(self):
        _crowdsec.enable(self)
        self.caddy.down = True
        row = service.status(None)["sites"][0]
        self.assertEqual({p["status"] for p in row["policies"].values()}, {"caddy_unreachable"})

    def test_held_sources_are_listed_for_recovery(self):
        _crowdsec.enable(self)
        service.add_ban({"value": "203.0.113.7", "duration": "24h", "reason": ""}, "op", None)
        fsio.atomic_write(CS.path, b"", 0o644)
        info = service.recovery_info()
        self.assertEqual((info["kind"], info["held_sources"], info["files"]), ("policy_hold", ["crowdsec"],
                                                                              ["bans-crowdsec.caddy"]))
        self.assertTrue(service.status(None)["sources"]["crowdsec"]["hold"])

    def test_the_key_never_appears_in_status_even_when_injected_into_messages(self):
        _crowdsec.enable(self)
        leaky = f"LAPI said {_crowdsec.KEY}"
        syncstate.write(sync_doc(lapi_state="auth_failed", lapi_message=leaky, apply_message=leaky))
        body = json.dumps(service.status(None))
        self.assertIn("auth_failed", body)                  # the report is really included
        self.assertNotIn(_crowdsec.KEY, body)


class ApiTest(_bans.ApiCase):
    def test_security_api_reports_crowdsec_and_bans_lists_it_read_only(self):
        _crowdsec.enable(self)
        write_state(crowdsec=("203.0.113.9",))
        body = self.get("/api/security").get_json()
        self.assertIn("crowdsec", body["sources"])
        rec = next(r for r in self.get("/api/bans").get_json()["records"] if r["source"] == "crowdsec")
        self.assertEqual(self.delete(f"/api/bans/{rec['id']}").status_code, 403)

    def test_an_injected_key_is_absent_from_every_response(self):
        _crowdsec.enable(self)
        write_state(crowdsec=("203.0.113.9",))
        leaky = f"LAPI said {_crowdsec.KEY}"
        syncstate.write(sync_doc(lapi_state="auth_failed", lapi_message=leaky, apply_message=leaky))
        rec = next(r for r in self.get("/api/bans").get_json()["records"] if r["source"] == "crowdsec")
        responses = [self.get("/api/security"), self.get("/api/bans"), self.delete(f"/api/bans/{rec['id']}")]
        self.assertIn("auth_failed", responses[0].get_data(as_text=True))
        for resp in responses:
            self.assertNotIn(_crowdsec.KEY, resp.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
