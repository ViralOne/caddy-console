"""The stream synchronizer against the fake LAPI and the fake admin API
(spec 2.4, 2.6, Testing: startup reconciliation, failover, malformed response,
auth failure, outage recovery, independent decisions).

Run with:  uv run --frozen python -m unittest tests.test_crowdsec_sync -v
"""
import fcntl
import logging
import os
import unittest
from datetime import timedelta
from unittest import mock

import tests._env as env
from tests import _bans, _crowdsec

from src import audit, config
from src.bans import fsio, lapi, protected, render, service, store, sync, syncstate
from src.routes import editor

CS, MANUAL = render.SOURCES["crowdsec"], render.SOURCES["manual"]
BOTH = ("example.com {{\n\timport {d}/bans-manual*.caddy\n\timport {d}/bans-crowdsec*.caddy\n"
        "\trespond 200\n}}\n").format(d=env.BANS_DIR)


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class SyncCase(unittest.TestCase):
    def setUp(self):
        _bans.reset(BOTH)
        _bans.fresh_audit(self)
        service.reset_caches()
        docker = mock.patch.object(protected, "read_docker_networks", lambda: [])
        docker.start()
        self.addCleanup(docker.stop)
        self.caddy = _bans.FakeCaddy().install(self)
        self.lapi = _crowdsec.FakeLapi().install(self)
        _crowdsec.enable(self)
        self.clock = Clock()
        self.sync = sync.Synchronizer(monotonic=self.clock)
        quiet = logging.NullHandler()                    # state-change warnings are expected here
        sync.log.addHandler(quiet)
        self.addCleanup(sync.log.removeHandler, quiet)

    def tearDown(self):
        service.reset_caches()

    def step(self, advance=0):
        self.clock.t += advance
        return self.sync.step()

    def startups(self):
        return [c["params"]["startup"] for c in self.lapi.calls]

    def policy_ips(self):
        lines = [l for l in (fsio.read_bytes(CS.path) or b"").decode().splitlines() if l.startswith("\tclient_ip ")]
        return lines[0].split()[1:] if lines else []

    def loads(self):
        return sum(1 for kind, _ in self.caddy.calls if kind == "load")

    def actions(self):
        return [e["action"] for e in audit.iter_entries()]


class StreamTest(SyncCase):
    def test_first_poll_is_a_snapshot_then_deltas(self):
        self.lapi.add("203.0.113.7")
        self.assertEqual(self.step(), "ok")
        self.assertEqual(self.policy_ips(), ["203.0.113.7"])
        self.step(10)
        self.assertEqual(self.startups(), ["true", "false"])
        doc = syncstate.read()
        self.assertEqual((doc["lapi_state"], doc["apply_state"], doc["decisions"], doc["leader_pid"]),
                         ("ok", "ok", 1, os.getpid()))
        self.assertTrue(doc["last_snapshot_at"] and doc["last_success_at"] and doc["last_apply_at"])
        self.assertEqual(os.stat(syncstate.PATH).st_mode & 0o777, 0o600)
        self.assertIn("crowdsec_snapshot", self.actions())

    def test_snapshot_never_rewrites_manual_records_or_policy(self):
        service.add_ban({"value": "198.51.100.7", "duration": "24h", "reason": ""}, "admin@example.com", None)
        manual = fsio.read_bytes(MANUAL.path)
        self.lapi.add("203.0.113.7")
        self.step()
        self.assertEqual(fsio.read_bytes(MANUAL.path), manual)
        self.assertEqual([r.value for r in store.load().records if r.source == "manual"], ["198.51.100.7"])

    def test_two_decisions_for_one_ip_stay_independent(self):
        self.lapi.add("203.0.113.7", id=1)
        self.lapi.add("203.0.113.7", id=2, scenario="crowdsecurity/http-bad-user-agent")
        self.step()
        self.assertEqual(sorted(r.source_id for r in store.load().records), ["1", "2"])
        self.lapi.delete(1)
        self.step(30)
        self.assertEqual(self.policy_ips(), ["203.0.113.7"])
        self.lapi.delete(2)
        self.step(30)
        self.assertEqual(self.policy_ips(), [])

    def test_unknown_deleted_id_is_a_noop(self):
        self.lapi.add("203.0.113.7", id=1)
        self.step()
        self.lapi.delete(999)
        self.assertEqual(self.step(30), "ok")
        self.assertEqual(self.policy_ips(), ["203.0.113.7"])

    def test_ignored_decisions_are_counted_by_reason(self):
        self.lapi.add("203.0.113.7", type="captcha")
        self.lapi.add("RO", scope="Country")
        self.lapi.add("203.0.113.8", origin="CAPI")
        self.lapi.add("10.0.0.5")
        self.step()
        self.assertEqual(syncstate.read()["ignored"], {"not_ban": 1, "scope": 1, "origin": 1, "protected:private": 1})
        self.assertEqual([r for r in store.load().records if r.source == "crowdsec"], [])

    def test_reloads_are_coalesced_to_the_sync_interval(self):
        self.lapi.add("203.0.113.7")
        self.step()
        self.assertEqual(self.loads(), 1)
        self.lapi.add("203.0.113.8")
        self.step(10)
        self.step(10)
        self.assertEqual((self.loads(), self.policy_ips()), (1, ["203.0.113.7"]))
        self.step(10)                                    # 30 s after the last apply
        self.assertEqual((self.loads(), self.policy_ips()), (2, ["203.0.113.7", "203.0.113.8"]))

    def test_already_expired_decisions_are_not_stored(self):
        self.sync = sync.Synchronizer(monotonic=self.clock, wall=lambda: store.utc_now() - timedelta(hours=2))
        self.lapi.add("203.0.113.7", duration="1h")
        self.step()
        self.assertEqual(self.policy_ips(), [])

    def test_no_op_syncs_are_silent(self):
        self.lapi.add("203.0.113.7")
        self.step()
        before = (len(self.actions()), fsio.read_bytes(CS.path), fsio.read_bytes(store.STATE_PATH), self.loads())
        for _ in range(3):                                       # deltas past the sync interval
            self.assertEqual(self.step(30), "ok")
        for _ in range(3):                                       # snapshots: new leaders reconcile the same set
            self.sync = sync.Synchronizer(monotonic=self.clock)
            self.assertEqual(self.step(30), "ok")
        self.assertEqual(self.startups(), ["true"] + ["false"] * 3 + ["true"] * 3)
        self.assertEqual((len(self.actions()), fsio.read_bytes(CS.path), fsio.read_bytes(store.STATE_PATH),
                          self.loads()), before)
        self.assertEqual(syncstate.read()["apply_state"], "ok")

    def test_origins_go_to_lapi_as_written_and_match_case_insensitively(self):
        _crowdsec.enable(self, CROWDSEC_ORIGINS="CrowdSec,cscli")
        self.lapi.add("203.0.113.7", origin="crowdsec")
        self.step()
        self.assertEqual(self.lapi.calls[-1]["params"]["origins"], "CrowdSec,cscli")
        self.assertEqual(self.policy_ips(), ["203.0.113.7"])

    def test_a_new_leader_starts_with_a_snapshot(self):
        self.lapi.add("203.0.113.7")
        self.step()
        self.step(10)
        successor = sync.Synchronizer(monotonic=self.clock)
        successor.step()
        self.assertEqual(self.startups(), ["true", "false", "true"])


class FailureTest(SyncCase):
    def setUp(self):
        super().setUp()
        self.lapi.add("203.0.113.7")
        self.step()
        self.records = [r.id for r in store.load().records]
        self.policy = fsio.read_bytes(CS.path)

    def assert_enforcement_kept(self):
        self.assertEqual([r.id for r in store.load().records], self.records)
        self.assertEqual(fsio.read_bytes(CS.path), self.policy)

    def test_malformed_response_keeps_enforcement_and_resnapshots(self):
        self.lapi.mode, self.lapi.raw = "raw", b'{"new": [{"id": "x"}], "deleted": null}'
        self.assertEqual(self.step(30), "malformed")
        self.assert_enforcement_kept()
        self.assertIn("crowdsec_degraded", self.actions())
        self.lapi.mode = "ok"
        self.assertEqual(self.step(10), "ok")
        self.assertEqual(self.startups()[-1], "true")
        self.assertIn("crowdsec_recovered", self.actions())

    def test_auth_failure_stops_delta_polling_until_a_snapshot_succeeds(self):
        self.lapi.mode, self.lapi.status = "status", 403
        self.assertEqual(self.step(10), "auth_failed")
        calls = len(self.lapi.calls)
        self.step(10)
        self.assertEqual(len(self.lapi.calls), calls)            # no polling inside AUTH_RETRY_SECONDS
        self.step(sync.AUTH_RETRY_SECONDS)
        self.assertEqual((len(self.lapi.calls), self.startups()[-1]), (calls + 1, "true"))
        self.assert_enforcement_kept()
        self.lapi.mode = "ok"
        self.assertEqual(self.step(sync.AUTH_RETRY_SECONDS), "ok")
        self.assertEqual(self.startups()[-1], "true")

    def test_outage_keeps_the_last_list_and_resnapshots_on_recovery(self):
        self.lapi.mode = "down"
        self.assertEqual(self.step(30), "unreachable")
        self.assertEqual(self.step(30), "unreachable")
        self.assert_enforcement_kept()
        self.assertEqual(syncstate.read()["lapi_state"], "unreachable")
        self.lapi.mode = "ok"
        self.assertEqual(self.step(10), "ok")
        self.assertEqual(self.startups()[-1], "true")

    def test_rotated_key_forces_a_snapshot(self):
        self.step(10)
        with mock.patch.object(config, "CROWDSEC_CONSOLE_BOUNCER_KEY", "rotated-key-2"):
            self.step(10)
        self.assertEqual((self.startups()[-1], self.lapi.calls[-1]["key"]), ("true", "rotated-key-2"))

    def test_a_fixed_key_is_retried_at_once_with_a_snapshot(self):
        self.lapi.mode, self.lapi.status = "status", 401
        self.assertEqual(self.step(10), "auth_failed")
        self.lapi.mode = "ok"
        with mock.patch.object(config, "CROWDSEC_CONSOLE_BOUNCER_KEY", "rotated-key-2"):
            self.assertEqual(self.step(1), "ok")
        self.assertEqual((self.startups()[-1], self.lapi.calls[-1]["key"]), ("true", "rotated-key-2"))

    def test_degraded_state_is_audited_once_per_change(self):
        self.lapi.mode = "down"
        for _ in range(3):
            self.step(30)
        self.assertEqual(self.actions().count("crowdsec_degraded"), 1)
        self.lapi.mode = "ok"
        self.step(10)
        self.step(10)
        self.assertEqual(self.actions().count("crowdsec_recovered"), 1)

    def test_missing_key_is_a_health_state(self):
        calls = len(self.lapi.calls)
        with mock.patch.object(config, "CROWDSEC_CONSOLE_BOUNCER_KEY", ""):
            self.assertEqual(self.step(10), "missing_key")
        self.assertEqual(len(self.lapi.calls), calls)
        self.assert_enforcement_kept()

    def test_capacity_pauses_apply_and_reports_counts_by_origin(self):
        self.lapi.add("203.0.113.8", origin="cscli")
        with mock.patch.object(config, "BANS_MAX", 1):
            self.step(30)
        doc = syncstate.read()
        self.assertEqual((doc["lapi_state"], doc["apply_state"]), ("ok", "capacity_exceeded"))
        self.assertEqual(doc["by_origin"], {"crowdsec": 1, "cscli": 1})
        self.assertEqual(doc["capacity"]["count"], 2)
        self.assert_enforcement_kept()

    def test_the_key_never_leaves_the_header(self):
        with self.assertLogs("src", level="DEBUG") as logs:
            logging.getLogger("src.test").info("capture start")
            for mode, status in (("status", 401), ("raw", 200), ("down", 200), ("ok", 200)):
                self.lapi.mode, self.lapi.status, self.lapi.raw = mode, status, b"[]"
                self.step(sync.AUTH_RETRY_SECONDS)
        with open(syncstate.PATH, encoding="utf-8") as f:
            status_text = f.read()
        with open(env.AUDIT_LOG, encoding="utf-8") as f:
            audit_text = f.read()
        for text in (status_text, audit_text, "\n".join(logs.output)):
            self.assertNotIn(_crowdsec.KEY, text)
        self.assertTrue(all(c["key"] == _crowdsec.KEY for c in self.lapi.calls))

    def test_no_lapi_request_while_caddyfile_lock_is_held(self):
        real = lapi.fetch_stream

        def checked(*args, **kwargs):
            fd = os.open(editor._LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)   # BlockingIOError if anyone holds it
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
            return real(*args, **kwargs)
        with mock.patch.object(lapi, "fetch_stream", checked):
            self.lapi.add("203.0.113.8")
            for _ in range(3):
                self.assertEqual(self.step(30), "ok")


if __name__ == "__main__":
    unittest.main()
