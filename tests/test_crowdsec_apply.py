"""service.apply_crowdsec(): reconcile the leader's decisions into crowdsec
records and bans-crowdsec.caddy through the Phase 1 transaction (spec 2.4-2.6).

Run with:  uv run --frozen python -m unittest tests.test_crowdsec_apply -v
"""
import os
import unittest
from datetime import timedelta
from unittest import mock

import tests._env as env
from tests import _bans, _crowdsec

from src import audit, config
from src.bans import addr, fsio, lapi, protected, render, service, store, txn

CS, MANUAL = render.SOURCES["crowdsec"], render.SOURCES["manual"]
BOTH = ("example.com {{\n\timport {d}/bans-manual*.caddy\n\timport {d}/bans-crowdsec*.caddy\n"
        "\trespond 200\n}}\n").format(d=env.BANS_DIR)
A = _crowdsec.accepted


def client_ip_line(path):
    lines = [l for l in (fsio.read_bytes(path) or b"").decode().splitlines() if l.startswith("\tclient_ip ")]
    return lines[0].split()[1:] if lines else []


class ApplyCase(unittest.TestCase):
    def setUp(self):
        _bans.reset(BOTH)
        _bans.fresh_audit(self)
        service.reset_caches()
        docker = mock.patch.object(protected, "read_docker_networks", lambda: [])
        docker.start()
        self.addCleanup(docker.stop)
        self.caddy = _bans.FakeCaddy().install(self)
        _crowdsec.enable(self)

    def tearDown(self):
        service.reset_caches()

    def loads(self):
        return sum(1 for kind, _ in self.caddy.calls if kind == "load")

    def crowdsec_records(self):
        return [r for r in store.load().records if r.source == "crowdsec"]


class ApplyTest(ApplyCase):
    def test_snapshot_replaces_only_crowdsec_records(self):
        service.add_ban({"value": "203.0.113.7", "duration": "24h", "reason": "x"}, "admin@example.com", None)
        manual_bytes = fsio.read_bytes(MANUAL.path)
        r = service.apply_crowdsec([A("203.0.113.9", 1), A("198.51.100.0/24", 2)], snapshot=True,
                                   ignored={"not_ban": 2})
        self.assertEqual((r.code, r.added, r.removed, r.active, r.by_origin), ("applied", 2, 0, 2, {"crowdsec": 2}))
        self.assertEqual([x.id for x in self.crowdsec_records()], ["crowdsec-1", "crowdsec-2"])
        self.assertEqual([x.value for x in store.load().records if x.source == "manual"], ["203.0.113.7"])
        self.assertEqual(fsio.read_bytes(MANUAL.path), manual_bytes)
        self.assertEqual(client_ip_line(CS.path), ["198.51.100.0/24", "203.0.113.9"])
        r = service.apply_crowdsec([A("203.0.113.9", 1)], snapshot=True)
        self.assertEqual((r.code, r.removed), ("applied", 1))
        self.assertEqual(client_ip_line(CS.path), ["203.0.113.9"])
        snap = [e for e in audit.iter_entries() if e["action"] == "crowdsec_snapshot"]
        self.assertIn("ignored: not_ban 2", snap[0]["detail"])
        self.assertEqual(snap[0]["user"], "system")

    def test_repeated_snapshot_is_idempotent(self):
        decisions = [A("203.0.113.9", 1)]
        self.assertEqual(service.apply_crowdsec(decisions, snapshot=True).code, "applied")
        state_bytes, loads = fsio.read_bytes(store.STATE_PATH), self.loads()
        again = [A("203.0.113.9", 1, now=store.utc_now() + timedelta(seconds=30))]
        self.assertEqual(service.apply_crowdsec(again, snapshot=True).code, "unchanged")
        self.assertEqual((fsio.read_bytes(store.STATE_PATH), self.loads()), (state_bytes, loads))

    def test_no_op_applies_write_no_audit_line_in_either_mode(self):
        service.apply_crowdsec([A("203.0.113.9", 1)], snapshot=True, ignored={"not_ban": 1})
        entries = len(list(audit.iter_entries()))
        files, loads = (fsio.read_bytes(CS.path), fsio.read_bytes(store.STATE_PATH)), self.loads()
        for snapshot in (True, False, True, False):
            r = service.apply_crowdsec([A("203.0.113.9", 1)], snapshot=snapshot, ignored={"not_ban": 1})
            self.assertEqual(r.code, "unchanged")
        self.assertEqual(len(list(audit.iter_entries())), entries)
        self.assertEqual(((fsio.read_bytes(CS.path), fsio.read_bytes(store.STATE_PATH)), self.loads()),
                         (files, loads))

    def test_extended_decision_is_refreshed_without_a_reload(self):
        service.apply_crowdsec([A("203.0.113.9", 1, hours=4)])
        loads = self.loads()
        r = service.apply_crowdsec([A("203.0.113.9", 1, hours=7)])
        self.assertEqual(r.code, "stored")
        self.assertEqual(self.loads(), loads)
        expires = store.parse_iso(self.crowdsec_records()[0].expires_at)
        self.assertGreater(expires, store.utc_now() + timedelta(hours=6))

    def test_decision_for_a_verified_console_address_is_ignored(self):
        # The operator used the console from 198.51.100.20: it is in the registry, not BANS_NEVER.
        service.add_ban({"value": "203.0.113.7", "duration": "24h", "reason": ""}, "admin@example.com", "198.51.100.20")
        r = service.apply_crowdsec([A("198.51.100.20", 1), A("10.1.2.3", 2), A("203.0.113.9", 3)])
        self.assertEqual(r.protected, {"operator": 1, "private": 1})
        self.assertEqual(sorted(s["value"] for s in r.protected_sample), ["10.1.2.3", "198.51.100.20"])
        self.assertEqual(client_ip_line(CS.path), ["203.0.113.9"])
        self.assertEqual([x.source_id for x in self.crowdsec_records()], ["3"])

    def test_protected_sample_is_bounded(self):
        r = service.apply_crowdsec([A(f"10.0.0.{i}", i) for i in range(1, 31)])
        self.assertEqual(r.protected, {"private": 30})
        self.assertEqual(len(r.protected_sample), service.PROTECTED_SAMPLE_MAX)
        self.assertEqual(self.crowdsec_records(), [])

    def test_too_wide_decision_is_ignored_like_a_manual_ban(self):
        now = store.utc_now()
        wide = lapi.Accepted("1", addr.canonical("203.0.0.0/8"), "crowdsec", "x", now, now + timedelta(hours=4))
        r = service.apply_crowdsec([wide, A("203.0.113.9", 2)], snapshot=True)
        self.assertEqual((r.ok, r.active), (True, 1))
        self.assertEqual(client_ip_line(CS.path), ["203.0.113.9"])
        snap = [e for e in audit.iter_entries() if e["action"] == "crowdsec_snapshot"]
        self.assertIn("too_wide 1", snap[0]["detail"])

    def test_expired_decisions_are_dropped(self):
        past = store.utc_now() - timedelta(hours=5)
        r = service.apply_crowdsec([A("203.0.113.9", 1, hours=1, now=past)])
        self.assertEqual((r.ok, r.active), (True, 0))
        self.assertEqual(self.crowdsec_records(), [])

    def test_sync_never_rewrites_the_manual_policy(self):
        # Spec 2.4 (F5): an expired manual ban is expire_tick's business, never the sync's.
        service.add_ban({"value": "203.0.113.7", "duration": "4h", "reason": ""}, "admin@example.com", None)
        manual_bytes = fsio.read_bytes(MANUAL.path)
        later = store.utc_now() + timedelta(hours=5)
        r = service.apply_crowdsec([A("203.0.113.9", 1, hours=24)], now=later)
        self.assertEqual(r.code, "applied")
        self.assertEqual(fsio.read_bytes(MANUAL.path), manual_bytes)
        self.assertEqual([x.value for x in store.load().records if x.source == "manual"], ["203.0.113.7"])
        self.assertEqual(client_ip_line(CS.path), ["203.0.113.9"])
        self.assertNotIn("ban_expired", [e["action"] for e in audit.iter_entries()])

    def test_capacity_refuses_the_whole_snapshot_and_keeps_the_last_policy(self):
        service.add_ban({"value": "203.0.113.7", "duration": "24h", "reason": ""}, "admin@example.com", None)
        with mock.patch.object(config, "BANS_MAX", 3):
            self.assertEqual(service.apply_crowdsec([A("192.0.2.1", 1), A("192.0.2.3", 2)]).code, "applied")
            before = (fsio.read_bytes(CS.path), fsio.read_bytes(store.STATE_PATH))
            r = service.apply_crowdsec([A("192.0.2.1", 1), A("192.0.2.3", 2), A("192.0.2.5", 3, origin="cscli")])
        self.assertEqual(r.code, "capacity_exceeded")
        self.assertEqual(r.capacity, {"count": 4, "limit": 3, "by_source": {"manual": 1, "crowdsec": 3}})
        self.assertEqual(r.by_origin, {"crowdsec": 2, "cscli": 1})
        self.assertIn("CROWDSEC_ORIGINS", r.message)
        self.assertEqual((fsio.read_bytes(CS.path), fsio.read_bytes(store.STATE_PATH)), before)

    def test_capacity_counts_non_local_origins_too(self):
        # F8: manual changes ignore non-local origins; the sync checks the full total.
        service.add_ban({"value": "203.0.113.7", "duration": "24h", "reason": ""}, "admin@example.com", None)
        before = (fsio.read_bytes(CS.path), fsio.read_bytes(store.STATE_PATH))
        with mock.patch.object(config, "BANS_MAX", 2):
            r = service.apply_crowdsec([A("192.0.2.1", 1, origin="capi"), A("192.0.2.3", 2, origin="lists")])
        self.assertEqual(r.code, "capacity_exceeded")
        self.assertEqual(r.capacity["by_source"], {"manual": 1, "crowdsec": 2})
        self.assertEqual(r.by_origin, {"capi": 1, "lists": 1})
        self.assertIn("capi 1", r.message)
        self.assertEqual((fsio.read_bytes(CS.path), fsio.read_bytes(store.STATE_PATH)), before)
        self.assertEqual([x.value for x in store.load().records if x.source == "manual"], ["203.0.113.7"])

    def test_held_crowdsec_file_pauses_sync_only(self):
        service.apply_crowdsec([A("203.0.113.9", 1)])
        fsio.atomic_write(CS.path, b"", 0o644)
        r = service.apply_crowdsec([A("203.0.113.9", 1), A("203.0.113.10", 2)])
        self.assertEqual(r.code, "held")
        self.assertEqual(fsio.read_bytes(CS.path), b"")
        body, status = service.add_ban({"value": "198.51.100.7", "duration": "4h", "reason": ""}, "op", None)
        self.assertEqual((status, body["enforcement"]), (201, "enforced"))

    def test_corrupt_state_is_left_alone(self):
        service.apply_crowdsec([A("203.0.113.9", 1)])
        policy = fsio.read_bytes(CS.path)
        fsio.atomic_write(store.STATE_PATH, b"{not json", 0o600)
        self.assertEqual(service.apply_crowdsec([A("203.0.113.10", 2)]).code, "corrupt")
        self.assertEqual((fsio.read_bytes(store.STATE_PATH), fsio.read_bytes(CS.path)), (b"{not json", policy))

    def test_pending_journal_pauses_sync(self):
        fsio.atomic_write(txn.JOURNAL_PATH, b"garbage", 0o600)
        self.assertEqual(service.apply_crowdsec([A("203.0.113.9", 1)]).code, "degraded")
        self.assertFalse(os.path.exists(CS.path))

    def test_adaptation_failure_rolls_back_and_reports(self):
        service.apply_crowdsec([A("203.0.113.9", 1)])
        policy = fsio.read_bytes(CS.path)
        synced = [e["action"] for e in audit.iter_entries()].count("crowdsec_sync")
        self.caddy.adapt_status = 400
        r = service.apply_crowdsec([A("203.0.113.10", 2)])
        self.assertEqual((r.ok, r.code), (False, "adaptation_failed"))
        self.assertEqual(fsio.read_bytes(CS.path), policy)
        actions = [e["action"] for e in audit.iter_entries()]
        self.assertEqual(actions.count("crowdsec_sync"), synced)      # a rolled-back change is never audited
        self.assertIn("bans_adapt_rejected", actions)

    def test_audit_never_contains_the_key(self):
        service.apply_crowdsec([A("203.0.113.9", 1)], snapshot=True, ignored={"origin": 1})
        with open(env.AUDIT_LOG, encoding="utf-8") as f:
            self.assertNotIn(_crowdsec.KEY, f.read())


if __name__ == "__main__":
    unittest.main()
