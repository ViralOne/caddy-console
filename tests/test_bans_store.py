"""bans.json: schema, round trip, expiry, registry, quarantine and snapshots.

Run with:  uv run --frozen python -m unittest tests.test_bans_store -v
"""
import json
import os
import stat
import unittest
from datetime import timedelta

import tests._env as env  # noqa: F401
from tests import _bans

from src.bans import addr, fsio, store

NOW = store.parse_iso("2026-11-23T20:00:00Z")


def rec(value="203.0.113.7", duration="24h", reason="", now=NOW):
    return store.new_manual_record(addr.canonical(value), duration, reason, "admin@example.com", now)


class StoreRoundTripTest(unittest.TestCase):
    def setUp(self):
        _bans.reset()

    def test_missing_file_is_an_empty_state(self):
        state = store.load()
        self.assertEqual((state.records, state.raw_hash, state.version), ([], None, "empty"))

    def test_round_trip_is_deterministic_and_private(self):
        state = store.State(records=[rec(), rec("198.51.100.0/24", "permanent", "line 1\n\tline 2")],
                            last_rendered_hashes={"bans-manual.caddy": fsio.sha256_tag(b"x")})
        data = store.dumps(state)
        self.assertEqual(data, store.dumps(store.parse(data)))
        fsio.atomic_write(store.STATE_PATH, data, 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(store.STATE_PATH).st_mode), 0o600)
        loaded = store.load()
        self.assertEqual([r.value for r in loaded.records], ["203.0.113.7", "198.51.100.0/24"])
        self.assertEqual(loaded.records[1].expires_at, None)
        self.assertEqual(loaded.version, fsio.sha256_tag(data)[7:23])
        doc = json.loads(data)
        self.assertEqual(doc["version"], 1)
        self.assertEqual(set(doc["records"][0]), {"id", "source", "source_id", "scope", "value", "reason",
                                                  "scenario", "origin", "actor", "created_at", "expires_at"})

    def test_invalid_documents_are_corrupt_not_empty(self):
        good = json.loads(store.dumps(store.State(records=[rec()])))
        bad_docs = {
            "not json": b"{nope",
            "array": b"[]",
            "future version": {**good, "version": 2},
            "unknown key": {**good, "extra": 1},
            "non-canonical value": {**good, "records": [{**good["records"][0], "value": "203.0.113.7/32"}]},
            "scope mismatch": {**good, "records": [{**good["records"][0], "scope": "range"}]},
            "control char": {**good, "records": [{**good["records"][0], "reason": "a\x07b"}]},
            "offset timestamp": {**good, "records": [{**good["records"][0], "created_at": "2026-11-23T20:00:00+00:00"}]},
            "duplicate id": {**good, "records": [good["records"][0], good["records"][0]]},
            "bad hash": {**good, "last_rendered_hashes": {"bans-manual.caddy": "md5:abc"}},
            "bad source": {**good, "records": [{**good["records"][0], "source": "other"}]},
        }
        for name, doc in bad_docs.items():
            with self.subTest(name=name):
                raw = doc if isinstance(doc, bytes) else json.dumps(doc).encode()
                with self.assertRaises(store.StateCorrupt) as cm:
                    store.parse(raw)
                self.assertEqual(cm.exception.raw, raw)

    def test_deeply_nested_json_is_corrupt(self):
        raw = b"[" * 200000
        with self.assertRaises(store.StateCorrupt) as cm:
            store.parse(raw)
        self.assertEqual(cm.exception.raw, raw)

    def test_unreadable_file_is_corrupt(self):
        if os.geteuid() == 0:
            self.skipTest("root can read a 0000 file")
        fsio.atomic_write(store.STATE_PATH, store.dumps(store.State()), 0o000)
        with self.assertRaises(store.StateCorrupt):
            store.load()


class InputValidationTest(unittest.TestCase):
    def test_reason_limits(self):
        self.assertEqual(store.validate_reason(None), "")
        self.assertEqual(store.validate_reason("é" * 500), "é" * 500)
        self.assertEqual(store.validate_reason("a\nb\tc"), "a\nb\tc")
        for bad in ("é" * 501, "a\rb", "a\x85b", 5, "a\ud800b"):
            with self.subTest(bad=bad), self.assertRaises(store.InputError) as cm:
                store.validate_reason(bad)
            self.assertEqual(cm.exception.code, "invalid_reason")

    def test_durations(self):
        for d in ("4h", "24h", "7d", "permanent"):
            self.assertEqual(store.validate_duration(d), d)
        for bad in ("1h", "", None, "PERMANENT"):
            with self.subTest(bad=bad), self.assertRaises(store.InputError) as cm:
                store.validate_duration(bad)
            self.assertEqual(cm.exception.code, "invalid_duration")
        r = rec(duration="4h")
        self.assertEqual(r.expires_at, "2026-11-24T00:00:00Z")
        self.assertEqual(r.created_at, "2026-11-23T20:00:00Z")


class ExpiryAndRegistryTest(unittest.TestCase):
    def test_expired_records_go_and_overlapping_records_stay_independent(self):
        short, long_, forever = rec(duration="4h"), rec(duration="7d"), rec("198.51.100.0/24", "permanent")
        state = store.State(records=[short, long_, forever])
        removed = store.prune_expired(state, NOW + timedelta(hours=5))
        self.assertEqual([r.id for r in removed], [short.id])
        self.assertEqual([r.id for r in state.records], [long_.id, forever.id])

    def test_prune_can_be_limited_to_sources(self):
        state = store.State(records=[rec(duration="4h")])
        self.assertEqual(store.prune_expired(state, NOW + timedelta(hours=5), sources=["crowdsec"]), [])
        self.assertEqual(len(state.records), 1)

    def test_registry_caps_at_16_and_expires_after_30_days(self):
        state = store.State()
        for i in range(20):
            store.touch_management(state, addr.client_address(f"203.0.113.{i}"), "direct", NOW + timedelta(minutes=i))
        self.assertEqual(len(state.management_addresses), 16)
        self.assertNotIn("203.0.113.0", [m["value"] for m in state.management_addresses])
        self.assertTrue(store.touch_management(state, addr.client_address("203.0.113.19"), "direct", NOW + timedelta(days=1)))
        self.assertEqual(len(state.management_addresses), 16)
        self.assertTrue(store.prune_management(state, NOW + timedelta(days=30, minutes=30)))
        self.assertEqual([m["value"] for m in state.management_addresses], ["203.0.113.19"])
        self.assertEqual([str(n) for n in store.management_networks(state)], ["203.0.113.19/32"])
        self.assertFalse(store.touch_management(state, None, "direct", NOW))


class QuarantineAndSnapshotTest(unittest.TestCase):
    def setUp(self):
        _bans.reset()

    def test_quarantine_is_bounded_private_and_written_once(self):
        raw = b"x" * (2 * 1024 * 1024)
        name = store.quarantine(raw, "bans.json is not valid JSON")
        path = os.path.join(env.BACKUP_DIR, name)
        self.assertEqual(os.path.getsize(path), 1024 * 1024)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(store.quarantine(raw, "again"), name)
        self.assertEqual(len([n for n in os.listdir(env.BACKUP_DIR) if n.startswith("bans.json.quarantine-")]), 1)
        self.assertEqual(store.read_error()["quarantine"], name)
        store.clear_error()
        self.assertIsNone(store.read_error())

    def test_snapshots_keep_five_with_opaque_ids(self):
        for i in range(7):
            store.save_snapshot(store.dumps(store.State(records=[rec(f"203.0.113.{i}")])))
        snaps = store.list_snapshots()
        self.assertEqual(len(snaps), 5)
        for s in snaps:
            self.assertRegex(s["id"], r"^[0-9a-f]{16}$")
            self.assertEqual(s["records"], 1)
            self.assertIsNotNone(store.snapshot_bytes(s["id"]))
        self.assertIsNone(store.snapshot_bytes("../../etc/passwd"))

    def test_snapshots_list_newest_first_within_one_second_and_skip_duplicates(self):
        raws = [store.dumps(store.State(records=[rec(f"203.0.113.{j}") for j in range(n)])) for n in (1, 2, 3)]
        for raw in raws:
            store.save_snapshot(raw)
        store.save_snapshot(raws[-1])
        snaps = store.list_snapshots()
        self.assertEqual([s["records"] for s in snaps], [3, 2, 1])
        self.assertEqual(store.snapshot_bytes(snaps[0]["id"]), raws[-1])


if __name__ == "__main__":
    unittest.main()
