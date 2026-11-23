"""Spec 1.5 steps 5-15 against the fake admin API.

Run with:  uv run --frozen python -m unittest tests.test_bans_txn -v
"""
import glob
import json
import os
import stat
import unittest
from unittest import mock

import tests._env as env
from tests import _bans

from src import audit
from src.bans import fsio, render, scan, store, txn

MANUAL = render.SOURCES["manual"]
mode = lambda p: stat.S_IMODE(os.stat(p).st_mode)
GLOBS = ("bans-manual*.caddy", "bans-crowdsec*.caddy", "geo*.caddy",
         "crowdsec-plugin-protect*.caddy", "cloudflare-trusted-proxies*.caddy", "*.caddy")


def actions():
    return [e["action"] for e in audit.iter_entries()]


class ApplyTest(unittest.TestCase):
    def setUp(self):
        _bans.reset()
        _bans.fresh_audit(self)
        self.caddy = _bans.FakeCaddy().install(self)

    def baseline(self):
        out = _bans.apply(_bans.manual_changes("203.0.113.7"))
        self.assertTrue(out.ok, out.message)
        self.caddy.calls.clear()
        return fsio.read_bytes(MANUAL.path), fsio.read_bytes(store.STATE_PATH)

    def assert_clean(self):
        self.assertFalse(os.path.exists(txn.JOURNAL_PATH))
        self.assertEqual(os.listdir(txn.TXN_ROOT) if os.path.isdir(txn.TXN_ROOT) else [], [])
        self.assertEqual([n for n in os.listdir(env.BANS_DIR) if n.endswith(".tmp")], [])

    def test_success_replaces_policy_then_state_and_cleans_up(self):
        changes = _bans.manual_changes("203.0.113.7")
        order, real = [], os.replace

        def spy(src, dst):
            order.append(os.path.basename(dst))
            real(src, dst)
        with mock.patch.object(os, "replace", spy):
            out = _bans.apply(changes)
        self.assertTrue(out.ok, out.message)
        self.assertEqual((out.reload_status, out.enforcement, out.code), ("applied", "enforced", None))
        self.assertEqual([n for n in order if n in ("bans-manual.caddy", "bans.json")], ["bans-manual.caddy", "bans.json"])
        self.assertEqual(fsio.read_bytes(MANUAL.path), changes[0].data)
        self.assertEqual(fsio.read_bytes(store.STATE_PATH), changes[1].data)
        self.assertEqual((mode(MANUAL.path), mode(store.STATE_PATH)), (0o644, 0o600))
        self.assert_clean()
        self.assertEqual([c[0] for c in self.caddy.calls], ["config", "adapt", "load", "config"])
        with open(env.CADDYFILE) as f:
            self.assertEqual(self.caddy.calls[2][1], f.read())
        self.assertIn("bans_policy_applied", actions())

    def test_not_imported_commits_without_adapt_or_load(self):
        _bans.reset("example.com {\n\trespond 200\n}\n")
        out = _bans.apply(_bans.manual_changes("203.0.113.7"))
        self.assertEqual((out.ok, out.reload_status, out.enforcement), (True, "not_required", "not_enabled"))
        self.assertEqual([c[0] for c in self.caddy.calls], ["config"])
        self.assertTrue(os.path.exists(MANUAL.path))
        self.assert_clean()

    def test_live_marker_alone_requires_reload(self):
        _bans.reset("example.com {\n\trespond 200\n}\n")
        self.caddy.live = {"x": [{"handler": "vars", MANUAL.marker: "1"}]}
        out = _bans.apply(_bans.manual_changes("203.0.113.7"))
        self.assertEqual(out.reload_status, "applied")
        self.assertIn("load", [c[0] for c in self.caddy.calls])

    def test_unchanged_files_are_skipped(self):
        self.baseline()
        out = _bans.apply(_bans.manual_changes("203.0.113.7"))
        policy_unchanged = fsio.read_bytes(MANUAL.path) == _bans.manual_changes("203.0.113.7")[0].data
        self.assertTrue(policy_unchanged)
        self.assertTrue(out.ok)
        self.assertNotIn("load", [c[0] for c in self.caddy.calls])

    def test_adapt_rejection_restores_and_never_loads(self):
        before = self.baseline()
        self.caddy.adapt_status = 400
        out = _bans.apply(_bans.manual_changes("198.51.100.0/24"))
        self.assertEqual((out.ok, out.code, out.http_status), (False, "adaptation_failed", 422))
        self.assertEqual((fsio.read_bytes(MANUAL.path), fsio.read_bytes(store.STATE_PATH)), before)
        self.assertNotIn("load", [c[0] for c in self.caddy.calls])
        self.assert_clean()

    def test_first_change_rolls_back_to_absent_files(self):
        self.caddy.adapt_status = 400
        out = _bans.apply(_bans.manual_changes("203.0.113.7"))
        self.assertEqual(out.code, "adaptation_failed")
        self.assertFalse(os.path.exists(MANUAL.path))
        self.assertFalse(os.path.exists(store.STATE_PATH))
        self.assert_clean()

    def test_load_rejection_restores_previous_bytes(self):
        before = self.baseline()
        self.caddy.load_mode = "reject"
        out = _bans.apply(_bans.manual_changes("198.51.100.0/24"))
        self.assertEqual((out.code, out.reload_status, out.http_status), ("reload_rejected", "rejected", 502))
        self.assertEqual((fsio.read_bytes(MANUAL.path), fsio.read_bytes(store.STATE_PATH)), before)
        self.assertIn("bans_reload_rejected", actions())
        self.assert_clean()

    def test_connect_timeout_keeps_candidate_and_journal(self):
        self.baseline()
        changes = _bans.manual_changes("198.51.100.0/24")
        self.caddy.load_mode = "connect_timeout"
        out = _bans.apply(changes)
        self.assertEqual((out.code, out.reload_status, out.http_status), ("reload_failed", "failed", 503))
        self.assertEqual(fsio.read_bytes(MANUAL.path), changes[0].data)
        self.assertEqual(txn.read_journal()["phase"], "reload_failed")

    def test_read_timeout_keeps_candidate_and_reports_unknown(self):
        self.baseline()
        changes = _bans.manual_changes("198.51.100.0/24")
        self.caddy.load_mode = "read_timeout"
        out = _bans.apply(changes)
        self.assertEqual((out.code, out.reload_status, out.http_status), ("reload_unknown", "unknown", 504))
        self.assertEqual(fsio.read_bytes(store.STATE_PATH), changes[1].data)
        self.assertEqual(txn.read_journal()["phase"], "reload_unknown")
        self.assertIn("bans_reload_unknown", actions())

    def test_live_mismatch_after_a_200_is_unknown(self):
        self.baseline()
        self.caddy.live_after_load = {"someone": "else"}
        out = _bans.apply(_bans.manual_changes("198.51.100.0/24"))
        self.assertEqual(out.code, "reload_unknown")
        self.assertIsNotNone(txn.read_journal())

    def test_unreachable_caddy_changes_nothing(self):
        self.caddy.down = True
        out = _bans.apply(_bans.manual_changes("203.0.113.7"))
        self.assertEqual((out.code, out.http_status, out.reload_status), ("caddy_unreachable", 503, "not_attempted"))
        self.assertFalse(os.path.exists(MANUAL.path))
        self.assert_clean()

    def test_write_failure_restores_and_never_reloads(self):
        before = self.baseline()
        real = os.replace

        def failing(src, dst):
            if dst == store.STATE_PATH:
                raise OSError(28, "No space left on device")
            real(src, dst)
        with mock.patch.object(os, "replace", failing):
            out = _bans.apply(_bans.manual_changes("198.51.100.0/24"))
        self.assertEqual((out.code, out.http_status), ("write_failed", 500))
        self.assertEqual((fsio.read_bytes(MANUAL.path), fsio.read_bytes(store.STATE_PATH)), before)
        self.assertEqual([c[0] for c in self.caddy.calls], ["config"])
        self.assert_clean()

    def test_rollback_failure_keeps_the_journal(self):
        self.baseline()
        self.caddy.load_mode = "reject"
        real = fsio.atomic_write

        def failing(path, data, mode):
            if path == MANUAL.path:
                raise OSError(5, "I/O error")
            real(path, data, mode)
        with mock.patch.object(fsio, "atomic_write", failing):
            out = _bans.apply(_bans.manual_changes("198.51.100.0/24"))
        self.assertEqual((out.code, out.http_status), ("rollback_failed", 500))
        self.assertEqual(txn.read_journal()["phase"], "rollback_failed")
        self.assertIn("bans_rollback_failed", actions())

    def test_temp_files_are_hidden_and_never_match_a_managed_glob(self):
        with _bans.crash_at("temps_written"), self.assertRaises(_bans.SimulatedCrash):
            _bans.apply(_bans.manual_changes("203.0.113.7"))
        temps = [os.path.join(env.BANS_DIR, n) for n in os.listdir(env.BANS_DIR)]
        self.assertTrue(temps)
        for temp in temps:
            name = os.path.basename(temp)
            self.assertTrue(name.startswith(".") and name.endswith(".tmp"), name)
            for pattern in GLOBS:
                self.assertFalse(scan.glob_matches(os.path.join(env.BANS_DIR, pattern), temp), (pattern, name))

    def test_backups_exist_before_replace_and_stay_out_of_bans_dir(self):
        self.baseline()
        with _bans.crash_at("journal_prepared"), self.assertRaises(_bans.SimulatedCrash):
            _bans.apply(_bans.manual_changes("198.51.100.0/24"))
        journal = txn.read_journal()
        self.assertEqual(journal["phase"], "prepared")
        self.assertEqual(journal["replaced_paths"], [])
        for e in journal["entries"]:
            for key in ("backup_path", "candidate_path"):
                self.assertTrue(e[key].startswith(txn.TXN_ROOT + os.sep))
                self.assertTrue(e[key].endswith(".bak"))
                self.assertTrue(os.path.exists(e[key]))
            self.assertEqual(fsio.sha256_tag(fsio.read_bytes(e["backup_path"])), e["previous_hash"])
            self.assertEqual(set(e), {"path", "kind", "mode", "previous_hash", "candidate_hash",
                                      "temp_path", "backup_path", "candidate_path"})
        self.assertEqual(glob.glob(os.path.join(env.BANS_DIR, "*.bak")), [])
        self.assertEqual(set(journal) - {"entries"}, {"version", "id", "phase", "actor", "source", "created_at",
                                                     "replaced_paths", "previous_live_hash", "candidate_live_hash",
                                                     "reload_required", "audit"})

    def test_state_must_embed_the_candidate_policy_hash(self):
        policy, state = _bans.manual_changes("203.0.113.7")
        doc = json.loads(state.data)
        doc["last_rendered_hashes"][MANUAL.filename] = fsio.sha256_tag(b"other")
        bad = txn.Change(state.path, "state", json.dumps(doc).encode(), owns=state.owns)
        with self.assertRaises(ValueError):
            _bans.apply([policy, bad])
        with self.assertRaises(ValueError):
            _bans.apply([policy])                      # a policy no state owns
        self.assertFalse(os.path.exists(MANUAL.path))

    def test_audit_events_are_emitted_when_the_journal_commits(self):
        out = _bans.apply(_bans.manual_changes("203.0.113.7"), audit=[("ban_created", "203.0.113.7")])
        self.assertTrue(out.ok, out.message)
        entries = [e for e in audit.iter_entries() if e["action"] == "ban_created"]
        self.assertEqual([(e["user"], e["detail"]) for e in entries], [("t@example.com", "203.0.113.7")])

    def test_audit_events_are_emitted_on_a_commit_without_reload(self):
        _bans.reset("example.com {\n\trespond 200\n}\n")
        out = _bans.apply(_bans.manual_changes("203.0.113.7"), audit=[("ban_created", "203.0.113.7")])
        self.assertEqual(out.reload_status, "not_required")
        self.assertIn("ban_created", actions())

    def test_audit_events_are_dropped_when_the_change_rolls_back(self):
        self.caddy.load_mode = "reject"
        out = _bans.apply(_bans.manual_changes("203.0.113.7"), audit=[("ban_created", "203.0.113.7")])
        self.assertEqual(out.code, "reload_rejected")
        self.assertNotIn("ban_created", actions())

    def test_audit_events_wait_in_the_journal_until_a_later_commit(self):
        self.caddy.load_mode = "read_timeout"
        out = _bans.apply(_bans.manual_changes("203.0.113.7"), audit=[("ban_created", "203.0.113.7")])
        self.assertEqual(out.code, "reload_unknown")
        self.assertNotIn("ban_created", actions())
        journal = txn.read_journal()
        self.assertEqual(journal["audit"], [["ban_created", "203.0.113.7"]])
        self.assertTrue(txn._commit(journal))            # the commit Task 8 recovery reuses
        self.assertIn("ban_created", actions())
        self.assert_clean()

    def test_adapt_load_verify_returns_the_adapted_hash(self):
        with open(env.CADDYFILE) as f:
            text = f.read()
        outcome, expected = txn._adapt_load_verify(text)
        self.assertIsNone(outcome)
        self.assertEqual(expected, txn.caddy_admin.config_hash(self.caddy.live))
        self.assertEqual([c[0] for c in self.caddy.calls], ["adapt", "load", "config"])

    def test_adapt_load_verify_reports_each_failure(self):
        with open(env.CADDYFILE) as f:
            text = f.read()
        for knob, value, code, status in (("adapt_status", 400, "adaptation_failed", 422),
                                          ("load_mode", "reject", "reload_rejected", 502),
                                          ("load_mode", "connection_refused", "reload_failed", 503),
                                          ("load_mode", "connection_reset", "reload_unknown", 504)):
            with self.subTest(knob=knob, value=value):
                caddy = _bans.FakeCaddy().install(self)
                setattr(caddy, knob, value)
                outcome, _ = txn._adapt_load_verify(text)
                self.assertEqual((outcome.ok, outcome.code, outcome.http_status), (False, code, status))

    def test_requires_a_resolved_journal(self):
        fsio.atomic_write(txn.JOURNAL_PATH, b'{"version": 1, "entries": []}', 0o600)
        with self.assertRaises(RuntimeError):
            _bans.apply(_bans.manual_changes("203.0.113.7"))


if __name__ == "__main__":
    unittest.main()
