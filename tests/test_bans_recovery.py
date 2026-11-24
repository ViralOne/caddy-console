"""Startup/lazy journal recovery (spec 1.5 'At startup'), operator actions and
the editor-reload hook.

Run with:  uv run --frozen python -m unittest tests.test_bans_recovery -v
"""
import json
import os
import unittest

import tests._env as env
from tests import _bans

from src import audit
from src.bans import caddy, fsio, render, store, txn
from src.routes.editor import caddyfile_lock

MANUAL = render.SOURCES["manual"]
BEFORE_LOAD = ("temps_written", "backups_written", "journal_prepared",
               "replaced:bans-manual.caddy", "replaced:bans.json", "adapted")


def files():
    return fsio.read_bytes(MANUAL.path), fsio.read_bytes(store.STATE_PATH)


def resolve():
    with caddyfile_lock():
        return txn.resolve_pending()


def act(action):
    with caddyfile_lock():
        return txn.recovery_action(action, "op@example.com")


class CrashRecoveryTest(unittest.TestCase):
    def setUp(self):
        _bans.reset()
        _bans.fresh_audit(self)
        self.caddy = _bans.FakeCaddy().install(self)
        self.assertTrue(_bans.apply(_bans.manual_changes("203.0.113.7")).ok)
        self.before = files()
        self.candidate = _bans.manual_changes("203.0.113.7", "198.51.100.0/24")

    def crash(self, point):
        with _bans.crash_at(point), self.assertRaises(_bans.SimulatedCrash):
            _bans.apply(self.candidate)

    def assert_clean(self):
        self.assertIsNone(txn.read_journal())
        self.assertEqual(os.listdir(txn.TXN_ROOT), [])
        self.assertEqual([n for n in os.listdir(env.BANS_DIR) if n.endswith(".tmp")], [])
        self.assertEqual([n for n in os.listdir(env.BACKUP_DIR) if n.startswith(".bans") and n.endswith(".tmp")], [])

    def test_a_crash_before_load_restores_previous_at_every_phase(self):
        for point in BEFORE_LOAD:
            with self.subTest(point=point):
                self.setUp()
                self.crash(point)
                self.assertIsNone(resolve())
                self.assertEqual(files(), self.before)
                self.assert_clean()

    def test_a_crash_after_caddy_applied_finishes_the_candidate(self):
        self.crash("loaded")
        self.assertIsNone(resolve())
        self.assertEqual(files(), (self.candidate[0].data, self.candidate[1].data))
        self.assert_clean()
        self.assertIn("bans_recovered", [e["action"] for e in audit.iter_entries()])

    def test_crash_between_policy_and_state_with_candidate_live(self):
        self.crash("replaced:bans-manual.caddy")
        with open(env.CADDYFILE) as f:
            self.caddy.live = self.caddy.adapt_text(f.read())      # as if Caddy had loaded it
        journal = txn.read_journal()
        journal["candidate_live_hash"] = caddy.config_hash(self.caddy.live)
        fsio.atomic_write(txn.JOURNAL_PATH, json.dumps(journal).encode(), 0o600)
        self.assertIsNone(resolve())
        self.assertEqual(fsio.read_bytes(store.STATE_PATH), self.candidate[1].data)

    def test_unmatched_live_config_waits_for_the_operator(self):
        for action in ("use_candidate", "use_previous"):
            with self.subTest(action=action):
                self.setUp()        # new record IDs, so expected bytes are taken after it
                expected = ((self.candidate[0].data, self.candidate[1].data)
                            if action == "use_candidate" else self.before)
                self.crash("adapted")
                self.caddy.live = {"edited": "elsewhere"}
                pending = resolve()
                self.assertEqual(pending.reason, "live_mismatch")
                self.assertNotIn("load", [c[0] for c in self.caddy.calls[-2:]])
                out = act(action)
                self.assertTrue(out.ok, out.message)
                self.assertEqual(files(), expected)
                self.assert_clean()

    def test_unreachable_caddy_is_degraded_until_it_answers(self):
        self.crash("adapted")
        self.caddy.down = True
        self.assertEqual(resolve().reason, "caddy_unreachable")
        self.assertIsNotNone(txn.read_journal())
        self.caddy.down = False
        self.assertIsNone(resolve())
        self.assertEqual(files(), self.before)

    def test_out_of_band_edit_blocks_recovery(self):
        self.crash("adapted")
        with open(MANUAL.path, "wb") as f:
            f.write(b"# hand edited\n")
        self.assertEqual(resolve().reason, "hash_mismatch")
        out = act("use_previous")
        self.assertEqual((out.ok, out.code, out.http_status), (False, "recovery_blocked", 409))

    def test_corrupt_journal_is_degraded(self):
        fsio.atomic_write(txn.JOURNAL_PATH, b"{junk", 0o600)
        self.assertEqual(resolve().reason, "journal_corrupt")

    def test_reload_unknown_resolves_when_live_matches_the_candidate(self):
        self.caddy.load_mode = "read_timeout"
        self.assertEqual(_bans.apply(self.candidate).code, "reload_unknown")
        self.caddy.load_mode = "ok"
        self.assertIsNone(resolve())
        self.assertEqual(files(), (self.candidate[0].data, self.candidate[1].data))

    def test_connect_timeout_resolves_to_previous(self):
        self.caddy.load_mode = "connect_timeout"
        self.assertEqual(_bans.apply(self.candidate).code, "reload_failed")
        self.assertIsNone(resolve())
        self.assertEqual(files(), self.before)

    def test_orphans_without_a_journal_are_swept(self):
        temp = fsio.write_temp(env.BANS_DIR, "bans-manual.caddy", b"partial", 0o644)
        os.makedirs(os.path.join(txn.TXN_ROOT, "deadbeef"))
        self.assertIsNone(resolve())
        self.assertFalse(os.path.exists(temp))
        self.assertEqual(os.listdir(txn.TXN_ROOT), [])

    def test_external_reload_settles_a_pending_journal(self):
        self.caddy.load_mode = "read_timeout"
        _bans.apply(self.candidate)
        with caddyfile_lock():
            txn.reconcile_after_external_reload()
        self.assertIsNone(txn.read_journal())
        self.assertEqual(files(), (self.candidate[0].data, self.candidate[1].data))


EVENTS = (("ban_created", "198.51.100.0/24"),)


def created_count():
    return [e["action"] for e in audit.iter_entries()].count("ban_created")


class RecoveryRulingsTest(unittest.TestCase):
    """Controller rulings: journal audit events are emitted exactly once wherever
    the journal commits (R6), recovery reports reload_unknown as 504 (R8), and
    debris that the current journal does not reference is swept."""

    def setUp(self):
        _bans.reset()
        _bans.fresh_audit(self)
        self.caddy = _bans.FakeCaddy().install(self)
        self.assertTrue(_bans.apply(_bans.manual_changes("203.0.113.7")).ok)
        self.candidate = _bans.manual_changes("203.0.113.7", "198.51.100.0/24")

    def crash(self, point):
        with _bans.crash_at(point), self.assertRaises(_bans.SimulatedCrash):
            _bans.apply(self.candidate, audit=EVENTS)

    def test_resolve_commit_emits_the_journal_audit_once(self):
        self.crash("loaded")
        self.assertIsNone(resolve())
        self.assertIsNone(resolve())
        self.assertEqual(created_count(), 1)

    def test_a_committed_journal_is_only_cleaned_up(self):
        self.crash("loaded")
        journal = txn.read_journal()
        journal["phase"] = "committed"
        fsio.atomic_write(txn.JOURNAL_PATH, json.dumps(journal).encode(), 0o600)
        self.assertIsNone(resolve())
        self.assertIsNone(txn.read_journal())
        self.assertEqual(os.listdir(txn.TXN_ROOT), [])
        self.assertEqual(created_count(), 0)

    def test_use_candidate_emits_the_journal_audit_once(self):
        self.crash("adapted")
        self.caddy.live = {"edited": "elsewhere"}
        self.assertTrue(act("use_candidate").ok)
        self.assertEqual(created_count(), 1)

    def test_use_previous_never_emits_the_journal_audit(self):
        self.crash("adapted")
        self.caddy.live = {"edited": "elsewhere"}
        self.assertTrue(act("use_previous").ok)
        self.assertEqual(created_count(), 0)

    def test_external_reload_emits_the_journal_audit_once(self):
        self.caddy.load_mode = "read_timeout"
        _bans.apply(self.candidate, audit=EVENTS)
        with caddyfile_lock():
            txn.reconcile_after_external_reload()
            txn.reconcile_after_external_reload()
        self.assertEqual(created_count(), 1)

    def test_recovery_reload_unknown_is_504(self):
        self.crash("adapted")
        self.caddy.live = {"edited": "elsewhere"}
        self.caddy.load_mode = "read_timeout"
        out = act("use_candidate")
        self.assertEqual((out.ok, out.code, out.http_status), (False, "reload_unknown", 504))
        self.assertIsNotNone(txn.read_journal())
        self.assertEqual(created_count(), 0)

    def test_a_crash_after_a_recovery_load_settles_on_the_next_resolve(self):
        self.crash("adapted")
        self.caddy.live = {"edited": "elsewhere"}
        with _bans.crash_at("loaded"), self.assertRaises(_bans.SimulatedCrash):
            act("use_candidate")
        self.assertIsNone(resolve())
        self.assertEqual(files(), (self.candidate[0].data, self.candidate[1].data))
        self.assertEqual(created_count(), 1)

    def test_unknown_action_is_rejected(self):
        self.crash("adapted")
        out = act("restore_everything")
        self.assertEqual((out.ok, out.http_status), (False, 400))
        self.assertIsNotNone(txn.read_journal())

    def test_debris_beside_a_pending_journal_is_swept(self):
        self.crash("adapted")
        journal = txn.read_journal()
        stray_dir = os.path.join(txn.TXN_ROOT, "deadbeef")
        os.makedirs(stray_dir)
        stray_state = fsio.write_temp(env.BACKUP_DIR, "bans.json", b"partial", 0o600)
        stray_policy = fsio.write_temp(env.BANS_DIR, "bans-manual.caddy", b"partial", 0o644)
        self.caddy.down = True
        self.assertEqual(resolve().reason, "caddy_unreachable")
        self.assertEqual(os.listdir(txn.TXN_ROOT), [journal["id"]])
        self.assertFalse(os.path.exists(stray_state))
        self.assertFalse(os.path.exists(stray_policy))
        self.caddy.down = False
        self.assertIsNone(resolve())
        self.assertEqual(os.listdir(txn.TXN_ROOT), [])


class EditorReloadTest(_bans.ApiCase):
    def test_editor_reload_commits_pending_candidate(self):
        self.assertTrue(_bans.apply(_bans.manual_changes("203.0.113.7")).ok)
        candidate = _bans.manual_changes("203.0.113.7", "198.51.100.0/24")
        self.caddy.load_mode = "read_timeout"
        _bans.apply(candidate)
        self.caddy.live = {"unknown": True}           # neither previous nor candidate
        self.caddy.load_mode = "ok"
        with open(env.CADDYFILE) as f:
            text = f.read() + "\nother.example.com {\n\trespond 200\n}\n"
        r = self.post("/api/save", {"content": text})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertIsNone(txn.read_journal())
        self.assertEqual(fsio.read_bytes(store.STATE_PATH), candidate[1].data)


if __name__ == "__main__":
    unittest.main()
