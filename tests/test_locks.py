"""Mutation and leader locks: a container-local lock (LOCK_DIR, on the
container's private /tmp) decides exclusion; the BACKUP_DIR flock stays as
best-effort cross-container protection. Covers the Docker Desktop failure
where two processes hold flock on one bind-mounted file through different
mount views (final review I4).

Run with:  uv run --frozen python -m unittest tests.test_locks -v
"""
import errno
import fcntl
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import tests._env as env

from src import config, locks
from src.bans import jobs, sync, syncstate
from src.routes import editor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# A child process with its own BACKUP_DIR (a split mount view: its shared lock
# never meets ours) and the same LOCK_DIR (the same container).
CHILD = ("import sys\n"
         "from src.routes.editor import caddyfile_lock\n"
         "with caddyfile_lock():\n"
         "    print('locked', flush=True)\n"
         "    sys.stdin.read()\n")
LEADER_CHILD = ("import sys\n"
                "from src.bans import sync\n"
                "leader = sync.Leadership()\n"
                "print('leads' if leader.try_acquire() else 'follows', flush=True)\n"
                "sys.stdin.read()\n")


def child(code, case):
    split = tempfile.mkdtemp(prefix="split-view-")
    e = dict(os.environ, BACKUP_DIR=split, AUDIT_LOG=os.path.join(split, "audit.log"),
             LOCK_DIR=config.LOCK_DIR, PYTHONPATH=ROOT)
    p = subprocess.Popen([sys.executable, "-c", code], cwd=ROOT, env=e,
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    case.addCleanup(p.stdout.close)
    case.addCleanup(p.kill)
    return p


def acquired_within(seconds):
    got = threading.Event()

    def take():
        with editor.caddyfile_lock():
            got.set()
    t = threading.Thread(target=take, daemon=True)
    t.start()
    return got.wait(seconds), got, t


class CaddyfileLockTest(unittest.TestCase):
    def test_lock_dir_is_the_test_one(self):
        self.assertTrue(config.LOCK_DIR.startswith(env.ROOT))

    def test_excludes_across_processes_even_when_the_shared_lock_does_not(self):
        p = child(CHILD, self)
        self.assertEqual(p.stdout.readline().strip(), "locked")
        ok, got, t = acquired_within(0.5)
        self.assertFalse(ok, "a second process took caddyfile_lock while the first held it")
        p.stdin.close()
        p.wait(10)
        self.assertTrue(got.wait(10))
        t.join(10)

    def test_excludes_threads_even_when_flock_does_not(self):
        with mock.patch.object(locks.fcntl, "flock", lambda fd, op: None):
            with editor.caddyfile_lock():
                ok, got, t = acquired_within(0.3)
                self.assertFalse(ok, "a second thread took caddyfile_lock while the first held it")
            self.assertTrue(got.wait(10))
            t.join(10)

    def test_a_shared_lock_failure_is_best_effort(self):
        real = fcntl.flock
        open(editor._LOCK_PATH, "a").close()
        shared = os.stat(editor._LOCK_PATH).st_ino

        def flock(fd, op):
            if os.fstat(fd).st_ino == shared:
                raise OSError(errno.ENOLCK, "No locks available")
            return real(fd, op)
        with mock.patch.object(locks.fcntl, "flock", flock), self.assertLogs(locks.log, "WARNING"):
            with editor.caddyfile_lock():
                pass

    def test_the_local_lock_is_still_required(self):
        with mock.patch.object(config, "LOCK_DIR", "/nonexistent-dir/x"), \
                mock.patch.object(locks.os, "makedirs", side_effect=OSError("read-only")):
            with self.assertRaises(editor.CaddyfileLockError):
                with editor.caddyfile_lock():
                    pass


class SelfTestTest(unittest.TestCase):
    def test_a_local_dir_excludes(self):
        self.assertTrue(locks.self_test(tempfile.mkdtemp()))

    def test_a_filesystem_without_flock_exclusion_is_logged(self):
        with mock.patch.object(locks.fcntl, "flock", lambda fd, op: None), \
                self.assertLogs(locks.log, "WARNING") as logs:
            self.assertFalse(locks.self_test(tempfile.mkdtemp()))
        self.assertIn("does not exclude", "\n".join(logs.output))


class LeaderLockTest(unittest.TestCase):
    def test_the_local_lock_decides_leadership_across_split_views(self):
        p = child(LEADER_CHILD, self)
        self.assertEqual(p.stdout.readline().strip(), "leads")
        mine = sync.Leadership(os.path.join(tempfile.mkdtemp(), "bans-sync.lock"))
        self.assertFalse(mine.try_acquire())
        p.stdin.close()
        p.wait(10)
        self.assertTrue(mine.try_acquire())
        mine.release()

    def test_a_cross_container_holder_of_the_shared_lock_still_blocks(self):
        shared = os.path.join(tempfile.mkdtemp(), "bans-sync.lock")
        fd = os.open(shared, os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        self.addCleanup(os.close, fd)
        leader = sync.Leadership(shared, local_dir=tempfile.mkdtemp())
        self.assertFalse(leader.try_acquire())
        leader.release()


class SecondLeaderTest(unittest.TestCase):
    def test_a_foreign_status_write_is_detected(self):
        s = sync.Synchronizer()
        s._write()
        self.assertFalse(s.second_leader())
        doc = syncstate.read()
        doc["leader_nonce"] = "someone-else"
        syncstate.write(doc)
        self.assertTrue(s.second_leader())

    def test_the_loop_steps_down_loudly(self):
        stop, steps, acquired = threading.Event(), [], []

        def step(self_):
            steps.append(1)
            self_._write()
            doc = syncstate.read()
            doc.update(leader_nonce="another-leader", updated_at=syncstate_now())
            syncstate.write(doc)                     # someone else writes after us
            return "ok"

        def acquire(self_):
            acquired.append(1)
            return True
        threading.Timer(0.5, stop.set).start()
        with mock.patch.object(sync.Leadership, "try_acquire", acquire), \
                mock.patch.object(sync.Leadership, "release", lambda self_: None), \
                mock.patch.object(sync.Synchronizer, "step", step), \
                mock.patch.object(config, "CROWDSEC_POLL_INTERVAL", 0.01), \
                self.assertLogs(jobs.log, "ERROR") as logs:
            jobs._sync_loop(stop)
        self.assertIn("second CrowdSec sync leader", "\n".join(logs.output))
        self.assertEqual((len(steps), len(acquired)), (1, 2))   # it stood down and stays down
        # Once the other leader's report is stale, it may lead again.
        doc = syncstate.read()
        doc["updated_at"] = "2000-01-01T00:00:00Z"
        syncstate.write(doc)
        self.assertFalse(sync.foreign_leader_live("mine"))


def syncstate_now():
    from src.bans import store
    return store.iso(store.utc_now())


if __name__ == "__main__":
    unittest.main()
