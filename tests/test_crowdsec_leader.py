"""Sync leadership across processes and the per-worker sync thread (spec 1.5
'bans-sync.lock', 2.6 'Sync worker exit').

Run with:  uv run --frozen python -m unittest tests.test_crowdsec_leader -v
"""
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

import tests._env  # noqa: F401
from tests import _crowdsec

from src import config
from src.bans import jobs, sync

HOLDER = ("import fcntl, os, sys\n"
          "fd = os.open(sys.argv[1], os.O_CREAT | os.O_RDWR, 0o600)\n"
          "fcntl.flock(fd, fcntl.LOCK_EX)\n"
          "print('locked', flush=True)\n"
          "sys.stdin.read()\n")


class LeadershipTest(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "bans-sync.lock")

    def test_one_leader_per_lock_file(self):
        a, b = sync.Leadership(self.path), sync.Leadership(self.path)
        self.assertTrue(a.try_acquire())
        self.assertTrue(a.try_acquire())                      # idempotent while held
        self.assertFalse(b.try_acquire())
        a.release()
        self.assertTrue(b.try_acquire())
        b.release()

    def test_a_lock_held_by_another_process_blocks_until_it_exits(self):
        holder = subprocess.Popen([sys.executable, "-c", HOLDER, self.path],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.addCleanup(holder.stdout.close)
        self.addCleanup(holder.kill)
        self.assertEqual(holder.stdout.readline().strip(), "locked")
        leader = sync.Leadership(self.path)
        self.assertFalse(leader.try_acquire())
        holder.stdin.close()                                 # the "worker" exits
        holder.wait(10)
        self.assertTrue(leader.try_acquire())
        leader.release()


class SyncThreadTest(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(jobs, "_started", False)
        p.start()
        self.addCleanup(p.stop)

    def started_names(self):
        names = []

        class FakeThread:
            def __init__(self, target=None, args=(), name=None, daemon=None):
                names.append(name)

            def start(self):
                pass
        with mock.patch.object(jobs.threading, "Thread", FakeThread):
            jobs.start_background()
        return names

    def test_sync_thread_only_when_crowdsec_is_configured(self):
        self.assertEqual(self.started_names(), ["bans-expiry"])
        jobs._started = False
        _crowdsec.enable(self)
        self.assertEqual(self.started_names(), ["bans-expiry", "bans-sync"])

    def run_loop(self, leads, steps_before_stop=2, crash=False):
        stop, steps = threading.Event(), []

        def step(_self):
            steps.append(1)
            if crash and len(steps) == 1:
                raise RuntimeError("boom")
            if len(steps) >= steps_before_stop:
                stop.set()
            return "ok"
        if not leads:
            threading.Timer(0.2, stop.set).start()
        with mock.patch.object(sync.Leadership, "try_acquire", lambda self: leads), \
                mock.patch.object(sync.Leadership, "release", lambda self: None), \
                mock.patch.object(sync.Synchronizer, "step", step), \
                mock.patch.object(config, "CROWDSEC_POLL_INTERVAL", 0.01):
            jobs._sync_loop(stop)
        return steps

    def test_loop_steps_only_while_leading(self):
        self.assertEqual(len(self.run_loop(leads=True)), 2)
        self.assertEqual(self.run_loop(leads=False), [])

    def test_loop_survives_a_crashing_step(self):
        with self.assertLogs(jobs.log, "ERROR"):
            self.assertEqual(len(self.run_loop(leads=True, crash=True)), 2)


if __name__ == "__main__":
    unittest.main()
