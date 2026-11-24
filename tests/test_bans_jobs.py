"""Expiry job wiring.

Run with:  uv run --frozen python -m unittest tests.test_bans_jobs -v
"""
import importlib.util
import inspect
import os
import threading
import unittest
from unittest import mock

import tests._env  # noqa: F401

from src import config
from src.bans import jobs, service

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class JobsTest(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(jobs, "_started", False)
        p.start()
        self.addCleanup(p.stop)

    def test_tick_runs_at_least_once_a_minute(self):
        self.assertLessEqual(jobs.TICK_SECONDS, 60)

    def test_disabled_starts_nothing(self):
        with mock.patch.object(config, "BANS_ENABLED", False):
            self.assertIsNone(jobs.start_background())

    def test_starts_once_per_process(self):
        with mock.patch.object(jobs, "_loop", lambda stop: None):
            self.assertIsInstance(jobs.start_background(), threading.Event)
            self.assertIsNone(jobs.start_background())

    def test_loop_ticks_immediately_and_survives_a_crash(self):
        calls, stop = [], threading.Event()

        def tick():
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("boom")
            stop.set()
        with mock.patch.object(service, "expire_tick", tick), mock.patch.object(jobs, "TICK_SECONDS", 0.01):
            with self.assertLogs(jobs.log, "ERROR"):
                jobs._loop(stop)
        self.assertEqual(len(calls), 2)

    def test_loop_warns_on_results_other_than_idle_or_applied(self):
        for result, warned in (("idle", False), ("applied", False),
                               ("capacity_exceeded", True), ("degraded", True)):
            stop = threading.Event()

            def tick(result=result, stop=stop):
                stop.set()
                return result
            with self.subTest(result=result), mock.patch.object(service, "expire_tick", tick):
                if warned:
                    with self.assertLogs(jobs.log, "WARNING") as cm:
                        jobs._loop(stop)
                    self.assertIn(result, cm.output[0])
                else:
                    with self.assertNoLogs(jobs.log, "WARNING"):
                        jobs._loop(stop)

    def run_ticks(self, results):
        """Run _loop over a sequence of tick results, returning its log records."""
        stop, pending = threading.Event(), list(results)

        def tick():
            if len(pending) == 1:
                stop.set()
            return pending.pop(0)
        with mock.patch.object(service, "expire_tick", tick), mock.patch.object(jobs, "TICK_SECONDS", 0):
            with self.assertLogs(jobs.log, "DEBUG") as cm:
                jobs.log.debug("start")
                jobs._loop(stop)
        return [(r.levelname, r.getMessage()) for r in cm.records[1:]]

    def test_loop_logs_a_stuck_result_once_until_it_changes(self):
        logs = self.run_ticks(["unavailable"] * 5 + ["capacity_exceeded"] * 3 + ["idle"] * 3
                              + ["unavailable", "applied", "idle"])
        self.assertEqual([lvl for lvl, _ in logs], ["WARNING", "WARNING", "INFO", "WARNING", "INFO"])
        self.assertIn("unavailable", logs[0][1])
        self.assertIn("capacity_exceeded", logs[1][1])
        self.assertIn("completes again", logs[2][1])

    def test_loop_logs_nothing_while_idle(self):
        self.assertEqual(self.run_ticks(["idle", "applied", "idle"]), [])

    def test_gunicorn_starts_jobs_in_workers_not_the_master(self):
        spec = importlib.util.spec_from_file_location("gconf", os.path.join(ROOT, "gunicorn.conf.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertNotIn("bans", inspect.getsource(module.when_ready))
        with mock.patch("src.bans.jobs.start_background") as start, \
                mock.patch("src.locks.self_test") as self_test:
            module.post_worker_init(object())
        start.assert_called_once_with()
        self_test.assert_called_once_with(config.BACKUP_DIR)     # the lock self-test runs first, per worker


if __name__ == "__main__":
    unittest.main()
