"""Upstream health transitions, shared across workers through one JSON file.

Run with:  uv run --frozen python -m unittest tests.test_upstream_health -v
"""
import importlib
import json
import os
import tempfile
import threading
import unittest
from unittest import mock

import tests._env  # noqa: F401  (sets env before src is imported)

from src import upstream_health


class RecordTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="upstream-health-")
        self.state = os.path.join(self.dir, "upstream-health.json")
        self.lock = os.path.join(self.dir, ".upstream-health.lock")
        self.patches = [
            mock.patch.object(upstream_health, "STATE_PATH", self.state),
            mock.patch.object(upstream_health, "LOCK_PATH", self.lock),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def read_state(self):
        with open(self.state) as f:
            return json.load(f)

    def test_first_observer_records_the_failure_time(self):
        self.assertEqual(upstream_health.record({"10.0.0.1:80": 0, "10.0.0.2:80": 1}, now=100.0),
                         {"10.0.0.1:80": 100.0})
        # A second worker, later: the recorded time stands.
        self.assertEqual(upstream_health.record({"10.0.0.1:80": 0, "10.0.0.2:80": 1}, now=130.0),
                         {"10.0.0.1:80": 100.0})

    def test_recovery_clears_and_a_new_failure_restarts_the_clock(self):
        upstream_health.record({"a:1": 0}, now=100.0)
        self.assertEqual(upstream_health.record({"a:1": 1}, now=160.0), {})
        self.assertEqual(self.read_state(), {})
        self.assertEqual(upstream_health.record({"a:1": 0}, now=200.0), {"a:1": 200.0})

    def test_survives_a_restart(self):
        upstream_health.record({"a:1": 0}, now=100.0)
        importlib.reload(upstream_health)          # a fresh process has no memory
        with mock.patch.object(upstream_health, "STATE_PATH", self.state), \
             mock.patch.object(upstream_health, "LOCK_PATH", self.lock):
            self.assertEqual(upstream_health.record({"a:1": 0}, now=500.0), {"a:1": 100.0})

    def test_corrupt_file_is_treated_as_empty_and_rewritten(self):
        for junk in ("{not json", "[1, 2]", '{"a:1": "yesterday"}'):
            with self.subTest(junk=junk):
                with open(self.state, "w") as f:
                    f.write(junk)
                self.assertEqual(upstream_health.record({"a:1": 0}, now=42.0), {"a:1": 42.0})
                self.assertEqual(self.read_state(), {"a:1": 42.0})

    def test_no_metrics_leaves_the_state_alone(self):
        upstream_health.record({"a:1": 0}, now=100.0)
        self.assertEqual(upstream_health.record({}, now=200.0), {})
        self.assertEqual(self.read_state(), {"a:1": 100.0})

    def test_upstreams_gone_from_the_metrics_are_forgotten(self):
        upstream_health.record({"a:1": 0, "b:2": 0}, now=100.0)
        upstream_health.record({"b:2": 0}, now=150.0)
        self.assertEqual(self.read_state(), {"b:2": 100.0})

    def test_concurrent_workers_agree_on_one_time(self):
        barrier = threading.Barrier(8)
        results = []

        def worker(i):
            barrier.wait()
            results.append(upstream_health.record({"a:1": 0}, now=1000.0 + i))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        times = {r["a:1"] for r in results}
        self.assertEqual(len(times), 1, f"workers disagreed: {times}")
        self.assertEqual(self.read_state(), {"a:1": times.pop()})


if __name__ == "__main__":
    unittest.main()
