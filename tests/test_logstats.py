"""Per-host access-log aggregation.

Every test builds its own aggregator against its own file so none of them
share the module-level singleton's state.
"""
import json
import os
import re
import tempfile
import unittest
from unittest import mock

import tests._env as env  # noqa: F401  (sets env before src is imported)

from src import create_app
from src.logstats import FAILURE_KEYS_MAX, LogStatsAggregator
from src.routes import ops as ops_mod

AUTH = {"Cf-Access-Authenticated-User-Email": "admin@example.com"}
MB = 1024 * 1024


def entry(host="a.example.com", status=200, duration=0.1, size=100, uri="/"):
    return {
        "level": "info",
        "msg": "handled request",
        "request": {"host": host, "uri": uri, "method": "GET", "client_ip": "1.2.3.4"},
        "status": status,
        "duration": duration,
        "size": size,
    }


class AggregatorTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="logstats-")
        self.path = os.path.join(self.dir, "access.log")
        self.agg = LogStatsAggregator(self.path)

    def write(self, *entries, partial=None):
        """Append complete lines, optionally leaving a partial line at the end."""
        with open(self.path, "a") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")
            if partial is not None:
                f.write(partial)

    def snap(self, window_mb=10):
        return self.agg.snapshot(window_mb * MB)

    def test_missing_file_reports_absent(self):
        snap = self.snap()
        self.assertFalse(snap["exists"])
        self.assertEqual(snap["sites"], {})
        self.assertEqual(snap["path"], self.path)

    def test_groups_requests_by_host(self):
        self.write(
            entry(host="a.example.com"),
            entry(host="a.example.com"),
            entry(host="b.example.com"),
        )
        sites = self.snap()["sites"]
        self.assertEqual(sites["a.example.com"]["requests"], 2)
        self.assertEqual(sites["b.example.com"]["requests"], 1)

    def test_counts_status_classes_and_error_rate(self):
        self.write(
            entry(status=200), entry(status=204), entry(status=304),
            entry(status=404), entry(status=502), entry(status=503),
        )
        site = self.snap()["sites"]["a.example.com"]
        self.assertEqual(site["status"], {"2xx": 2, "3xx": 1, "4xx": 1, "5xx": 2})
        self.assertEqual(site["errors"], 2)
        self.assertEqual(site["error_rate"], 33.33)

    def test_latency_and_bytes(self):
        self.write(
            entry(duration=0.1, size=100),
            entry(duration=0.3, size=200),
        )
        site = self.snap()["sites"]["a.example.com"]
        self.assertEqual(site["avg_latency_ms"], 200.0)
        self.assertEqual(site["bytes_out"], 300)

    def test_p95_latency(self):
        # 100 requests, 1ms..100ms. The 95th percentile lands on 95ms.
        self.write(*[entry(duration=i / 1000) for i in range(1, 101)])
        site = self.snap()["sites"]["a.example.com"]
        self.assertEqual(site["p95_latency_ms"], 95.0)

    def test_tracks_slowest_request(self):
        self.write(
            entry(duration=0.1, uri="/fast"),
            entry(duration=2.5, uri="/slow"),
            entry(duration=0.2, uri="/medium"),
        )
        slowest = self.snap()["sites"]["a.example.com"]["slowest"]
        self.assertEqual(slowest["uri"], "/slow")
        self.assertEqual(slowest["ms"], 2500.0)

    def test_appended_lines_counted_once(self):
        self.write(entry(), entry())
        self.assertEqual(self.snap()["sites"]["a.example.com"]["requests"], 2)
        self.write(entry())
        snap = self.snap()
        self.assertEqual(snap["sites"]["a.example.com"]["requests"], 3)
        # A poll with nothing new must not re-count anything.
        self.assertEqual(self.snap()["sites"]["a.example.com"]["requests"], 3)

    def test_partial_trailing_line_is_not_counted_until_complete(self):
        self.write(entry(), partial='{"request":{"host":"a.example.com"},"stat')
        self.assertEqual(self.snap()["sites"]["a.example.com"]["requests"], 1)
        # Finish the line; it should now count exactly once.
        with open(self.path, "a") as f:
            f.write('us":200,"duration":0.1,"size":10}\n')
        self.assertEqual(self.snap()["sites"]["a.example.com"]["requests"], 2)

    def test_truncation_rebuilds_from_scratch(self):
        self.write(entry(), entry(), entry())
        self.assertEqual(self.snap()["sites"]["a.example.com"]["requests"], 3)
        # Caddy rolled the file: same path, smaller.
        with open(self.path, "w") as f:
            f.write(json.dumps(entry()) + "\n")
        snap = self.snap()
        self.assertEqual(snap["sites"]["a.example.com"]["requests"], 1)
        self.assertTrue(snap["rebuilt"])

    def test_malformed_lines_are_skipped_not_fatal(self):
        with open(self.path, "a") as f:
            f.write("not json at all\n")
            f.write(json.dumps({"msg": "no request key"}) + "\n")
            f.write(json.dumps(entry()) + "\n")
        snap = self.snap()
        self.assertEqual(snap["skipped"], 2)
        self.assertEqual(snap["entries"], 1)
        self.assertEqual(snap["sites"]["a.example.com"]["requests"], 1)

    def test_host_port_is_stripped(self):
        self.write(entry(host="a.example.com:8443"), entry(host="A.example.com"))
        sites = self.snap()["sites"]
        self.assertEqual(list(sites), ["a.example.com"])
        self.assertEqual(sites["a.example.com"]["requests"], 2)

    def test_window_limits_how_far_back_the_scan_anchors(self):
        line = json.dumps(entry()) + "\n"
        self.write(*[entry() for _ in range(100)])
        total = os.path.getsize(self.path)
        # A window of roughly ten lines must not pick up all one hundred, and
        # the fragment it lands mid-way through must not be counted.
        snap = self.agg.snapshot(len(line) * 10)
        requests = snap["sites"]["a.example.com"]["requests"]
        self.assertLessEqual(requests, 10)
        self.assertGreater(requests, 0)
        self.assertLess(snap["covered_bytes"], total)
        self.assertEqual(snap["skipped"], 0)

    def test_changing_the_window_rebuilds(self):
        self.write(*[entry() for _ in range(50)])
        line = len(json.dumps(entry()) + "\n")
        narrow = self.agg.snapshot(line * 5)
        wide = self.agg.snapshot(line * 50)
        self.assertGreater(
            wide["sites"]["a.example.com"]["requests"],
            narrow["sites"]["a.example.com"]["requests"],
        )
        self.assertTrue(wide["rebuilt"])

    def test_window_smaller_than_file_reanchors_as_it_grows(self):
        line = len(json.dumps(entry()) + "\n")
        window = line * 10
        self.write(*[entry() for _ in range(10)])
        self.agg.snapshot(window)
        # Write well past the rebuild slack; coverage must stay bounded rather
        # than growing with the file forever.
        self.write(*[entry() for _ in range(40)])
        snap = self.agg.snapshot(window)
        self.assertLessEqual(snap["covered_bytes"], window * 1.5)


class FailureDetailTest(unittest.TestCase):
    """The per-host drill-down: which paths are failing, and with what code."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="logstats-detail-")
        self.path = os.path.join(self.dir, "access.log")
        self.agg = LogStatsAggregator(self.path)

    def write(self, *entries):
        with open(self.path, "a") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")

    def detail(self, host="a.example.com"):
        return self.agg.snapshot(10 * MB, host=host)["detail"]

    def test_absent_unless_a_host_is_requested(self):
        self.write(entry(status=502))
        self.assertNotIn("detail", self.agg.snapshot(10 * MB))

    def test_groups_by_status_and_path_worst_first(self):
        self.write(
            entry(status=502, uri="/api/sync"),
            entry(status=502, uri="/api/sync"),
            entry(status=404, uri="/favicon.ico"),
            entry(status=200, uri="/fine"),
            entry(status=304, uri="/cached"),
        )
        d = self.detail()
        self.assertEqual(d["failures"], [
            {"status": 502, "path": "/api/sync", "count": 2},
            {"status": 404, "path": "/favicon.ico", "count": 1},
        ])
        self.assertEqual(d["total"], 3)
        self.assertFalse(d["capped"])

    def test_same_path_different_codes_are_separate_rows(self):
        self.write(
            entry(status=502, uri="/api"),
            entry(status=404, uri="/api"),
        )
        rows = {(f["status"], f["path"]): f["count"] for f in self.detail()["failures"]}
        self.assertEqual(rows, {(502, "/api"): 1, (404, "/api"): 1})

    def test_query_string_is_stripped(self):
        self.write(
            entry(status=502, uri="/api?page=1"),
            entry(status=502, uri="/api?page=2"),
        )
        self.assertEqual(self.detail()["failures"],
                         [{"status": 502, "path": "/api", "count": 2}])

    def test_failures_do_not_leak_between_hosts(self):
        self.write(
            entry(host="a.example.com", status=502, uri="/a"),
            entry(host="b.example.com", status=404, uri="/b"),
        )
        self.assertEqual(self.detail("a.example.com")["failures"],
                         [{"status": 502, "path": "/a", "count": 1}])
        self.assertEqual(self.detail("b.example.com")["failures"],
                         [{"status": 404, "path": "/b", "count": 1}])

    def test_unknown_host_is_empty_not_an_error(self):
        self.write(entry(status=502))
        d = self.detail("nope.example.com")
        self.assertEqual(d["failures"], [])
        self.assertEqual(d["total"], 0)
        self.assertFalse(d["capped"])

    def test_distinct_paths_are_capped_but_tracked_ones_keep_counting(self):
        # A bot walking random paths must not grow this without bound.
        self.write(*[entry(status=404, uri=f"/rand/{i}") for i in range(FAILURE_KEYS_MAX + 25)])
        self.write(entry(status=404, uri="/rand/0"))  # already tracked
        d = self.detail()
        self.assertTrue(d["capped"])
        self.assertEqual(len(d["failures"]), FAILURE_KEYS_MAX)
        self.assertEqual(d["other"], 25)
        self.assertEqual(d["total"], FAILURE_KEYS_MAX + 26)
        tracked = next(f for f in d["failures"] if f["path"] == "/rand/0")
        self.assertEqual(tracked["count"], 2)

    def test_missing_uri_does_not_break_grouping(self):
        with open(self.path, "a") as f:
            f.write(json.dumps({
                "request": {"host": "a.example.com"}, "status": 502,
                "duration": 0.1, "size": 0,
            }) + "\n")
        self.assertEqual(self.detail()["total"], 1)


class LogStatsEndpointTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.testing = True

    def setUp(self):
        self.client = self.app.test_client()
        self.dir = tempfile.mkdtemp(prefix="logstats-api-")
        self.path = os.path.join(self.dir, "access.log")
        with open(self.path, "w") as f:
            f.write(json.dumps(entry(host="api.example.com")) + "\n")
            f.write(json.dumps(entry(host="api.example.com", status=502, uri="/boom")) + "\n")
        self.agg = LogStatsAggregator(self.path)
        self.patch = mock.patch.object(ops_mod, "log_stats", self.agg)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()

    def test_requires_auth(self):
        self.assertIn(self.client.get("/api/logstats").status_code, (302, 401))

    def test_returns_per_site_figures(self):
        data = self.client.get("/api/logstats", headers=AUTH).get_json()
        self.assertEqual(data["sites"]["api.example.com"]["requests"], 2)
        self.assertNotIn("detail", data)

    def test_host_param_adds_the_failure_breakdown(self):
        data = self.client.get("/api/logstats?host=api.example.com", headers=AUTH).get_json()
        self.assertEqual(data["detail"]["host"], "api.example.com")
        self.assertEqual(data["detail"]["failures"],
                         [{"status": 502, "path": "/boom", "count": 1}])

    def test_unknown_host_param_returns_an_empty_breakdown(self):
        data = self.client.get("/api/logstats?host=ghost.example.com", headers=AUTH).get_json()
        self.assertEqual(data["detail"]["failures"], [])

    def test_window_is_reported_and_clamped_to_the_maximum(self):
        data = self.client.get("/api/logstats?window_mb=10", headers=AUTH).get_json()
        self.assertEqual(data["window_mb"], 10)

        data = self.client.get("/api/logstats?window_mb=9999", headers=AUTH).get_json()
        self.assertEqual(data["window_mb"], ops_mod.LOG_STATS_WINDOW_MAX_MB)

        for bad in ("0", "-5", "abc", ""):
            data = self.client.get(f"/api/logstats?window_mb={bad}", headers=AUTH).get_json()
            self.assertGreaterEqual(data["window_mb"], 1)


if __name__ == "__main__":
    unittest.main()
