"""Columnar event index + query engine behind /api/explore."""
import json
import os
import tempfile
import unittest

import tests._env as env  # noqa: F401  (sets env before src is imported)

from src.eventindex import EventIndex, parse_query

MB = 1024 * 1024
T0 = 1790000000.0  # a fixed epoch so bucket boundaries are predictable


def entry(ts=T0, host="a.example.com", status=200, duration=0.1, size=100,
          uri="/", method="GET", client="1.2.3.4"):
    return {
        "level": "info", "msg": "handled request",
        "ts": ts,
        "request": {"host": host, "uri": uri, "method": method, "client_ip": client},
        "status": status, "duration": duration, "size": size,
    }


class ParseQueryTest(unittest.TestCase):
    def test_empty_query_matches_everything(self):
        f = parse_query("")
        self.assertTrue(f.is_empty())

    def test_key_value_terms(self):
        f = parse_query("host:a.example.com method:get status:502 path:/api")
        self.assertEqual(f.hosts, {"a.example.com"})
        self.assertEqual(f.methods, {"GET"})
        self.assertEqual(f.codes, {502})
        self.assertEqual(f.paths, ["/api"])

    def test_status_class_and_code_are_distinguished(self):
        f = parse_query("status:5xx status:404")
        self.assertEqual(f.classes, {"5xx"})
        self.assertEqual(f.codes, {404})

    def test_same_key_repeats_or_together(self):
        f = parse_query("host:a host:b")
        self.assertEqual(f.hosts, {"a", "b"})

    def test_negation(self):
        f = parse_query("-status:2xx -host:noisy")
        self.assertEqual(f.not_classes, {"2xx"})
        self.assertEqual(f.not_hosts, {"noisy"})

    def test_bare_words_are_free_text(self):
        f = parse_query("timeout /api/v2")
        self.assertEqual(f.text, ["timeout", "/api/v2"])

    def test_quoted_value_keeps_spaces(self):
        f = parse_query('path:"/a b" plain')
        self.assertEqual(f.paths, ["/a b"])
        self.assertEqual(f.text, ["plain"])

    def test_unknown_key_falls_back_to_free_text(self):
        # Better to search for it than to silently drop what the user typed.
        f = parse_query("wat:x")
        self.assertEqual(f.text, ["wat:x"])

    def test_junk_status_is_not_a_crash(self):
        f = parse_query("status:abc status: status:99999")
        self.assertEqual(f.codes, set())
        self.assertEqual(f.classes, set())


class IndexTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="eventindex-")
        self.path = os.path.join(self.dir, "access.log")
        self.index = EventIndex(self.path)

    def write(self, *entries):
        with open(self.path, "a") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")

    def q(self, query="", **kw):
        return self.index.query(query, **kw)

    def test_missing_file(self):
        r = self.q()
        self.assertFalse(r["exists"])
        self.assertEqual(r["entries"], [])
        self.assertEqual(r["total"], 0)

    def test_indexes_and_returns_newest_first(self):
        self.write(entry(ts=T0, uri="/one"), entry(ts=T0 + 1, uri="/two"), entry(ts=T0 + 2, uri="/three"))
        r = self.q()
        self.assertEqual(r["total"], 3)
        self.assertEqual([e["uri"] for e in r["entries"]], ["/three", "/two", "/one"])
        self.assertEqual(r["indexed"], 3)

    def test_entry_fields_round_trip(self):
        self.write(entry(ts=T0, host="h.example.com", status=502, duration=0.25,
                         size=1234, uri="/api/x", method="POST", client="9.9.9.9"))
        e = self.q()["entries"][0]
        self.assertEqual(e["host"], "h.example.com")
        self.assertEqual(e["status"], 502)
        self.assertEqual(e["method"], "POST")
        self.assertEqual(e["uri"], "/api/x")
        self.assertEqual(e["client_ip"], "9.9.9.9")
        self.assertEqual(e["size"], 1234)
        self.assertAlmostEqual(e["duration_ms"], 250.0, places=3)
        self.assertAlmostEqual(e["ts"], T0, places=3)

    def test_incremental_append(self):
        self.write(entry(ts=T0))
        self.assertEqual(self.q()["total"], 1)
        self.write(entry(ts=T0 + 1))
        self.assertEqual(self.q()["total"], 2)
        self.assertEqual(self.q()["total"], 2)  # a second poll must not re-count

    def test_truncation_rebuilds(self):
        self.write(entry(ts=T0), entry(ts=T0 + 1), entry(ts=T0 + 2))
        self.assertEqual(self.q()["total"], 3)
        with open(self.path, "w") as f:
            f.write(json.dumps(entry(ts=T0 + 9)) + "\n")
        self.assertEqual(self.q()["total"], 1)

    def test_malformed_lines_are_skipped(self):
        with open(self.path, "a") as f:
            f.write("not json\n")
            f.write(json.dumps({"msg": "no request"}) + "\n")
            f.write(json.dumps(entry(ts=T0)) + "\n")
        r = self.q()
        self.assertEqual(r["total"], 1)
        self.assertEqual(r["skipped"], 2)

    # --- filtering ---

    def test_filter_by_host(self):
        self.write(entry(host="a.example.com"), entry(host="b.example.com"))
        self.assertEqual(self.q("host:a.example.com")["total"], 1)

    def test_filter_by_status_code_and_class(self):
        self.write(entry(status=200), entry(status=404), entry(status=502), entry(status=503))
        self.assertEqual(self.q("status:5xx")["total"], 2)
        self.assertEqual(self.q("status:502")["total"], 1)
        self.assertEqual(self.q("status:5xx status:404")["total"], 3)  # OR within a key

    def test_filter_by_method_case_insensitive(self):
        self.write(entry(method="GET"), entry(method="POST"))
        self.assertEqual(self.q("method:post")["total"], 1)

    def test_path_filter_is_an_exact_path(self):
        # Exact, so a path facet's count always equals what clicking it returns.
        self.write(entry(uri="/api"), entry(uri="/api/v1/sync"), entry(uri="/apikeys"))
        self.assertEqual(self.q("path:/api")["total"], 1)
        self.assertEqual(self.q("path:/api/v1/sync")["total"], 1)

    def test_free_text_still_matches_substrings_of_the_path(self):
        # Substring search did not disappear with the exact path filter.
        self.write(entry(uri="/api"), entry(uri="/api/v1/sync"), entry(uri="/apikeys"))
        self.assertEqual(self.q("/api")["total"], 3)

    def test_path_facet_count_equals_the_filtered_total(self):
        self.write(entry(uri="/api"), entry(uri="/api"), entry(uri="/api/v1"), entry(uri="/apikeys"))
        facet = {v["value"]: v["count"] for v in self.q()["facets"]["path"]}
        for path, count in facet.items():
            self.assertEqual(self.q(f"path:{path}")["total"], count, path)

    def test_query_string_is_ignored_when_matching_paths(self):
        self.write(entry(uri="/search?q=1"), entry(uri="/search?q=2"))
        self.assertEqual(self.q("path:/search")["total"], 2)

    def test_cross_key_terms_and_together(self):
        self.write(
            entry(host="a.example.com", status=502),
            entry(host="a.example.com", status=200),
            entry(host="b.example.com", status=502),
        )
        self.assertEqual(self.q("host:a.example.com status:5xx")["total"], 1)

    def test_negation_excludes(self):
        self.write(entry(status=200), entry(status=200), entry(status=502))
        self.assertEqual(self.q("-status:2xx")["total"], 1)

    def test_free_text_matches_host_or_uri_case_insensitively(self):
        self.write(entry(host="nas.example.com", uri="/x"), entry(host="other.example.com", uri="/UGREEN/v1"))
        self.assertEqual(self.q("NAS")["total"], 1)
        self.assertEqual(self.q("ugreen")["total"], 1)

    def test_no_match_is_empty_not_an_error(self):
        self.write(entry())
        r = self.q("host:nope")
        self.assertEqual(r["total"], 0)
        self.assertEqual(r["entries"], [])
        self.assertEqual(r["stats"]["requests"], 0)

    # --- time range ---

    def test_range_limits_matches(self):
        self.write(*[entry(ts=T0 + i * 60) for i in range(10)])  # 10 minutes apart
        r = self.q(from_ts=T0 + 5 * 60, to_ts=T0 + 10 * 60)
        self.assertEqual(r["total"], 5)

    def test_range_predating_a_fully_read_log_is_not_truncation(self):
        # The whole file was read, so there is no older history being withheld;
        # saying otherwise would tell the user to read more of the log for
        # events that do not exist.
        self.write(entry(ts=T0 + 1000))
        r = self.q(from_ts=T0, to_ts=T0 + 2000)
        self.assertFalse(r["range"]["truncated"])
        self.assertAlmostEqual(r["range"]["earliest_ts"], T0 + 1000, places=3)

    def test_facets_count_by_value(self):
        self.write(
            entry(host="a.example.com", status=200, method="GET"),
            entry(host="a.example.com", status=502, method="GET"),
            entry(host="b.example.com", status=200, method="POST"),
        )
        f = self.q()["facets"]
        self.assertEqual({v["value"]: v["count"] for v in f["host"]},
                         {"a.example.com": 2, "b.example.com": 1})
        self.assertEqual({v["value"]: v["count"] for v in f["status_class"]},
                         {"2xx": 2, "5xx": 1})
        self.assertEqual({v["value"]: v["count"] for v in f["method"]},
                         {"GET": 2, "POST": 1})

    def test_facet_ignores_its_own_filter_but_honours_others(self):
        # With host:a active, the host facet must still show b as clickable,
        # while the status facet narrows to host a only.
        self.write(
            entry(host="a.example.com", status=200),
            entry(host="a.example.com", status=502),
            entry(host="b.example.com", status=404),
        )
        f = self.q("host:a.example.com")["facets"]
        hosts = {v["value"]: v["count"] for v in f["host"]}
        self.assertEqual(hosts, {"a.example.com": 2, "b.example.com": 1})
        classes = {v["value"]: v["count"] for v in f["status_class"]}
        self.assertEqual(classes, {"2xx": 1, "5xx": 1})

    def test_facet_values_are_capped_with_a_remainder(self):
        self.write(*[entry(host=f"h{i}.example.com") for i in range(60)])
        f = self.q(facet_limit=50)["facets"]
        self.assertEqual(len(f["host"]), 50)
        self.assertEqual(self.q(facet_limit=50)["facet_other"]["host"], 10)

    # --- histogram ---

    def test_histogram_totals_match_the_match_count(self):
        self.write(*[entry(ts=T0 + i * 30, status=200 if i % 2 else 502) for i in range(20)])
        r = self.q()
        h = r["histogram"]
        total = sum(sum(v for k, v in b.items() if k != "t") for b in h["buckets"])
        self.assertEqual(total, r["total"])

    def test_histogram_splits_by_status_class(self):
        self.write(entry(ts=T0, status=200), entry(ts=T0 + 1, status=502))
        b = self.q()["histogram"]["buckets"]
        self.assertEqual(sum(x.get("2xx", 0) for x in b), 1)
        self.assertEqual(sum(x.get("5xx", 0) for x in b), 1)

    def test_histogram_bucket_width_grows_with_the_span(self):
        self.write(entry(ts=T0), entry(ts=T0 + 60))
        narrow = self.q(from_ts=T0, to_ts=T0 + 120)["histogram"]["bucket_seconds"]
        self.write(entry(ts=T0 + 7 * 86400))
        wide = self.q(from_ts=T0, to_ts=T0 + 7 * 86400)["histogram"]["bucket_seconds"]
        self.assertGreater(wide, narrow)

    # --- stats ---

    def test_stats_are_exact(self):
        # 100 requests, 1ms..100ms; p95 is the 95th value.
        self.write(*[entry(ts=T0 + i, duration=i / 1000, size=10) for i in range(1, 101)])
        s = self.q()["stats"]
        self.assertEqual(s["requests"], 100)
        self.assertEqual(s["p95_latency_ms"], 95.0)
        self.assertAlmostEqual(s["avg_latency_ms"], 50.5, places=1)
        self.assertEqual(s["bytes_out"], 1000)

    def test_error_rate_counts_5xx_only(self):
        self.write(entry(status=200), entry(status=404), entry(status=502), entry(status=503))
        self.assertEqual(self.q()["stats"]["error_rate"], 50.0)

    # --- paging + caps ---

    def test_limit_caps_entries_but_not_total(self):
        self.write(*[entry(ts=T0 + i) for i in range(30)])
        r = self.q(limit=10)
        self.assertEqual(len(r["entries"]), 10)
        self.assertEqual(r["total"], 30)

    def test_paging_returns_events_sharing_the_boundary_timestamp(self):
        # Several events can share a ts; a strict comparison skipped the rest of
        # that instant, so the last page could never be reached.
        self.write(*[entry(ts=T0, uri=f"/same/{i}") for i in range(5)])
        first = self.q(limit=2)
        self.assertEqual(len(first["entries"]), 2)
        oldest = first["entries"][-1]
        rest = self.q(limit=10, before_ts=oldest["ts"], before_offset=oldest["offset"])
        self.assertEqual(len(rest["entries"]), 3)
        seen = {e["offset"] for e in first["entries"]} & {e["offset"] for e in rest["entries"]}
        self.assertEqual(seen, set())

    def test_before_ts_pages_strictly_older(self):
        self.write(*[entry(ts=T0 + i) for i in range(30)])
        first = self.q(limit=10)
        oldest = first["entries"][-1]["ts"]
        second = self.q(limit=10, before_ts=oldest)
        self.assertTrue(all(e["ts"] < oldest for e in second["entries"]))
        overlap = {e["ts"] for e in first["entries"]} & {e["ts"] for e in second["entries"]}
        self.assertEqual(overlap, set())

    def test_site_summary_groups_by_host(self):
        self.write(
            entry(ts=T0, host="a.example.com", status=200, duration=0.1, size=10),
            entry(ts=T0 + 1, host="a.example.com", status=502, duration=0.3, size=20),
            entry(ts=T0 + 2, host="b.example.com", status=200, duration=0.2, size=30),
        )
        r = self.index.site_summary()
        by = {s["host"]: s for s in r["sites"]}
        self.assertEqual(by["a.example.com"]["requests"], 2)
        self.assertEqual(by["a.example.com"]["errors"], 1)
        self.assertEqual(by["a.example.com"]["error_rate"], 50.0)
        self.assertEqual(by["a.example.com"]["bytes_out"], 30)
        self.assertEqual(by["b.example.com"]["requests"], 1)

    def test_site_summary_is_sorted_busiest_first(self):
        self.write(entry(host="quiet.example.com"), *[entry(host="busy.example.com") for _ in range(5)])
        hosts = [s["host"] for s in self.index.site_summary()["sites"]]
        self.assertEqual(hosts, ["busy.example.com", "quiet.example.com"])

    def test_site_summary_series_sums_to_requests(self):
        self.write(*[entry(ts=T0 + i * 60, host="a.example.com") for i in range(24)])
        site = self.index.site_summary()["sites"][0]
        self.assertEqual(sum(site["series"]), site["requests"])
        self.assertEqual(len(site["series"]), 24)

    def test_raw_line_round_trips_by_offset(self):
        self.write(entry(ts=T0, uri="/first"), entry(ts=T0 + 1, uri="/second"))
        r = self.q()
        newest = r["entries"][0]
        raw = self.index.raw_line(newest["file"], newest["offset"])
        self.assertIn('"/second"', raw)
        self.assertEqual(json.loads(raw)["request"]["uri"], "/second")

    def test_raw_line_outside_the_window_is_none(self):
        self.write(entry(ts=T0))
        self.q()
        self.assertIsNone(self.index.raw_line(99, 0))

    def test_max_events_drops_oldest_and_reports_it(self):
        idx = EventIndex(self.path, max_events=20)
        self.write(*[entry(ts=T0 + i) for i in range(30)])
        r = idx.query("")
        self.assertLessEqual(r["indexed"], 20)
        self.assertGreater(r["dropped"], 0)
        # The survivors must be the newest ones.
        self.assertAlmostEqual(r["entries"][0]["ts"], T0 + 29, places=3)


if __name__ == "__main__":
    unittest.main()
