"""Columnar event index + query engine behind /api/explore."""
import gzip
import json
import math
import os
import tempfile
import time
import unittest
from datetime import datetime, timezone

import tests._env as env  # noqa: F401  (sets env before src is imported)

from src import logfiles
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

    def test_client_is_a_key(self):
        f = parse_query("client:1.2.3.4 -client:2001:DB8::1")
        self.assertEqual(f.clients, {"1.2.3.4"})
        self.assertEqual(f.not_clients, {"2001:db8::1"})
        self.assertEqual(f.text, [])

    def test_status_other_is_a_class(self):
        f = parse_query("status:other")
        self.assertEqual(f.classes, {"other"})
        self.assertEqual(f.codes, set())
        self.assertEqual(f.text, [])

    def test_same_key_repeats_or_together(self):
        f = parse_query("host:a host:b")
        self.assertEqual(f.hosts, {"a", "b"})

    def test_negation(self):
        f = parse_query("-status:2xx -host:noisy")
        self.assertEqual(f.not_classes, {"2xx"})
        self.assertEqual(f.not_hosts, {"noisy"})

    def test_every_facet_key_can_be_negated(self):
        f = parse_query("-host:a -method:get -status:404 -path:/api")
        self.assertEqual(f.not_hosts, {"a"})
        self.assertEqual(f.not_methods, {"GET"})
        self.assertEqual(f.not_codes, {404})
        self.assertEqual(f.not_paths, ["/api"])
        # A negated term is a filter, not something to also search for as text.
        self.assertEqual(f.text, [])

    def test_a_bare_minus_word_is_still_free_text(self):
        f = parse_query("-timeout")
        self.assertEqual(f.text, ["-timeout"])

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

    def test_filter_by_status_other_matches_the_other_facet(self):
        # The Status facet buckets a missing or out-of-range code as "other";
        # clicking that row has to narrow to exactly those rows.
        self.write(entry(status=200), entry(status=404), entry(status=None))
        res = self.q("status:other")
        self.assertEqual(res["total"], 1)
        self.assertEqual([e["status"] for e in res["entries"]], [0])
        self.assertEqual(self.q("-status:other")["total"], 2)

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

    def test_negation_is_the_complement_of_inclusion(self):
        # What a facet promises when it shows an ✗: everything the ☑ would not.
        self.write(
            entry(host="a.example.com", method="GET", status=200, uri="/api"),
            entry(host="a.example.com", method="POST", status=404, uri="/api/v1"),
            entry(host="b.example.com", method="GET", status=502, uri="/api"),
            entry(host="c.example.com", method="HEAD", status=301, uri="/"),
        )
        total = self.q()["total"]
        for term in ("host:a.example.com", "method:GET", "status:404",
                     "status:5xx", "path:/api"):
            self.assertEqual(self.q(term)["total"] + self.q("-" + term)["total"],
                             total, term)

    def test_negated_path_excludes_the_exact_path(self):
        # Same grouping as the positive filter, so excluding a facet row removes
        # exactly the events that row counted.
        self.write(entry(uri="/api"), entry(uri="/api?x=1"),
                   entry(uri="/api/v1"), entry(uri="/apikeys"))
        self.assertEqual(self.q("-path:/api")["total"], 2)

    def test_negated_terms_and_across_keys(self):
        self.write(
            entry(host="a.example.com", status=200),
            entry(host="a.example.com", status=502),
            entry(host="b.example.com", status=200),
        )
        self.assertEqual(self.q("-host:a.example.com -status:5xx")["total"], 1)

    def test_excluding_a_code_narrows_an_included_class(self):
        # "5xx, but not the 502s I already know about" — the reason a query mixes
        # the two polarities for one key.
        self.write(entry(status=500), entry(status=502), entry(status=502), entry(status=200))
        self.assertEqual(self.q("status:5xx -status:502")["total"], 1)

    def test_excluded_classes_and_codes_are_both_kept_out(self):
        self.write(entry(status=200), entry(status=404), entry(status=502))
        self.assertEqual(self.q("-status:2xx -status:404")["total"], 1)

    def test_including_and_excluding_the_same_value_matches_nothing(self):
        # Contradictory but not an error: the UI keeps one polarity per value, so
        # this only happens when it is typed by hand.
        self.write(entry(host="a.example.com"), entry(host="b.example.com"))
        self.assertEqual(self.q("host:a.example.com -host:a.example.com")["total"], 0)

    def test_an_excluded_facet_still_reports_its_own_count(self):
        # The row you just excluded has to keep a truthful count, or clicking it
        # again would be a leap in the dark.
        self.write(*([entry(host="a.example.com")] * 3), entry(host="b.example.com"))
        facet = {v["value"]: v["count"] for v in self.q("-host:a.example.com")["facets"]["host"]}
        self.assertEqual(facet, {"a.example.com": 3, "b.example.com": 1})

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

    def test_client_filter_includes_and_excludes(self):
        self.write(entry(client="1.1.1.1"), entry(client="2.2.2.2"), entry(client="1.1.1.1"))
        self.assertEqual(self.q("client:1.1.1.1")["total"], 2)
        self.assertEqual(self.q("-client:1.1.1.1")["total"], 1)

    def test_client_filter_is_exact_not_substring(self):
        self.write(entry(client="10.0.0.1"), entry(client="10.0.0.12"))
        self.assertEqual(self.q("client:10.0.0.1")["total"], 1)

    def test_ip_summary_counts_and_ranks(self):
        self.write(
            entry(ts=T0, client="9.9.9.9", host="a.example.com", uri="/x?q=1", status=200),
            entry(ts=T0 + 5, client="9.9.9.9", host="a.example.com", uri="/x", status=502),
            entry(ts=T0 + 9, client="9.9.9.9", host="b.example.com", uri="/y", status=404),
            entry(ts=T0 + 3, client="8.8.8.8", host="c.example.com"),
        )
        s = self.index.ip_summary("9.9.9.9")
        self.assertEqual(s["requests"], 3)
        self.assertEqual(s["errors"], 1)
        self.assertEqual((s["first_ts"], s["last_ts"]), (T0, T0 + 9))
        self.assertEqual(s["hosts"][0], {"value": "a.example.com", "count": 2})
        self.assertEqual(s["host_count"], 2)
        # Query strings are grouped away, as in the path facet.
        self.assertEqual(s["paths"][0], {"value": "/x", "count": 2})
        self.assertEqual([c["value"] for c in s["status_classes"]], ["2xx", "4xx", "5xx"])

    def test_ip_summary_respects_the_range(self):
        self.write(entry(ts=T0, client="9.9.9.9"), entry(ts=T0 + 100, client="9.9.9.9"))
        self.assertEqual(self.index.ip_summary("9.9.9.9", T0 + 50, T0 + 200)["requests"], 1)

    def test_ip_summary_for_an_unseen_ip_is_empty(self):
        self.write(entry(client="1.1.1.1"))
        s = self.index.ip_summary("7.7.7.7")
        self.assertEqual(s["requests"], 0)
        self.assertIsNone(s["first_ts"])
        self.assertEqual(s["hosts"], [])


class SupersetCacheTest(unittest.TestCase):
    """Sliding and narrower ranges reuse the loaded index instead of rebuilding.

    A rebuild replaces the column arrays, so `index.ts is before` means reuse.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="superset-")
        self.path = os.path.join(self.dir, "access.log")
        self.index = EventIndex(self.path)
        self.future = time.time() + 3600   # "now" for an open-ended relative range

    def write(self, *entries):
        with open(self.path, "a") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")

    def test_shifted_open_range_reuses_the_cache_and_stays_exact(self):
        self.write(*[entry(ts=T0 + i, uri=f"/{i}") for i in range(100)])
        first = self.index.query("", from_ts=T0 + 10, to_ts=self.future)
        self.assertEqual(first["total"], 90)
        ts_before = self.index.ts

        second = self.index.query("", from_ts=T0 + 20, to_ts=self.future + 5)
        self.assertIs(self.index.ts, ts_before, "a narrower from must not rebuild")
        self.assertEqual(second["total"], 80)           # honours the requested from
        self.assertAlmostEqual(second["entries"][-1]["ts"], T0 + 20, places=3)

    def test_relative_range_resolved_at_request_time_is_open_ended(self):
        # The route resolves "last 30m" as (now - 1800, now), so `to` is already a
        # few microseconds old when the index sees it. That must still follow the
        # live file instead of rebuilding on every poll.
        now = time.time()
        self.write(*[entry(ts=now - 60 + i, uri=f"/a{i}") for i in range(10)])
        t = time.time()
        first = self.index.query("", from_ts=t - 1800, to_ts=t)
        self.assertEqual(first["total"], 10)
        ts_before = self.index.ts

        self.write(*[entry(ts=now - 20 + i, uri=f"/b{i}") for i in range(5)])
        t = time.time()
        second = self.index.query("", from_ts=t - 1800, to_ts=t)
        self.assertIs(self.index.ts, ts_before, "a sliding range must not rebuild")
        self.assertEqual(second["total"], 15)
        self.assertEqual(len({e["offset"] for e in second["entries"]}), 15)

        # Paging echoes ceil(to) of the first request, which can sit just ahead
        # of or a few seconds behind the current time; both stay on the cache.
        paged = self.index.query("", from_ts=math.floor(t - 1800), to_ts=math.ceil(t) - 5)
        self.assertIs(self.index.ts, ts_before)
        self.assertEqual(paged["total"], 15)

    def test_historical_subrange_reuses_the_cache_and_honours_to(self):
        self.write(*[entry(ts=T0 + i) for i in range(100)])
        self.index.query("", from_ts=T0, to_ts=self.future)
        ts_before = self.index.ts
        r = self.index.query("", from_ts=T0 + 20, to_ts=T0 + 50)
        self.assertIs(self.index.ts, ts_before)
        self.assertEqual(r["total"], 31)
        self.assertAlmostEqual(r["entries"][0]["ts"], T0 + 50, places=3)

    def test_growing_live_file_is_folded_into_a_shifted_range(self):
        self.write(*[entry(ts=T0 + i) for i in range(10)])
        self.index.query("", from_ts=T0, to_ts=self.future)
        ts_before = self.index.ts
        self.write(*[entry(ts=T0 + 10 + i) for i in range(5)])
        r = self.index.query("", from_ts=T0 + 5, to_ts=self.future + 1)
        self.assertIs(self.index.ts, ts_before, "growth must be folded, not rebuilt")
        self.assertEqual(r["total"], 10)                # T0+5 .. T0+14, none twice
        r = self.index.query("", from_ts=T0 + 5, to_ts=self.future + 2)
        self.assertEqual(r["total"], 10, "an unchanged poll must not re-count")

    def test_a_wider_range_rebuilds(self):
        self.write(*[entry(ts=T0 + i) for i in range(20)])
        self.index.query("", from_ts=T0 + 10, to_ts=self.future)
        ts_before = self.index.ts
        r = self.index.query("", from_ts=T0, to_ts=self.future)
        self.assertIsNot(self.index.ts, ts_before)
        self.assertEqual(r["total"], 20)

    def test_replaced_live_file_is_detected_and_rebuilt(self):
        self.write(*[entry(ts=T0 + i, uri="/old") for i in range(10)])
        self.index.query("", from_ts=T0, to_ts=self.future)
        ts_before = self.index.ts
        # Rotation: the old file keeps existing under another name, so the new
        # one is guaranteed a different inode. The new file is larger, so size
        # alone would wrongly look like growth.
        os.rename(self.path, self.path + ".old")
        self.write(*[entry(ts=T0 + 100 + i, uri="/new") for i in range(30)])
        r = self.index.query("", from_ts=T0, to_ts=self.future + 1)
        self.assertIsNot(self.index.ts, ts_before)
        self.assertEqual(r["total"], 30)
        self.assertEqual({e["uri"] for e in r["entries"]}, {"/new"})

    def test_event_cap_still_applies_when_folding(self):
        idx = EventIndex(self.path, max_events=20)
        self.write(*[entry(ts=T0 + i) for i in range(15)])
        idx.query("", from_ts=T0, to_ts=self.future)
        self.write(*[entry(ts=T0 + 15 + i) for i in range(15)])
        r = idx.query("", from_ts=T0, to_ts=self.future + 1)
        self.assertLessEqual(r["indexed"], 20)
        self.assertGreater(r["dropped"], 0)
        self.assertAlmostEqual(r["entries"][0]["ts"], T0 + 29, places=3)


class RawReferenceTest(unittest.TestCase):
    """Raw-line references work in any worker and cannot name other files."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="rawref-")
        self.path = os.path.join(self.dir, "access.log")
        stamp = datetime.fromtimestamp(T0 + 60, timezone.utc).strftime("%Y-%m-%dT%H-%M-%S.%f")[:-3]
        self.archive = os.path.join(self.dir, f"access-{stamp}-size.log.gz")
        with gzip.open(self.archive, "wt") as f:
            for i in range(5):
                f.write(json.dumps(entry(ts=T0 + i, host="old.example.com", uri=f"/old{i}")) + "\n")
        with open(self.path, "w") as f:
            for i in range(5):
                f.write(json.dumps(entry(ts=T0 + 7200 + i, host="live.example.com", uri=f"/live{i}")) + "\n")

    def entries(self):
        r = EventIndex(self.path).query("", from_ts=T0, to_ts=T0 + 8000, limit=100)
        return {e["uri"]: e for e in r["entries"]}

    def test_reference_resolves_in_a_fresh_index_without_loading_anything(self):
        found = self.entries()
        other = EventIndex(self.path)   # another worker: nothing loaded, other range
        for uri in ("/old3", "/live2"):
            e = found[uri]
            raw = other.raw_line(e["file"], e["offset"])
            self.assertEqual(json.loads(raw)["request"]["uri"], uri)
        self.assertFalse(other._built)

    def test_reference_does_not_depend_on_the_requested_range(self):
        wide = self.entries()["/live1"]
        narrow = EventIndex(self.path).query("", from_ts=T0 + 7200, to_ts=T0 + 8000)
        same = next(e for e in narrow["entries"] if e["uri"] == "/live1")
        self.assertEqual((wide["file"], wide["offset"]), (same["file"], same["offset"]))

    def test_reference_is_not_a_path(self):
        e = self.entries()["/old1"]
        self.assertNotIn(os.sep, e["file"])
        self.assertIsInstance(e["file"], str)

    def test_unsafe_and_unknown_references_are_rejected(self):
        with open(os.path.join(self.dir, "secret.txt"), "w") as f:
            f.write("secret\n")
        idx = EventIndex(self.path)
        for bad in ("../secret.txt", "/etc/passwd", os.path.join(self.dir, "secret.txt"),
                    "secret.txt", "..", ".", "", "a\0b", "sub/../access.log",
                    "access.log",          # live file without its identity suffix
                    "nope.log", 3, None):
            self.assertIsNone(idx.raw_line(bad, 0), repr(bad))

    def test_reference_to_a_rotated_live_file_stops_resolving(self):
        e = self.entries()["/live0"]
        os.rename(self.path, self.path + ".old")
        with open(self.path, "w") as f:
            f.write(json.dumps(entry(ts=T0 + 9000, uri="/other")) + "\n")
        self.assertIsNone(EventIndex(self.path).raw_line(e["file"], e["offset"]))

    def test_offset_past_the_end_is_none(self):
        e = self.entries()["/old0"]
        idx = EventIndex(self.path)
        self.assertIsNone(idx.raw_line(e["file"], 10 ** 9))
        self.assertIsNone(idx.raw_line(e["file"], -1))


class CorruptArchiveTest(unittest.TestCase):
    """A damaged archive must not leave a partial or replaced index behind."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="corrupt-")
        self.path = os.path.join(self.dir, "access.log")
        stamp = datetime.fromtimestamp(T0 + 600, timezone.utc).strftime("%Y-%m-%dT%H-%M-%S.%f")[:-3]
        self.archive = os.path.join(self.dir, f"access-{stamp}-size.log.gz")
        with gzip.open(self.archive, "wt") as f:
            for i in range(400):
                f.write(json.dumps(entry(ts=T0 + i, uri=f"/old/{i}/{'x' * (i % 17)}")) + "\n")
        with open(self.path, "w") as f:
            for i in range(10):
                f.write(json.dumps(entry(ts=T0 + 7200 + i, uri=f"/live{i}")) + "\n")

    def truncate_archive(self):
        with open(self.archive, "rb") as f:
            data = f.read()
        with open(self.archive, "wb") as f:
            f.write(data[: len(data) // 2])

    def test_a_failed_first_build_leaves_nothing_marked_built(self):
        self.truncate_archive()
        idx = EventIndex(self.path)
        with self.assertRaises(logfiles.READ_ERRORS):
            idx.query("", from_ts=T0, to_ts=T0 + 8000)
        self.assertFalse(idx._built)
        self.assertEqual(len(idx.ts), 0)

    def test_a_failed_rebuild_keeps_the_previous_good_index(self):
        idx = EventIndex(self.path)
        good = idx.query("", from_ts=T0 + 7200, to_ts=T0 + 8000)
        self.assertEqual(good["total"], 10)
        ts_before, n_before = idx.ts, len(idx.ts)

        self.truncate_archive()
        with self.assertRaises(logfiles.READ_ERRORS):
            idx.query("", from_ts=T0, to_ts=T0 + 8000)   # wider: needs the archive

        self.assertIs(idx.ts, ts_before)
        self.assertEqual(len(idx.ts), n_before)
        self.assertTrue(idx._built)
        # A range that never touches the damaged archive still works.
        again = idx.query("", from_ts=T0 + 7200, to_ts=T0 + 8000)
        self.assertEqual(again["total"], 10)

    def test_a_failed_rebuild_keeps_a_previously_good_wide_index(self):
        idx = EventIndex(self.path)
        self.assertEqual(idx.query("", from_ts=T0, to_ts=T0 + 8000)["total"], 410)
        ts_before = idx.ts
        self.truncate_archive()
        with self.assertRaises(logfiles.READ_ERRORS):
            idx.query("", from_ts=T0 - 5, to_ts=T0 + 8000)
        self.assertIs(idx.ts, ts_before)
        self.assertEqual(len(idx.ts), 410)


class PreviousWindowTest(unittest.TestCase):
    """site_summary's previous_total counts the equal window before the range."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="eventindex-prev-")
        self.path = os.path.join(self.dir, "access.log")
        self.index = EventIndex(self.path)
        with open(self.path, "a") as f:
            for i in range(120):   # one event a minute for two hours
                f.write(json.dumps(entry(ts=T0 + i * 60)) + "\n")

    def test_both_windows_have_data(self):
        r = self.index.site_summary(T0 + 3600, T0 + 7200)
        self.assertEqual(sum(s["requests"] for s in r["sites"]), 60)
        self.assertEqual(r["previous_total"], 60)

    def test_empty_previous_window_is_zero(self):
        r = self.index.site_summary(T0 - 100, T0 + 3500)
        self.assertEqual(r["previous_total"], 0)

    def test_is_null_without_a_range(self):
        self.assertIsNone(self.index.site_summary()["previous_total"])

    def test_current_range_stats_are_unchanged(self):
        r = self.index.site_summary(T0 + 3600, T0 + 7200)
        self.assertEqual(r["from"], T0 + 3600)
        self.assertEqual(r["to"], T0 + 7200)
        self.assertEqual(r["sites"][0]["requests"], 60)


if __name__ == "__main__":
    unittest.main()


def cf_entry(country, **kw):
    e = entry(**kw)
    e["cf_country"] = country
    e["cf_ray"] = "8f1e2d3c4b5a6978-OTP"
    return e


class CloudflareCountryTest(unittest.TestCase):
    """cf_country comes from an opt-in `log_append` in the Caddyfile."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="eventindex-cf-")
        self.path = os.path.join(self.dir, "access.log")
        self.index = EventIndex(self.path)

    def write(self, *entries):
        with open(self.path, "a") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")

    def test_parse_country_terms(self):
        f = parse_query("country:ro -country:us")
        self.assertEqual(f.countries, {"RO"})
        self.assertEqual(f.not_countries, {"US"})
        self.assertEqual(f.text, [])

    def test_country_is_indexed_and_returned(self):
        self.write(cf_entry("RO", ts=T0))
        e = self.index.query("")["entries"][0]
        self.assertEqual(e["cf_country"], "RO")

    def test_filter_and_exclude_by_country(self):
        self.write(cf_entry("RO", ts=T0), cf_entry("US", ts=T0 + 1), cf_entry("RO", ts=T0 + 2))
        self.assertEqual(self.index.query("country:ro")["total"], 2)
        self.assertEqual(self.index.query("-country:RO")["total"], 1)

    def test_country_facet_counts(self):
        self.write(cf_entry("RO", ts=T0), cf_entry("US", ts=T0 + 1), cf_entry("RO", ts=T0 + 2))
        facet = self.index.query("")["facets"]["country"]
        self.assertEqual(facet, [{"value": "RO", "count": 2}, {"value": "US", "count": 1}])

    def test_without_cloudflare_nothing_changes(self):
        # No log_append: entries have no cf_* keys, the facet is empty (the UI
        # hides it) and entries carry no extra field.
        self.write(entry(ts=T0), entry(ts=T0 + 1))
        r = self.index.query("")
        self.assertEqual(r["facets"]["country"], [])
        self.assertNotIn("cf_country", r["entries"][0])

    def test_empty_header_value_is_not_a_country(self):
        # log_append writes "" when the request did not come through Cloudflare.
        self.write(cf_entry("", ts=T0))
        r = self.index.query("")
        self.assertEqual(r["facets"]["country"], [])
        self.assertNotIn("cf_country", r["entries"][0])

    def test_junk_country_values_are_ignored(self):
        self.write(cf_entry("<script>", ts=T0), cf_entry("ROMANIA", ts=T0 + 1), cf_entry(7, ts=T0 + 2))
        r = self.index.query("")
        self.assertEqual(r["total"], 3)
        self.assertEqual(r["facets"]["country"], [])

    def test_cloudflare_special_codes_are_kept(self):
        # XX = unknown, T1 = Tor.
        self.write(cf_entry("XX", ts=T0), cf_entry("T1", ts=T0 + 1))
        values = {v["value"] for v in self.index.query("")["facets"]["country"]}
        self.assertEqual(values, {"XX", "T1"})


class ProxyIpWarningTest(unittest.TestCase):
    """site_summary flags logs where nearly every request comes from one proxy IP."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="eventindex-proxy-")
        self.path = os.path.join(self.dir, "access.log")
        self.index = EventIndex(self.path)

    def write_many(self, n, client, start=0):
        with open(self.path, "a") as f:
            for i in range(n):
                f.write(json.dumps(entry(ts=T0 + start + i, client=client)) + "\n")

    def test_docker_range_single_ip_is_flagged(self):
        self.write_many(60, "172.24.0.3")
        warn = self.index.site_summary()["single_proxy_ip"]
        self.assertEqual(warn, {"ip": "172.24.0.3", "share": 100.0, "requests": 60})

    def test_flagged_at_95_percent(self):
        self.write_many(95, "172.17.0.1")
        self.write_many(5, "81.2.69.160", start=1000)
        self.assertIsNotNone(self.index.site_summary()["single_proxy_ip"])

    def test_not_flagged_below_95_percent(self):
        self.write_many(90, "172.17.0.1")
        self.write_many(10, "81.2.69.160", start=1000)
        self.assertIsNone(self.index.site_summary()["single_proxy_ip"])

    def test_home_lan_single_user_is_not_flagged(self):
        self.write_many(100, "192.168.0.5")
        self.assertIsNone(self.index.site_summary()["single_proxy_ip"])

    def test_too_few_requests_is_not_flagged(self):
        self.write_many(49, "172.24.0.3")
        self.assertIsNone(self.index.site_summary()["single_proxy_ip"])

    def test_public_ip_is_not_flagged(self):
        self.write_many(100, "81.2.69.160")
        self.assertIsNone(self.index.site_summary()["single_proxy_ip"])

    def test_empty_log(self):
        self.assertIsNone(self.index.site_summary()["single_proxy_ip"])
