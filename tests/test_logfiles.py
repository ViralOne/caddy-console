"""Locating log data in time: file discovery, bisection, and archives."""
import gzip
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone

import tests._env as env  # noqa: F401  (sets env before src is imported)

from src import logfiles
from src.eventindex import EventIndex

T0 = 1790000000.0


def line(ts, host="a.example.com", uri="/", status=200):
    return json.dumps({
        "ts": ts, "status": status, "duration": 0.1, "size": 10,
        "request": {"host": host, "uri": uri, "method": "GET", "client_ip": "1.2.3.4"},
    }) + "\n"


class DiscoverTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="logfiles-")
        self.live = os.path.join(self.dir, "access.log")
        open(self.live, "w").close()

    def touch(self, name, body=""):
        path = os.path.join(self.dir, name)
        if name.endswith(".gz"):
            with gzip.open(path, "wt") as f:
                f.write(body)
        else:
            with open(path, "w") as f:
                f.write(body)
        return path

    def test_live_file_alone(self):
        files = logfiles.discover(self.live)
        self.assertEqual(len(files), 1)
        self.assertTrue(files[0].is_live)
        self.assertIsNone(files[0].rolled_at)

    def test_rolls_are_found_and_ordered_oldest_first(self):
        # Caddy's naming: <name>-<stamp>-<reason>.log[.gz]
        self.touch("access-2026-01-30T22-15-42.123-size.log.gz")
        self.touch("access-2026-01-29T00-00-00.000-time.log.gz")
        names = [os.path.basename(f.path) for f in logfiles.discover(self.live)]
        self.assertEqual(names, [
            "access-2026-01-29T00-00-00.000-time.log.gz",
            "access-2026-01-30T22-15-42.123-size.log.gz",
            "access.log",
        ])

    def test_gzip_and_plain_rolls_are_both_recognised(self):
        self.touch("access-2026-01-30T22-15-42.123-size.log.gz")
        self.touch("access-2026-01-31T22-15-42.123-size.log")
        flags = {os.path.basename(f.path): f.gzip for f in logfiles.discover(self.live) if not f.is_live}
        self.assertTrue(flags["access-2026-01-30T22-15-42.123-size.log.gz"])
        self.assertFalse(flags["access-2026-01-31T22-15-42.123-size.log"])

    def test_unrelated_files_are_ignored(self):
        self.touch("other-2026-01-30T22-15-42.123-size.log.gz")   # different base
        self.touch("access.log.1")                                 # not Caddy's scheme
        self.touch("notes.txt")
        self.assertEqual(len(logfiles.discover(self.live)), 1)

    def test_a_roll_spans_from_the_previous_roll_to_its_own_stamp(self):
        # The stamp is when the file stopped being written, so it is the end.
        self.touch("access-2026-01-29T00-00-00.000-time.log.gz")
        self.touch("access-2026-01-30T00-00-00.000-time.log.gz")
        rolls = [f for f in logfiles.discover(self.live) if not f.is_live]
        self.assertIsNone(rolls[0].starts_at)                       # nothing precedes it
        self.assertEqual(rolls[1].starts_at, rolls[0].rolled_at)

    def test_covers_excludes_files_outside_the_range(self):
        self.touch("access-2026-01-29T00-00-00.000-time.log.gz")
        self.touch("access-2026-01-30T00-00-00.000-time.log.gz")
        old, recent, live = logfiles.discover(self.live)
        # A range starting after the first roll closed cannot be in it.
        after = recent.rolled_at + 3600
        self.assertFalse(old.covers(after, after + 60))
        self.assertTrue(live.covers(after, after + 60))

    def test_an_unparseable_stamp_is_kept_rather_than_skipped(self):
        # Better to read a file needlessly than to hide history.
        self.touch("access-not-a-date-size.log.gz")
        names = [os.path.basename(f.path) for f in logfiles.discover(self.live)]
        self.assertIn("access-not-a-date-size.log.gz", names)


class BisectTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="bisect-")
        self.path = os.path.join(self.dir, "access.log")

    def write(self, count, step=1.0):
        with open(self.path, "w") as f:
            for i in range(count):
                f.write(line(T0 + i * step, uri=f"/{i}"))

    def test_offset_is_zero_when_the_target_predates_the_file(self):
        self.write(50)
        self.assertEqual(logfiles.offset_at(self.path, T0 - 100), 0)

    def test_offset_skips_ahead_for_a_later_target(self):
        self.write(4000)
        size = os.path.getsize(self.path)
        offset = logfiles.offset_at(self.path, T0 + 3500)
        self.assertGreater(offset, 0)
        self.assertLess(offset, size)

    def test_no_entry_at_or_after_the_target_is_missed(self):
        # The whole point: reading from the returned offset must still see every
        # entry from the target onwards.
        self.write(4000)
        target = T0 + 2500
        offset = logfiles.offset_at(self.path, target)
        live = logfiles.discover(self.path)[-1]
        seen = 0
        for _, raw in logfiles.iter_lines(live, offset):
            ts = json.loads(raw)["ts"]
            if ts >= target:
                seen += 1
        self.assertEqual(seen, 1500)

    def test_empty_file(self):
        open(self.path, "w").close()
        self.assertEqual(logfiles.offset_at(self.path, T0), 0)

    def test_tolerates_out_of_order_timestamps(self):
        # Real logs interleave slightly under concurrent writes; the slack
        # back-off must stop that hiding an entry.
        with open(self.path, "w") as f:
            for i in range(2000):
                skew = -0.5 if i % 500 == 0 else 0.0
                f.write(line(T0 + i + skew, uri=f"/{i}"))
        target = T0 + 1000
        offset = logfiles.offset_at(self.path, target)
        live = logfiles.discover(self.path)[-1]
        found = sum(1 for _, raw in logfiles.iter_lines(live, offset)
                    if json.loads(raw)["ts"] >= target)
        expected = sum(1 for i in range(2000)
                       if T0 + i + (-0.5 if i % 500 == 0 else 0.0) >= target)
        self.assertEqual(found, expected)


class AcrossFilesTest(unittest.TestCase):
    """Reading a range that reaches back into rolled archives."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="across-")
        self.live = os.path.join(self.dir, "access.log")
        # Two archives and a live file, an hour apart each.
        self.t_old = T0
        self.t_mid = T0 + 3600
        self.t_now = T0 + 7200
        # Names must agree with the timestamps inside, since the stamp is what
        # decides whether a file is worth opening.
        def roll(end_ts, host, start_ts):
            stamp = datetime.fromtimestamp(end_ts, timezone.utc).strftime("%Y-%m-%dT%H-%M-%S.%f")[:-3]
            with gzip.open(os.path.join(self.dir, f"access-{stamp}-size.log.gz"), "wt") as f:
                for i in range(10):
                    f.write(line(start_ts + i, host=host))

        roll(self.t_old + 60, "old.example.com", self.t_old)
        roll(self.t_mid + 60, "mid.example.com", self.t_mid)
        with open(self.live, "w") as f:
            for i in range(10):
                f.write(line(self.t_now + i, host="live.example.com"))
        self.index = EventIndex(self.live)

    def test_a_wide_range_reads_archives_too(self):
        r = self.index.query("", from_ts=self.t_old, to_ts=self.t_now + 100)
        hosts = {v["value"] for v in r["facets"]["host"]}
        self.assertEqual(hosts, {"old.example.com", "mid.example.com", "live.example.com"})
        self.assertEqual(r["total"], 30)
        self.assertEqual(r["history"]["rolls_read"], 2)

    def test_a_recent_range_reads_only_the_live_file(self):
        # The saving that makes a 30-minute default cheap: archives are not
        # touched at all when the range does not reach them.
        r = self.index.query("", from_ts=self.t_now, to_ts=self.t_now + 100)
        self.assertEqual(r["total"], 10)
        self.assertEqual(r["history"]["rolls_read"], 0)
        self.assertEqual(r["history"]["rolls_available"], 2)

    def test_entries_outside_the_range_are_not_counted(self):
        r = self.index.query("", from_ts=self.t_mid, to_ts=self.t_mid + 5)
        self.assertEqual(r["total"], 6)
        self.assertEqual({v["value"] for v in r["facets"]["host"]}, {"mid.example.com"})

    def test_raw_line_works_for_an_archived_entry(self):
        r = self.index.query("host:old.example.com", from_ts=self.t_old, to_ts=self.t_now + 100)
        e = r["entries"][0]
        raw = self.index.raw_line(e["file"], e["offset"])
        self.assertEqual(json.loads(raw)["request"]["host"], "old.example.com")

    def test_history_reports_what_is_available(self):
        r = self.index.query("", from_ts=self.t_now, to_ts=self.t_now + 100)
        self.assertEqual(r["history"]["rolls_available"], 2)
        self.assertIn("access.log", r["history"]["files_read"])


if __name__ == "__main__":
    unittest.main()
