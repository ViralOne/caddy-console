"""DB-IP Country Lite dataset: parsing, CIDR conversion and the updater (spec 4.3).

Synthetic documentation-range fixtures only; nothing is downloaded.
Run with:  uv run --frozen python -m unittest tests.test_country_dataset -v
"""
import datetime
import gzip
import os
import shutil
import tempfile
import unittest

import tests._env as env  # noqa: F401  (sets env before src is imported)

from src import geoip_update
from src.bans import countrydata

CSV = """192.0.2.0,192.0.2.127,RO
192.0.2.128,192.0.2.255,RO
198.51.100.0,198.51.100.255,DE
203.0.113.0,203.0.113.255,FR
2001:db8:1::,2001:db8:1:ffff:ffff:ffff:ffff:ffff,RO
"""
NOV = datetime.date(2026, 11, 12)


def rows(text):
    return countrydata.parse_csv(text.splitlines())


class ParseTest(unittest.TestCase):
    def test_adjacent_same_country_ranges_merge_into_canonical_cidrs(self):
        self.assertEqual(rows(CSV), [("192.0.2.0/24", "RO"), ("198.51.100.0/24", "DE"),
                                     ("203.0.113.0/24", "FR"), ("2001:db8:1::/48", "RO")])

    def test_overlapping_same_country_ranges_merge(self):
        self.assertEqual(rows("192.0.2.0,192.0.2.200,RO\n192.0.2.100,192.0.2.255,RO\n"), [("192.0.2.0/24", "RO")])

    def test_adjacent_ranges_of_different_countries_stay_apart(self):
        self.assertEqual(rows("192.0.2.0,192.0.2.127,RO\n192.0.2.128,192.0.2.255,DE\n"),
                         [("192.0.2.0/25", "RO"), ("192.0.2.128/25", "DE")])

    def test_unaligned_range_becomes_several_prefixes(self):
        self.assertEqual([c for c, _ in rows("192.0.2.1,192.0.2.6,RO\n")],
                         ["192.0.2.1/32", "192.0.2.2/31", "192.0.2.4/31", "192.0.2.6/32"])

    def test_every_row_is_validated(self):
        bad = {
            "not an address": "192.0.2.x,192.0.2.9,RO",
            "reversed": "192.0.2.9,192.0.2.1,RO",
            "mixed families": "192.0.2.1,2001:db8::1,RO",
            "lowercase code": "192.0.2.1,192.0.2.9,ro",
            "long code": "192.0.2.1,192.0.2.9,ROU",
            "missing field": "192.0.2.1,192.0.2.9",
            "mapped ipv6": "::ffff:192.0.2.1,::ffff:192.0.2.9,RO",
            "different countries overlap": "192.0.2.0,192.0.2.200,RO\n192.0.2.100,192.0.2.255,DE",
            "empty": "",
        }
        for name, text in bad.items():
            with self.subTest(name), self.assertRaises(countrydata.DatasetError):
                rows(text)

    def test_long_lines_are_refused(self):
        with self.assertRaises(countrydata.DatasetError):
            rows("192.0.2.1,192.0.2.9,RO" + " " * 300)


class LoadTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)

    def write(self, data):
        with open(countrydata.path(self.dir), "wb") as f:
            f.write(data)

    def test_load_selects_codes_and_collapses(self):
        self.write(countrydata.dumps(rows(CSV), "2026-11"))
        ranges, month = countrydata.load(["RO", "DE"], self.dir)
        self.assertEqual(month, "2026-11")
        self.assertEqual([str(n) for n in ranges["v4"]], ["192.0.2.0/24", "198.51.100.0/24"])
        self.assertEqual([str(n) for n in ranges["v6"]], ["2001:db8:1::/48"])
        self.assertEqual(countrydata.info(self.dir), {"present": True, "month": "2026-11", "prefixes": 4})

    def test_missing_or_malformed_dataset_raises(self):
        with self.assertRaises(countrydata.DatasetError):
            countrydata.load(["RO"], self.dir)
        self.write(b"garbage\n")
        with self.assertRaises(countrydata.DatasetError):
            countrydata.load(["RO"], self.dir)
        self.assertFalse(countrydata.info(self.dir)["present"])
        self.write(countrydata.dumps(rows(CSV), "2026-11") + b"192.0.2.1/24 RO\n")
        with self.assertRaises(countrydata.DatasetError):
            countrydata.load(["RO"], self.dir)


class FakeResp:
    def __init__(self, status, body):
        self.status_code, self.body = status, body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def iter_content(self, n):
        for i in range(0, len(self.body), n):
            yield self.body[i:i + n]


class FakeSession:
    def __init__(self, bodies):
        self.bodies, self.calls = bodies, []

    def get(self, url, **kw):
        self.calls.append(url)
        if url not in self.bodies:
            return FakeResp(404, b"")
        return FakeResp(200, self.bodies[url])


def url(month):
    return geoip_update.COUNTRY_URL.format(month=month)


class UpdaterTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)

    def run_update(self, bodies, today=NOV):
        return geoip_update.update_country_once(self.dir, today, FakeSession(bodies))

    def test_installs_the_current_month_and_leaves_no_debris(self):
        self.assertEqual(self.run_update({url("2026-11"): gzip.compress(CSV.encode())}), "updated")
        self.assertEqual(countrydata.info(self.dir), {"present": True, "month": "2026-11", "prefixes": 4})
        self.assertEqual(sorted(n for n in os.listdir(self.dir) if n.startswith(".") and n != ".update.lock"), [])
        self.assertEqual(self.run_update({}), "current")

    def test_falls_back_to_last_month_then_reports_not_published(self):
        self.assertEqual(self.run_update({url("2026-10"): gzip.compress(CSV.encode())},
                                         today=datetime.date(2026, 11, 1)), "updated")
        self.assertEqual(countrydata.info(self.dir)["month"], "2026-10")
        self.assertEqual(self.run_update({}, today=datetime.date(2026, 11, 1)), "not-published")

    def test_any_error_keeps_the_previous_dataset(self):
        self.assertEqual(self.run_update({url("2026-10"): gzip.compress(CSV.encode())}, today=datetime.date(2026, 10, 5)),
                         "updated")
        before = open(countrydata.path(self.dir), "rb").read()
        for name, body in {"bad row": gzip.compress(b"192.0.2.9,192.0.2.1,RO\n"),
                           "not gzip": b"plain text", "empty": gzip.compress(b""),
                           "non ascii": gzip.compress("192.0.2.1,192.0.2.9,RÔ\n".encode())}.items():
            with self.subTest(name):
                self.assertEqual(self.run_update({url("2026-11"): body}), "failed")
                self.assertEqual(open(countrydata.path(self.dir), "rb").read(), before)
        meta = geoip_update._read_meta(self.dir)
        self.assertEqual(meta["country_month"], "2026-10")
        self.assertIn("country_last_error", meta)

    def test_size_limits_apply_to_both_sides(self):
        body = gzip.compress(CSV.encode())
        self.addCleanup(setattr, geoip_update, "COUNTRY_MAX_DOWNLOAD_BYTES", geoip_update.COUNTRY_MAX_DOWNLOAD_BYTES)
        geoip_update.COUNTRY_MAX_DOWNLOAD_BYTES = len(body) - 1
        self.assertEqual(self.run_update({url("2026-11"): body}), "failed")
        geoip_update.COUNTRY_MAX_DOWNLOAD_BYTES = 10 ** 6
        self.addCleanup(setattr, geoip_update, "COUNTRY_MAX_UNCOMPRESSED_BYTES",
                        geoip_update.COUNTRY_MAX_UNCOMPRESSED_BYTES)
        geoip_update.COUNTRY_MAX_UNCOMPRESSED_BYTES = len(CSV) - 1
        self.assertEqual(self.run_update({url("2026-11"): body}), "failed")
        self.assertFalse(countrydata.info(self.dir)["present"])

    def test_city_and_asn_files_are_not_touched(self):
        for name in (geoip_update.CITY_FILE, geoip_update.ASN_FILE):
            with open(os.path.join(self.dir, name), "wb") as f:
                f.write(b"old")
        self.run_update({url("2026-11"): gzip.compress(CSV.encode())})
        for name in (geoip_update.CITY_FILE, geoip_update.ASN_FILE):
            self.assertEqual(open(os.path.join(self.dir, name), "rb").read(), b"old")


if __name__ == "__main__":
    unittest.main()
