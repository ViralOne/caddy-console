"""IP lookups and the monthly DB-IP updater. Offline: downloads are faked."""
import datetime
import fcntl
import gzip
import json
import os
import shutil
import tempfile
import unittest

import tests._env as env  # noqa: F401  (sets env before src is imported)

import requests

from src import geoip_update
from src.geoip import ASN_FILE, CITY_FILE, VERSION_FILE, GeoIP, classify
from tests._mmdb import ASN, CITY, build, write_fixtures

OCT = datetime.date(2026, 10, 12)


class ClassifyTest(unittest.TestCase):
    def test_kinds(self):
        cases = {
            "172.126.2.72": "public", "2606:4700::1111": "public",
            "10.1.2.3": "private", "192.168.0.10": "private", "fd00::1": "private",
            "127.0.0.1": "loopback", "::1": "loopback",
            "169.254.1.1": "link-local", "100.64.3.4": "cgnat",
            "224.0.0.1": "multicast", "::ffff:10.0.0.1": "private",
        }
        for ip, kind in cases.items():
            self.assertEqual(classify(ip), kind, ip)

    def test_not_an_ip(self):
        for bad in ("", "example.com", "1.2.3", "1.2.3.4/24"):
            self.assertIsNone(classify(bad))


class LookupTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.now = [0.0]
        self.geo = GeoIP(self.dir, recheck=600, clock=lambda: self.now[0])

    def test_without_databases_it_still_classifies(self):
        r = self.geo.lookup("172.126.2.72")
        self.assertEqual(r, {"kind": "public", "location": None, "asn": None})
        self.assertFalse(self.geo.status()["available"])

    def test_location_and_asn(self):
        write_fixtures(self.dir)
        r = self.geo.lookup("172.126.2.72")
        self.assertEqual(r["location"]["city"], "Oakland")
        self.assertEqual(r["location"]["region"], "California")
        self.assertEqual(r["location"]["country_code"], "US")
        self.assertEqual(r["asn"], {"number": 7018, "org": "AT&T Enterprises, LLC"})

    def test_private_ranges_skip_the_database(self):
        write_fixtures(self.dir)
        self.assertEqual(self.geo.lookup("10.0.0.1")["location"], None)

    def test_ip_not_in_database(self):
        write_fixtures(self.dir)
        r = self.geo.lookup("8.8.8.8")
        self.assertIsNone(r["location"])
        self.assertIsNone(r["asn"])

    def test_ipv6_against_an_ipv4_database_is_not_an_error(self):
        write_fixtures(self.dir)
        self.assertIsNone(self.geo.lookup("2606:4700::1111")["location"])

    def test_invalid_ip(self):
        self.assertIsNone(self.geo.lookup("nope"))

    def test_corrupt_file_is_treated_as_missing(self):
        with open(os.path.join(self.dir, CITY_FILE), "wb") as f:
            f.write(b"not a database")
        self.assertIsNone(self.geo.lookup("172.126.2.72")["location"])

    def test_reopens_a_replaced_file_after_the_recheck_interval(self):
        write_fixtures(self.dir)
        self.assertEqual(self.geo.lookup("172.126.2.72")["location"]["city"], "Oakland")
        moved = dict(CITY)
        moved["172.126.0.0/16"] = {**CITY["172.126.0.0/16"], "city": {"names": {"en": "Berkeley"}}}
        path = os.path.join(self.dir, CITY_FILE)
        with open(path + ".new", "wb") as f:
            f.write(build(moved))
        os.replace(path + ".new", path)
        os.utime(path, (1, 1))   # a distinct mtime even on coarse filesystems
        self.now[0] += 60
        self.assertEqual(self.geo.lookup("172.126.2.72")["location"]["city"], "Oakland",
                         "within the recheck interval the open file is still used")
        self.now[0] += 600
        self.assertEqual(self.geo.lookup("172.126.2.72")["location"]["city"], "Berkeley")

    def test_status_reports_version(self):
        write_fixtures(self.dir)
        with open(os.path.join(self.dir, VERSION_FILE), "w") as f:
            json.dump({"month": "2026-10"}, f)
        s = self.geo.status()
        self.assertTrue(s["available"])
        self.assertEqual(s["version"], "2026-10")
        self.assertFalse(s["downloading"])


class FakeResponse:
    def __init__(self, status, body=b""):
        self.status_code = status
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def iter_content(self, size):
        for i in range(0, len(self._body), size):
            yield self._body[i:i + size]


class FakeSession:
    """Serves gzipped fixtures for the months in `published`."""

    def __init__(self, published=("2026-10",), body=None, error=None):
        self.published = set(published)
        self.body = body
        self.error = error
        self.urls = []

    def get(self, url, stream=False, timeout=None):
        self.urls.append(url)
        if self.error:
            raise self.error
        month = url.rsplit("-lite-", 1)[1].split(".")[0]
        if month not in self.published:
            return FakeResponse(404)
        if self.body is not None:
            return FakeResponse(200, self.body)
        db = build(CITY) if "-city-" in url else build(ASN, "DBIP-ASN-Lite")
        return FakeResponse(200, gzip.compress(db))


class UpdaterTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)

    def meta(self):
        with open(os.path.join(self.dir, VERSION_FILE)) as f:
            return json.load(f)

    def install(self, month):
        write_fixtures(self.dir)
        with open(os.path.join(self.dir, VERSION_FILE), "w") as f:
            json.dump({"month": month}, f)

    def city_bytes(self):
        with open(os.path.join(self.dir, CITY_FILE), "rb") as f:
            return f.read()

    def leftovers(self):
        return [n for n in os.listdir(self.dir) if n.endswith((".part", ".gz"))]

    def test_month_arithmetic(self):
        self.assertEqual(geoip_update.previous_month("2026-01"), "2025-12")
        self.assertEqual(geoip_update.previous_month("2026-10"), "2026-09")

    def test_candidates(self):
        self.assertEqual(geoip_update.candidates(None, OCT), ["2026-10", "2026-09"])
        self.assertEqual(geoip_update.candidates("2026-09", OCT), ["2026-10"])
        self.assertEqual(geoip_update.candidates("2026-10", OCT), [])
        self.assertEqual(geoip_update.candidates("2026-07", OCT), ["2026-10", "2026-09"])

    def test_fresh_install_downloads_current_month(self):
        s = FakeSession()
        self.assertEqual(geoip_update.update_once(self.dir, OCT, s), "updated")
        self.assertEqual(self.meta()["month"], "2026-10")
        geo = GeoIP(self.dir)
        self.assertEqual(geo.lookup("172.126.2.72")["asn"]["number"], 7018)
        self.assertEqual(self.leftovers(), [])
        self.assertFalse(os.path.exists(os.path.join(self.dir, ".downloading")))

    def test_fresh_install_falls_back_to_last_month_when_not_published(self):
        s = FakeSession(published=("2026-09",))
        self.assertEqual(geoip_update.update_once(self.dir, OCT, s), "updated")
        self.assertEqual(self.meta()["month"], "2026-09")

    def test_up_to_date_makes_no_request(self):
        self.install("2026-10")
        s = FakeSession()
        self.assertEqual(geoip_update.update_once(self.dir, OCT, s), "current")
        self.assertEqual(s.urls, [])

    def test_new_month_not_out_yet_keeps_last_month(self):
        self.install("2026-09")
        s = FakeSession(published=("2026-09",))
        self.assertEqual(geoip_update.update_once(self.dir, OCT, s), "not-published")
        self.assertEqual(self.meta()["month"], "2026-09")
        self.assertTrue(os.path.exists(os.path.join(self.dir, CITY_FILE)))

    def test_missing_file_triggers_a_redownload(self):
        self.install("2026-10")
        os.remove(os.path.join(self.dir, ASN_FILE))
        self.assertEqual(geoip_update.update_once(self.dir, OCT, FakeSession()), "updated")
        self.assertTrue(os.path.exists(os.path.join(self.dir, ASN_FILE)))

    def test_corrupt_download_keeps_the_old_files(self):
        self.install("2026-09")
        before = self.city_bytes()
        s = FakeSession(body=gzip.compress(b"garbage"))
        self.assertEqual(geoip_update.update_once(self.dir, OCT, s), "failed")
        self.assertEqual(self.city_bytes(), before)
        self.assertEqual(self.meta()["month"], "2026-09")
        self.assertTrue(self.meta()["last_error"])
        self.assertEqual(self.leftovers(), [])

    def test_not_gzip_keeps_the_old_files(self):
        self.install("2026-09")
        s = FakeSession(body=b"<html>rate limited</html>")
        self.assertEqual(geoip_update.update_once(self.dir, OCT, s), "failed")
        self.assertEqual(self.meta()["month"], "2026-09")
        self.assertEqual(self.leftovers(), [])

    def test_network_error_records_the_error(self):
        s = FakeSession(error=requests.ConnectionError("no route"))
        self.assertEqual(geoip_update.update_once(self.dir, OCT, s), "failed")
        self.assertIn("no route", self.meta()["last_error"])
        self.assertFalse(os.path.exists(os.path.join(self.dir, CITY_FILE)))

    def test_success_clears_a_previous_error(self):
        geoip_update.update_once(self.dir, OCT, FakeSession(error=requests.ConnectionError("x")))
        geoip_update.update_once(self.dir, OCT, FakeSession())
        self.assertIsNone(self.meta()["last_error"])

    def test_half_published_month_swaps_nothing(self):
        """City out but ASN 404: neither file may change, or they'd mismatch."""
        self.install("2026-09")

        class Half(FakeSession):
            def get(self, url, **kw):
                if "-asn-" in url and "2026-10" in url:
                    return FakeResponse(404)
                return super().get(url, **kw)

        before = os.stat(os.path.join(self.dir, CITY_FILE)).st_mtime_ns
        self.assertEqual(geoip_update.update_once(self.dir, OCT, Half()), "not-published")
        self.assertEqual(os.stat(os.path.join(self.dir, CITY_FILE)).st_mtime_ns, before)
        self.assertEqual(self.leftovers(), [])

    def test_a_concurrent_update_is_skipped(self):
        held = open(os.path.join(self.dir, geoip_update.LOCK_FILE), "w")
        self.addCleanup(held.close)
        fcntl.flock(held, fcntl.LOCK_EX)
        s = FakeSession()
        self.assertEqual(geoip_update.update_once(self.dir, OCT, s), "busy")
        self.assertEqual(s.urls, [])

    def test_auto_update_off_starts_nothing(self):
        self.assertIsNone(geoip_update.start_background(self.dir))


if __name__ == "__main__":
    unittest.main()
