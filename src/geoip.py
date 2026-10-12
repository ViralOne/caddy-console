"""Where an IP is from, for the Explore IP popover.

Backed by DB-IP's free Lite databases, read locally with maxminddb, so looking an
IP up never sends it anywhere. The files are optional: without them a lookup
still classifies the address (private, loopback, CGNAT...) and says the location
data is missing, rather than failing.

Files are memory-mapped, so every gunicorn worker shares one copy through the
page cache instead of each holding ~130 MB. The updater swaps new files in with
os.replace(); each worker notices the changed mtime on its next check and reopens.
"""
import ipaddress
import json
import os
import threading
import time
from collections import OrderedDict

import maxminddb

from .config import GEOIP_DIR

CITY_FILE = "dbip-city-lite.mmdb"
ASN_FILE = "dbip-asn-lite.mmdb"
VERSION_FILE = "version.json"
# Present while the updater is downloading, so the UI can say so instead of
# "not configured" on a fresh install.
DOWNLOADING_MARKER = ".downloading"

RECHECK_SECONDS = 600
CACHE_SIZE = 4096

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def classify(ip):
    """What kind of address this is, or None when it is not an IP at all."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    # Order matters: loopback and link-local are also "private" to ipaddress.
    if addr.is_loopback: return "loopback"
    if addr.is_link_local: return "link-local"
    if addr.is_multicast: return "multicast"
    if isinstance(addr, ipaddress.IPv4Address) and addr in _CGNAT: return "cgnat"
    if addr.is_private: return "private"
    if addr.is_reserved or addr.is_unspecified: return "reserved"
    return "public"


def _name(record, key):
    names = (record.get(key) or {}).get("names") or {}
    return names.get("en")


class GeoIP:
    def __init__(self, directory=GEOIP_DIR, recheck=RECHECK_SECONDS, clock=time.monotonic):
        self._dir = directory
        self._recheck = recheck
        self._clock = clock
        self._lock = threading.Lock()
        self._readers = {}      # filename -> (mtime, reader)
        self._checked_at = None
        self._cache = OrderedDict()

    def _path(self, name):
        return os.path.join(self._dir, name)

    def _refresh(self):
        """Reopen any file that changed on disk. Called with the lock held.

        Throttled, since a stat per lookup would be wasted work for a file that
        changes once a month.
        """
        now = self._clock()
        if self._checked_at is not None and now - self._checked_at < self._recheck:
            return
        self._checked_at = now
        changed = False
        for name in (CITY_FILE, ASN_FILE):
            try:
                mtime = os.stat(self._path(name)).st_mtime
            except OSError:
                mtime = None
            held = self._readers.get(name)
            if (held[0] if held else None) == mtime:
                continue
            changed = True
            if held:
                held[1].close()
                del self._readers[name]
            if mtime is None:
                continue
            try:
                reader = maxminddb.open_database(self._path(name), maxminddb.MODE_MMAP)
            except (OSError, ValueError, maxminddb.InvalidDatabaseError):
                # A broken file is the same as no file; the updater replaces it.
                continue
            self._readers[name] = (mtime, reader)
        if changed:
            self._cache.clear()

    def _get(self, name, ip):
        held = self._readers.get(name)
        if not held:
            return None
        try:
            return held[1].get(ip)
        except (ValueError, maxminddb.InvalidDatabaseError):
            return None

    def lookup(self, ip):
        """{kind, location, asn} for one IP; location/asn are None when unknown."""
        kind = classify(ip)
        if kind is None:
            return None
        if kind != "public":
            # Nothing to look up: these ranges are not in any geo database.
            return {"kind": kind, "location": None, "asn": None}
        with self._lock:
            self._refresh()
            hit = self._cache.get(ip)
            if hit is not None:
                self._cache.move_to_end(ip)
                return hit
            city = self._get(CITY_FILE, ip)
            asn = self._get(ASN_FILE, ip)
            result = {"kind": kind, "location": None, "asn": None}
            if city:
                country = city.get("country") or {}
                subdivisions = city.get("subdivisions") or []
                result["location"] = {
                    "country": _name(city, "country"),
                    "country_code": country.get("iso_code"),
                    "region": ((subdivisions[0].get("names") or {}).get("en")
                               if subdivisions else None),
                    "city": _name(city, "city"),
                    "continent": _name(city, "continent"),
                }
            if asn:
                result["asn"] = {
                    "number": asn.get("autonomous_system_number"),
                    "org": asn.get("autonomous_system_organization"),
                }
            self._cache[ip] = result
            if len(self._cache) > CACHE_SIZE:
                self._cache.popitem(last=False)
            return result

    def status(self):
        """What the UI says about the data source: version, or why there is none."""
        with self._lock:
            self._refresh()
            available = bool(self._readers)
        version = None
        last_error = None
        try:
            with open(self._path(VERSION_FILE)) as f:
                meta = json.load(f)
            version = meta.get("month")
            last_error = meta.get("last_error")
        except (OSError, ValueError, AttributeError):
            pass
        return {
            "available": available,
            "version": version,
            "downloading": os.path.exists(self._path(DOWNLOADING_MARKER)),
            "last_error": last_error,
        }


geoip = GeoIP()
