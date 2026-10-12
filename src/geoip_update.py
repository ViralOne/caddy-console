"""Keeps the DB-IP Lite databases in GEOIP_DIR current.

DB-IP publishes a new release at the start of each month, under a URL naming the
month. So the check is cheap — compare the installed month with today's — and a
download happens about once a month. Early in a month the new files may not be
out yet; a 404 then just means "try again tomorrow", and a fresh install falls
back to last month's release so it has something to show.

A download never touches the live files until it has been decompressed and
opened successfully, and then each file is swapped in with os.replace(), so a
reader sees either the old file or the new one, never half of one.

Runs as one daemon thread in the gunicorn master (see gunicorn.conf.py). A file
lock covers the cases that does not: the Flask dev server, or two containers
sharing the volume.
"""
import datetime
import fcntl
import gzip
import json
import logging
import os
import shutil
import tempfile
import threading

import maxminddb
import requests

from .config import GEOIP_AUTO_UPDATE, GEOIP_DIR
from .geoip import ASN_FILE, CITY_FILE, DOWNLOADING_MARKER, VERSION_FILE

log = logging.getLogger(__name__)

URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz"
DATABASES = (("city", CITY_FILE), ("asn", ASN_FILE))
LOCK_FILE = ".update.lock"

CHECK_INTERVAL = 24 * 3600
RETRY_INTERVAL = 3600            # after a network error, not a 404
TIMEOUT = 60
# The city file is ~60 MB compressed; anything far past that is not DB-IP.
MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024


class NotPublished(Exception):
    """This month's release is not out yet."""


def month_of(day):
    return f"{day.year:04d}-{day.month:02d}"


def previous_month(month):
    year, mon = (int(p) for p in month.split("-"))
    return f"{year - 1:04d}-12" if mon == 1 else f"{year:04d}-{mon - 1:02d}"


def _read_meta(directory):
    try:
        with open(os.path.join(directory, VERSION_FILE)) as f:
            meta = json.load(f)
        return meta if isinstance(meta, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_meta(directory, meta):
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".version.")
    with os.fdopen(fd, "w") as f:
        json.dump(meta, f)
    # mkstemp makes it 0600; workers may run as another user than the updater.
    os.chmod(tmp, 0o644)
    os.replace(tmp, os.path.join(directory, VERSION_FILE))


def _installed(directory):
    """The installed month, or None when any database file is missing."""
    if not all(os.path.exists(os.path.join(directory, name)) for _, name in DATABASES):
        return None
    return _read_meta(directory).get("month")


def candidates(installed, today):
    """Months worth trying, newest first.

    Last month only matters when what is installed is older still — typically a
    fresh install on the 1st, before this month's files are published.
    """
    current = month_of(today)
    prev = previous_month(current)
    return [m for m in (current, prev) if installed is None or m > installed]


def _fetch(url, dest, session):
    """Download a .mmdb.gz to `dest`, decompressed, and check it opens."""
    gz_path = dest + ".gz"
    try:
        with session.get(url, stream=True, timeout=TIMEOUT) as res:
            if res.status_code == 404:
                raise NotPublished(url)
            res.raise_for_status()
            total = 0
            with open(gz_path, "wb") as out:
                for chunk in res.iter_content(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_BYTES:
                        raise ValueError(f"{url} is larger than {MAX_DOWNLOAD_BYTES} bytes")
                    out.write(chunk)
        with gzip.open(gz_path, "rb") as src, open(dest, "wb") as out:
            shutil.copyfileobj(src, out, 1024 * 1024)
    finally:
        try:
            os.remove(gz_path)
        except OSError:
            pass
    # Opening reads the metadata section, which a truncated or wrong file lacks.
    maxminddb.open_database(dest, maxminddb.MODE_FILE).close()


def _download_month(directory, month, session):
    staged = []
    try:
        for kind, name in DATABASES:
            tmp = os.path.join(directory, f".{name}.{month}.part")
            staged.append((tmp, name))
            _fetch(URL.format(kind=kind, month=month), tmp, session)
        # Every file is verified before any is swapped, so city and ASN never
        # end up from different months.
        for tmp, name in staged:
            os.replace(tmp, os.path.join(directory, name))
        staged = []
    finally:
        for tmp, _ in staged:
            try:
                os.remove(tmp)
            except OSError:
                pass


def update_once(directory=GEOIP_DIR, today=None, session=None):
    """One check, downloading if due. Returns what happened, for logs and tests:

    'current', 'updated', 'not-published', 'busy', or 'failed'.
    """
    today = today or datetime.datetime.now(datetime.timezone.utc).date()
    session = session or requests.Session()
    os.makedirs(directory, exist_ok=True)

    lock = open(os.path.join(directory, LOCK_FILE), "w")
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return "busy"

        months = candidates(_installed(directory), today)
        if not months:
            return "current"

        marker = os.path.join(directory, DOWNLOADING_MARKER)
        open(marker, "w").close()
        meta = _read_meta(directory)
        meta["checked_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            for month in months:
                try:
                    _download_month(directory, month, session)
                except NotPublished:
                    continue
                meta.update(month=month, last_error=None)
                _write_meta(directory, meta)
                log.info("GeoIP: installed DB-IP Lite %s", month)
                return "updated"
            meta["last_error"] = None
            _write_meta(directory, meta)
            return "not-published"
        except Exception as e:  # noqa: BLE001 — any failure keeps the old files
            meta["last_error"] = f"{type(e).__name__}: {e}"
            _write_meta(directory, meta)
            log.warning("GeoIP: update failed, keeping current files: %s", e)
            return "failed"
        finally:
            try:
                os.remove(marker)
            except OSError:
                pass
    finally:
        lock.close()


def _loop(directory, stop):
    while True:
        try:
            outcome = update_once(directory)
        except Exception:  # noqa: BLE001 — the thread must survive anything
            log.exception("GeoIP: update check crashed")
            outcome = "failed"
        if stop.wait(RETRY_INTERVAL if outcome == "failed" else CHECK_INTERVAL):
            return


_started = False


def start_background(directory=GEOIP_DIR):
    """Start the daily check, once per process. No-op when auto-update is off."""
    global _started
    if _started or not GEOIP_AUTO_UPDATE:
        return None
    _started = True
    stop = threading.Event()
    threading.Thread(target=_loop, args=(directory, stop),
                     name="geoip-update", daemon=True).start()
    return stop
