"""Per-host aggregation of Caddy's JSON access log.

Caddy's Prometheus metrics carry no `host` label, so `/api/traffic` can only
report figures per server (srv0, srv1). With a dozen sites behind one server
that lumps everything together, and the access log is the only place the host
of each request is recorded. This module reads it.

Re-parsing the file on every poll would mean a full JSON decode of up to
LOG_STATS_WINDOW_MAX_MB on each refresh, so the aggregate is built once and
then extended from the last byte offset, the same way /api/logs tails.

The window is how far back a build anchors its scan, not a sliding time range:
counters accumulate forward from that anchor until the covered span outgrows
the window by REBUILD_SLACK, at which point the scan re-anchors. `covered_bytes`
always reports the span the numbers actually describe, so a figure is never
presented as covering more than it does.
"""
import json
import math
import os
import threading
from collections import deque

from .config import CADDY_LOG_FILE

# Read in chunks so a 100 MB rebuild never loads the whole file into memory.
CHUNK = 1024 * 1024

# Rebuild once the covered span exceeds the window by this factor. Rebuilding
# the moment it exceeds the window would rebuild on nearly every poll; this
# spreads it to one rebuild per half-window of new traffic.
REBUILD_SLACK = 1.5

# Durations kept per host for the percentile. Bounded so a busy site cannot
# grow this without limit; p95 therefore describes the most recent requests
# for that host rather than every request in the window.
P95_SAMPLE = 2048

# Distinct (status, path) pairs tracked per host for the failure breakdown.
# A scanner walking random paths would otherwise grow this without bound; past
# the cap, already-tracked pairs keep counting and the rest land in one bucket.
FAILURE_KEYS_MAX = 200


def _normalize_host(host):
    """Lowercase and drop any :port, which Caddy includes for non-default ports."""
    if not isinstance(host, str) or not host:
        return None
    name, sep, port = host.rpartition(":")
    if sep and port.isdigit():
        host = name
    return host.lower() or None


def _new_host():
    return {
        "requests": 0,
        "status": {},
        "duration_sum": 0.0,
        "duration_count": 0,
        "bytes_out": 0,
        "slowest_uri": None,
        "slowest": 0.0,
        "durations": deque(maxlen=P95_SAMPLE),
        "failures": {},        # (status, path) -> count
        "failures_other": 0,   # pairs seen after the cap was reached
        "failures_total": 0,
    }


class LogStatsAggregator:
    """Incrementally folds access-log lines into per-host counters.

    One instance owns one file. Callers only use snapshot(); everything else is
    internal bookkeeping guarded by a single lock, since Flask serves polls
    from multiple worker threads.
    """

    def __init__(self, path):
        self._path = path
        self._lock = threading.Lock()
        self._clear()

    def _clear(self):
        self._hosts = {}
        self._pos = 0
        self._scan_start = 0
        self._last_size = 0
        self._entries = 0
        self._skipped = 0
        self._window = None
        self._built = False

    def snapshot(self, window_bytes, host=None):
        """Fold in whatever is new and return the current per-host figures.

        Pass `host` to also get that one host's failure breakdown under
        "detail". It is per-host on purpose: including every site's failing
        paths would make the payload grow with the number of sites.
        """
        with self._lock:
            rebuilt, exists, size = self._refresh(int(window_bytes))
            payload = self._render(window_bytes, rebuilt, exists, size)
            if host is not None:
                payload["detail"] = self._detail(host)
            return payload

    # --- reading -----------------------------------------------------------

    def _refresh(self, window_bytes):
        try:
            size = os.path.getsize(self._path)
        except OSError:
            # Missing file: forget everything so a later re-create starts clean
            # instead of resuming at a stale offset.
            self._clear()
            return False, False, 0

        rebuild = (
            not self._built
            or window_bytes != self._window
            or size < self._last_size  # rolled or truncated
            # Measured against the file's current size, not the last offset:
            # what matters is the span we are about to cover, not the one we
            # already covered.
            or (size - self._scan_start) > window_bytes * REBUILD_SLACK
        )

        if rebuild:
            self._hosts = {}
            self._entries = 0
            self._skipped = 0
            self._window = window_bytes
            self._scan_start = max(0, size - window_bytes)
            # Anchoring by byte offset lands mid-line unless we start at 0, so
            # the first fragment is dropped rather than parsed as garbage.
            self._pos = self._fold_from(self._scan_start, size, drop_first=self._scan_start > 0)
            self._built = True
        else:
            self._pos = self._fold_from(self._pos, size, drop_first=False)

        self._last_size = size
        return rebuild, True, size

    def _fold_from(self, start, size, drop_first):
        """Fold complete lines in [start, size) and return the new offset.

        A partially written final line is left for the next poll, so an entry
        is never counted twice or half-parsed.
        """
        consumed = start
        read_to = start
        buf = b""
        dropped = not drop_first
        with open(self._path, "rb") as f:
            f.seek(start)
            while read_to < size:
                chunk = f.read(min(CHUNK, size - read_to))
                if not chunk:
                    break
                read_to += len(chunk)
                buf += chunk
                while True:
                    nl = buf.find(b"\n")
                    if nl == -1:
                        break
                    line, buf = buf[:nl], buf[nl + 1:]
                    consumed += nl + 1
                    if not dropped:
                        dropped = True  # partial line at the anchor
                        continue
                    self._fold_line(line)
        return consumed

    def _fold_line(self, raw):
        if not raw.strip():
            return
        try:
            entry = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            self._skipped += 1
            return
        if not isinstance(entry, dict):
            self._skipped += 1
            return
        request = entry.get("request")
        host = _normalize_host(request.get("host")) if isinstance(request, dict) else None
        if host is None:
            # Runtime log lines (startup, TLS) share the file but have no host.
            self._skipped += 1
            return

        h = self._hosts.get(host)
        if h is None:
            h = self._hosts[host] = _new_host()

        h["requests"] += 1
        self._entries += 1

        status = entry.get("status")
        key = f"{status // 100}xx" if isinstance(status, int) and 100 <= status <= 599 else "other"
        h["status"][key] = h["status"].get(key, 0) + 1

        if isinstance(status, int) and status >= 400:
            self._fold_failure(h, status, request.get("uri"))

        duration = entry.get("duration")
        if isinstance(duration, (int, float)):
            h["duration_sum"] += duration
            h["duration_count"] += 1
            h["durations"].append(duration)
            if duration > h["slowest"]:
                h["slowest"] = duration
                h["slowest_uri"] = request.get("uri")

        size = entry.get("size")
        if isinstance(size, (int, float)):
            h["bytes_out"] += int(size)

    @staticmethod
    def _fold_failure(h, status, uri):
        """Count a 4xx/5xx against its path.

        The query string is dropped: grouping by full URI would split
        /api?page=1 and /api?page=2 into separate rows and bury the pattern,
        which is the opposite of what this view is for.
        """
        path = uri.split("?", 1)[0] if isinstance(uri, str) else ""
        h["failures_total"] += 1
        key = (status, path)
        if key in h["failures"]:
            h["failures"][key] += 1
        elif len(h["failures"]) < FAILURE_KEYS_MAX:
            h["failures"][key] = 1
        else:
            h["failures_other"] += 1

    def _detail(self, host):
        """Failure breakdown for one host, worst first.

        Callers must hold the lock; snapshot() is the only one. The lock is not
        reentrant, so this must not take it itself.
        """
        h = self._hosts.get(host)
        if h is None:
            return {"host": host, "failures": [], "total": 0, "other": 0, "capped": False}
        failures = [
            {"status": status, "path": path, "count": count}
            for (status, path), count in h["failures"].items()
        ]
        failures.sort(key=lambda f: (-f["count"], -f["status"], f["path"]))
        return {
            "host": host,
            "failures": failures,
            "total": h["failures_total"],
            "other": h["failures_other"],
            "capped": h["failures_other"] > 0,
        }

    # --- output ------------------------------------------------------------

    def _render(self, window_bytes, rebuilt, exists, size):
        sites = {}
        for host, h in self._hosts.items():
            requests = h["requests"]
            errors = h["status"].get("5xx", 0)
            count = h["duration_count"]
            avg_ms = (h["duration_sum"] / count * 1000) if count else 0.0
            sites[host] = {
                "requests": requests,
                "status": dict(h["status"]),
                "errors": errors,
                "error_rate": round(errors / requests * 100, 2) if requests else 0.0,
                "avg_latency_ms": round(avg_ms, 1),
                "p95_latency_ms": _p95_ms(h["durations"]),
                "bytes_out": h["bytes_out"],
                "slowest": {
                    "uri": h["slowest_uri"],
                    "ms": round(h["slowest"] * 1000, 1),
                },
            }
        return {
            "exists": exists,
            "path": self._path,
            "sites": sites,
            "entries": self._entries,
            "skipped": self._skipped,
            "file_size": size,
            "window_bytes": int(window_bytes),
            "covered_bytes": max(0, self._pos - self._scan_start),
            "truncated": self._scan_start > 0,
            "rebuilt": rebuilt,
        }


def _p95_ms(durations):
    if not durations:
        return 0.0
    ordered = sorted(durations)
    idx = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return round(ordered[idx] * 1000, 1)


log_stats = LogStatsAggregator(CADDY_LOG_FILE)
