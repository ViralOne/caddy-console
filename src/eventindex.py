"""Columnar index over the Caddy access log, and the query engine on top of it.

The explorer needs facet counts and a histogram *per query*, because both reflect
the active filters. Pre-aggregated counters cannot answer that, and re-decoding
the window on every keystroke is far too slow (JSON-parsing 100 MB is ~600 ms).
So the window is parsed once into parallel arrays and queried many times.

Columns rather than a list of dicts or tuples because Python object overhead
dominates at this size: ~30 bytes per event here against ~140 for a tuple of the
same fields, so 200k events cost about 6 MB instead of 28 MB.

Strings (host, method, uri, client_ip) are interned to ints. A lowercase copy is
kept per *distinct* string, not per event, so case-insensitive matching never has
to call .lower() inside the scan loop.

The file-following bookkeeping mirrors logstats.py rather than sharing it. That
duplication is deliberate and temporary: the explorer replaces logstats entirely,
and refactoring a module that is about to be deleted would be work thrown away.
"""
import bisect
import json
import os
import threading
from array import array

from .config import CADDY_LOG_FILE, EXPLORE_MAX_EVENTS

CHUNK = 1024 * 1024
REBUILD_SLACK = 1.5

# Buckets are chosen from this ladder so the histogram lands near TARGET_BUCKETS
# columns whatever the span, and always on a round, human-readable width.
BUCKET_LADDER = (1, 5, 10, 15, 30, 60, 300, 900, 1800, 3600, 10800, 21600, 86400)
TARGET_BUCKETS = 120

STATUS_CLASSES = ("2xx", "3xx", "4xx", "5xx", "other")
FACET_KEYS = ("host", "status_class", "status", "method", "path")


def _status_class(status):
    if 200 <= status < 300: return "2xx"
    if 300 <= status < 400: return "3xx"
    if 400 <= status < 500: return "4xx"
    if 500 <= status < 600: return "5xx"
    return "other"


class Filters:
    """A parsed query. Same-key terms OR, different keys AND, `-` negates."""

    __slots__ = ("hosts", "methods", "codes", "classes", "paths", "text",
                 "not_hosts", "not_methods", "not_codes", "not_classes")

    def __init__(self):
        self.hosts = set(); self.methods = set(); self.codes = set()
        self.classes = set(); self.paths = []; self.text = []
        self.not_hosts = set(); self.not_methods = set()
        self.not_codes = set(); self.not_classes = set()

    def is_empty(self):
        return not any((self.hosts, self.methods, self.codes, self.classes, self.paths,
                        self.text, self.not_hosts, self.not_methods, self.not_codes,
                        self.not_classes))

    def active_keys(self):
        """Which facet keys this query constrains, so facets can exclude their own."""
        keys = set()
        if self.hosts or self.not_hosts: keys.add("host")
        if self.methods or self.not_methods: keys.add("method")
        # One key with two spellings: constraining either makes both facets
        # exclude both, or the OR between them would be half-applied.
        if self.codes or self.not_codes or self.classes or self.not_classes:
            keys.add("status"); keys.add("status_class")
        if self.paths: keys.add("path")
        return keys


def _tokenize(q):
    """Split on whitespace, but keep "quoted values" together."""
    out, buf, quoted = [], [], False
    for ch in q:
        if ch == '"':
            quoted = not quoted
        elif ch.isspace() and not quoted:
            if buf: out.append("".join(buf)); buf = []
        else:
            buf.append(ch)
    if buf: out.append("".join(buf))
    return out


def parse_query(q):
    f = Filters()
    for raw in _tokenize(q or ""):
        negated = raw.startswith("-") and len(raw) > 1
        token = raw[1:] if negated else raw
        key, sep, value = token.partition(":")
        key = key.lower()
        if not sep or not value or key not in ("host", "status", "method", "path"):
            # Unknown key or a bare word: search for it rather than drop what
            # the user typed.
            f.text.append(raw)
            continue
        if key == "host":
            (f.not_hosts if negated else f.hosts).add(value.lower())
        elif key == "method":
            (f.not_methods if negated else f.methods).add(value.upper())
        elif key == "path":
            # Negated paths are not supported; treat as text so nothing is lost.
            (f.text.append(raw) if negated else f.paths.append(value))
        elif key == "status":
            low = value.lower()
            if len(low) == 3 and low.endswith("xx") and low[0].isdigit():
                (f.not_classes if negated else f.classes).add(low)
            elif value.isdigit() and 100 <= int(value) <= 599:
                (f.not_codes if negated else f.codes).add(int(value))
            # Anything else (status:abc, status:99999) is not a filter and not
            # text either — silently constraining nothing is the safe reading.
    return f


class _Intern:
    """str -> int, with a lowercase copy per distinct string for matching."""

    def __init__(self):
        self._ids = {}
        self.values = []
        self.lowers = []

    def id_of(self, s):
        got = self._ids.get(s)
        if got is None:
            got = self._ids[s] = len(self.values)
            self.values.append(s)
            self.lowers.append(s.lower())
        return got

    def ids_matching_exact(self, wanted):
        """Ids whose lowercase value is in `wanted` (already lowercased)."""
        return {i for i, low in enumerate(self.lowers) if low in wanted}

    def ids_containing(self, needle):
        return {i for i, low in enumerate(self.lowers) if needle in low}


class EventIndex:
    def __init__(self, path=CADDY_LOG_FILE, max_events=EXPLORE_MAX_EVENTS):
        self._path = path
        self._max = max_events
        self._lock = threading.Lock()
        self._clear()

    def _clear(self):
        self.ts = array("d")
        self.status = array("h")
        self.duration_ms = array("f")
        self.size = array("q")
        # Byte offset of the line this event came from. 8 bytes per event buys a
        # raw-line view without retaining the line itself.
        self.offset = array("q")
        self.host_id = array("i")
        self.method_id = array("i")
        self.uri_id = array("i")
        self.client_id = array("i")
        self.hosts = _Intern(); self.methods = _Intern()
        self.uris = _Intern(); self.clients = _Intern()
        self._pos = 0
        self._scan_start = 0
        self._last_size = 0
        self._skipped = 0
        self._dropped = 0
        self._window = None
        self._built = False

    # --- reading -----------------------------------------------------------

    def _refresh(self, window_bytes):
        try:
            size = os.path.getsize(self._path)
        except OSError:
            self._clear()
            return False, 0
        rebuild = (
            not self._built
            or window_bytes != self._window
            or size < self._last_size
            or (size - self._scan_start) > window_bytes * REBUILD_SLACK
        )
        if rebuild:
            self._clear()
            self._window = window_bytes
            self._scan_start = max(0, size - window_bytes)
            self._built = True
            self._pos = self._fold(self._scan_start, size, drop_first=self._scan_start > 0)
        else:
            self._pos = self._fold(self._pos, size, drop_first=False)
        self._last_size = size
        self._evict()
        return True, size

    def _fold(self, start, size, drop_first):
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
                        dropped = True  # partial line at the byte anchor
                        continue
                    self._add(line, consumed - (nl + 1))
        return consumed

    def _add(self, raw, offset=0):
        if not raw.strip():
            return
        try:
            e = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            self._skipped += 1
            return
        if not isinstance(e, dict):
            self._skipped += 1
            return
        req = e.get("request")
        host = req.get("host") if isinstance(req, dict) else None
        ts = e.get("ts")
        if not isinstance(host, str) or not host or not isinstance(ts, (int, float)):
            # Caddy runtime lines (startup, TLS) share the file and have neither.
            self._skipped += 1
            return
        name, sep, port = host.rpartition(":")
        if sep and port.isdigit():
            host = name
        status = e.get("status")
        duration = e.get("duration")
        size = e.get("size")
        self.ts.append(float(ts))
        self.offset.append(offset)
        self.status.append(int(status) if isinstance(status, int) and 0 <= status <= 32767 else 0)
        self.duration_ms.append(float(duration) * 1000.0 if isinstance(duration, (int, float)) else 0.0)
        self.size.append(int(size) if isinstance(size, (int, float)) else 0)
        self.host_id.append(self.hosts.id_of(host.lower()))
        method = req.get("method")
        self.method_id.append(self.methods.id_of(method.upper() if isinstance(method, str) else ""))
        uri = req.get("uri")
        self.uri_id.append(self.uris.id_of(uri if isinstance(uri, str) else ""))
        client = req.get("client_ip") or req.get("remote_ip")
        self.client_id.append(self.clients.id_of(client if isinstance(client, str) else ""))

    def _evict(self):
        """Drop the oldest events once over the cap.

        Trimmed in one slice rather than per event so the cost is amortised; the
        intern tables are left alone, since a stale entry costs one string and
        re-interning on rebuild would cost more.
        """
        over = len(self.ts) - self._max
        if over <= 0:
            return
        cut = over + max(1, self._max // 10)
        cut = min(cut, len(self.ts))
        for col in (self.ts, self.status, self.duration_ms, self.size, self.offset,
                    self.host_id, self.method_id, self.uri_id, self.client_id):
            del col[:cut]
        self._dropped += cut

    # --- querying ----------------------------------------------------------

    def query(self, q="", window_bytes=10 * 1024 * 1024, from_ts=None, to_ts=None,
              limit=200, before_ts=None, before_offset=None, facet_limit=50):
        with self._lock:
            exists, size = self._refresh(int(window_bytes))
            filters = parse_query(q)
            n = len(self.ts)

            # ts is ascending because the log is append-ordered, so the range is
            # a slice rather than a scan.
            lo = bisect.bisect_left(self.ts, from_ts) if from_ts is not None else 0
            hi = bisect.bisect_right(self.ts, to_ts) if to_ts is not None else n

            matches = self._scan(filters, lo, hi)
            facets, other = self._facets(filters, lo, hi, matches, facet_limit)

            page = matches
            if before_ts is not None:
                # Several events can share a timestamp, so a strict ts comparison
                # would skip the rest of that instant entirely. The byte offset is
                # unique and monotonic, so it breaks the tie exactly.
                page = [i for i in matches
                        if self.ts[i] < before_ts
                        or (self.ts[i] == before_ts
                            and before_offset is not None
                            and self.offset[i] < before_offset)]

            newest = list(reversed(page[-limit:])) if limit else list(reversed(page))
            return {
                "exists": exists,
                "path": self._path,
                "entries": [self._entry(i) for i in newest],
                "total": len(matches),
                "stats": self._stats(matches),
                "facets": facets,
                "facet_other": other,
                "histogram": self._histogram(matches, lo, hi, from_ts, to_ts),
                "range": {
                    "from": from_ts, "to": to_ts,
                    "earliest_ts": self.ts[0] if n else None,
                    "latest_ts": self.ts[n - 1] if n else None,
                    # True only when the byte window is what cut history short:
                    # anchoring at 0 means the whole file was read, so an earlier
                    # `from` just predates the log rather than exceeding it.
                    # True when history was cut short either by the byte window
                    # or by the in-memory cap evicting the oldest events.
                    "truncated": bool(n and (self._scan_start > 0 or self._dropped)
                                      and from_ts is not None and from_ts < self.ts[0]),
                },
                "window": {"bytes": int(window_bytes), "covered_bytes": max(0, self._pos - self._scan_start),
                           "file_size": size},
                "indexed": n,
                "dropped": self._dropped,
                "skipped": self._skipped,
            }

    def _scan(self, f, lo, hi, skip_key=None):
        """Indices in [lo, hi) matching `f`, ignoring constraints on `skip_key`.

        Every string filter is resolved to a set of interned ids first, so the
        inner loop only compares ints.
        """
        host_ids = None if skip_key == "host" or not f.hosts else self.hosts.ids_matching_exact(f.hosts)
        not_host_ids = set() if skip_key == "host" else (self.hosts.ids_matching_exact(f.not_hosts) if f.not_hosts else set())
        # Methods are held upper-case in Filters but the intern table matches on
        # lower-case, so fold before resolving.
        method_ids = None if skip_key == "method" or not f.methods else self.methods.ids_matching_exact({m.lower() for m in f.methods})
        not_method_ids = set() if skip_key == "method" else (self.methods.ids_matching_exact({m.lower() for m in f.not_methods}) if f.not_methods else set())

        # Exact path, query string ignored — the same grouping the path facet
        # uses, so a facet count always equals what clicking it returns. Substring
        # search is what free text is for.
        path_ids = None
        if f.paths and skip_key != "path":
            wanted = {p.lower().split("?", 1)[0] for p in f.paths}
            path_ids = {i for i, low in enumerate(self.uris.lowers)
                        if low.split("?", 1)[0] in wanted}

        text_uri, text_host = [], []
        for t in f.text:
            low = t.lower()
            text_uri.append(self.uris.ids_containing(low))
            text_host.append(self.hosts.ids_containing(low))

        # status: and status:Nxx are two spellings of one key, so they OR with
        # each other rather than narrowing. Both facets therefore drop both.
        skip_status = skip_key in ("status", "status_class")
        codes = set() if skip_status else f.codes
        classes = set() if skip_status else f.classes
        want_status = bool(codes) or bool(classes)
        not_codes = set() if skip_status else f.not_codes
        not_classes = set() if skip_status else f.not_classes

        ts, st, hid, mid, uid = self.ts, self.status, self.host_id, self.method_id, self.uri_id
        out = []
        for i in range(lo, hi):
            h = hid[i]
            if host_ids is not None and h not in host_ids: continue
            if not_host_ids and h in not_host_ids: continue
            m = mid[i]
            if method_ids is not None and m not in method_ids: continue
            if not_method_ids and m in not_method_ids: continue
            u = uid[i]
            if path_ids is not None and u not in path_ids: continue
            s = st[i]
            if want_status and not (s in codes or (classes and _status_class(s) in classes)):
                continue
            if not_codes and s in not_codes: continue
            if not_classes and _status_class(s) in not_classes: continue
            # Free text is AND across terms, each matching host OR uri.
            ok = True
            for k in range(len(text_uri)):
                if u not in text_uri[k] and h not in text_host[k]:
                    ok = False
                    break
            if not ok: continue
            out.append(i)
        return out

    def _facets(self, filters, lo, hi, matches, facet_limit):
        """Counts per facet value.

        A facet excludes its own constraint, so an active host filter still
        leaves the other hosts clickable with a truthful count. That needs one
        extra scan per constrained key — typically none or one, not five.
        """
        active = filters.active_keys()
        counts = {k: {} for k in FACET_KEYS}
        cache = {}
        for key in FACET_KEYS:
            rows = matches if key not in active else cache.setdefault(
                key, self._scan(filters, lo, hi, skip_key=key))
            bucket = counts[key]
            if key == "host":
                vals = self.hosts.values; col = self.host_id
            elif key == "method":
                vals = self.methods.values; col = self.method_id
            elif key == "path":
                vals = self.uris.values; col = self.uri_id
            else:
                vals = col = None
            if col is not None:
                for i in rows:
                    v = vals[col[i]]
                    if key == "path":
                        v = v.split("?", 1)[0]
                    bucket[v] = bucket.get(v, 0) + 1
            elif key == "status":
                for i in rows:
                    v = str(self.status[i])
                    bucket[v] = bucket.get(v, 0) + 1
            else:
                for i in rows:
                    v = _status_class(self.status[i])
                    bucket[v] = bucket.get(v, 0) + 1

        out, other = {}, {}
        for key, bucket in counts.items():
            ordered = sorted(bucket.items(), key=lambda kv: (-kv[1], kv[0]))
            kept = ordered[:facet_limit]
            out[key] = [{"value": v, "count": c} for v, c in kept]
            other[key] = sum(c for _, c in ordered[facet_limit:])
        return out, other

    def _stats(self, matches):
        n = len(matches)
        if not n:
            return {"requests": 0, "errors": 0, "error_rate": 0.0, "avg_latency_ms": 0.0,
                    "p95_latency_ms": 0.0, "bytes_out": 0}
        durations = sorted(self.duration_ms[i] for i in matches)
        errors = sum(1 for i in matches if 500 <= self.status[i] < 600)
        total_ms = sum(durations)
        # Exact, because the matching durations are in hand — no estimation.
        idx = max(0, -(-95 * n // 100) - 1)
        return {
            "requests": n,
            "errors": errors,
            "error_rate": round(errors / n * 100, 2),
            "avg_latency_ms": round(total_ms / n, 1),
            "p95_latency_ms": round(durations[idx], 1),
            "bytes_out": sum(self.size[i] for i in matches),
        }

    def _histogram(self, matches, lo, hi, from_ts, to_ts):
        if not matches:
            return {"bucket_seconds": BUCKET_LADDER[0], "buckets": []}
        first = from_ts if from_ts is not None else self.ts[matches[0]]
        last = to_ts if to_ts is not None else self.ts[matches[-1]]
        span = max(1.0, last - first)
        width = BUCKET_LADDER[-1]
        for w in BUCKET_LADDER:
            if span / w <= TARGET_BUCKETS:
                width = w
                break
        buckets = {}
        for i in matches:
            slot = int(self.ts[i] // width) * width
            b = buckets.get(slot)
            if b is None:
                b = buckets[slot] = {"t": slot}
            cls = _status_class(self.status[i])
            b[cls] = b.get(cls, 0) + 1
        return {"bucket_seconds": width, "buckets": [buckets[k] for k in sorted(buckets)]}

    def site_summary(self, window_bytes, from_ts=None, to_ts=None, points=24):
        """Per-host traffic summary for the dashboard.

        One grouped pass rather than a query per host: a dozen sites would
        otherwise mean a dozen scans of the whole index.
        """
        with self._lock:
            exists, size = self._refresh(int(window_bytes))
            n = len(self.ts)
            lo = bisect.bisect_left(self.ts, from_ts) if from_ts is not None else 0
            hi = bisect.bisect_right(self.ts, to_ts) if to_ts is not None else n

            span_from = from_ts if from_ts is not None else (self.ts[lo] if lo < hi else 0)
            span_to = to_ts if to_ts is not None else (self.ts[hi - 1] if lo < hi else 1)
            step = max(1.0, (span_to - span_from) / max(1, points))

            sites = {}
            for i in range(lo, hi):
                host = self.hosts.values[self.host_id[i]]
                site = sites.get(host)
                if site is None:
                    site = sites[host] = {"requests": 0, "errors": 0, "bytes_out": 0,
                                          "durations": [], "series": [0] * points}
                site["requests"] += 1
                status = self.status[i]
                if 500 <= status < 600:
                    site["errors"] += 1
                site["bytes_out"] += self.size[i]
                site["durations"].append(self.duration_ms[i])
                # The newest event sits exactly on span_to and so computes
                # `points`; it belongs in the last bucket, not outside the chart.
                slot = min(points - 1, max(0, int((self.ts[i] - span_from) / step)))
                site["series"][slot] += 1

            out = []
            for host, d in sites.items():
                durations = sorted(d["durations"])
                count = len(durations)
                idx = max(0, -(-95 * count // 100) - 1)
                out.append({
                    "host": host,
                    "requests": d["requests"],
                    "errors": d["errors"],
                    "error_rate": round(d["errors"] / d["requests"] * 100, 2) if d["requests"] else 0.0,
                    "avg_latency_ms": round(sum(durations) / count, 1) if count else 0.0,
                    "p95_latency_ms": round(durations[idx], 1) if count else 0.0,
                    "bytes_out": d["bytes_out"],
                    "series": d["series"],
                })
            out.sort(key=lambda s: -s["requests"])
            return {
                "exists": exists, "sites": out,
                "from": span_from, "to": span_to, "points": points,
                "indexed": n, "dropped": self._dropped, "skipped": self._skipped,
                "window": {"bytes": int(window_bytes),
                           "covered_bytes": max(0, self._pos - self._scan_start),
                           "file_size": size},
            }

    def _entry(self, i):
        return {
            "ts": self.ts[i],
            "host": self.hosts.values[self.host_id[i]],
            "method": self.methods.values[self.method_id[i]],
            "uri": self.uris.values[self.uri_id[i]],
            "status": self.status[i],
            "duration_ms": round(self.duration_ms[i], 3),
            "size": self.size[i],
            "client_ip": self.clients.values[self.client_id[i]],
            "offset": self.offset[i],
        }

    def raw_line(self, offset):
        """The original log line at `offset`, for the raw view in Explore.

        Read on demand rather than retained: at ~378 bytes per entry, keeping
        every line would cost as much memory as the log file itself.
        """
        with self._lock:
            if offset < self._scan_start or offset >= self._pos:
                return None  # outside what is currently indexed
            with open(self._path, "rb") as f:
                f.seek(offset)
                line = f.readline()
        return line.decode("utf-8", errors="replace").rstrip("\n")


event_index = EventIndex()
