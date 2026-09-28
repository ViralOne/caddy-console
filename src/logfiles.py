"""Locating log data in time: the live file plus Caddy's rolled archives.

Two things make time-range loading cheap.

First, the live log is append-ordered, so a byte offset for any timestamp can be
found by binary search — about twenty small reads instead of parsing the file.
Timestamps are not *strictly* monotonic (concurrent writes can interleave by
microseconds), so the search brackets conservatively and the caller filters
exactly; a stray inversion costs a few extra lines, never a wrong answer.

Second, Caddy names rolled files after the moment they were rolled:

    <name>-<backup_time_format>-<reason>.log[.gz]
    access-2026-01-30T22-15-42.123-size.log.gz

so which archives overlap a requested range can be decided from filenames alone,
without decompressing any of them. The timestamp is the *end* of a file's range
(it stopped being written then), so a roll covers from the previous roll's
timestamp up to its own.

Rolled files are gzipped by default and gzip cannot be seeked, so an archive is
read whole — but only when a range actually reaches into it.
"""
import gzip
import json
import os
import re
from datetime import datetime, timezone

# Caddy's default backup_time_format, as a regex over the rolled filename.
# Matched loosely on purpose: an unparseable name still yields a usable file,
# it just cannot be ruled out by time.
_ROLL = re.compile(r"^(?P<base>.+?)-(?P<rest>.+)\.log(?P<gz>\.gz)?$")
_STAMP = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.\d{3})")


def _parse_stamp(text):
    """`2026-01-30T22-15-42.123` -> epoch seconds, or None.

    Parsed as UTC: backup_time_format carries no zone, and Caddy uses UTC unless
    roll_local_time is set. A wrong guess only shifts which archives look
    relevant by the zone offset, and since entries are filtered by their own
    timestamps afterwards, the worst case is reading one file too many.
    """
    try:
        dt = datetime.strptime(text, "%Y-%m-%dT%H-%M-%S.%f")
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


class LogFile:
    """One file in the series, with the time span it is believed to cover."""

    __slots__ = ("path", "gzip", "rolled_at", "starts_at", "is_live")

    def __init__(self, path, gzip_, rolled_at, is_live):
        self.path = path
        self.gzip = gzip_
        self.rolled_at = rolled_at    # end of range; None for the live file
        self.starts_at = None         # filled in by discover(), from the previous roll
        self.is_live = is_live

    def covers(self, from_ts, to_ts):
        """Could this file hold entries in [from_ts, to_ts]?

        Unknown bounds are treated as open, so a file is only excluded when its
        filename positively rules it out.
        """
        if to_ts is not None and self.starts_at is not None and self.starts_at > to_ts:
            return False
        if from_ts is not None and self.rolled_at is not None and self.rolled_at < from_ts:
            return False
        return True

    def open(self):
        if self.gzip:
            return gzip.open(self.path, "rb")
        return open(self.path, "rb")

    def size(self):
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def __repr__(self):
        return f"<LogFile {os.path.basename(self.path)} rolled_at={self.rolled_at}>"


def discover(live_path):
    """Every file in the series, oldest first, with the live file last.

    Rolls whose names cannot be parsed are kept but left unbounded, so they are
    never wrongly skipped — only never skipped either.
    """
    directory = os.path.dirname(live_path) or "."
    live_name = os.path.basename(live_path)
    base = live_name[:-4] if live_name.endswith(".log") else live_name

    rolls = []
    try:
        names = os.listdir(directory)
    except OSError:
        names = []
    for name in names:
        if name == live_name:
            continue
        m = _ROLL.match(name)
        if not m or m.group("base") != base:
            continue
        stamp = _STAMP.search(m.group("rest"))
        rolls.append(LogFile(
            os.path.join(directory, name),
            gzip_=bool(m.group("gz")),
            # No recognisable stamp leaves the file unbounded, so it is read when
            # any range needs it rather than being silently skipped.
            rolled_at=_parse_stamp(stamp.group(1)) if stamp else None,
            is_live=False,
        ))

    # Unparseable stamps sort oldest, since they cannot be placed.
    rolls.sort(key=lambda f: (f.rolled_at is not None, f.rolled_at or 0))

    files = rolls
    if os.path.exists(live_path):
        files = files + [LogFile(live_path, gzip_=False, rolled_at=None, is_live=True)]

    # A file starts where the previous one stopped being written.
    previous_end = None
    for f in files:
        f.starts_at = previous_end
        if f.rolled_at is not None:
            previous_end = f.rolled_at
    return files


def _ts_of(line):
    try:
        value = json.loads(line).get("ts")
    except (ValueError, UnicodeDecodeError, AttributeError):
        return None
    return value if isinstance(value, (int, float)) else None


def _first_ts_at(handle, offset, size, probe=65536):
    """Timestamp of the first complete line at or after `offset`."""
    handle.seek(offset)
    if offset:
        handle.readline()  # discard the partial line the offset landed inside
    for _ in range(8):     # skip unparseable lines rather than give up
        start = handle.tell()
        line = handle.readline()
        if not line:
            return None, size
        ts = _ts_of(line)
        if ts is not None:
            return ts, start
    return None, size


def offset_at(path, target_ts, slack=64 * 1024):
    """Byte offset to start reading from to catch every entry at or after target_ts.

    Binary search, then back off by `slack` bytes so the small timestamp
    inversions real logs contain cannot hide an entry just before the boundary.
    Returns 0 when the whole file is needed.
    """
    size = os.path.getsize(path)
    if size == 0 or target_ts is None:
        return 0
    with open(path, "rb") as f:
        first, _ = _first_ts_at(f, 0, size)
        if first is None or first >= target_ts:
            return 0
        lo, hi = 0, size
        while hi - lo > 4096:
            mid = (lo + hi) // 2
            ts, _ = _first_ts_at(f, mid, size)
            if ts is None or ts >= target_ts:
                hi = mid
            else:
                lo = mid
    return max(0, lo - slack)


def iter_lines(logfile, start_offset=0, exact=False):
    """Complete lines from a file, with each line's byte offset.

    `exact` says whether start_offset is known to sit on a line boundary. A
    bisected offset lands mid-line, so the fragment it starts in must be
    discarded; a resume position from a previous read is already a boundary, and
    discarding there would silently skip a whole entry.

    The final partial line is withheld either way: the live file may be mid-write.
    """
    with logfile.open() as f:
        if logfile.gzip:
            # gzip has no seek worth using; discard the prefix instead.
            if start_offset:
                f.read(start_offset)
                if not exact:
                    f.readline()
        else:
            f.seek(start_offset)
            if start_offset and not exact:
                f.readline()
        offset = f.tell() if not logfile.gzip else start_offset
        while True:
            line = f.readline()
            if not line:
                return
            if not line.endswith(b"\n"):
                return  # partial trailing line; leave it for the next read
            yield offset, line[:-1]
            offset += len(line)


def read_line_at(logfile, offset):
    """The original line at `offset`, for the raw view.

    A gzip archive is decompressed up to that point rather than seeked, which is
    fine for a single on-demand click.
    """
    with logfile.open() as f:
        if logfile.gzip:
            f.read(offset)
        else:
            f.seek(offset)
        line = f.readline()
    return line.decode("utf-8", errors="replace").rstrip("\n")
