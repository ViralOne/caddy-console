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
import zlib
from datetime import datetime, timezone

# What a damaged log can raise while being read. gzip.BadGzipFile is an OSError;
# a truncated archive raises EOFError and a corrupt deflate stream zlib.error,
# neither of which is an OSError. API boundaries catch this tuple.
READ_ERRORS = (OSError, EOFError, zlib.error)

# Longest single line the raw view will read. Real access-log lines are well under
# 10 KB; the cap stops a file with no newlines from being pulled into memory.
MAX_LINE = 1024 * 1024
_SKIP_CHUNK = 64 * 1024

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

    __slots__ = ("path", "gzip", "rolled_at", "starts_at", "is_live",
                 "ident", "stat_sig")

    def __init__(self, path, gzip_, rolled_at, is_live):
        self.path = path
        # (device, inode) is what survives a rename and changes on replacement,
        # so it is how rotation of the live file is told apart from growth.
        try:
            st = os.stat(path)
            self.ident = (st.st_dev, st.st_ino)
            self.stat_sig = (st.st_size, st.st_mtime_ns)
        except OSError:
            self.ident = None
            self.stat_sig = None
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

    @property
    def name(self):
        return os.path.basename(self.path)

    @property
    def token(self):
        """Process-independent reference to this file, for the raw-line API.

        A file is identified by both basename and inode. After rotation or any
        replacement, an old reference stops resolving instead of silently
        pointing at different bytes under the same name.
        """
        if self.ident is not None:
            return f"{self.name}~{self.ident[1]:x}"
        return self.name

    def signature(self):
        """Identity plus size and mtime, to notice an archive that was replaced."""
        return (self.name, self.ident, self.stat_sig)

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


def is_safe_token(token):
    """A bare file name: no directory part, no NUL, not a dot entry."""
    return (isinstance(token, str)
            and 0 < len(token) <= 255
            and token not in (".", "..")
            and "/" not in token and "\\" not in token and "\0" not in token)


def resolve(live_path, token):
    """The LogFile a token refers to, or None.

    Only a file that discover() lists for this log series can be returned; the
    token is never joined onto a path, so it cannot reach anything else.
    """
    if not is_safe_token(token):
        return None
    for f in discover(live_path):
        if f.token == token:
            return f
    return None


def _skip(handle, count):
    """Discard `count` bytes in bounded chunks. False if the stream ended first."""
    while count > 0:
        got = handle.read(min(count, _SKIP_CHUNK))
        if not got:
            return False
        count -= len(got)
    return True


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
                if not _skip(f, start_offset):
                    return
                if not exact:
                    f.readline()
        else:
            f.seek(start_offset)
            if start_offset and not exact:
                f.readline()
        # tell() is the uncompressed position for gzip too, so a discarded
        # fragment is accounted for in both cases.
        offset = f.tell()
        while True:
            line = f.readline()
            if not line:
                return
            if not line.endswith(b"\n"):
                return  # partial trailing line; leave it for the next read
            yield offset, line[:-1]
            offset += len(line)


def read_line_at(logfile, offset):
    """The original line at `offset`, for the raw view; None past the end.

    A gzip archive is decompressed up to that point in bounded chunks rather than
    seeked, which is fine for a single on-demand click.
    """
    if offset < 0:
        return None
    with logfile.open() as f:
        if logfile.gzip:
            if not _skip(f, offset):
                return None
        else:
            f.seek(offset)
        line = f.readline(MAX_LINE)
    if not line:
        return None
    return line.decode("utf-8", errors="replace").rstrip("\n")
