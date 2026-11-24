"""The DB-IP Country Lite range dataset (spec 4.3), as the console stores it.

DB-IP publishes `start,end,CC` rows. Stock Caddy has no country matcher, so the
console converts the rows to canonical CIDRs once, at download time, and keeps
them in GEOIP_DIR/country-ranges.txt as sorted `cidr CC` lines. The City and ASN
MMDB readers are display-only and are never scanned to rebuild ranges.

parse_csv() validates every start and end address and every country code, merges
only adjacent or overlapping rows of the same country and refuses overlapping
rows of different countries (the dataset would be ambiguous). It never touches
the filesystem or the network: the updater (src/geoip_update.py) streams rows
in and swaps the finished file into place, keeping the previous one on any error.
"""
import ipaddress
import os
import re

from ..config import GEOIP_DIR

FILE = "country-ranges.txt"
FORMAT = "caddy-console-country-ranges 1"
MAX_ROWS = 2_000_000             # the real dataset is a few hundred thousand rows
MAX_LINE = 200
_CODE = re.compile(r"[A-Z]{2}")
_HEADER = re.compile(r"# (\w+)=(\S+)")


class DatasetError(ValueError):
    pass


def _address(text, line_no):
    try:
        ip = ipaddress.ip_address(text.strip())
    except ValueError:
        raise DatasetError(f"row {line_no}: {text.strip()[:60]!r} is not an IP address") from None
    if ip.version == 6 and (ip.ipv4_mapped is not None or ip in ipaddress.ip_network("::ffff:0:0/96")):
        raise DatasetError(f"row {line_no}: IPv4-mapped IPv6 addresses are not accepted")
    return ip


def parse_csv(lines) -> list:
    """`start,end,CC` rows (str lines) -> sorted [(CIDR str, CC)]. Raises DatasetError."""
    rows = []
    for n, raw in enumerate(lines, 1):
        if len(raw) > MAX_LINE:
            raise DatasetError(f"row {n} is longer than {MAX_LINE} characters")
        line = raw.strip()
        if not line:
            continue
        if len(rows) >= MAX_ROWS:
            raise DatasetError(f"more than {MAX_ROWS} rows")
        parts = [p.strip().strip('"') for p in line.split(",")]
        if len(parts) != 3:
            raise DatasetError(f"row {n} does not have three fields")
        start, end, code = _address(parts[0], n), _address(parts[1], n), parts[2]
        if start.version != end.version:
            raise DatasetError(f"row {n} mixes IPv4 and IPv6")
        if int(start) > int(end):
            raise DatasetError(f"row {n} ends before it starts")
        if not _CODE.fullmatch(code):
            raise DatasetError(f"row {n}: {code[:10]!r} is not a two-letter country code")
        rows.append((start.version, int(start), int(end), code))
    if not rows:
        raise DatasetError("the dataset has no rows")
    rows.sort()
    merged = []
    for version, start, end, code in rows:
        if merged and merged[-1][0] == version:
            _, p_start, p_end, p_code = merged[-1]
            if start <= p_end + 1 and code == p_code:
                merged[-1] = (version, p_start, max(p_end, end), code)
                continue
            if start <= p_end:
                raise DatasetError(f"overlapping ranges for {p_code} and {code}")
        merged.append((version, start, end, code))
    out = []
    for version, start, end, code in merged:
        cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
        out += [(str(net), code) for net in ipaddress.summarize_address_range(cls(start), cls(end))]
    return out


def dumps(prefixes, month) -> bytes:
    head = f"# {FORMAT}\n# month={month}\n# prefixes={len(prefixes)}\n"
    return (head + "".join(f"{cidr} {code}\n" for cidr, code in prefixes)).encode("ascii")


def path(directory=None) -> str:
    return os.path.join(directory or GEOIP_DIR, FILE)


def _open(directory):
    try:
        return open(path(directory), "r", encoding="ascii")
    except FileNotFoundError:
        raise DatasetError("The country range dataset has not been downloaded yet.") from None
    except (OSError, UnicodeDecodeError) as e:
        raise DatasetError(f"The country range dataset cannot be read ({e}).") from None


def info(directory=None) -> dict:
    """{present, month, prefixes} from the header; never raises."""
    try:
        with _open(directory) as f:
            first = f.readline().strip()
            meta = dict(m.groups() for m in (_HEADER.fullmatch(f.readline().strip()),
                                             _HEADER.fullmatch(f.readline().strip())) if m)
        if first != f"# {FORMAT}":
            raise DatasetError("unknown format")
        return {"present": True, "month": meta.get("month"), "prefixes": int(meta.get("prefixes", 0))}
    except (DatasetError, ValueError, UnicodeDecodeError):
        return {"present": False, "month": None, "prefixes": 0}


def load(codes, directory=None):
    """The allowed ranges for `codes`: ({"v4": [net], "v6": [net]}, month).
    Raises DatasetError for a missing, unreadable or malformed file. Local
    reads only, so this is safe under caddyfile_lock()."""
    wanted = set(codes)
    out = {4: [], 6: []}
    month = None
    try:
        with _open(directory) as f:
            if f.readline().strip() != f"# {FORMAT}":
                raise DatasetError("The country range dataset has an unknown format.")
            for line in f:
                if line.startswith("#"):
                    m = _HEADER.fullmatch(line.strip())
                    if m and m.group(1) == "month":
                        month = m.group(2)
                    continue
                cidr, _, code = line.strip().partition(" ")
                if code not in wanted:
                    continue
                try:
                    net = ipaddress.ip_network(cidr, strict=True)
                except ValueError:
                    raise DatasetError("The country range dataset is malformed.") from None
                out[net.version].append(net)
    except UnicodeDecodeError:
        raise DatasetError("The country range dataset is malformed.") from None
    return {f"v{v}": list(ipaddress.collapse_addresses(nets)) for v, nets in out.items()}, month
