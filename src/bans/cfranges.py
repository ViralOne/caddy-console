"""Cloudflare's published edge ranges (spec 4.2): a bundled last-known-good
list, strict parsing and a plausibility gate for refreshed lists.

Parsing never trusts the response: every line must be a canonical public
network of the family the endpoint names, and the whole list is bounded.
"""
import ipaddress

# https://www.cloudflare.com/ips-v4 and /ips-v6, last checked 2026-11.
BUNDLED = {
    "v4": ("173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
           "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
           "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"),
    "v6": ("2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
           "2a06:98c0::/29", "2c0f:f248::/32"),
}
URLS = {"v4": "https://www.cloudflare.com/ips-v4", "v6": "https://www.cloudflare.com/ips-v6"}
MAX_BYTES = 16 * 1024            # each list is well under 1 KiB
MAX_ENTRIES = 64                 # per family
WIDEST = {4: 8, 6: 12}           # no edge range is wider than this
MIN_SHARED = 0.5                 # of the previous address space a new list must still cover


class RangeError(ValueError):
    pass


def parse_list(text, family: str) -> list:
    """One canonical network per line, sorted and collapsed. Raises RangeError."""
    version = 4 if family == "v4" else 6
    if not isinstance(text, str) or len(text.encode("utf-8", "replace")) > MAX_BYTES:
        raise RangeError(f"the IPv{version} list is missing or larger than {MAX_BYTES} bytes")
    nets = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            net = ipaddress.ip_network(line, strict=True)
        except ValueError:
            raise RangeError(f"the IPv{version} list has an invalid line {line[:60]!r}") from None
        if net.version != version:
            raise RangeError(f"the IPv{version} list has an IPv{net.version} network {line}")
        if net.prefixlen < WIDEST[version] or not net.is_global:
            raise RangeError(f"the IPv{version} list has an implausible network {line}")
        nets.append(net)
    if not nets:
        raise RangeError(f"the IPv{version} list is empty")
    if len(nets) > MAX_ENTRIES:
        raise RangeError(f"the IPv{version} list has more than {MAX_ENTRIES} networks")
    return [str(n) for n in ipaddress.collapse_addresses(nets)]


def _size(nets) -> int:
    return sum(n.num_addresses for n in nets)


def plausible(old: dict, new: dict):
    """None if `new` may replace `old`, else why not. Each family must keep at
    least MIN_SHARED of the previous address space: a refresh that drops most
    of the edge is a broken or hostile response, not a range update."""
    for family in ("v4", "v6"):
        before = [ipaddress.ip_network(x) for x in old.get(family) or ()]
        after = [ipaddress.ip_network(x) for x in new.get(family) or ()]
        if not after:
            return f"the {family} list is empty"
        if not before:
            continue
        shared = 0
        for a in before:
            for b in after:
                if a.overlaps(b):
                    shared += min(a.num_addresses, b.num_addresses)
        if shared < MIN_SHARED * _size(before):
            return f"the {family} list keeps less than {int(MIN_SHARED * 100)}% of the previous ranges"
    return None


def bundled() -> dict:
    """The bundled list in canonical (parsed, collapsed and sorted) form."""
    return {k: parse_list("\n".join(v), k) for k, v in BUNDLED.items()}


def networks(ranges: dict) -> list:
    return [ipaddress.ip_network(x) for fam in ("v4", "v6") for x in (ranges or {}).get(fam) or ()]


TIMEOUT = 10


def _get_text(session, url) -> str:
    with session.get(url, stream=True, timeout=TIMEOUT, allow_redirects=False) as res:
        if res.status_code != 200:
            raise RangeError(f"{url} answered HTTP {res.status_code}")
        body = b""
        for chunk in res.iter_content(4096):
            body += chunk
            if len(body) > MAX_BYTES:
                raise RangeError(f"{url} is larger than {MAX_BYTES} bytes")
    try:
        return body.decode("ascii")
    except UnicodeDecodeError:
        raise RangeError(f"{url} is not plain ASCII") from None


def fetch(session) -> dict:
    """Both official lists over HTTPS, parsed. Raises RangeError or a requests
    error. Never called while caddyfile_lock() is held."""
    return {fam: parse_list(_get_text(session, URLS[fam]), fam) for fam in ("v4", "v6")}
