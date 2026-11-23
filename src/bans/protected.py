"""Addresses that can never be banned, checked at input and repeated in the
generated `not client_ip` line (spec 1.3)."""
import ipaddress
import re
import socket
import struct
from dataclasses import dataclass

from . import addr

_n = ipaddress.ip_network
CORE = (
    ("loopback", ("127.0.0.0/8", "::1/128")),
    ("private", ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")),
    ("link_local", ("169.254.0.0/16", "fe80::/10")),
    ("cgnat", ("100.64.0.0/10",)),
    ("ula", ("fc00::/7",)),
    ("special", ("0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4", "::/128", "ff00::/8")),
)
LABELS = {
    "loopback": "Loopback", "private": "Private (RFC 1918)", "link_local": "Link-local",
    "cgnat": "Carrier-grade NAT", "ula": "IPv6 unique local",
    "special": "Unspecified, multicast and reserved", "docker": "Docker networks",
    "never": "BANS_NEVER", "operator": "Verified console addresses", "profile": "Client-IP profile",
}
# What the rendered exclusion always starts with. Caddy's private_ranges is
# 127/8, 10/8, 172.16/12, 192.168/16, fd00::/8 and ::1/128.
RENDER_BASE = ("private_ranges", "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10")
_RENDER_BASE_NETS = tuple(_n(x) for x in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8", "::1/128",
    "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10"))
DYNAMIC = ("docker", "never", "operator", "profile")


class ConfigError(ValueError):
    pass


def overlaps(a, b) -> bool:
    """Interval intersection, so containment in either direction counts."""
    return (a.version == b.version
            and a.network_address <= b.broadcast_address
            and b.network_address <= a.broadcast_address)


def parse_never(raw: str) -> tuple:
    out = []
    for item in re.split(r"[\s,]+", raw or ""):
        if not item:
            continue
        try:
            out.append(addr.canonical(item))
        except addr.AddressError as e:
            raise ConfigError(f"invalid entry {item!r}: {e}") from None
    return tuple(out)


def docker_networks(route_text: str) -> list:
    """IPv4 networks this container is attached to, from /proc/net/route."""
    nets = []
    for line in (route_text or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 8:
            continue
        try:
            dest = socket.inet_ntoa(struct.pack("<I", int(parts[1], 16)))
            mask = socket.inet_ntoa(struct.pack("<I", int(parts[7], 16)))
            candidate = ipaddress.ip_network(f"{dest}/{mask}")
        except (ValueError, struct.error, OSError):
            continue
        if candidate.prefixlen > 0 and candidate not in nets:
            nets.append(candidate)
    return nets


def read_docker_networks() -> list:
    try:
        with open("/proc/net/route", encoding="ascii") as f:
            return docker_networks(f.read())
    except OSError:
        return []


@dataclass(frozen=True)
class Protected:
    entries: tuple   # ((category, network), ...)

    def overlap(self, candidate):
        for category, protected_net in self.entries:
            if overlaps(candidate, protected_net):
                return category
        return None

    def exclusion_tokens(self) -> list:
        extras = [n for cat, n in self.entries if cat in DYNAMIC]
        out = list(RENDER_BASE)
        for family in (4, 6):
            for n in ipaddress.collapse_addresses([e for e in extras if e.version == family]):
                if not any(n.version == b.version and n.subnet_of(b) for b in _RENDER_BASE_NETS):
                    out.append(addr.token(n))
        return out

    def summary(self) -> list:
        groups = {}
        for category, n in self.entries:
            groups.setdefault(category, []).append(addr.token(n))
        return [{"category": c, "label": LABELS[c], "values": v} for c, v in groups.items()]


def build(*, never=(), management=(), docker=(), profile=()) -> Protected:
    entries = [(cat, _n(v)) for cat, values in CORE for v in values]
    for category, nets in (("never", never), ("operator", management), ("docker", docker), ("profile", profile)):
        entries.extend((category, addr.unmap(_n(x, strict=False))) for x in nets)
    return Protected(tuple(entries))
