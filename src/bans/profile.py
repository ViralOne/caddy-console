"""Client-IP trust profiles (spec 4.1) and BACKUP_DIR/cloudflare-ranges.json.

The state file is a Phase 1 transaction state file: it owns
BANS_DIR/cloudflare-trusted-proxies.caddy and embeds its candidate hash. It
holds the selected profile, the tunnel peers and the current Cloudflare edge
list. Until an operator saves a profile, CLIENT_IP_MODE and the bundled list
apply and nothing is written in direct mode.

The rendered file is the body of a global `servers` block, never a second
global options block. Direct mode renders a comment only, so a stale import
can never trust a forwarding header.
"""
import ipaddress
import json
import os
from dataclasses import dataclass, field

from .. import config
from ..config import BACKUP_DIR
from . import addr, cfranges, fsio
from .render import HEADER, PROFILE

PATH = os.path.join(BACKUP_DIR, "cloudflare-ranges.json")
VERSION = 1
MAX_BYTES = 64 * 1024
MODES = ("direct", "cloudflare-proxied", "cloudflare-tunnel")
MAX_PEERS = 4
# A tunnel peer is one fixed cloudflared address or a narrow dedicated subnet.
NARROWEST_SUBNET = {4: 24, 6: 64}
PRIVATE_RANGES = "private_ranges"
_PRIVATE = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))


class ConfigError(ValueError):
    pass


class InputError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class Corrupt(Exception):
    pass


@dataclass
class Profile:
    mode: str = "direct"
    tunnel_peers: list = field(default_factory=list)      # canonical tokens, or ["private_ranges"]
    tunnel_only: bool = False                               # operator confirmed an isolated tunnel-only listener
    ranges: dict = field(default_factory=cfranges.bundled)
    ranges_source: str = "bundled"                          # bundled | cloudflare
    ranges_fetched_at: object = None
    last_rendered_hashes: dict = field(default_factory=dict)
    stored: bool = False                                    # read from PATH rather than defaulted

    def peers(self) -> list:
        """The immediate peers this profile trusts for CF-Connecting-IP / CF-IPCountry."""
        if self.mode == "cloudflare-proxied":
            return [x for fam in ("v4", "v6") for x in self.ranges.get(fam, ())]
        if self.mode == "cloudflare-tunnel":
            return list(self.tunnel_peers)
        return []

    def protected_networks(self) -> list:
        """Added to the protected set: the complete proxy layer in proxied mode (spec 4.1)."""
        return cfranges.networks(self.ranges) if self.mode == "cloudflare-proxied" else []


def parse_mode(value) -> str:
    mode = str(value or "").strip().lower()
    if mode not in MODES:
        raise ConfigError(f"CLIENT_IP_MODE must be one of {', '.join(MODES)}, got {value!r}")
    return mode


def default() -> Profile:
    return Profile(mode=parse_mode(config.CLIENT_IP_MODE))


def exists() -> bool:
    return os.path.exists(PATH)


def _from_doc(doc) -> Profile:
    if not isinstance(doc, dict) or doc.get("version") != VERSION:
        raise Corrupt("unknown cloudflare-ranges.json format")
    try:
        mode = parse_mode(doc.get("mode"))
        ranges = {fam: cfranges.parse_list("\n".join(doc["ranges"][fam]), fam) for fam in ("v4", "v6")}
        peers = validate_peers(doc.get("tunnel_peers") or [], mode, bool(doc.get("tunnel_only")))
        hashes = doc.get("last_rendered_hashes") or {}
        if not isinstance(hashes, dict) or not all(isinstance(v, str) for v in hashes.values()):
            raise ValueError("bad last_rendered_hashes")
    except (KeyError, TypeError, ValueError, ConfigError) as e:
        raise Corrupt(f"cloudflare-ranges.json is invalid ({e})") from None
    return Profile(mode=mode, tunnel_peers=peers, tunnel_only=bool(doc.get("tunnel_only")), ranges=ranges,
                   ranges_source=str(doc.get("ranges_source") or "bundled")[:20],
                   ranges_fetched_at=doc.get("ranges_fetched_at"), last_rendered_hashes=dict(hashes), stored=True)


def load() -> Profile:
    """The stored profile, or the CLIENT_IP_MODE default. Raises Corrupt."""
    try:
        with open(PATH, "rb") as f:
            raw = f.read(MAX_BYTES + 1)
    except FileNotFoundError:
        return default()
    except OSError as e:
        raise Corrupt(f"cannot read cloudflare-ranges.json ({e.strerror or e})") from None
    if len(raw) > MAX_BYTES:
        raise Corrupt("cloudflare-ranges.json is too large")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        raise Corrupt("cloudflare-ranges.json is not valid JSON") from None
    return _from_doc(doc)


def load_or_default() -> Profile:
    try:
        return load()
    except Corrupt:
        return default()


def recorded_hash():
    try:
        return load().last_rendered_hashes.get(PROFILE.filename) if exists() else None
    except Corrupt:
        return None


def dumps(p: Profile) -> bytes:
    doc = {"version": VERSION, "mode": p.mode, "tunnel_peers": list(p.tunnel_peers), "tunnel_only": p.tunnel_only,
           "ranges": {fam: list(p.ranges.get(fam, ())) for fam in ("v4", "v6")},
           "ranges_source": p.ranges_source, "ranges_fetched_at": p.ranges_fetched_at,
           "last_rendered_hashes": dict(sorted(p.last_rendered_hashes.items()))}
    return (json.dumps(doc, sort_keys=True, indent=1) + "\n").encode("utf-8")


def validate_peers(values, mode, tunnel_only) -> list:
    """Canonical tunnel peers. Only a fixed private address or a narrow private
    subnet is accepted; the broad private_ranges shortcut only for a listener
    the operator confirmed is reachable from the tunnel network alone."""
    if mode != "cloudflare-tunnel":
        return []
    if not isinstance(values, list) or not values:
        raise InputError("tunnel_peer_required", "Enter the fixed cloudflared address or its dedicated subnet.")
    if len(values) > MAX_PEERS:
        raise InputError("too_many_peers", f"Enter at most {MAX_PEERS} cloudflared addresses or subnets.")
    out = []
    for raw in values:
        text = raw.strip() if isinstance(raw, str) else ""
        if text == PRIVATE_RANGES:
            if not tunnel_only:
                raise InputError("broad_trust_refused", "Trusting private_ranges lets any LAN or published-port "
                                 "peer forge CF-Connecting-IP. Use the fixed cloudflared address, or confirm that "
                                 "this listener is reachable only from the isolated tunnel network.")
            out.append(PRIVATE_RANGES)
            continue
        try:
            net = addr.canonical(text)
        except addr.AddressError as e:
            raise InputError("invalid_peer", str(e)) from None
        if not any(net.version == p.version and net.subnet_of(p) for p in _PRIVATE):
            raise InputError("invalid_peer", f"{text} is not a private address; cloudflared reaches Caddy over "
                             "a dedicated Docker network.")
        if net.prefixlen < NARROWEST_SUBNET[net.version]:
            raise InputError("broad_trust_refused", f"{text} is wider than /{NARROWEST_SUBNET[net.version]}; give "
                             "cloudflared a fixed address or a narrow dedicated subnet.")
        token = addr.token(net) if addr.scope_of(net) == "range" else f"{net.network_address}/{net.max_prefixlen}"
        if token not in out:
            out.append(token)
    return out


def from_payload(payload, current: Profile) -> Profile:
    """The candidate profile for PUT /api/security/client-ip-profile. Raises InputError."""
    if not isinstance(payload, dict):
        raise InputError("invalid_request", "Send a JSON object.")
    try:
        mode = parse_mode(payload.get("mode"))
    except ConfigError:
        raise InputError("invalid_mode", f"mode must be one of {', '.join(MODES)}.") from None
    tunnel_only = payload.get("tunnel_only") is True
    peers = validate_peers(payload.get("tunnel_peers"), mode, tunnel_only)
    return Profile(mode=mode, tunnel_peers=peers, tunnel_only=tunnel_only and mode == "cloudflare-tunnel",
                   ranges={k: list(v) for k, v in current.ranges.items()}, ranges_source=current.ranges_source,
                   ranges_fetched_at=current.ranges_fetched_at,
                   last_rendered_hashes=dict(current.last_rendered_hashes), stored=True)


def render(p: Profile) -> bytes:
    """cloudflare-trusted-proxies.caddy: a `servers` block body (spec 4.1)."""
    out = [HEADER]
    if p.mode == "direct":
        out.append("# Direct mode: no trusted proxies. client_ip is the TCP peer; forwarded and Cloudflare\n"
                   "# headers are ignored.\n")
    elif not p.peers():
        out.append("# Cloudflare Tunnel mode without a cloudflared address: nothing is trusted yet.\n")
    else:
        out.append("trusted_proxies static " + " ".join(p.peers()) + "\n")
    return "".join(out).encode("ascii")


def current(p: Profile) -> bool:
    return fsio.read_bytes(PROFILE.path) == render(p)
