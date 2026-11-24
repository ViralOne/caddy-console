"""Parse ban targets into canonical networks. Raw request text never reaches a
Caddyfile: everything written out is serialized from the parsed object."""
import ipaddress

IPV4_MIN_PREFIX = 16
IPV6_MIN_PREFIX = 48
_MAPPED = ipaddress.ip_network("::ffff:0:0/96")


class AddressError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def unmap(net):
    """::ffff:a.b.c.d/(96+n) -> a.b.c.d/n, so IPv4 clients compare as IPv4."""
    if net.version == 6 and net.prefixlen >= 96 and net.subnet_of(_MAPPED):
        return ipaddress.ip_network(f"{net.network_address.ipv4_mapped}/{net.prefixlen - 96}")
    return net


def canonical(value):
    text = value.strip() if isinstance(value, str) else ""
    code = "invalid_range" if "/" in text else "invalid_ip"
    kind = "CIDR range" if code == "invalid_range" else "IP address"
    if not text or len(text) > 64 or "%" in text or any(c.isspace() for c in text):
        raise AddressError(code, f"Enter a single {kind}.")
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise AddressError(code, f"{text} is not a valid {kind}.") from None
    return unmap(net)


def scope_of(net) -> str:
    return "ip" if net.prefixlen == net.max_prefixlen else "range"


def token(net) -> str:
    return str(net.network_address) if scope_of(net) == "ip" else str(net)


def check_width(net) -> None:
    limit = IPV4_MIN_PREFIX if net.version == 4 else IPV6_MIN_PREFIX
    if net.prefixlen < limit:
        raise AddressError("range_too_wide", f"Ranges wider than /{limit} cannot be banned for IPv{net.version}.")


def client_address(raw):
    """The canonical address of a transport peer string, or None."""
    if not isinstance(raw, str) or "/" in raw:
        return None
    try:
        ip = ipaddress.ip_address(raw.strip())
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip
