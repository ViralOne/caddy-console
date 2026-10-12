"""A minimal MaxMind DB writer, for fixtures only.

Enough of the format (IPv4 tree, 32-bit records, maps/strings/uints/arrays) to
build tiny databases shaped like DB-IP's, so the GeoIP tests run offline and
without a writer dependency. Spec: https://maxmind.github.io/MaxMind-DB/
"""
import ipaddress
import struct

METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"


def _control(type_num, size):
    if size < 29:
        size_bits, extra = size, b""
    elif size < 285:
        size_bits, extra = 29, bytes([size - 29])
    elif size < 65821:
        size_bits, extra = 30, (size - 285).to_bytes(2, "big")
    else:
        size_bits, extra = 31, (size - 65821).to_bytes(3, "big")
    if type_num <= 7:
        return bytes([(type_num << 5) | size_bits]) + extra
    return bytes([size_bits, type_num - 7]) + extra


class U16(int):
    pass


class U64(int):
    pass


def encode(value):
    if isinstance(value, (U16, U64)):
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""
        return _control(5 if isinstance(value, U16) else 9, len(raw)) + raw
    if isinstance(value, str):
        raw = value.encode()
        return _control(2, len(raw)) + raw
    if isinstance(value, bool):
        return _control(14, int(value))
    if isinstance(value, int):
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""
        return _control(6 if value < 2 ** 32 else 9, len(raw)) + raw
    if isinstance(value, dict):
        out = _control(7, len(value))
        for k, v in value.items():
            out += encode(k) + encode(v)
        return out
    if isinstance(value, (list, tuple)):
        return _control(11, len(value)) + b"".join(encode(v) for v in value)
    raise TypeError(type(value))


def build(records, database_type="DBIP-City-Lite"):
    """Bytes of an IPv4 database mapping each CIDR in `records` to its value."""
    nodes = [[None, None]]
    data = b""
    for cidr, value in records.items():
        net = ipaddress.ip_network(cidr)
        offset = len(data)
        data += encode(value)
        bits = int(net.network_address)
        node = 0
        for depth in range(net.prefixlen):
            bit = (bits >> (31 - depth)) & 1
            if depth == net.prefixlen - 1:
                nodes[node][bit] = ("data", offset)
            else:
                nxt = nodes[node][bit]
                if not isinstance(nxt, int):
                    nodes.append([None, None])
                    nxt = nodes[node][bit] = len(nodes) - 1
                node = nxt
    count = len(nodes)

    def record(r):
        if r is None:
            return count
        if isinstance(r, int):
            return r
        return count + 16 + r[1]

    tree = b"".join(struct.pack(">II", record(l), record(r)) for l, r in nodes)
    meta = encode({
        # libmaxminddb checks these types exactly, unlike the pure-Python reader.
        "node_count": count, "record_size": U16(32), "ip_version": U16(4),
        "database_type": database_type, "languages": ["en"],
        "binary_format_major_version": U16(2), "binary_format_minor_version": U16(0),
        "build_epoch": U64(1790000000), "description": {"en": "test fixture"},
    })
    return tree + b"\x00" * 16 + data + METADATA_MARKER + meta


CITY = {
    "172.126.0.0/16": {
        "city": {"names": {"en": "Oakland"}},
        "continent": {"code": "NA", "names": {"en": "North America"}},
        "country": {"iso_code": "US", "names": {"en": "United States"}},
        "subdivisions": [{"names": {"en": "California"}}],
    },
}
ASN = {
    "172.126.0.0/16": {"autonomous_system_number": 7018,
                       "autonomous_system_organization": "AT&T Enterprises, LLC"},
}


def write_fixtures(directory, city=CITY, asn=ASN):
    import os
    with open(os.path.join(directory, "dbip-city-lite.mmdb"), "wb") as f:
        f.write(build(city))
    with open(os.path.join(directory, "dbip-asn-lite.mmdb"), "wb") as f:
        f.write(build(asn, "DBIP-ASN-Lite"))
