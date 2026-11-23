"""Render one source's effective bans into its own Caddy policy file (spec 1.3).

Each source owns a file, a vars marker and a matcher name, so sites can import
any combination and live detection can tell them apart after adaptation
(matcher names and comments do not survive it; the marker does)."""
import ipaddress
import os
from dataclasses import dataclass

from .. import config
from . import addr

HEADER = "# Managed by Caddy Console. Do not edit; changes are overwritten.\n"


@dataclass(frozen=True)
class PolicySource:
    name: str
    filename: str
    marker: str
    matcher: str

    @property
    def glob(self) -> str:
        return self.filename[: -len(".caddy")] + "*.caddy"

    @property
    def path(self) -> str:
        return os.path.join(config.BANS_DIR, self.filename)

    @property
    def import_line(self) -> str:
        return f"import {os.path.join(config.BANS_DIR, self.glob)}"


SOURCES = {
    "manual": PolicySource("manual", "bans-manual.caddy",
                           "caddy_console_manual_policy", "caddy_console_manual_banned"),
    # Phase 2 adds: "crowdsec": PolicySource("crowdsec", "bans-crowdsec.caddy",
    #   "caddy_console_crowdsec_policy", "caddy_console_crowdsec_banned")
}


class CapacityError(Exception):
    def __init__(self, count: int, limit: int):
        super().__init__(f"{count} prefixes exceed the limit of {limit}")
        self.count, self.limit = count, limit


def effective_prefixes(records, now, source_name: str) -> list:
    nets = [r.network for r in records if r.source == source_name and not r.expired(now)]
    return (list(ipaddress.collapse_addresses([n for n in nets if n.version == 4]))
            + list(ipaddress.collapse_addresses([n for n in nets if n.version == 6])))


def render_policy(source: PolicySource, prefixes, exclusion_tokens, limit: int) -> bytes:
    if len(prefixes) > limit:
        raise CapacityError(len(prefixes), limit)
    out = [HEADER, f"vars {source.marker} 1\n"]
    if prefixes:
        out += [
            f"@{source.matcher} {{\n",
            "\tclient_ip " + " ".join(addr.token(p) for p in prefixes) + "\n",
            "\tnot client_ip " + " ".join(exclusion_tokens) + "\n",
            "}\n",
            f"handle @{source.matcher} {{\n",
            "\trespond 403\n",
            "}\n",
        ]
    return "".join(out).encode("ascii")
