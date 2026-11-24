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
    "crowdsec": PolicySource("crowdsec", "bans-crowdsec.caddy",
                             "caddy_console_crowdsec_policy", "caddy_console_crowdsec_banned"),
}
# Import order between sources: the CrowdSec import goes after the manual import.
AFTER = {"crowdsec": ("manual",)}
# CrowdSec origins that count as "local" for manual-ban priority (spec 2.5).
LOCAL_ORIGINS = ("crowdsec", "cscli")


def active_sources(state=None) -> dict:
    """The sources the console renders. Manual always. CrowdSec once it is
    configured, or once it left something behind (records or a recorded policy
    hash), so turning CrowdSec off still lets expiry and Reset clear what it
    rendered. An install that never used CrowdSec never gets bans-crowdsec.caddy."""
    out = {"manual": SOURCES["manual"]}
    cs = SOURCES["crowdsec"]
    if config.CROWDSEC_URL or (state is not None and (
            any(r.source == "crowdsec" for r in state.records) or cs.filename in state.last_rendered_hashes)):
        out["crowdsec"] = cs
    return out


class CapacityError(Exception):
    def __init__(self, count: int, limit: int, by_source=None):
        super().__init__(f"{count} prefixes exceed the limit of {limit}")
        self.count, self.limit, self.by_source = count, limit, dict(by_source or {})


def check_capacity(by_source: dict, limit: int) -> None:
    """BANS_MAX is a total over every source rendered into stock Caddy (spec 2.5)."""
    total = sum(by_source.values())
    if total > limit:
        raise CapacityError(total, limit, by_source)


def is_local(record) -> bool:
    return record.source == "manual" or (record.origin or "").lower() in LOCAL_ORIGINS


def capacity_counts(records, now) -> dict:
    """Prefixes that count against BANS_MAX for a manual-side change: manual
    bans plus CrowdSec decisions of local origin. Non-local CrowdSec origins
    (CAPI, lists) never cause a manual ban to be refused (spec 2.5)."""
    local = [r for r in records if is_local(r)]
    return {"manual": len(effective_prefixes(local, now, "manual")),
            "crowdsec": len(effective_prefixes(local, now, "crowdsec"))}


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
