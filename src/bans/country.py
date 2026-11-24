"""Country allowlist policy (spec 4.3): BACKUP_DIR/country-policy.json and geo.caddy.

The state file is a transaction state file like cloudflare-ranges.json: it owns
BANS_DIR/geo.caddy and embeds the candidate hash before the journaled
replacement. geo.caddy always holds exactly one shape: disabled, direct (country
ranges from the DB-IP dataset) or cloudflare (the CF-IPCountry header, trusted
only from the selected Cloudflare peers). The shape follows the client-IP trust
profile, so a profile change regenerates it in the same transaction.

Protected ranges are always on the allowed side. A policy over the prefix cap is
rejected before any file is written.
"""
import json
import os
from dataclasses import dataclass, field

from .. import config
from ..config import BACKUP_DIR
from . import countrydata, fsio
from .render import COUNTRY, HEADER

PATH = os.path.join(BACKUP_DIR, "country-policy.json")
VERSION = 1
MAX_BYTES = 64 * 1024
# Measured (tests/integration/country_benchmark.py, docs/security.md): 20000
# prefixes stay within the Phase 1 budget on stock Caddy, so that is the cap
# (src/config.py); above WARN_PREFIXES a reload already takes about half a
# second more than without a policy, which is worth telling the operator.
DEFAULT_MAX_PREFIXES = 20000
WARN_PREFIXES = 10000
SPECIAL = ("XX", "T1")           # unknown and Tor in Cloudflare's header; allowed only when named
MARKER = COUNTRY.marker
ISO = frozenset("""AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV
BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO
FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP
KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU
MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB
SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY
UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW""".split())
STATUS = {}


class CountryError(Exception):
    def __init__(self, code, message, status=400, **extra):
        super().__init__(message)
        self.code, self.status, self.extra = code, status, extra


class Corrupt(Exception):
    pass


@dataclass
class Policy:
    enabled: bool = False
    countries: list = field(default_factory=list)
    cloudflare_geolocation_confirmed: bool = False
    profile: str = "direct"                  # the client-IP mode geo.caddy was last rendered for
    dataset: dict = field(default_factory=dict)      # month and prefix counts at the last render
    updated_at: object = None
    last_rendered_hashes: dict = field(default_factory=dict)
    stored: bool = False


def max_prefixes() -> int:
    return config.COUNTRY_MAX_PREFIXES


def warn_prefixes() -> int:
    return min(WARN_PREFIXES, max_prefixes() // 2)


def exists() -> bool:
    return os.path.exists(PATH)


def _from_doc(doc) -> Policy:
    if not isinstance(doc, dict) or doc.get("version") != VERSION:
        raise Corrupt("unknown country-policy.json format")
    try:
        codes = doc.get("countries") or []
        if not isinstance(codes, list) or not all(isinstance(c, str) and (c in ISO or c in SPECIAL) for c in codes):
            raise ValueError("bad countries")
        hashes = doc.get("last_rendered_hashes") or {}
        if not isinstance(hashes, dict) or not all(isinstance(v, str) for v in hashes.values()):
            raise ValueError("bad last_rendered_hashes")
        dataset = doc.get("dataset") or {}
        if not isinstance(dataset, dict):
            raise ValueError("bad dataset")
    except ValueError as e:
        raise Corrupt(f"country-policy.json is invalid ({e})") from None
    return Policy(enabled=doc.get("enabled") is True, countries=sorted(set(codes)),
                  cloudflare_geolocation_confirmed=doc.get("cloudflare_geolocation_confirmed") is True,
                  profile=str(doc.get("profile") or "direct")[:30], dataset=dict(dataset),
                  updated_at=doc.get("updated_at"), last_rendered_hashes=dict(hashes), stored=True)


def load() -> Policy:
    """The stored policy, or a disabled default. Raises Corrupt."""
    try:
        with open(PATH, "rb") as f:
            raw = f.read(MAX_BYTES + 1)
    except FileNotFoundError:
        return Policy()
    except OSError as e:
        raise Corrupt(f"cannot read country-policy.json ({e.strerror or e})") from None
    if len(raw) > MAX_BYTES:
        raise Corrupt("country-policy.json is too large")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        raise Corrupt("country-policy.json is not valid JSON") from None
    return _from_doc(doc)


def load_or_default() -> Policy:
    try:
        return load()
    except Corrupt:
        return Policy()


def recorded_hash():
    try:
        return load().last_rendered_hashes.get(COUNTRY.filename) if exists() else None
    except Corrupt:
        return None


def dumps(p: Policy) -> bytes:
    doc = {"version": VERSION, "enabled": p.enabled, "countries": sorted(p.countries),
           "cloudflare_geolocation_confirmed": p.cloudflare_geolocation_confirmed, "profile": p.profile,
           "dataset": p.dataset, "updated_at": p.updated_at,
           "last_rendered_hashes": dict(sorted(p.last_rendered_hashes.items()))}
    return (json.dumps(doc, sort_keys=True, indent=1) + "\n").encode("utf-8")


def parse_codes(values) -> list:
    if not isinstance(values, list):
        raise CountryError("invalid_country", "countries must be a list of two-letter ISO country codes.")
    if len(values) > len(ISO) + len(SPECIAL):
        raise CountryError("invalid_country", "Too many country codes.")
    out = set()
    for raw in values:
        code = raw.strip().upper() if isinstance(raw, str) else ""
        if code not in ISO and code not in SPECIAL:
            raise CountryError("invalid_country", f"{str(raw)[:20]!r} is not an ISO 3166-1 country code "
                               "(XX and T1 only when named).")
        out.add(code)
    return sorted(out)


def from_payload(payload, current: Policy) -> Policy:
    """The candidate for PUT /api/security/country-policy. Raises CountryError."""
    if not isinstance(payload, dict):
        raise CountryError("invalid_request", "Send a JSON object.")
    enabled = payload.get("enabled")
    if not isinstance(enabled, bool):
        raise CountryError("invalid_request", "enabled must be true or false.")
    codes = parse_codes(payload.get("countries", current.countries))
    confirmed = payload.get("cloudflare_geolocation_confirmed", current.cloudflare_geolocation_confirmed)
    if not isinstance(confirmed, bool):
        raise CountryError("invalid_request", "cloudflare_geolocation_confirmed must be true or false.")
    if enabled and not codes:
        raise CountryError("country_required", "Select at least one country before enabling the policy.")
    return Policy(enabled=enabled, countries=codes, cloudflare_geolocation_confirmed=confirmed,
                  profile=current.profile, dataset=dict(current.dataset), updated_at=current.updated_at,
                  last_rendered_hashes=dict(current.last_rendered_hashes), stored=True)


def effective_enabled(p: Policy) -> bool:
    return p.enabled


def _tokens(nets) -> list:
    return [str(n) for n in nets]


def render(p: Policy, mode: str, peers, exclusion_tokens, directory=None):
    """geo.caddy bytes and facts about them: {profile, prefixes{v4,v6,total}, month, warnings}.
    mode: the client-IP profile mode; peers: its trusted Cloudflare peers.
    Raises CountryError; nothing is written here."""
    facts = {"profile": "off", "prefixes": {"v4": 0, "v6": 0, "total": 0}, "month": None, "warnings": []}
    if not effective_enabled(p):
        text = (HEADER + "# Country policy is off: no matcher or handler is generated.\n"
                f"vars {MARKER} off\n")
        return text.encode("ascii"), facts
    matcher = COUNTRY.matcher
    tail = [f"handle @{matcher} {{\n", "\trespond 403\n", "}\n"]
    if mode == "direct":
        try:
            ranges, month = countrydata.load(p.countries, directory)
        except countrydata.DatasetError as e:
            raise CountryError("country_dataset_unavailable", str(e), 409) from None
        v4, v6 = _tokens(ranges["v4"]), _tokens(ranges["v6"])
        total = len(v4) + len(v6)
        if total == 0:
            raise CountryError("country_no_ranges", "The selected countries have no address ranges in the "
                               "dataset; the policy would deny every public client.", 409)
        if total > max_prefixes():
            raise CountryError("country_prefix_cap_exceeded", f"The selected countries need {total} prefixes; "
                               f"the limit (COUNTRY_MAX_PREFIXES) is {max_prefixes()}. Select fewer countries "
                               "or use Cloudflare WAF country rules.", 409, count=total, limit=max_prefixes())
        facts.update(profile="direct", prefixes={"v4": len(v4), "v6": len(v6), "total": total}, month=month)
        if total > warn_prefixes():
            facts["warnings"].append(f"{total} prefixes is above the {warn_prefixes()} warning threshold; "
                                     "reloads and adaptation get slower. Cloudflare WAF country rules scale better.")
        body = [f"vars {MARKER} direct\n", f"@{matcher} {{\n",
                "\tnot client_ip " + " ".join(v4 + v6 + list(exclusion_tokens)) + "\n", "}\n"]
    else:
        if not peers:
            raise CountryError("cloudflare_peers_required", "The Cloudflare profile has no trusted peer, so the "
                               "country header cannot be trusted. Configure the profile first.", 409)
        facts["profile"] = "cloudflare"
        # Stock Caddy's `header` matcher takes one value; the anchored alternation matches any selected code.
        body = [f"vars {MARKER} cloudflare\n", f"@{matcher} {{\n",
                "\tnot client_ip " + " ".join(exclusion_tokens) + "\n",
                "\tnot {\n", "\t\tremote_ip " + " ".join(peers) + "\n",
                "\t\theader_regexp CF-IPCountry ^(?:" + "|".join(p.countries) + ")$\n", "\t}\n", "}\n"]
    return (HEADER + "".join(body + tail)).encode("ascii"), facts


def current(data) -> bool:
    return fsio.read_bytes(COUNTRY.path) == data
