"""CrowdSec Local API from the read-only bouncer side (spec 2.3, 2.4).

Settings, Go durations and the decision stream. The bouncer key is only ever
placed in the X-Api-Key header: it never appears in an exception message, a
log line, the status file, an audit entry or an API response.
"""
import json
import re
from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from urllib.parse import urlsplit

import requests as http_client

from .. import config
from . import addr

KEY_MAX = 256
LIST_ORIGINS = ("capi", "lists")
_KEY = re.compile(r"^[\x21-\x7e]{1,256}$")
_ORIGIN = re.compile(r"^[a-z0-9_-]{1,32}$")


class ConfigError(ValueError):
    pass


def parse_url(raw) -> str:
    """Validate CROWDSEC_URL. Errors name the offending part, never the value:
    it may carry credentials and ends up in startup logs."""
    text = (raw or "").strip().rstrip("/")
    if not text:
        return ""
    problem = None
    try:
        parts = urlsplit(text)
        port = parts.port
        if parts.scheme not in ("http", "https"):
            problem = "scheme (only http and https)"
        elif not parts.hostname or any(c.isspace() for c in text):
            problem = "host"
        elif parts.username is not None or parts.password is not None:
            problem = "userinfo"
        elif parts.path:
            problem = "path"
        elif parts.query:
            problem = "query"
        elif parts.fragment:
            problem = "fragment"
        elif parts.netloc.endswith(":") or (port is not None and not 0 < port < 65536):
            problem = "port"
    except ValueError:
        problem = "port or host"
    if problem:
        raise ConfigError(f"CROWDSEC_URL must be http(s)://host[:port] and nothing else: invalid {problem}")
    return text


def parse_origins(raw) -> tuple:
    out = []
    for item in (raw or "").split(","):
        item = item.strip().lower()
        if not item:
            continue
        if not _ORIGIN.match(item):
            raise ConfigError(f"CROWDSEC_ORIGINS has an invalid origin {item!r}")
        if item not in out:
            out.append(item)
    if not out:
        raise ConfigError("CROWDSEC_ORIGINS must list at least one origin, for example crowdsec,cscli")
    return tuple(out)


def wire_origins(raw) -> tuple:
    """Origins as the operator wrote them, for the LAPI `origins=` query. LAPI
    (v1.8.2 pkg/database/decisionfilter.go) filters with a plain SQL IN, so the
    case is not folded server-side; parse_origins() lowercases for local use."""
    parse_origins(raw)  # validates and rejects an empty list
    out = []
    for item in raw.split(","):
        item = item.strip()
        if item and item not in out:
            out.append(item)
    return tuple(out)


def url() -> str:
    return parse_url(config.CROWDSEC_URL)


def origins() -> tuple:
    return parse_origins(config.CROWDSEC_ORIGINS)


def enabled() -> bool:
    return bool(config.BANS_ENABLED and url())


def read_key():
    """(key, None) or (None, problem). The _FILE variant wins when set and is
    re-read on every poll, so a rotated secret is picked up (and forces a new
    startup snapshot, see sync.Synchronizer). Problems never contain the key."""
    path = config.CROWDSEC_CONSOLE_BOUNCER_KEY_FILE
    if path:
        try:
            with open(path, "rb") as f:
                text = f.read(KEY_MAX + 2).decode("utf-8", "replace").strip()
        except OSError as e:
            return None, f"Cannot read CROWDSEC_CONSOLE_BOUNCER_KEY_FILE ({e.strerror or type(e).__name__})."
    else:
        text = (config.CROWDSEC_CONSOLE_BOUNCER_KEY or "").strip()
    if not text:
        return None, "No bouncer key: set CROWDSEC_CONSOLE_BOUNCER_KEY or CROWDSEC_CONSOLE_BOUNCER_KEY_FILE."
    if not _KEY.match(text):
        return None, "The bouncer key must be 1-256 printable ASCII characters without spaces."
    return text, None


# --- Go durations (time.ParseDuration) ----------------------------------------------

_UNITS = {"ns": Decimal("1e-9"), "us": Decimal("1e-6"), "µs": Decimal("1e-6"), "μs": Decimal("1e-6"),
          "ms": Decimal("1e-3"), "s": Decimal(1), "m": Decimal(60), "h": Decimal(3600)}
_PART = re.compile(r"([0-9]+(?:\.[0-9]*)?|\.[0-9]+)(ns|us|µs|μs|ms|s|m|h)")
DURATION_MAX_TEXT = 64
DURATION_MAX_SECONDS = Decimal(100 * 366 * 86400)


def parse_go_duration(text) -> float:
    """Seconds as a float, negative for LAPI's deleted decisions. Bounded: at
    most 64 characters and 100 years, so a hostile payload cannot cost much."""
    if not isinstance(text, str) or not 0 < len(text) <= DURATION_MAX_TEXT:
        raise ValueError("duration must be a short string")
    sign, body = 1, text
    if body[0] in "+-":
        sign, body = (-1 if body[0] == "-" else 1), body[1:]
    if body == "0":
        return 0.0
    if not body:
        raise ValueError(f"invalid duration {text!r}")
    total, pos = Decimal(0), 0
    while pos < len(body):
        m = _PART.match(body, pos)
        if not m:
            raise ValueError(f"invalid duration {text!r}")
        try:
            total += Decimal(m.group(1)) * _UNITS[m.group(2)]
        except InvalidOperation:
            raise ValueError(f"invalid duration {text!r}") from None
        if total > DURATION_MAX_SECONDS:
            raise ValueError(f"duration {text!r} is out of range")
        pos = m.end()
    return float(sign * total)


# --- decision stream (spec 2.4) --------------------------------------------------------

STREAM_PATH = "/v1/decisions/stream"
SCOPES = "Ip,Range"
TIMEOUT = (3.05, 15)
MAX_BYTES = 32 * 1024 * 1024
MAX_DECISIONS = 200000
IGNORE_REASONS = ("not_ban", "scope", "origin", "expired", "invalid_value", "too_wide")


class LapiUnavailable(Exception):
    pass


class LapiAuthError(Exception):
    pass


class LapiMalformed(Exception):
    pass


@dataclass(frozen=True)
class Decision:
    id: str
    scope: str
    value: str
    type: str
    origin: str
    scenario: str
    remaining: float


@dataclass(frozen=True)
class Stream:
    new: tuple
    deleted: tuple


@dataclass(frozen=True)
class Accepted:
    decision_id: str
    net: object
    origin: str
    scenario: str
    fetched_at: object
    expires_at: object


def _read_bounded(resp) -> bytes:
    chunks, size = [], 0
    try:
        for chunk in resp.iter_content(65536):
            size += len(chunk)
            if size > MAX_BYTES:
                raise LapiMalformed("the response is larger than 32 MiB")
            chunks.append(chunk)
    except http_client.RequestException as e:
        raise LapiUnavailable(f"reading the response failed ({type(e).__name__})") from None
    return b"".join(chunks)


def fetch_stream(base_url, key, *, startup: bool, origins) -> Stream:
    """One poll. Raises LapiUnavailable, LapiAuthError or LapiMalformed; the
    messages name only exception types and status codes, never the key."""
    params = {"startup": "true" if startup else "false", "scopes": SCOPES, "origins": ",".join(origins)}
    headers = {"X-Api-Key": key, "Accept": "application/json", "User-Agent": "caddy-console"}
    try:
        resp = http_client.get(base_url + STREAM_PATH, params=params, headers=headers, timeout=TIMEOUT,
                               stream=True, allow_redirects=False)
    except http_client.RequestException as e:
        raise LapiUnavailable(type(e).__name__) from None
    try:
        if resp.status_code in (401, 403):
            raise LapiAuthError(f"HTTP {resp.status_code}")
        if resp.status_code != 200:
            raise LapiUnavailable(f"HTTP {resp.status_code}")
        body = _read_bounded(resp)
    finally:
        resp.close()
    return parse_stream(body)


def _text(item, name, limit, required=True) -> str:
    value = item.get(name)
    if value is None and not required:
        return ""
    if not isinstance(value, str) or len(value) > limit:
        raise LapiMalformed(f"decision field {name!r} is missing or invalid")
    return value


def _decision(item) -> Decision:
    if not isinstance(item, dict):
        raise LapiMalformed("a decision is not an object")
    did = item.get("id")
    if isinstance(did, bool) or not isinstance(did, int) or not 0 < did < 10 ** 20:
        raise LapiMalformed("decision field 'id' is missing or invalid")
    try:
        remaining = parse_go_duration(item.get("duration"))
    except ValueError:
        raise LapiMalformed("decision field 'duration' is missing or invalid") from None
    return Decision(str(did), _text(item, "scope", 16), _text(item, "value", 64), _text(item, "type", 32),
                    _text(item, "origin", 64), _text(item, "scenario", 256, required=False), remaining)


def parse_stream(body: bytes) -> Stream:
    """The whole response or nothing: one bad item rejects all of it (spec 2.6)."""
    try:
        doc = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise LapiMalformed("the response is not JSON") from None
    if not isinstance(doc, dict) or "new" not in doc or "deleted" not in doc:
        raise LapiMalformed("the response has no new/deleted lists")
    lists = []
    for name in ("new", "deleted"):
        items = doc[name]
        if items is None:
            items = []
        if not isinstance(items, list):
            raise LapiMalformed(f"{name!r} is not a list")
        lists.append(items)
    if len(lists[0]) + len(lists[1]) > MAX_DECISIONS:
        raise LapiMalformed(f"more than {MAX_DECISIONS} decisions in one response")
    return Stream(tuple(_decision(i) for i in lists[0]), tuple(_decision(i).id for i in lists[1]))


def classify(d: Decision, origins, fetched_at):
    """(Accepted, None) or (None, reason). The protected-set check needs the
    stored management registry, so service.apply_crowdsec() does it later."""
    if d.type.lower() != "ban":
        return None, "not_ban"
    scope = d.scope.lower()
    if scope not in ("ip", "range"):
        return None, "scope"
    if d.origin.lower() not in origins:
        return None, "origin"
    seconds = int(d.remaining)              # floor: never ban longer than CrowdSec says
    if seconds <= 0:
        return None, "expired"
    try:
        net = addr.canonical(d.value)
    except addr.AddressError:
        return None, "invalid_value"
    if scope == "ip" and addr.scope_of(net) != "ip":
        return None, "invalid_value"
    try:
        addr.check_width(net)
    except addr.AddressError:
        return None, "too_wide"
    return Accepted(d.id, net, d.origin, d.scenario, fetched_at, fetched_at + timedelta(seconds=seconds)), None
