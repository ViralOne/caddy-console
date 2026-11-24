"""CrowdSec Local API from the read-only bouncer side (spec 2.3, 2.4).

Settings, Go durations and the decision stream. The bouncer key is only ever
placed in the X-Api-Key header: it never appears in an exception message, a
log line, the status file, an audit entry or an API response.
"""
import re
from decimal import Decimal, InvalidOperation
from urllib.parse import urlsplit

from .. import config

KEY_MAX = 256
LIST_ORIGINS = ("capi", "lists")
_KEY = re.compile(r"^[\x21-\x7e]{1,256}$")
_ORIGIN = re.compile(r"^[a-z0-9_-]{1,32}$")


class ConfigError(ValueError):
    pass


def parse_url(raw) -> str:
    text = (raw or "").strip().rstrip("/")
    if not text:
        return ""
    parts = urlsplit(text)
    try:
        port_ok = parts.port is None or 0 < parts.port < 65536
    except ValueError:
        port_ok = False
    if (parts.scheme not in ("http", "https") or not parts.hostname or parts.username is not None
            or parts.password is not None or parts.path or parts.query or parts.fragment or not port_ok):
        raise ConfigError(f"CROWDSEC_URL must be http(s)://host[:port] and nothing else, got {text!r}")
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
_PART = re.compile(r"(\d+(?:\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h)")
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
