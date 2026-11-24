"""bans.json: versioned ban records, rendered-policy hashes and the verified
console-address registry (spec 1.2). A security-control file: anything that is
not exactly this schema is quarantined and reported, never rewritten as empty
(spec 1.6). Writes happen only through txn.apply_locked()."""
import hashlib
import json
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from ..config import BACKUP_DIR
from . import addr, fsio

STATE_PATH = os.path.join(BACKUP_DIR, "bans.json")
ERROR_PATH = os.path.join(BACKUP_DIR, "bans-state-error.json")
SNAPSHOT_DIR = os.path.join(BACKUP_DIR, ".bans-snapshots")
SNAPSHOT_KEEP = 5
STATE_MAX_BYTES = 32 * 1024 * 1024
QUARANTINE_MAX_BYTES = 1024 * 1024
SCHEMA_VERSION = 1
SOURCES = ("manual", "crowdsec")
TRUST_PROFILES = ("direct", "cloudflare-proxied", "cloudflare-tunnel")
DURATIONS = {"4h": timedelta(hours=4), "24h": timedelta(hours=24),
             "7d": timedelta(days=7), "permanent": None}
REASON_MAX = 500
MANAGEMENT_MAX = 16
MANAGEMENT_TTL = timedelta(days=30)
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DECISION_ID = re.compile(r"^[0-9]{1,20}$")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_KEYS = {"version", "records", "last_rendered_hashes", "management_addresses"}
_RECORD_KEYS = {"id", "source", "source_id", "scope", "value", "reason", "scenario",
                "origin", "actor", "created_at", "expires_at"}


class StateCorrupt(Exception):
    def __init__(self, message, raw=None):
        super().__init__(message)
        self.raw = raw


class InputError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(text):
    if not isinstance(text, str) or not text.endswith("Z"):
        raise ValueError(f"not a UTC RFC 3339 timestamp: {text!r}")
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


@dataclass
class Record:
    id: str
    source: str
    source_id: object
    scope: str
    value: str
    reason: str
    scenario: object
    origin: object
    actor: str
    created_at: str
    expires_at: object

    @property
    def network(self):
        return addr.canonical(self.value)

    def expired(self, now) -> bool:
        return self.expires_at is not None and parse_iso(self.expires_at) <= now


@dataclass
class State:
    records: list = field(default_factory=list)
    last_rendered_hashes: dict = field(default_factory=dict)
    management_addresses: list = field(default_factory=list)
    raw: object = None          # bytes as read; None when the file did not exist
    raw_hash: object = None

    @property
    def version(self) -> str:
        return self.raw_hash[7:23] if self.raw_hash else "empty"


def validate_reason(value) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise InputError("invalid_reason", "Reason must be text.")
    if len(value) > REASON_MAX:
        raise InputError("invalid_reason", f"Reason must be at most {REASON_MAX} characters.")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise InputError("invalid_reason", "Reason must be valid Unicode text.") from None
    if _CONTROL.search(value):
        raise InputError("invalid_reason", "Reason may not contain control characters other than newline and tab.")
    return value


def validate_duration(value) -> str:
    if value not in DURATIONS:
        raise InputError("invalid_duration", "Duration must be 4h, 24h, 7d or permanent.")
    return value


def _opt_str(value, limit=200):
    if value is not None and (not isinstance(value, str) or len(value) > limit):
        raise ValueError("optional field must be a short string or null")


def _check_record(r: Record) -> None:
    if not isinstance(r.id, str) or not 0 < len(r.id) <= 64:
        raise ValueError("record id")
    if r.source not in SOURCES:
        raise ValueError(f"unknown source {r.source!r}")
    if not isinstance(r.actor, str) or len(r.actor) > 320:
        raise ValueError("actor")
    for v in (r.source_id, r.scenario, r.origin):
        _opt_str(v)
    if r.source == "manual" and (r.source_id, r.scenario, r.origin) != (None, None, None):
        raise ValueError("manual records carry no source_id, scenario or origin")
    if r.source == "crowdsec":
        if not isinstance(r.source_id, str) or not _DECISION_ID.match(r.source_id):
            raise ValueError("crowdsec records carry their LAPI decision id")
        if not r.origin:
            raise ValueError("crowdsec records carry their LAPI origin")
        if r.reason:
            raise ValueError("crowdsec records carry no reason")
    validate_reason(r.reason)
    parse_iso(r.created_at)
    if r.expires_at is not None:
        parse_iso(r.expires_at)
    if not isinstance(r.value, str):
        raise ValueError("value")
    net = addr.canonical(r.value)
    if addr.token(net) != r.value:
        raise ValueError(f"value {r.value!r} is not canonical")
    if addr.scope_of(net) != r.scope:
        raise ValueError(f"scope of {r.value!r} must be {addr.scope_of(net)}")


def migrate(doc):
    """Bring an older document to SCHEMA_VERSION. A newer one is never downgraded."""
    if not isinstance(doc, dict):
        raise TypeError("top level must be an object")
    if doc.get("version") == SCHEMA_VERSION:
        return doc
    raise ValueError(f"unsupported schema version {doc.get('version')!r}")


def _from_doc(doc) -> State:
    unknown = set(doc) - _KEYS
    if unknown:
        raise ValueError(f"unknown keys {sorted(unknown)}")
    records, ids = [], set()
    for item in doc["records"]:
        if not isinstance(item, dict) or set(item) != _RECORD_KEYS:
            raise ValueError("record keys do not match the schema")
        r = Record(**item)
        _check_record(r)
        if r.id in ids:
            raise ValueError(f"duplicate record id {r.id}")
        ids.add(r.id)
        records.append(r)
    hashes = doc["last_rendered_hashes"]
    if not isinstance(hashes, dict) or not all(
            isinstance(k, str) and k.endswith(".caddy") and "/" not in k
            and isinstance(v, str) and _HASH_RE.match(v) for k, v in hashes.items()):
        raise ValueError("last_rendered_hashes")
    mgmt = doc["management_addresses"]
    if not isinstance(mgmt, list) or len(mgmt) > MANAGEMENT_MAX:
        raise ValueError("management_addresses")
    for m in mgmt:
        if not isinstance(m, dict) or set(m) != {"value", "trust_profile", "last_seen"}:
            raise ValueError("management address keys")
        ip = addr.client_address(m["value"])
        if ip is None or str(ip) != m["value"] or m["trust_profile"] not in TRUST_PROFILES:
            raise ValueError("management address")
        parse_iso(m["last_seen"])
    return State(records, dict(hashes), [dict(m) for m in mgmt])


def parse(raw: bytes) -> State:
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise StateCorrupt(f"bans.json is not valid JSON ({e})", raw) from None
    try:
        state = _from_doc(migrate(doc))
    except (KeyError, TypeError, ValueError) as e:
        raise StateCorrupt(f"bans.json has an invalid schema ({e})", raw) from None
    state.raw, state.raw_hash = raw, fsio.sha256_tag(raw)
    return state


def load(path=None) -> State:
    path = path or STATE_PATH
    try:
        with open(path, "rb") as f:
            raw = f.read(STATE_MAX_BYTES + 1)
    except FileNotFoundError:
        return State()
    except OSError as e:
        raise StateCorrupt(f"Cannot read bans.json ({e.strerror or e})", None) from None
    if len(raw) > STATE_MAX_BYTES:
        raise StateCorrupt("bans.json is larger than 32 MiB", raw)
    return parse(raw)


def dumps(state: State) -> bytes:
    doc = {"version": SCHEMA_VERSION,
           "records": [asdict(r) for r in state.records],
           "last_rendered_hashes": dict(sorted(state.last_rendered_hashes.items())),
           "management_addresses": state.management_addresses}
    return (json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def new_manual_record(net, duration, reason, actor, now) -> Record:
    delta = DURATIONS[duration]
    return Record(id=str(uuid.uuid4()), source="manual", source_id=None,
                  scope=addr.scope_of(net), value=addr.token(net), reason=reason,
                  scenario=None, origin=None, actor=actor, created_at=iso(now),
                  expires_at=None if delta is None else iso(now + delta))


def new_crowdsec_record(decision_id, net, origin, scenario, fetched_at, expires_at) -> Record:
    """One LAPI decision. The id is derived from the decision id, so the same
    decision always maps to the same record; created_at is when it was fetched."""
    return Record(id=f"crowdsec-{decision_id}", source="crowdsec", source_id=str(decision_id),
                  scope=addr.scope_of(net), value=addr.token(net), reason="", scenario=scenario or None,
                  origin=origin, actor="system", created_at=iso(fetched_at), expires_at=iso(expires_at))


def prune_expired(state: State, now, sources=None) -> list:
    removed = [r for r in state.records
               if r.expired(now) and (sources is None or r.source in sources)]
    state.records = [r for r in state.records if r not in removed]
    return removed


def prune_management(state: State, now) -> bool:
    keep = [m for m in state.management_addresses if parse_iso(m["last_seen"]) > now - MANAGEMENT_TTL]
    changed = len(keep) != len(state.management_addresses)
    state.management_addresses = keep
    return changed


def touch_management(state: State, ip, profile: str, now) -> bool:
    if ip is None:
        return False
    value = str(ip)
    entry = next((m for m in state.management_addresses if m["value"] == value), None)
    if entry is None:
        entry = {"value": value}
        state.management_addresses.append(entry)
    entry.update(trust_profile=profile, last_seen=iso(now))
    state.management_addresses.sort(key=lambda m: m["last_seen"], reverse=True)
    del state.management_addresses[MANAGEMENT_MAX:]
    return True


def management_networks(state: State) -> list:
    return [addr.canonical(m["value"]) for m in state.management_addresses]


def quarantine(raw, error) -> object:
    """A bounded copy of unusable state for diagnosis, at most one per content."""
    name = None
    if raw is not None:
        digest = fsio.sha256_tag(raw)[7:15]
        existing = sorted(n for n in os.listdir(BACKUP_DIR)
                          if n.startswith("bans.json.quarantine-") and n.endswith("-" + digest))
        name = existing[0] if existing else (
            f"bans.json.quarantine-{utc_now().strftime('%Y%m%dT%H%M%SZ')}-{digest}")
        if not existing:
            fsio.atomic_write(os.path.join(BACKUP_DIR, name), raw[:QUARANTINE_MAX_BYTES], 0o600)
    meta = {"detected_at": iso(utc_now()), "error": str(error)[:500], "quarantine": name,
            "size": None if raw is None else len(raw)}
    fsio.atomic_write(ERROR_PATH, json.dumps(meta, sort_keys=True).encode(), 0o600)
    return name


def read_error():
    try:
        with open(ERROR_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def clear_error() -> None:
    try:
        os.remove(ERROR_PATH)
    except FileNotFoundError:
        pass


def _snapshot_id(name: str) -> str:
    return hashlib.sha256(name.encode()).hexdigest()[:16]


_SNAPSHOT_RE = re.compile(r"^bans-(\d{8}T\d{6}Z)-(\d{8})-[0-9a-f]{12}\.json\.bak$")


def _snapshot_names() -> list:
    """Snapshot file names, newest first by their sequence number (timestamps
    are per second, so they cannot order snapshots taken in the same second)."""
    try:
        names = os.listdir(SNAPSHOT_DIR)
    except OSError:
        return []
    found = [(int(m.group(2)), n) for n in names for m in [_SNAPSHOT_RE.match(n)] if m]
    return [n for _, n in sorted(found, reverse=True)]


def save_snapshot(raw) -> None:
    """Keep the last few committed bans.json versions as restore choices for a
    later corrupt file (spec 1.6 'restore a valid backup'). The caller passes
    the bytes it just committed; a repeat of the newest snapshot is skipped."""
    if not raw:
        return
    os.makedirs(SNAPSHOT_DIR, mode=0o700, exist_ok=True)
    names = _snapshot_names()
    if names and fsio.read_bytes(os.path.join(SNAPSHOT_DIR, names[0])) == raw:
        return
    seq = int(_SNAPSHOT_RE.match(names[0]).group(2)) + 1 if names else 1
    stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    name = f"bans-{stamp}-{seq % 10 ** 8:08d}-{fsio.sha256_tag(raw)[7:19]}.json.bak"
    fsio.atomic_write(os.path.join(SNAPSHOT_DIR, name), raw, 0o600)
    for old in _snapshot_names()[SNAPSHOT_KEEP:]:
        os.remove(os.path.join(SNAPSHOT_DIR, old))


def list_snapshots() -> list:
    out = []
    for name in _snapshot_names():
        try:
            state = load(os.path.join(SNAPSHOT_DIR, name))
        except StateCorrupt:
            continue
        stamp = _SNAPSHOT_RE.match(name).group(1)
        out.append({"id": _snapshot_id(name),
                    "created_at": f"{stamp[0:4]}-{stamp[4:6]}-{stamp[6:8]}T{stamp[9:11]}:{stamp[11:13]}:{stamp[13:15]}Z",
                    "records": len(state.records)})
    return out


def snapshot_bytes(snapshot_id):
    for name in _snapshot_names():
        if _snapshot_id(name) == snapshot_id:
            return fsio.read_bytes(os.path.join(SNAPSHOT_DIR, name))
    return None
