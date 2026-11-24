"""The operator's "never ban" list: BACKUP_DIR/allowlist.json (docs/security.md).

A transaction state file: written only through txn.apply_locked(), in the same
journal that regenerates every policy file repeating the protected set. A file
that is not exactly this schema is reported as corrupt (never rewritten as
empty); while it is, the last generated policies stay in place and every
policy write is refused.
"""
import ipaddress
import json
import os
import uuid
from dataclasses import asdict, dataclass

from ..config import BACKUP_DIR
from . import addr

PATH = os.path.join(BACKUP_DIR, "allowlist.json")
VERSION = 1
MAX_ENTRIES = 500
NOTE_MAX = 200
MAX_BYTES = 512 * 1024
IPV4_MIN_PREFIX = 8
IPV6_MIN_PREFIX = 32


class Corrupt(Exception):
    pass


class InputError(ValueError):
    def __init__(self, code, message, status=400):
        super().__init__(message)
        self.code, self.status = code, status


@dataclass(frozen=True)
class Entry:
    id: str
    value: str
    note: str
    actor: str
    created_at: str

    @property
    def network(self):
        return ipaddress.ip_network(self.value)


def exists() -> bool:
    return os.path.exists(PATH)


def _entry(doc) -> Entry:
    if not isinstance(doc, dict) or set(doc) != {"id", "value", "note", "actor", "created_at"}:
        raise ValueError("bad entry")
    if not all(isinstance(doc[k], str) for k in doc) or len(doc["note"]) > NOTE_MAX:
        raise ValueError("bad entry")
    net = validate_value(doc["value"])
    if addr.token(net) != doc["value"]:
        raise ValueError("non-canonical value")
    return Entry(**doc)


def load() -> list:
    """The stored entries ([] when the file is absent). Raises Corrupt."""
    try:
        with open(PATH, "rb") as f:
            raw = f.read(MAX_BYTES + 1)
    except FileNotFoundError:
        return []
    except OSError as e:
        raise Corrupt(f"cannot read allowlist.json ({e.strerror or e})") from None
    if len(raw) > MAX_BYTES:
        raise Corrupt("allowlist.json is too large")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        raise Corrupt("allowlist.json is not valid JSON") from None
    if not isinstance(doc, dict) or doc.get("version") != VERSION or not isinstance(doc.get("entries"), list):
        raise Corrupt("unknown allowlist.json format")
    try:
        entries = [_entry(e) for e in doc["entries"]]
    except (ValueError, InputError, addr.AddressError) as e:
        raise Corrupt(f"allowlist.json is invalid ({e})") from None
    if len(entries) > MAX_ENTRIES or len({e.value for e in entries}) != len(entries):
        raise Corrupt("allowlist.json is invalid (too many or duplicate entries)")
    return entries


def load_or_default() -> list:
    try:
        return load()
    except Corrupt:
        return []


def networks(entries) -> list:
    return [e.network for e in entries]


def dumps(entries) -> bytes:
    doc = {"version": VERSION, "entries": [asdict(e) for e in entries]}
    return (json.dumps(doc, sort_keys=True, indent=1) + "\n").encode("utf-8")


def validate_value(value):
    """A canonical IP or CIDR no wider than /8 (IPv4) or /32 (IPv6)."""
    net = addr.canonical(value)
    limit = IPV4_MIN_PREFIX if net.version == 4 else IPV6_MIN_PREFIX
    if net.prefixlen < limit:
        raise InputError("range_too_wide", f"Ranges wider than /{limit} cannot be added for IPv{net.version}.")
    return net


def validate_note(note) -> str:
    if note is None:
        return ""
    if not isinstance(note, str):
        raise InputError("invalid_note", "The note must be text.")
    note = note.strip()
    if len(note) > NOTE_MAX or any(ord(c) < 32 for c in note):
        raise InputError("invalid_note", f"The note must be one line of at most {NOTE_MAX} characters.")
    return note


def add(entries, net, note, actor, now_iso) -> tuple:
    """A new list with the entry appended, or InputError (duplicate, full)."""
    value = addr.token(net)
    if any(e.value == value for e in entries):
        raise InputError("duplicate", f"{value} is already in the never-ban list.", 409)
    if len(entries) >= MAX_ENTRIES:
        raise InputError("allowlist_full", f"The never-ban list holds at most {MAX_ENTRIES} entries.", 409)
    entry = Entry(id=uuid.uuid4().hex[:16], value=value, note=note, actor=str(actor)[:200], created_at=now_iso)
    return [*entries, entry], entry
