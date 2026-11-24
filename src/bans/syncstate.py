"""BACKUP_DIR/bans-crowdsec-sync.json: the CrowdSec health the sync leader
reports so every worker's Security view can show it.

Disposable diagnostics, not security-control state: an unreadable file means
"no report", never degraded bans. Only the listed fields are written or read,
and none of them is the bouncer key.
"""
import json
import os

from ..config import BACKUP_DIR
from . import fsio

PATH = os.path.join(BACKUP_DIR, "bans-crowdsec-sync.json")
MAX_BYTES = 256 * 1024
VERSION = 1
FIELDS = ("version", "leader_pid", "leader_host", "leader_nonce", "updated_at", "lapi_state", "lapi_message", "apply_state", "apply_message",
          "last_poll_at", "last_success_at", "last_snapshot_at", "last_apply_at", "decisions", "by_origin",
          "ignored", "protected_sample", "capacity", "origins", "poll_interval", "sync_interval",
          "pending_apply")


def write(doc) -> None:
    data = json.dumps({k: doc.get(k) for k in FIELDS}, sort_keys=True, ensure_ascii=False).encode("utf-8")
    fsio.atomic_write(PATH, data, 0o600)


def read():
    try:
        with open(PATH, "rb") as f:
            raw = f.read(MAX_BYTES + 1)
    except OSError:
        return None
    if len(raw) > MAX_BYTES:
        return None
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        return None
    if not isinstance(doc, dict) or doc.get("version") != VERSION:
        return None
    return {k: doc.get(k) for k in FIELDS}
