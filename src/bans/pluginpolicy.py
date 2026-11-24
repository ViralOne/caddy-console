"""BACKUP_DIR/plugin-policy.json: schema version and last rendered hash of
BANS_DIR/crowdsec-plugin-protect.caddy (spec 1.1, 3.4).

A transaction state file in the Phase 1 sense: it owns the route file and
embeds its candidate hash (txn._check_embedded_hashes). An unreadable file
records nothing, so an existing route file is held until Re-apply rather
than silently regenerated.
"""
import json
import os

from ..config import BACKUP_DIR
from .render import PLUGIN

PATH = os.path.join(BACKUP_DIR, "plugin-policy.json")
VERSION = 1
SCHEMA = 1                       # the layout render.render_plugin_route() writes
MAX_BYTES = 64 * 1024


def exists() -> bool:
    return os.path.exists(PATH)


def recorded_hash():
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
    if not isinstance(doc, dict) or doc.get("version") != VERSION or doc.get("schema") != SCHEMA:
        return None
    hashes = doc.get("last_rendered_hashes")
    value = hashes.get(PLUGIN.filename) if isinstance(hashes, dict) else None
    return value if isinstance(value, str) else None


def dumps(policy_hash: str) -> bytes:
    doc = {"version": VERSION, "schema": SCHEMA, "last_rendered_hashes": {PLUGIN.filename: policy_hash}}
    return (json.dumps(doc, sort_keys=True, indent=1) + "\n").encode("utf-8")
