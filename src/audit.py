import json
import os
from datetime import datetime

from .config import AUDIT_LOG, AUDIT_LOG_MAX_BYTES


def rotated_path() -> str:
    return AUDIT_LOG + ".1"


def _rotate_if_needed() -> None:
    """Keep the audit log bounded: once it passes the cap, move it to .1.

    A rename is atomic, so a concurrent writer either lands in the old file
    (now .1) or the new one; nothing is lost. Only one rotated file is kept.
    """
    try:
        if os.path.getsize(AUDIT_LOG) < AUDIT_LOG_MAX_BYTES:
            return
        os.replace(AUDIT_LOG, rotated_path())
    except OSError:
        pass


def log_action(action: str, user: str, detail: str = ""):
    entry = {
        "time": datetime.now().isoformat(),
        "user": user,
        "action": action,
        "detail": detail[:300],
    }
    _rotate_if_needed()
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def tail_lines(path: str, count: int, block: int = 8192) -> list[str]:
    """Return the last `count` lines of a file without reading all of it."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            end = f.tell()
            data = b""
            pos = end
            while pos > 0 and data.count(b"\n") <= count:
                step = min(block, pos)
                pos -= step
                f.seek(pos)
                data = f.read(step) + data
    except OSError:
        return []
    lines = data.decode("utf-8", errors="replace").splitlines()
    return lines[-count:]


def iter_entries():
    """Yield every parsed audit entry, oldest first, across the rotated file too."""
    for path in (rotated_path(), AUDIT_LOG):
        try:
            with open(path) as f:
                for line in f:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
        except OSError:
            continue


# Audit actions after which the Caddyfile on disk is different. A rejected reload
# normally rolls the file back; only a failed rollback leaves it changed.
CHANGE_ACTIONS = {
    "save_reload": "save", "save_no_reload": "save", "save_reload_unknown": "save",
    "restore_reload": "restore", "restore_no_reload": "restore", "restore_reload_unknown": "restore",
}


def _as_change(entry):
    action = entry.get("action", "")
    kind = CHANGE_ACTIONS.get(action)
    if kind is None and action.endswith("_reload_failed") and "rolled_back=False" in str(entry.get("detail", "")):
        kind = action.split("_", 1)[0]
    if kind is None:
        return None
    try:
        ts = datetime.fromisoformat(entry["time"]).timestamp()
    except (KeyError, TypeError, ValueError):
        return None
    return {"action": kind, "user": entry.get("user", ""), "ts": ts}


def last_change(scan: int = 500):
    """The newest save/restore that changed the file on disk, or None."""
    for path in (AUDIT_LOG, rotated_path()):
        for line in reversed(tail_lines(path, scan)):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(entry, dict):
                change = _as_change(entry)
                if change:
                    return change
    return None
