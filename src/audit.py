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
