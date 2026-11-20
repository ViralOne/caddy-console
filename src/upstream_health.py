"""When each upstream became unhealthy, shared by every worker and kept across restarts.

Caddy only reports whether an upstream is healthy right now. The dashboard wants
"down since 14:31", so the first worker to notice a change records it in a small
JSON file in BACKUP_DIR. The read-modify-write happens under an flock and the
write is atomic (temp file + os.replace), so concurrent workers never record a
transition twice or read a torn file. A corrupt or unreadable file is treated as
empty and rewritten. The time then means "since this console noticed", which is
the honest fallback.
"""
import fcntl
import json
import logging
import os
import tempfile
import time

from .config import BACKUP_DIR

logger = logging.getLogger(__name__)

STATE_PATH = os.path.join(BACKUP_DIR, "upstream-health.json")
LOCK_PATH = os.path.join(BACKUP_DIR, ".upstream-health.lock")


def _read(path: str) -> tuple[dict, bool]:
    """(state, needs_rewrite). Anything unusable reads as an empty state."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}, False
    except (OSError, ValueError):
        return {}, True
    if not isinstance(data, dict):
        return {}, True
    clean = {
        k: float(v) for k, v in data.items()
        if isinstance(k, str) and isinstance(v, (int, float)) and not isinstance(v, bool)
    }
    return clean, clean != data


def _write(path: str, state: dict) -> None:
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".upstream-health.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def record(healthy: dict, now: float | None = None) -> dict:
    """Fold the current health flags into the shared state.

    Returns {address: unhealthy_since} for every address currently reported
    unhealthy. An empty `healthy` (metrics unavailable) changes nothing.
    """
    now = time.time() if now is None else now
    try:
        lock_fd = os.open(LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o600)
    except OSError:
        lock_fd = None   # read-only volume: still answer, just without the lock
    try:
        if lock_fd is not None:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
        state, dirty = _read(STATE_PATH)
        if healthy:
            for address in [a for a in state if a not in healthy]:
                del state[address]          # no longer in Caddy's metrics
                dirty = True
        for address, flag in healthy.items():
            if flag == 0 and address not in state:
                state[address] = float(now)
                dirty = True
            elif flag != 0 and address in state:
                del state[address]
                dirty = True
        if dirty:
            try:
                _write(STATE_PATH, state)
            except OSError as e:
                logger.warning("Could not write %s: %s", STATE_PATH, e)
        return {a: state[a] for a, flag in healthy.items() if flag == 0 and a in state}
    finally:
        if lock_fd is not None:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
