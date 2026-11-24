"""Mutation and leader locks that hold on any BACKUP_DIR filesystem.

flock on a bind-mounted BACKUP_DIR does not always exclude: on Docker Desktop
(virtiofs, gRPC-FUSE) two processes can reach one file through different mount
views and both hold the lock; NFS, SMB and FUSE mounts can drop it entirely.
So exclusion inside the container is decided by a lock under config.LOCK_DIR
(the container's private tmpfs /tmp, shared by every worker and every
`docker compose exec` tool), plus a threading.Lock per process for threads.
The BACKUP_DIR flock is still taken afterwards, as best-effort protection
against a second container on the same volume.

Lock order (unchanged from Phase 2, each pair local before shared):
bans-sync local, bans-sync shared, caddyfile thread, caddyfile local,
caddyfile shared. Nothing is re-entrant: callers never nest a lock.
"""
import errno
import fcntl
import logging
import os
import threading
from contextlib import contextmanager

from . import config

log = logging.getLogger(__name__)
_warned = set()


class LockUnavailable(RuntimeError):
    """The required container-local lock cannot be created or acquired."""


def local_path(name: str) -> str:
    directory = config.LOCK_DIR
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    except OSError as e:
        raise LockUnavailable(f"Cannot create lock directory {directory}: {e}") from e
    return os.path.join(directory, name)


def _open(path: str) -> int:
    return os.open(path, os.O_CREAT | os.O_RDWR, 0o600)


def _warn_once(key, message, *args) -> None:
    if key not in _warned:
        _warned.add(key)
        log.warning(message, *args)


def shared_flock(path: str, *, blocking: bool):
    """Best-effort flock on a BACKUP_DIR file. Returns (fd or None, held_elsewhere).
    A filesystem that cannot lock is logged once and treated as "not locked"."""
    try:
        fd = _open(path)
    except OSError as e:
        _warn_once(("open", path), "Cannot open shared lock %s (%s); relying on the container-local lock", path, e)
        return None, False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
    except BlockingIOError:
        os.close(fd)
        return None, True
    except OSError as e:
        os.close(fd)
        if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK) and not blocking:
            return None, True
        _warn_once(("flock", path), "Cannot flock shared lock %s (%s); relying on the container-local lock", path, e)
        return None, False
    return fd, False


@contextmanager
def mutation_lock(name: str, shared: str, thread_lock: threading.Lock, error=LockUnavailable):
    """Blocking exclusive lock: thread lock, then LOCK_DIR/<name>, then the
    best-effort shared BACKUP_DIR file. `error` is raised when the local lock
    cannot be taken (fail closed)."""
    with thread_lock:
        try:
            path = local_path(name)
            fd = _open(path)
        except (OSError, LockUnavailable) as e:
            raise error(f"Cannot open lock {os.path.join(config.LOCK_DIR, name)}: {e}") from e
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError as e:
                raise error(f"Cannot acquire lock {path}: {e}") from e
            shared_fd, _ = shared_flock(shared, blocking=True)
            try:
                yield
            finally:
                if shared_fd is not None:
                    os.close(shared_fd)
        finally:
            os.close(fd)                       # closing the last fd releases the flock


def self_test(directory: str) -> bool:
    """Does flock in `directory` exclude between two open file descriptions
    (which is what two processes have)? Logs a clear warning when it does not.
    It catches static failures (nolock NFS, FUSE without flock); a split mount
    view can still appear later, which is why LOCK_DIR decides exclusion."""
    path = os.path.join(directory, f".lock-selftest-{os.getpid()}")
    a = b = None
    try:
        a = _open(path)
        b = _open(path)
    except OSError as e:
        log.warning("Lock self-test: %s cannot be opened or written (%s). Check that BACKUP_DIR exists and is "
                    "writable by the console user.", directory, e)
        for fd in (a, b):
            if fd is not None:
                os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            pass
        return False
    try:
        fcntl.flock(a, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            fcntl.flock(b, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        excluded = False
    except OSError as e:
        log.warning("Lock self-test: flock in %s does not exclude across processes (%s). It is only best-effort "
                    "cross-container protection; use a local filesystem or a named volume for BACKUP_DIR.",
                    directory, e)
        return False
    finally:
        for fd in (a, b):
            if fd is not None:
                os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            pass
    if not excluded:
        log.warning("Lock self-test: flock in %s does not exclude across processes (two holders at once). "
                    "Mutations and CrowdSec sync rely on the container-local lock in %s; a second console "
                    "container on this BACKUP_DIR is not excluded. Use a local filesystem or a named volume.",
                    directory, config.LOCK_DIR)
    return excluded
