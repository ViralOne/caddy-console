"""Small, fully flushed file operations shared by the ban store and transaction."""
import hashlib
import os
import tempfile


def sha256_tag(data):
    return None if data is None else "sha256:" + hashlib.sha256(data).hexdigest()


def read_bytes(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        return None


def fsync_dir(directory: str) -> None:
    """Best effort, like the editor's save path: a filesystem that refuses a
    directory fsync must not turn a completed replace into a failure."""
    try:
        fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def write_temp(directory: str, basename: str, data: bytes, mode: int) -> str:
    """A flushed, hidden temp file beside its target: ".<basename>.<random>.tmp".

    The leading dot and the .tmp suffix mean no `*.caddy` import glob can ever
    match a partial or abandoned file.
    """
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=f".{basename}.", suffix=".tmp")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            fd = -1
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        if fd >= 0:
            os.close(fd)
        try:
            os.remove(tmp)
        except FileNotFoundError:
            pass
        raise
    return tmp


def atomic_write(path: str, data: bytes, mode: int) -> None:
    directory = os.path.dirname(path) or "."
    tmp = write_temp(directory, os.path.basename(path), data, mode)
    try:
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except FileNotFoundError:
            pass
        raise
    fsync_dir(directory)
