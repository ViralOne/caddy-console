import fcntl
import hashlib
import json
import os
import re
import shutil
import threading
from contextlib import contextmanager
from datetime import datetime
from urllib.parse import urlparse

import requests as http_client
from flask import Blueprint, jsonify, render_template, request, session

from ..audit import log_action
from ..auth import get_or_create_csrf, login_required
from ..caddy_api import get_servers, invalidate_servers_cache
from ..config import BACKUP_DIR, BACKUP_KEEP, BACKUP_PREFIX, CADDY_API_URL, CADDY_LOG_FILE, CADDYFILE
from ..validator import caddy_fmt, caddy_validate, smart_validate


editor_bp = Blueprint("editor", __name__)


def _version(content: str) -> str:
    """Short content hash used for optimistic-locking on save."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


def _current_file_version() -> str:
    try:
        with open(CADDYFILE) as f:
            return _version(f.read())
    except OSError:
        return ""


# --- Caddyfile write lock ---------------------------------------------------------
#
# Save requests can land on different gunicorn workers, so a threading.Lock is not
# enough: the version check and the write have to happen under a file lock or two
# editors can both pass the check and both write.

_LOCK_PATH = os.path.join(BACKUP_DIR, ".lock")
_fallback_lock = threading.Lock()


@contextmanager
def caddyfile_lock():
    try:
        fd = os.open(_LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o600)
    except OSError:
        # Read-only backup volume: process-local lock is the best we can do.
        with _fallback_lock:
            yield
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _write_caddyfile(content: str) -> None:
    # The Caddyfile is a bind-mounted single file, so an atomic rename would
    # replace the inode the containers hold open. Write in place, but make sure
    # it reaches disk before we tell Caddy about it.
    with open(CADDYFILE, "w") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())


_BACKUP_NAME_RE = re.compile(r"^(.*?\d{8}-\d{6})(?:-(\d+))?$")


def _backup_sort_key(name: str):
    """Chronological key: timestamp, then the same-second counter as a number."""
    m = _BACKUP_NAME_RE.match(name)
    if not m:
        return (name, 0)
    return (m.group(1), int(m.group(2) or 0))


def _backup_name() -> str:
    """A name that doesn't collide even if several saves land in the same second.

    Same-second saves get an increasing "-N" suffix. The counter continues from
    the highest existing sibling rather than the first free slot, so a name
    freed by pruning is never reused (that would make a new backup sort as the
    oldest and be pruned next).
    """
    base = f"{BACKUP_PREFIX}{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    try:
        siblings = [n for n in os.listdir(BACKUP_DIR) if n == base or n.startswith(base + "-")]
    except OSError:
        siblings = []
    if not siblings:
        return base
    highest = max(_backup_sort_key(n)[1] for n in siblings)
    return f"{base}-{highest + 1}"


def _make_backup() -> str | None:
    """Copy the live Caddyfile into BACKUP_DIR. Returns the name, or None if there was nothing to back up."""
    if not os.path.isfile(CADDYFILE):
        return None
    name = _backup_name()
    shutil.copy2(CADDYFILE, os.path.join(BACKUP_DIR, name))
    return name


def list_backup_names() -> list[str]:
    """Backup file names, newest first (the timestamp format sorts chronologically)."""
    try:
        names = [f for f in os.listdir(BACKUP_DIR) if f.startswith(BACKUP_PREFIX) and f != BACKUP_PREFIX]
    except OSError:
        return []
    return sorted(names, key=_backup_sort_key, reverse=True)


def prune_backups(keep: int = BACKUP_KEEP) -> list[str]:
    """Delete the oldest backups beyond `keep`. keep <= 0 disables pruning."""
    if keep <= 0:
        return []
    removed = []
    for name in list_backup_names()[keep:]:
        try:
            os.remove(os.path.join(BACKUP_DIR, name))
            removed.append(name)
        except OSError:
            pass
    return removed


def _backup_path(name: str) -> str | None:
    """Resolve a user-supplied backup name to a path inside BACKUP_DIR.

    Only real backups are addressable. BACKUP_DIR also holds the session secret,
    the audit log and the lock file, none of which may be read or deleted here.
    """
    safe_name = os.path.basename(name)
    if not safe_name.startswith(BACKUP_PREFIX) or safe_name == BACKUP_PREFIX:
        return None
    path = os.path.join(BACKUP_DIR, safe_name)
    return path if os.path.isfile(path) else None


def _apply_config(content: str, user: str, source: str, expected_version: str | None = None, detail: str = ""):
    """Back up the current Caddyfile, write new content, reload Caddy.

    `content` must already be formatted and validated. Returns a Flask response
    tuple. Shared by /api/save and /api/backups/<name>/restore.

    If Caddy rejects the config the on-disk file is rolled back to the backup,
    so what is on disk always matches what is running.
    """
    with caddyfile_lock():
        if expected_version is not None:
            current = _current_file_version()
            if current and expected_version != current:
                log_action("save_conflict", user, f"client={expected_version} disk={current}")
                return jsonify({
                    "ok": False,
                    "conflict": True,
                    "message": "The Caddyfile changed on disk since you loaded it. Reload to get the latest version before saving.",
                    "version": current,
                }), 409
        previous_version = _current_file_version()
        backup_name = _make_backup()
        _write_caddyfile(content)
        prune_backups()

    new_version = _version(content)
    extra = f", {detail}" if detail else ""

    try:
        resp = http_client.post(
            f"{CADDY_API_URL}/load",
            data=content.encode("utf-8"),
            headers={"Content-Type": "text/caddyfile"},
            timeout=10,
        )
    except http_client.ConnectionError:
        log_action(f"{source}_no_reload", user, f"backup={backup_name}, caddy not reachable{extra}")
        return jsonify({
            "ok": True,
            "message": f"Saved by {user} (Caddy not reachable — reload skipped)",
            "content": content,
            "version": new_version,
        })
    except http_client.RequestException as e:
        # Typically a read timeout: Caddy got the config but hasn't answered.
        # It may well have applied it, so leave the file in place.
        log_action(f"{source}_reload_unknown", user, f"backup={backup_name}, {type(e).__name__}{extra}")
        return jsonify({
            "ok": True,
            "message": f"Saved by {user}, but Caddy did not confirm the reload in time. Check the Status panel.",
            "content": content,
            "version": new_version,
        })
    finally:
        invalidate_servers_cache()

    if resp.status_code == 200:
        log_action(f"{source}_reload", user, f"backup={backup_name}{extra}")
        return jsonify({
            "ok": True,
            "message": f"Saved and reloaded by {user}",
            "content": content,
            "version": new_version,
        })

    # Caddy refused it (runtime-only problems that `caddy validate` can't see,
    # like a port already in use). Put the previous file back so a container
    # restart doesn't load a config Caddy just rejected.
    rolled_back = False
    if backup_name:
        with caddyfile_lock():
            try:
                shutil.copy2(os.path.join(BACKUP_DIR, backup_name), CADDYFILE)
                rolled_back = True
            except OSError:
                pass
    log_action(f"{source}_reload_failed", user, f"rolled_back={rolled_back}, {resp.text[:160]}")
    where = "on-disk config restored" if rolled_back else "on-disk config NOT restored"
    return jsonify({
        "ok": False,
        "message": f"Caddy rejected the config ({where}): {resp.text}",
        "version": previous_version if rolled_back else new_version,
    }), 500


@editor_bp.route("/")
@login_required
def index():
    return render_template("index.html", csrf_token=get_or_create_csrf())


@editor_bp.route("/health")
def health():
    return jsonify({"status": "ok"}), 200


@editor_bp.route("/api/me")
@login_required
def me():
    return jsonify({**session["user"], "csrf_token": get_or_create_csrf()})


@editor_bp.route("/api/caddyfile", methods=["GET"])
@login_required
def get_caddyfile():
    try:
        with open(CADDYFILE) as f:
            content = f.read()
    except OSError as e:
        return jsonify({
            "error": f"Cannot read {CADDYFILE}: {e.strerror or e}",
        }), 500
    return jsonify({"content": content, "version": _version(content)})


@editor_bp.route("/api/fmt", methods=["POST"])
@login_required
def fmt():
    data = request.get_json(silent=True) or {}
    content = data.get("content", "")
    formatted = caddy_fmt(content)
    return jsonify({"content": formatted, "changed": formatted != content})


@editor_bp.route("/api/validate", methods=["POST"])
@login_required
def validate():
    data = request.get_json(silent=True) or {}
    content = data.get("content", "")

    formatted = caddy_fmt(content)
    warnings = smart_validate(formatted)
    is_valid, message = caddy_validate(formatted)

    if not is_valid:
        return jsonify({"valid": False, "message": message, "warnings": [], "formatted": None})

    if warnings:
        return jsonify({"valid": True, "message": "Caddy valid, but check warnings", "warnings": warnings, "formatted": formatted if formatted != content else None})

    return jsonify({"valid": True, "message": "Config is valid", "warnings": [], "formatted": formatted if formatted != content else None})


@editor_bp.route("/api/save", methods=["POST"])
@login_required
def save():
    data = request.get_json(silent=True) or {}
    content = data.get("content", "")
    client_version = data.get("version")
    user = session.get("user", {}).get("email", "unknown")

    # Cheap early conflict check so the user isn't kept waiting through fmt and
    # validate only to be told to reload. The authoritative check happens again
    # under the file lock in _apply_config.
    if client_version is not None:
        current = _current_file_version()
        if current and client_version != current:
            log_action("save_conflict", user, f"client={client_version} disk={current}")
            return jsonify({
                "ok": False,
                "conflict": True,
                "message": "The Caddyfile changed on disk since you loaded it. Reload to get the latest version before saving.",
                "version": current,
            }), 409

    content = caddy_fmt(content)

    is_valid, message = caddy_validate(content)
    if not is_valid:
        log_action("save_failed", user, message[:200])
        return jsonify({"ok": False, "message": f"Invalid config: {message}"}), 400

    return _apply_config(content, user, "save", expected_version=client_version)


@editor_bp.route("/api/backups", methods=["GET"])
@login_required
def list_backups():
    return jsonify({"backups": list_backup_names()[:20]})


@editor_bp.route("/api/backups/<name>", methods=["GET"])
@login_required
def get_backup(name):
    path = _backup_path(name)
    if not path:
        return jsonify({"error": "not found"}), 404
    with open(path) as f:
        return jsonify({"content": f.read()})


@editor_bp.route("/api/backups/<name>", methods=["DELETE"])
@login_required
def delete_backup(name):
    path = _backup_path(name)
    if not path:
        return jsonify({"error": "not found"}), 404
    user = session.get("user", {}).get("email", "unknown")
    os.remove(path)
    safe_name = os.path.basename(path)
    log_action("backup_deleted", user, safe_name)
    return jsonify({"ok": True, "message": f"Deleted {safe_name}"})


@editor_bp.route("/api/backups/<name>/restore", methods=["POST"])
@login_required
def restore_backup(name):
    """Restore a backup to the live Caddyfile and reload Caddy in one step."""
    path = _backup_path(name)
    if not path:
        return jsonify({"error": "not found"}), 404
    safe_name = os.path.basename(path)

    user = session.get("user", {}).get("email", "unknown")
    with open(path) as f:
        content = f.read()

    content = caddy_fmt(content)
    is_valid, message = caddy_validate(content)
    if not is_valid:
        log_action("restore_failed", user, f"{safe_name}: {message[:160]}")
        return jsonify({"ok": False, "message": f"Backup is not valid, not restored: {message}"}), 400

    return _apply_config(content, user, "restore", detail=f"from={safe_name}")


@editor_bp.route("/api/logs", methods=["GET"])
@login_required
def get_logs():
    """Tail the Caddy log file for the Logs panel (polled by the client).

    Pass ?pos=<byte-offset> to fetch only new content since the last poll.
    Without pos, returns roughly the last 8 KB. Only complete lines are
    returned; a partially written last line is left for the next poll.
    """
    path = CADDY_LOG_FILE
    if not os.path.isfile(path):
        return jsonify({"exists": False, "path": path, "lines": [], "pos": 0})

    size = os.path.getsize(path)
    pos = request.args.get("pos", type=int)

    MAX_CHUNK = 131072  # 128 KB cap per poll
    if pos is None or pos < 0 or pos > size:
        # First poll, or the file was rotated/truncated: start near the end.
        start = max(0, size - 8192)
    else:
        start = pos
    if size - start > MAX_CHUNK:
        start = size - MAX_CHUNK
    resumed = pos is not None and start == pos

    with open(path, "rb") as f:
        f.seek(start)
        chunk = f.read(size - start)

    cut = chunk.rfind(b"\n")
    if cut == -1:
        # No complete line yet; don't advance so the next poll picks it up.
        return jsonify({"exists": True, "path": path, "lines": [], "pos": start, "size": size})
    new_pos = start + cut + 1
    lines = chunk[:cut + 1].decode("utf-8", errors="replace").splitlines()
    # If we didn't resume exactly where the client left off we started mid-line.
    if not resumed and start > 0 and lines:
        lines = lines[1:]

    return jsonify({"exists": True, "path": path, "lines": lines, "pos": new_pos, "size": size})


@editor_bp.route("/api/logs/ping", methods=["POST"])
@login_required
def ping_caddy():
    """Hit Caddy's HTTP port to generate an access log entry for testing.

    Sends a request with a matching Host header so it routes through a site
    block that has the access_log import (generating a real log entry).
    """
    host = urlparse(CADDY_API_URL).hostname or "caddy"
    port, site_host = 80, None
    for srv in get_servers().values():
        if not isinstance(srv, dict):
            continue
        for listen in srv.get("listen", []) or []:
            # Prefer a plain-HTTP listener; ":443" needs TLS we can't speak here.
            p = str(listen).rsplit(":", 1)[-1]
            if p.isdigit() and p != "443":
                port = int(p)
        for route in srv.get("routes", []) or []:
            for match in (route.get("match", []) or []) if isinstance(route, dict) else []:
                hosts = match.get("host", []) if isinstance(match, dict) else []
                if hosts and not site_host:
                    site_host = hosts[0]
    headers = {"Host": site_host} if site_host else {}
    try:
        http_client.get(f"http://{host}:{port}", timeout=3, allow_redirects=False, headers=headers)
    except Exception:
        pass
    return jsonify({"ok": True})


@editor_bp.route("/api/snippets", methods=["GET"])
@login_required
def get_snippets():
    snippets_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "snippets.json")
    with open(snippets_path) as f:
        snippets = json.load(f)
    return jsonify({"snippets": snippets})
