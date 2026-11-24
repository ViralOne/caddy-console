import hashlib
import json
import logging
import os
import re
import shutil
import stat
import tempfile
import threading
from datetime import datetime
from urllib.parse import urlparse

import requests as http_client
from flask import Blueprint, jsonify, render_template, request, session

from .. import config, locks
from ..audit import log_action
from ..auth import get_or_create_csrf, login_required
from ..bans import lapi as bans_lapi, render as bans_render, scan as bans_scan, txn as bans_txn
from ..bans import cfranges as bans_cfranges, plugin as bans_plugin, profile as bans_profile, protected as bans_protected
from ..caddy_api import get_servers, invalidate_servers_cache
from ..config import (
    APP_VERSION,
    AUTH_MODE,
    BACKUP_DIR,
    BACKUP_KEEP,
    BACKUP_PREFIX,
    CADDY_API_URL,
    CADDYFILE,
    SESSION_TIMEOUT_HOURS,
)
from ..validator import caddy_check, caddy_fmt, caddy_validate, fmt_warning, smart_validate, upstream_resolve_warnings


editor_bp = Blueprint("editor", __name__)


def _version(content: str) -> str:
    """Short content hash used for optimistic-locking on save."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


def _current_file_version() -> str:
    try:
        with open(CADDYFILE, encoding="utf-8", newline="") as f:
            return _version(f.read())
    except OSError:
        return ""


# --- Caddyfile write lock ---------------------------------------------------------
#
# Save requests can land on different gunicorn workers and threads, so the
# version check and the write have to happen under one lock or two editors can
# both pass the check and both write. src/locks.py: a threading.Lock, then a
# container-local flock (decides), then the BACKUP_DIR flock (best effort
# across containers; on some bind mounts it does not exclude).


class CaddyfileLockError(RuntimeError):
    """The required mutation lock is unavailable."""


_LOCK_PATH = os.path.join(BACKUP_DIR, ".lock")
_THREAD_LOCK = threading.Lock()


def caddyfile_lock():
    """Lock for every Caddyfile mutation. Not re-entrant: never nest it.

    Correctness depends on this lock spanning the disk write, Caddy reload and
    any rollback. If the container-local lock cannot be created or acquired,
    fail closed.
    """
    return locks.mutation_lock("caddyfile.lock", _LOCK_PATH, _THREAD_LOCK, CaddyfileLockError)


def ensure_caddyfile_lock_available() -> None:
    """Fail application startup when cross-process mutation locking is unavailable."""
    with caddyfile_lock():
        pass


def _fsync_directory(directory: str) -> None:
    """Best-effort directory flush after an atomic replace.

    The replacement has already happened when this runs, so a filesystem that
    rejects directory fsync must not turn a successful write into a false
    `saved: false` response or prevent the matching reload.
    """
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(directory, flags)
    except OSError:
        return
    try:
        try:
            os.fsync(fd)
        except OSError:
            pass
    finally:
        os.close(fd)


def _write_caddyfile(content: str) -> None:
    """Atomically replace the Caddyfile with fully flushed UTF-8 content.

    Deployment mounts the containing directory, not the file itself, so the
    temporary file and destination share a filesystem and os.replace() is
    atomic. Readers see either the complete old file or the complete new file.
    """
    directory = os.path.dirname(CADDYFILE) or "."
    basename = os.path.basename(CADDYFILE)
    try:
        mode = stat.S_IMODE(os.stat(CADDYFILE).st_mode)
    except OSError:
        mode = 0o644

    fd, tmp = tempfile.mkstemp(dir=directory, prefix=f".{basename}.", suffix=".tmp")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            fd = -1
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, CADDYFILE)
        _fsync_directory(directory)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.remove(tmp)
        except FileNotFoundError:
            pass


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


def _reconcile_bans() -> None:
    """A successful /load of the on-disk Caddyfile also loaded the managed ban
    policy on disk; settle a pending ban transaction to match (src/bans/txn.py).
    Runs inside _apply_config's caddyfile_lock() section, which is not
    re-entrant, so nothing here may take the lock again."""
    if not config.BANS_ENABLED:
        return
    try:
        bans_txn.reconcile_after_external_reload()
    except Exception:  # noqa: BLE001 - ban bookkeeping must never fail a save
        logging.getLogger(__name__).exception("IP bans: reconciling after a reload failed")


def _apply_config(content: str, user: str, source: str, expected_version: str | None = None, detail: str = ""):
    """Atomically persist and reload one Caddyfile change under one lock.

    `content` must already be formatted and checked. The cross-process lock spans
    the version check, backup, atomic write, blocking Caddy /load request and any
    rollback, so two workers cannot reorder disk and running configurations.

    A transport failure cannot prove whether Caddy applied the request. In that
    case the complete file remains on disk, but the response is explicitly not
    successful and reports the reload state as failed or unknown.
    """
    new_version = _version(content)
    extra = f", {detail}" if detail else ""

    with caddyfile_lock():
        try:
            with open(CADDYFILE, encoding="utf-8", newline="") as f:
                previous_content = f.read()
            had_previous = True
        except FileNotFoundError:
            previous_content = ""
            had_previous = False
        except (OSError, UnicodeError) as e:
            return jsonify({"ok": False, "message": f"Cannot read {CADDYFILE}: {e}"}), 500

        current = _version(previous_content) if had_previous else ""
        if expected_version is not None and current and expected_version != current:
            log_action("save_conflict", user, f"client={expected_version} disk={current}")
            return jsonify({
                "ok": False,
                "conflict": True,
                "message": "The Caddyfile changed on disk since you loaded it. Reload to get the latest version before saving.",
                "version": current,
            }), 409

        previous_version = current
        try:
            backup_name = _make_backup()
            _write_caddyfile(content)
            prune_backups()
        except OSError as e:
            log_action(f"{source}_write_failed", user, f"{type(e).__name__}: {e}{extra}")
            return jsonify({
                "ok": False,
                "saved": False,
                "reload_status": "not_attempted",
                "message": f"Could not atomically write the Caddyfile: {e}",
                "version": previous_version,
            }), 500

        try:
            resp = http_client.post(
                f"{CADDY_API_URL}/load",
                data=content.encode("utf-8"),
                headers={"Content-Type": "text/caddyfile"},
                timeout=10,
            )
        except http_client.ConnectTimeout as e:
            log_action(f"{source}_no_reload", user,
                       f"backup={backup_name}, {type(e).__name__}{extra}")
            return jsonify({
                "ok": False,
                "saved": True,
                "reload_status": "failed",
                "message": f"Saved to disk by {user}, but a connection to Caddy could not be established.",
                "content": content,
                "version": new_version,
            }), 503
        except http_client.RequestException as e:
            # Connection resets and read timeouts can happen after Caddy accepts
            # the body. Rolling back the file could create a disk/running mismatch.
            log_action(f"{source}_reload_unknown", user,
                       f"backup={backup_name}, {type(e).__name__}{extra}")
            return jsonify({
                "ok": False,
                "saved": True,
                "reload_status": "unknown",
                "message": f"Saved to disk by {user}, but Caddy did not confirm the reload. Verify the running configuration before another change.",
                "content": content,
                "version": new_version,
            }), 504
        finally:
            invalidate_servers_cache()

        if resp.status_code == 200:
            _reconcile_bans()
            log_action(f"{source}_reload", user, f"backup={backup_name}{extra}")
            return jsonify({
                "ok": True,
                "saved": True,
                "reload_status": "applied",
                "message": f"Saved and reloaded by {user}",
                "content": content,
                "version": new_version,
            })

        # Caddy guarantees that a rejected /load leaves its previous running
        # configuration active. Restore the matching disk state atomically.
        rolled_back = False
        try:
            if had_previous:
                _write_caddyfile(previous_content)
            else:
                os.remove(CADDYFILE)
                _fsync_directory(os.path.dirname(CADDYFILE) or ".")
            rolled_back = True
        except OSError as e:
            log_action(f"{source}_rollback_failed", user,
                       f"backup={backup_name}, {type(e).__name__}: {e}{extra}")

        error_text = (resp.text or "Caddy rejected the configuration")[:2000]
        log_action(f"{source}_reload_failed", user,
                   f"rolled_back={rolled_back}, {error_text[:160]}{extra}")
        where = "on-disk config restored" if rolled_back else "on-disk config NOT restored"
        return jsonify({
            "ok": False,
            "saved": not rolled_back,
            "reload_status": "rejected",
            "message": f"Caddy rejected the config ({where}): {error_text}",
            "content": content if not rolled_back else None,
            "version": previous_version if rolled_back else new_version,
        }), 500


# Every view is the same document; the client reads location.pathname to decide
# which one to show. Listed explicitly rather than with a catch-all so an unknown
# path still 404s instead of silently rendering the app.
@editor_bp.route("/")
@editor_bp.route("/editor")
@editor_bp.route("/explore")
@login_required
def index():
    return render_template("index.html", csrf_token=get_or_create_csrf(), bans_enabled=config.BANS_ENABLED)


@editor_bp.route("/health")
def health():
    return jsonify({"status": "ok"}), 200


@editor_bp.route("/api/me")
@login_required
def me():
    """Identity plus how it was established, for the account menu.

    Session lifetime differs by mode: login_required enforces
    SESSION_TIMEOUT_HOURS only for google, while cloudflare returns early and
    Access owns the session. Reporting an expiry in cloudflare mode would be a
    number this app does not control, so it is null there.
    """
    expires_at = None
    if AUTH_MODE == "google":
        login_time = session.get("login_time")
        if login_time:
            expires_at = login_time + SESSION_TIMEOUT_HOURS * 3600
    return jsonify({
        **session["user"],
        "csrf_token": get_or_create_csrf(),
        "auth_mode": AUTH_MODE,
        "session_expires_at": expires_at,
        "version": APP_VERSION,
    })


@editor_bp.route("/api/caddyfile", methods=["GET"])
@login_required
def get_caddyfile():
    try:
        with open(CADDYFILE, encoding="utf-8", newline="") as f:
            content = f.read()
    except (OSError, UnicodeError) as e:
        return jsonify({
            "error": f"Cannot read {CADDYFILE}: {getattr(e, 'strerror', None) or e}",
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

    # Every check runs on `content`, the text the editor shows, so each
    # "Line N" (ours and Caddy's) points at the editor's line. Formatting only
    # changes whitespace, which never changes validity, but it can collapse
    # blank lines and shift every line after them. `formatted` is still
    # returned so Check can apply it.
    formatted = caddy_fmt(content)
    is_valid, message, check_level = caddy_check(content)

    if not is_valid:
        return jsonify({"valid": False, "message": message, "warnings": [],
                        "formatted": None, "check_level": check_level})

    warnings = [w for w in (fmt_warning(content, formatted),) if w]
    warnings += smart_validate(content)
    warnings += upstream_resolve_warnings(content)
    if config.BANS_ENABLED:
        mgmt = bans_scan.management_hosts(content, bans_scan.console_host())
        manual_path = bans_render.SOURCES["manual"].path
        warnings += bans_scan.bans_warnings(content, manual_path, mgmt)
        if bans_lapi.url():
            warnings += bans_scan.bans_warnings(content, bans_render.SOURCES["crowdsec"].path, mgmt,
                                                label="CrowdSec ban list", short="the CrowdSec ban list",
                                                after=tuple(bans_render.SOURCES[n].path for n in bans_render.AFTER["crowdsec"]),
                                                reserved=False)
        try:
            prof = bans_profile.load()
        except bans_profile.Corrupt:
            prof = bans_profile.default()
        warnings += bans_scan.trust_warnings(content, prof.mode, prof.tunnel_only)
        warnings += bans_scan.bans_warnings(content, bans_render.COUNTRY.path, mgmt, label="country policy",
                                            short="the country policy", reserved=False,
                                            after=tuple(bans_render.SOURCES[n].path for n in bans_render.COUNTRY_AFTER))
        if "crowdsec" in content.lower():
            warnings += bans_scan.plugin_warnings(
                content, bans_render.PLUGIN.path, mgmt, placeholder=bans_plugin.api_key_placeholder(),
                crowdsec_path=bans_render.SOURCES["crowdsec"].path)

    return jsonify({"valid": True,
                    "message": "Caddyfile check passed, but review warnings" if warnings else message,
                    "warnings": warnings,
                    "formatted": formatted if formatted != content else None,
                    "check_level": check_level})


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
    exposed = bans_plugin.admin_guard(content)
    if exposed:
        log_action("save_refused", user, "admin bind would expose the Caddy admin API")
        return jsonify({"ok": False, "code": "admin_exposed", "message": f"Not saved: {exposed}"}), 409

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
    exposed = bans_plugin.admin_guard(content)
    if exposed:
        log_action("save_refused", user, f"{safe_name}: admin bind")
        return jsonify({"ok": False, "code": "admin_exposed", "message": f"Not saved: {exposed}"}), 409

    data = request.get_json(silent=True) or {}
    expected_version = data.get("version") if isinstance(data, dict) else None
    return _apply_config(
        content,
        user,
        "restore",
        expected_version=expected_version,
        detail=f"from={safe_name}",
    )


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
    if not config.BANS_ENABLED:
        return jsonify({"snippets": [s for s in snippets if "BANS_ENABLED" not in s.get("prerequisites", [])],
                        "context": {}})
    try:
        with open(CADDYFILE, encoding="utf-8", newline="") as f:
            text = f.read()
    except (OSError, UnicodeError):
        text = ""
    crowdsec = bool(bans_lapi.url())
    from ..bans import service as bans_service           # service imports this module; keep it lazy
    plugin_ctx = bans_service.plugin_snippet_context(text) if crowdsec else None
    mode = bans_plugin.key_mode()

    def offered(s):
        pre = s.get("prerequisites", [])
        if "CROWDSEC_URL" in pre and not crowdsec:
            return False
        if "CROWDSEC_PLUGIN" in pre and plugin_ctx is None:
            return False
        return s.get("key_mode") in (None, mode)
    snippets = [s for s in snippets if offered(s)]
    client_ip = bans_service.client_ip_snippet_context()
    bans_dir = config.BANS_DIR.rstrip("/")
    for s in snippets:
        if s.get("phase"):
            s["code"] = s["code"].replace("/etc/caddy/console/", bans_dir + "/")
        if s.get("id") == "crowdsec-plugin-global-file":
            s["code"] = s["code"].replace(bans_plugin.DEFAULT_KEY_FILE, bans_plugin.key_file())
        elif s.get("id") == "cloudflare-origin-guard":
            s["code"] = s["code"].replace(" ".join(bans_cfranges.BUNDLED["v4"] + bans_cfranges.BUNDLED["v6"]),
                                          " ".join(client_ip["ranges"]) or " ".join(bans_cfranges.BUNDLED["v4"]
                                                                                    + bans_cfranges.BUNDLED["v6"]))
        elif s.get("id") == "crowdsec-plugin-allowlist":
            s["code"] = bans_plugin.allowlist_commands(
                bans_protected.build(never=bans_service.never_networks(), docker=bans_protected.read_docker_networks()))
    return jsonify({"snippets": snippets, "context": {
        "bans_dir": bans_dir,
        "crowdsec": crowdsec,
        "management_hosts": sorted(bans_scan.management_hosts(text, bans_scan.console_host())),
        "plugin": plugin_ctx,
        "client_ip": client_ip,
    }})
