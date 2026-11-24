"""IP-ban operations behind the Security API (spec 1.5-1.8).

Every write: availability() -> caddyfile_lock() -> txn.resolve_pending() ->
load state -> build every candidate in memory -> txn.apply_locked().
availability() takes the lock for its probe, so it is never called while the
lock is held (flock is per fd, not re-entrant).
"""
import ipaddress
import json
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass, field

from .. import audit, config
from ..geoip import geoip
from ..routes.editor import caddyfile_lock
from . import addr, detect, fsio, protected, render, scan, store, txn
from . import caddy as caddy_admin

AVAILABLE_TTL = 300.0
UNAVAILABLE_TTL = 30.0
# Unavailable for a reason only an operator fixes (mount, permission, path):
# the background tick reuses the cached result this long instead of writing a
# probe and POSTing /adapt every tick. The Security view keeps UNAVAILABLE_TTL,
# so a fixed mount shows up as soon as someone looks.
BACKGROUND_UNAVAILABLE_TTL = AVAILABLE_TTL
RESET_SOURCES = ("manual", "crowdsec", "country", "cloudflare")
RECOVERY_ACTIONS = ("use_candidate", "use_previous", "restore_backup")
PROBE_VAR = "caddy_console_probe"
EXPIRED_AUDIT_MAX = 20
log = logging.getLogger(__name__)
_lock = threading.Lock()
_cache = {}
_CORE = protected.build()


class BanError(Exception):
    def __init__(self, code, message, http_status=400, audit_events=(), **extra):
        super().__init__(message)
        self.code, self.http_status, self.audit_events, self.extra = code, http_status, list(audit_events), extra


@dataclass
class Mutation:
    body: dict = field(default_factory=dict)
    status: int = 200
    audit: list = field(default_factory=list)


@dataclass(frozen=True)
class Availability:
    ok: bool
    code: object = None
    message: object = None


def _error(code, message, status, **extra):
    return {"ok": False, "code": code, "message": message, **extra}, status


def _outcome_body(o):
    return {"ok": o.ok, "code": o.code, "message": o.message,
            "reload_status": o.reload_status, "enforcement": o.enforcement}


def reset_caches() -> None:
    with _lock:
        _cache.clear()


def never_networks():
    with _lock:
        if "never" not in _cache:
            _cache["never"] = protected.parse_never(config.BANS_NEVER)
        return _cache["never"]


def init_config() -> None:
    """create_app() calls this: an invalid BANS_NEVER token refuses startup."""
    try:
        never_networks()
    except protected.ConfigError as e:
        raise RuntimeError(f"BANS_NEVER has an {e}") from e


# --- availability (spec 1.1) ------------------------------------------------------

def _path_problem():
    caddy_dir = os.path.dirname(os.path.abspath(config.CADDYFILE))
    bans_dir = os.path.abspath(config.BANS_DIR)
    if bans_dir == caddy_dir or os.path.commonpath([caddy_dir, bans_dir]) != caddy_dir:
        return Availability(False, "bans_dir_outside",
                            f"BANS_DIR ({bans_dir}) must be a directory inside {caddy_dir}, "
                            "the directory that holds the Caddyfile and is mounted into Caddy.")
    current = caddy_dir
    for part in os.path.relpath(bans_dir, caddy_dir).split(os.sep):
        current = os.path.join(current, part)
        if os.path.islink(current):
            return Availability(False, "bans_dir_symlink", f"{current} is a symlink; BANS_DIR must not traverse one.")
    try:
        os.makedirs(bans_dir, mode=0o755, exist_ok=True)
        os.remove(fsio.write_temp(bans_dir, "write-check", b"", 0o600))
    except OSError as e:
        return Availability(False, "bans_dir_not_writable",
                            f"The console cannot write to {bans_dir} ({e.strerror or e}). "
                            "Mount the Caddyfile directory read-write in the console container.")
    return None


def _probe_seen(node, token) -> bool:
    """Is there a `vars` handler carrying this probe's token in the adapted config?"""
    stack = [node]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if node.get("handler") == "vars" and str(node.get(PROBE_VAR)) == token:
                return True
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return False


def _probe() -> Availability:
    """Ask Caddy to adapt a throwaway site that imports a file in BANS_DIR by its
    absolute path. The file is hidden and not *.caddy, so no site's ban import
    glob can pick it up; txn._sweep_orphans removes one left by a crash. The
    caller holds caddyfile_lock(). The token starts with a letter so Caddy keeps
    it a string (vars values that look numeric are adapted as numbers)."""
    token = "p" + secrets.token_hex(8)
    path = os.path.join(config.BANS_DIR, f".console-probe-{token}.probe")
    glob = os.path.join(config.BANS_DIR, f".console-probe-{token}*.probe")
    text = f"http://caddy-console-probe.invalid {{\n\timport {glob}\n}}\n"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(f"vars {PROBE_VAR} {token}\n")
        try:
            result = caddy_admin.adapt(text)
        finally:
            os.remove(path)
    except caddy_admin.CaddyUnavailable:
        return Availability(False, "caddy_unreachable",
                            "The Caddy admin API is unreachable, so the managed directory cannot be verified yet.")
    except OSError as e:
        return Availability(False, "bans_dir_not_writable", f"Writing a probe file failed ({e.strerror or e}).")
    if result.ok and _probe_seen(result.config, token):
        return Availability(True)
    return Availability(False, "caddy_cannot_see_bans_dir",
                        f"Caddy cannot read {config.BANS_DIR}. Mount the same host directory at the same "
                        "path in the Caddy container (read-only is enough).")


def _ttl(result, background) -> float:
    if result.ok:
        return AVAILABLE_TTL
    if background and result.code != "caddy_unreachable":
        return BACKGROUND_UNAVAILABLE_TTL
    return UNAVAILABLE_TTL


def availability(force=False, background=False) -> Availability:
    """background: the expiry tick, which tolerates an older configuration
    failure (see BACKGROUND_UNAVAILABLE_TTL). An unreachable Caddy is still
    re-checked on the short cache, so expiry resumes soon after it returns."""
    now = time.monotonic()
    with _lock:
        hit = _cache.get("availability")
        if hit and not force and now - hit[1] < _ttl(hit[0], background):
            return hit[0]
    result = _path_problem()
    if result is None:
        with caddyfile_lock():
            result = _probe()
    with _lock:
        _cache["availability"] = (result, time.monotonic())
    return result


# --- building blocks ----------------------------------------------------------------

def _verified_client(remote_addr):
    """Trust profile `direct`: only the TCP peer is verified. Behind cloudflared
    or a front proxy that peer is a private Docker address, already protected,
    so nothing is registered; operators put their WAN address in BANS_NEVER."""
    ip = addr.client_address(remote_addr)
    if ip is None or _CORE.overlap(ipaddress.ip_network(ip)) is not None:
        return None
    return ip


def protected_for(state, client=None):
    management = store.management_networks(state)
    if client is not None:
        management.append(ipaddress.ip_network(client))
    return protected.build(never=never_networks(), management=management,
                           docker=protected.read_docker_networks())


def _holds(state) -> dict:
    """Sources whose file differs from the hash recorded at their last render:
    an out-of-band recovery override (spec 1.6). Not regenerated until Re-apply."""
    out = {}
    for name, src in render.SOURCES.items():
        recorded = state.last_rendered_hashes.get(src.filename)
        actual = fsio.sha256_tag(fsio.read_bytes(src.path))
        if recorded != actual:
            out[name] = "missing" if actual is None else "differs"
    return out


def _candidates(state, prot, holds, now) -> list:
    changes, owns = [], []
    for name, src in render.SOURCES.items():
        if name in holds:
            continue
        data = render.render_policy(src, render.effective_prefixes(state.records, now, name),
                                    prot.exclusion_tokens(), config.BANS_MAX)
        state.last_rendered_hashes[src.filename] = fsio.sha256_tag(data)
        changes.append(txn.Change(src.path, "policy", data, marker=src.marker))
        owns.append(src.filename)
    changes.append(txn.Change(store.STATE_PATH, "state", store.dumps(state), owns=tuple(owns)))
    return changes


def _corrupt_version(e) -> str:
    return fsio.sha256_tag(e.raw or b"")[7:23]


def _expired_events(removed) -> list:
    """ban_expired audit events, bounded so a mass expiry stays one transaction."""
    events = [("ban_expired", f"{r.value} id={r.id}") for r in removed[:EXPIRED_AUDIT_MAX]]
    if len(removed) > EXPIRED_AUDIT_MAX:
        events.append(("ban_expired", f"and {len(removed) - EXPIRED_AUDIT_MAX} more"))
    return events


def _after_commit(corrupt) -> None:
    """Under the lock, once a change committed: keep the bans.json just
    committed as a restore choice (spec 1.6), so a later corruption loses
    nothing, and clear a corrupt-state report it replaced."""
    try:
        store.save_snapshot(fsio.read_bytes(store.STATE_PATH))
    except OSError as e:
        log.warning("Could not keep a bans.json snapshot: %s", e)
    if corrupt:
        store.clear_error()


def _transact(actor, client, mutate, *, source="manual", force=(), allow_corrupt=False, force_reload=False):
    """mutate(state, now, version) edits state in place and returns a Mutation,
    or raises BanError. Everything between load and apply runs under the lock.
    The mutation's audit events travel in the transaction journal, so txn
    writes them exactly when (and if) the change commits."""
    avail = availability()
    if not avail.ok:
        return _error("bans_unavailable", avail.message, 503, reason=avail.code)
    with caddyfile_lock():
        pending = txn.resolve_pending()
        if pending is not None:
            return _error("state_degraded", pending.message, 503, recovery=True)
        corrupt = None
        try:
            state = store.load()
        except store.StateCorrupt as e:
            store.quarantine(e.raw, str(e))
            if not allow_corrupt:
                return _error("state_degraded", f"{e}. The last generated policy stays enforced; "
                              "open Security to recover.", 503, recovery=True)
            corrupt, state = e, store.State()
        version = _corrupt_version(corrupt) if corrupt else state.version
        holds = {} if corrupt else {k: v for k, v in _holds(state).items() if k not in force}
        now = store.utc_now()
        expired = store.prune_expired(state, now, sources=[n for n in render.SOURCES if n not in holds])
        store.prune_management(state, now)
        store.touch_management(state, client, "direct", now)
        try:
            result = mutate(state, now, version)
            changes = _candidates(state, protected_for(state), holds, now)
        except BanError as e:
            for action, detail in e.audit_events:
                audit.log_action(action, actor, detail)
            return _error(e.code, str(e), e.http_status, **e.extra)
        except render.CapacityError as e:
            return _error("capacity_exceeded", f"This would render {e.count} prefixes; the limit (BANS_MAX) "
                          f"is {e.limit}. Remove or merge bans first.", 409, count=e.count, limit=e.limit)
        outcome = txn.apply_locked(changes, actor=actor, source=source,
                                   audit_events=_expired_events(expired) + result.audit, force_reload=force_reload)
        if outcome.ok:
            _after_commit(corrupt)
    body = {**_outcome_body(outcome), **result.body}
    if outcome.ok and holds:
        body["enforcement"] = "held"
        body["message"] = ("Stored. The ban file differs from the stored state, so it was not regenerated; "
                           "use Re-apply in Security.")
    return body, (result.status if outcome.ok else outcome.http_status)


def _public(r, now, prot) -> dict:
    out = {k: getattr(r, k) for k in ("id", "source", "scope", "value", "reason", "actor",
                                      "created_at", "expires_at", "scenario", "origin")}
    out.update(expired=r.expired(now), protected=prot.overlap(r.network), geo=_geo(r))
    return out


def _geo(r):
    if r.scope != "ip":
        return None
    found = geoip.lookup(r.value) or {}
    loc, asn = found.get("location") or {}, found.get("asn") or {}
    if not loc and not asn:
        return None
    return {"country_code": loc.get("country_code"), "country": loc.get("country"), "asn_org": asn.get("org")}


# --- mutations ------------------------------------------------------------------------

def add_ban(payload, actor, remote_addr):
    if not isinstance(payload, dict):
        return _error("invalid_request", "Send a JSON object.", 400)
    try:
        net = addr.canonical(payload.get("value"))
        duration = store.validate_duration(payload.get("duration"))
        reason = store.validate_reason(payload.get("reason"))
    except (addr.AddressError, store.InputError) as e:
        return _error(e.code, str(e), 400)
    try:
        addr.check_width(net)
    except addr.AddressError as e:
        audit.log_action("ban_refused", actor, f"{addr.token(net)} too wide")
        return _error(e.code, str(e), 400)
    client = _verified_client(remote_addr)
    value = addr.token(net)

    def mutate(state, now, version):
        category = protected_for(state, client).overlap(net)
        if category:
            raise BanError("protected_overlap", f"{value} overlaps a protected range ({protected.LABELS[category]}).",
                           400, [("ban_refused", f"{value} protected={category}")], category=category)
        r = store.new_manual_record(net, duration, reason, actor, now)
        state.records.append(r)
        return Mutation({"record": _public(r, now, protected_for(state))}, 201,
                        [("ban_created", f"{value} {duration} id={r.id}")])
    return _transact(actor, client, mutate)


def remove_ban(record_id, actor, remote_addr):
    def mutate(state, now, version):
        r = next((x for x in state.records if x.id == record_id), None)
        if r is None:
            raise BanError("not_found", "No ban with that ID.", 404)
        if r.source != "manual":
            raise BanError("not_manual", "Only manual bans can be removed here; CrowdSec decisions are read-only.", 403)
        state.records.remove(r)
        still = sorted({x.value for x in state.records if not x.expired(now)
                        and protected.overlaps(x.network, r.network)})
        return Mutation({"removed": r.id, "value": r.value, "still_covered_by": still}, 200,
                        [("ban_removed", f"{r.value} id={r.id}")])
    return _transact(actor, _verified_client(remote_addr), mutate)


def reapply(payload, actor, remote_addr):
    source = payload.get("source", "manual") if isinstance(payload, dict) else None
    if source not in render.SOURCES:
        return _error("invalid_source", "Unknown policy source.", 400)

    def mutate(state, now, version):
        return Mutation({"source": source}, 200, [("bans_reapply", source)])
    # Re-apply also reloads unchanged files: Caddy may never have loaded the
    # policy (an import in an included file, added before the file existed).
    return _transact(actor, _verified_client(remote_addr), mutate, force=(source,), source="reapply",
                     force_reload=True)


def reset(payload, actor, remote_addr):
    if not isinstance(payload, dict):
        return _error("invalid_request", "Send a JSON object.", 400)
    source = payload.get("source")
    if source not in RESET_SOURCES:
        return _error("invalid_source", "source must be manual, crowdsec, country or cloudflare.", 400)
    if source not in render.SOURCES:
        return _error("source_not_enabled", f"The {source} source is not part of this version.", 400)
    if payload.get("confirm") is not True:
        return _error("confirmation_required", "Resetting deletes every manual ban; send confirm: true.", 400)
    expected = payload.get("version")

    def mutate(state, now, version):
        if expected != version:
            raise BanError("version_conflict", "The ban list changed since you loaded it; reload the Security view.", 409)
        removed = [r for r in state.records if r.source == source]
        state.records = [r for r in state.records if r.source != source]
        return Mutation({"removed": len(removed)}, 200, [("bans_reset", f"{source}: removed {len(removed)} records")])
    return _transact(actor, _verified_client(remote_addr), mutate, force=(source,), allow_corrupt=True, source="reset")


# --- reads ------------------------------------------------------------------------------

def list_bans(covering=None):
    try:
        state = store.load()
    except store.StateCorrupt as e:
        return _error("state_degraded", f"{e}. Open Security to recover.", 503, recovery=True)
    now = store.utc_now()
    prot = protected_for(state)
    if covering is not None:
        try:
            ip = addr.canonical(covering)
        except addr.AddressError as e:
            return _error(e.code, str(e), 400)
        if addr.scope_of(ip) != "ip":
            return _error("invalid_ip", "Look up a single IP address.", 400)
        hits = [r for r in state.records if not r.expired(now) and protected.overlaps(r.network, ip)]
        token = addr.token(ip)
        return {"ip": token, "protected": prot.overlap(ip),
                "records": [_public(r, now, prot) for r in hits],
                "exact_ids": [r.id for r in hits if r.source == "manual" and r.value == token]}, 200
    records = sorted(state.records, key=lambda r: r.created_at, reverse=True)
    return {"records": [_public(r, now, prot) for r in records], "state_version": state.version,
            "rendered_prefixes": len(render.effective_prefixes(state.records, now, "manual")),
            "max_prefixes": config.BANS_MAX}, 200


def _rid(*parts) -> str:
    return fsio.sha256_tag("|".join(str(p) for p in parts).encode())[7:23]


def _recovery_info_locked() -> dict:
    base = {"required": True, "phase": None, "backups": [], "reapply": False, "reset": False, "state_version": None}
    pending = txn.resolve_pending()
    if pending is not None:
        j = pending.journal or {}
        return {**base, "kind": "journal", "recovery_id": _rid("journal", j.get("id"), pending.reason),
                "reason": pending.reason, "phase": j.get("phase"), "summary": pending.message,
                "files": [os.path.basename(e["path"]) for e in j.get("entries", [])],
                "actions": ([] if pending.reason in ("journal_corrupt", "hash_mismatch")
                            else ["use_candidate", "use_previous"])}
    try:
        state = store.load()
    except store.StateCorrupt as e:
        store.quarantine(e.raw, str(e))
        backups = store.list_snapshots()
        return {**base, "kind": "state_corrupt", "recovery_id": _rid("state", _corrupt_version(e)),
                "reason": "state_corrupt", "files": ["bans.json"], "backups": backups,
                "summary": f"{e}. The last generated ban policy stays enforced; nothing is regenerated "
                           "until you restore a backup or reset the list.",
                "actions": ["restore_backup"] if backups else [], "reset": True,
                "state_version": _corrupt_version(e)}
    holds = _holds(state)
    if holds:
        return {**base, "kind": "policy_hold", "recovery_id": _rid("hold", sorted(holds.items()), state.version),
                "reason": "policy_differs", "files": [render.SOURCES[n].filename for n in holds], "actions": [],
                "summary": "A managed ban file differs from the stored state, for example after host recovery. "
                           "It is not regenerated and its expiry is paused until you fix the records and Re-apply.",
                "reapply": True, "reset": True, "state_version": state.version}
    return {**base, "required": False, "kind": None, "recovery_id": None, "reason": None, "summary": "",
            "files": [], "actions": [], "state_version": state.version}


def recovery_info() -> dict:
    with caddyfile_lock():
        return _recovery_info_locked()


def recovery_post(payload, actor):
    if not isinstance(payload, dict):
        return _error("invalid_request", "Send a JSON object.", 400)
    action = payload.get("action")
    if action not in RECOVERY_ACTIONS:
        return _error("invalid_action", "Unknown recovery action.", 400)
    with caddyfile_lock():
        info = _recovery_info_locked()
        if not info["required"] or payload.get("recovery_id") != info["recovery_id"]:
            return _error("recovery_stale", "The recovery situation changed; reload the Security view.", 409)
        if action not in info["actions"]:
            return _error("invalid_action", "That action is not available here.", 400)
        if action == "restore_backup":
            backup_id = payload.get("backup_id")
            if backup_id not in {b["id"] for b in info["backups"]}:
                return _error("invalid_backup", "Unknown backup.", 400)
            raw = store.snapshot_bytes(backup_id)
            try:
                if raw is None:
                    raise store.StateCorrupt("the backup file is gone")
                store.parse(raw)
            except store.StateCorrupt as e:
                return _error("invalid_backup", f"That backup is not usable ({e}).", 400)
            outcome = txn.apply_locked([txn.Change(store.STATE_PATH, "state", raw)], actor=actor,
                                       source="recovery", audit_events=[("bans_recovered", action)])
            if outcome.ok:
                store.clear_error()
        else:
            outcome = txn.recovery_action(action, actor)
            if outcome.ok:
                audit.log_action("bans_recovered", actor, action)
    return _outcome_body(outcome), (200 if outcome.ok else outcome.http_status)


def _read_caddyfile() -> str:
    try:
        with open(config.CADDYFILE, encoding="utf-8", newline="") as f:
            return f.read()
    except (OSError, UnicodeError):
        return ""


def _site_rows(live, text, prefixes, held) -> list:
    """prefixes: what the manual policy renders now, or None when unknown (held
    or corrupt state); detection then accepts any managed ban route."""
    src = render.SOURCES["manual"]
    blocks = scan.site_blocks(text)
    management = scan.management_hosts(text, scan.console_host())
    expected = None if held or prefixes is None else [addr.token(p) for p in prefixes]
    live_rows = detect.site_statuses(live, src, bool(prefixes), expected_ranges=expected) if live is not None else []
    rows, seen = [], set()
    for s in live_rows:
        block = next((b for b in blocks if set(b.hosts) & set(s.hosts)), None) if s.hosts \
            else next((b for b in blocks if s.label in b.addresses), None)
        if block is not None:
            seen.add(block.start)
        imp = scan.block_import_state(text, block, src.path) if block else None
        status = s.status
        if set(s.hosts) & management:
            status = _management_status(s.status, imp)
        rows.append({"label": s.label, "hosts": s.hosts, "status": status,
                     "pre_handlers": s.pre_handlers, "detail": s.detail,
                     "source": "main" if block else "external", "line": block.start if block else None,
                     "import": imp})
    for b in blocks:
        if b.start not in seen:
            imp = scan.block_import_state(text, b, src.path)
            rows.append({"label": b.hosts[0] if b.hosts else b.addresses[0], "hosts": b.hosts,
                         "status": _management_status("not_loaded", imp) if set(b.hosts) & management
                         else "not_loaded",
                         "pre_handlers": [], "detail": "This site block is not in Caddy's running configuration.",
                         "source": "main", "line": b.start, "import": imp})
    return rows


def _management_status(live_status, imp) -> str:
    """A console site is only "never banned" while it neither enforces the ban
    list (live) nor imports it (on disk, applied by the next reload). The
    snippet guard is advisory, so a hand-typed import is reported as the
    lockout risk it is, never as safe."""
    if live_status in ("not_imported", "not_loaded") and not (imp and imp.get("present")):
        return "management"
    return "management_imported"


def _last_apply():
    """Newest successful apply, from the audit log (the state file is never
    rewritten after commit, so it cannot carry this)."""
    for path in (config.AUDIT_LOG, audit.rotated_path()):
        for line in reversed(audit.tail_lines(path, 500)):
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict) and entry.get("action") == "bans_policy_applied":
                return {"time": entry.get("time"), "user": entry.get("user"), "detail": entry.get("detail")}
    return None


def status(remote_addr) -> dict:
    avail = availability()
    info = recovery_info()
    try:
        state = store.load()
    except store.StateCorrupt:
        state = None
    now = store.utc_now()
    src = render.SOURCES["manual"]
    prefixes = render.effective_prefixes(state.records, now, "manual") if state else []
    holds = _holds(state) if state else {}
    try:
        live, caddy = caddy_admin.live_config(), {"reachable": True, "message": None}
    except caddy_admin.CaddyUnavailable as e:
        live, caddy = None, {"reachable": False, "message": f"The Caddy admin API is unreachable ({e})."}
    degraded = None
    if info["required"] and info["kind"] in ("journal", "state_corrupt"):
        degraded = {"kind": info["kind"], "reason": info["reason"], "phase": info["phase"], "message": info["summary"]}
    return {
        "enabled": True, "available": avail.ok,
        "unavailable": None if avail.ok else {"code": avail.code, "message": avail.message},
        "state_version": info["state_version"], "degraded": degraded, "recovery": info,
        "sources": {"manual": {
            "file": src.path, "import_line": src.import_line, "hold": "manual" in holds,
            "hold_reason": holds.get("manual"), "rendered_prefixes": len(prefixes),
            "active_records": sum(1 for r in (state.records if state else []) if r.source == "manual" and not r.expired(now)),
        }},
        "protected": protected_for(state or store.State(), _verified_client(remote_addr)).summary(),
        "sites": _site_rows(live, _read_caddyfile(), prefixes if state else None, "manual" in holds),
        "caddy": caddy, "limits": {"max_prefixes": config.BANS_MAX}, "last_apply": _last_apply(),
    }


# --- expiry (spec 1.5 'The expiry cleanup job') -------------------------------------------

def expire_tick(now=None) -> str:
    if not availability(background=True).ok:
        return "unavailable"
    with caddyfile_lock():
        if txn.resolve_pending() is not None:
            return "degraded"
        try:
            state = store.load()
        except store.StateCorrupt as e:
            store.quarantine(e.raw, str(e))
            return "corrupt"
        now = now or store.utc_now()
        holds = _holds(state)
        removed = store.prune_expired(state, now, sources=[n for n in render.SOURCES if n not in holds])
        aged = store.prune_management(state, now)
        if not removed and not aged:
            return "idle"
        try:
            changes = _candidates(state, protected_for(state), holds, now)
        except render.CapacityError:
            return "capacity_exceeded"      # BANS_MAX was lowered below the stored bans; never drop one to fit
        outcome = txn.apply_locked(changes, actor="system", source="expiry", audit_events=_expired_events(removed))
        if outcome.ok:
            _after_commit(None)
    return "applied" if outcome.ok else outcome.code
