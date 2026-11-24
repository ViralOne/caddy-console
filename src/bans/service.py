"""IP-ban operations behind the Security API (spec 1.5-1.8).

Every write: availability() -> caddyfile_lock() -> txn.resolve_pending() ->
load state -> build every candidate in memory -> txn.apply_locked().
availability() takes the lock for its probe, so it is never called while the
lock is held (flock is per fd, not re-entrant).
"""
import collections
import dataclasses
import ipaddress
import json
import logging
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import timedelta

import requests as http_client

from .. import audit, config, locks
from ..geoip import geoip
from ..routes.editor import caddyfile_lock
from . import addr, allowlist, cfranges, country, countrydata, detect, fsio, lapi, lapimachine, plugin, pluginpolicy, profile, protected, render, scan, store, syncstate, txn
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
STALE_POLLS = 3
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
    """create_app() calls this: an invalid BANS_NEVER, CROWDSEC_URL,
    CROWDSEC_ORIGINS, CROWDSEC_PLUGIN_BOUNCER_KEY_FILE or CADDY_ADMIN_ADDRESS
    refuses startup."""
    try:
        never_networks()
    except protected.ConfigError as e:
        raise RuntimeError(f"BANS_NEVER has an {e}") from e
    try:
        lapi.parse_url(config.CROWDSEC_URL)
        lapi.parse_origins(config.CROWDSEC_ORIGINS)
    except lapi.ConfigError as e:
        raise RuntimeError(str(e)) from e
    try:
        plugin.parse_key_file(config.CROWDSEC_PLUGIN_BOUNCER_KEY_FILE)
        plugin.parse_admin_address(config.CADDY_ADMIN_ADDRESS)
    except plugin.ConfigError as e:
        raise RuntimeError(str(e)) from e
    try:
        profile.parse_mode(config.CLIENT_IP_MODE)
    except profile.ConfigError as e:
        raise RuntimeError(str(e)) from e


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
    if lapi.enabled():
        plugin.module_available()            # outside caddyfile_lock(); cached
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


def protected_for(state, client=None, prof=None, allow=None):
    """prof: the profile a transaction is about to commit; default the stored one.
    allow: the never-ban entries about to be committed; default the stored ones.
    Proxied mode adds the Cloudflare edge to the protected set (spec 4.1)."""
    management = store.management_networks(state)
    if client is not None:
        management.append(ipaddress.ip_network(client))
    prof = prof if prof is not None else profile.load_or_default()
    entries = allow if allow is not None else allowlist.load_or_default()
    return protected.build(never=never_networks(), allowlist=allowlist.networks(entries), management=management,
                           docker=protected.read_docker_networks(), profile=prof.protected_networks())


def _profile_active() -> bool:
    """Render cloudflare-trusted-proxies.caddy once a Cloudflare profile is
    configured, or once one left something behind. Direct mode by default
    writes nothing, so it stays independent of Cloudflare."""
    return (config.BANS_ENABLED and (profile.parse_mode(config.CLIENT_IP_MODE) != "direct" or profile.exists()
                                     or os.path.exists(render.PROFILE.path)))


def _profile_changes(prof) -> list:
    data = profile.render(prof)
    prof = dataclasses.replace(prof, last_rendered_hashes={**prof.last_rendered_hashes,
                                                           render.PROFILE.filename: fsio.sha256_tag(data)})
    return [txn.Change(render.PROFILE.path, "policy", data, marker=None),
            txn.Change(profile.PATH, "state", profile.dumps(prof), owns=(render.PROFILE.filename,))]


def _file_hold(recorded, path):
    actual = fsio.sha256_tag(fsio.read_bytes(path))
    if recorded != actual and not (recorded is None and actual is None):
        return "missing" if actual is None else "differs"
    return None


def _holds(state) -> dict:
    """Sources whose file differs from the hash recorded at their last render:
    an out-of-band recovery override (spec 1.6). Not regenerated until Re-apply."""
    out = {}
    for name, src in render.active_sources(state).items():
        recorded = state.last_rendered_hashes.get(src.filename)
        actual = fsio.sha256_tag(fsio.read_bytes(src.path))
        if recorded != actual:
            out[name] = "missing" if actual is None else "differs"
    if _plugin_active():
        hold = _file_hold(pluginpolicy.recorded_hash(), render.PLUGIN.path)
        if hold:
            out["plugin"] = hold
    if _profile_active():
        try:
            recorded = profile.load().last_rendered_hashes.get(render.PROFILE.filename) if profile.exists() else None
        except profile.Corrupt:
            recorded = "corrupt"
        hold = _file_hold(recorded, render.PROFILE.path)
        if hold:
            out["cloudflare"] = hold
    if _country_active():
        try:
            recorded = country.load().last_rendered_hashes.get(render.COUNTRY.filename) if country.exists() else None
        except country.Corrupt:
            recorded = "corrupt"
        hold = _file_hold(recorded, render.COUNTRY.path)
        if hold:
            out["country"] = hold
    return out


def _plugin_active() -> bool:
    """Render the protected route once the running Caddy has the module (with
    CrowdSec configured), or once it left something behind (the file or its
    recorded hash), so a Re-apply still manages it after the plugin is gone.
    Only the cached probe result is used: this runs under caddyfile_lock()."""
    if not config.BANS_ENABLED:
        return False
    return ((lapi.enabled() and plugin.cached_module() is True)
            or os.path.exists(render.PLUGIN.path) or pluginpolicy.exists())


def _plugin_changes(prot) -> list:
    data = render.render_plugin_route(prot.exclusion_tokens())
    return [txn.Change(render.PLUGIN.path, "policy", data, marker=render.PLUGIN.marker),
            txn.Change(pluginpolicy.PATH, "state", pluginpolicy.dumps(fsio.sha256_tag(data)),
                       owns=(render.PLUGIN.filename,))]


def plugin_route_current(state) -> bool:
    """The route file on disk equals what the current protected set renders."""
    want = render.render_plugin_route(protected_for(state).exclusion_tokens())
    return fsio.read_bytes(render.PLUGIN.path) == want


AUX_FILES = {"plugin": render.PLUGIN.filename, "cloudflare": render.PROFILE.filename,
             "country": render.COUNTRY.filename}


def _policy_filename(name) -> str:
    return AUX_FILES.get(name) or render.SOURCES[name].filename


def _route_detail(data: bytes) -> str:
    line = next((l for l in data.decode("ascii").splitlines() if l.strip().startswith("not client_ip ")), "")
    return f"{len(line.split()) - 2} protected ranges, {fsio.sha256_tag(data)[7:19]}"


def _country_changes(policy, prof, prot, strict) -> list:
    """geo.caddy and country-policy.json for `policy` under the profile `prof`.
    strict (an explicit country change) raises country.CountryError; otherwise
    a policy that cannot be rendered now (dataset missing, over the cap, no
    Cloudflare peer) leaves the last good file in place."""
    try:
        data, facts = country.render(policy, prof.mode, prof.peers(), prot.exclusion_tokens())
    except country.CountryError:
        if strict:
            raise
        return []
    policy = dataclasses.replace(
        policy, profile=prof.mode, dataset={"month": facts["month"], "prefixes": facts["prefixes"]},
        last_rendered_hashes={**policy.last_rendered_hashes, render.COUNTRY.filename: fsio.sha256_tag(data)})
    return [txn.Change(render.COUNTRY.path, "policy", data, marker=render.COUNTRY.marker),
            txn.Change(country.PATH, "state", country.dumps(policy), owns=(render.COUNTRY.filename,))]


def _aux_changes(prot, holds, prof=None, with_profile=False, country_candidate=None) -> list:
    """Policies that hold no ban records but repeat the protected set or the
    profile: the plugin route and the trusted proxies file. Each is included
    whenever it is active, so one transaction always carries every dependent
    file (spec 4.2); unchanged bytes are dropped by txn.apply_locked."""
    prof = prof if prof is not None else profile.load_or_default()
    changes = []
    if _plugin_active() and "plugin" not in holds:
        changes += _plugin_changes(prot)
    if (with_profile or _profile_active()) and "cloudflare" not in holds:
        changes += _profile_changes(prof)
    if (country_candidate is not None or _country_active()) and "country" not in holds:
        changes += _country_changes(country_candidate if country_candidate is not None else country.load_or_default(),
                                    prof, prot, strict=country_candidate is not None)
    return changes


def _bans_present(state) -> bool:
    return (state.raw is not None or bool(state.records)
            or any(os.path.exists(src.path) for src in render.active_sources(state).values()))


def _candidates(state, prot, holds, now, *, prof=None, bans=True, with_profile=False, country_candidate=None) -> list:
    """Every active source's candidate policy (held ones excepted) plus the
    state that embeds their hashes, then the record-less policies. Held
    sources still count toward BANS_MAX: their file stays loaded in Caddy.
    Non-local CrowdSec origins do not count here, so they never block a manual
    change (spec 2.5); the CrowdSec sync checks the whole total itself before
    it stores anything. bans=False (a profile or country change on an install
    that never stored a ban) renders only the record-less policies."""
    changes = []
    if bans:
        sources = render.active_sources(state)
        render.check_capacity(render.capacity_counts(state.records, now), config.BANS_MAX)
        owns = []
        for name, src in sources.items():
            if name in holds:
                continue
            data = render.render_policy(src, render.effective_prefixes(state.records, now, name),
                                        prot.exclusion_tokens())
            state.last_rendered_hashes[src.filename] = fsio.sha256_tag(data)
            changes.append(txn.Change(src.path, "policy", data, marker=src.marker))
            owns.append(src.filename)
        changes.append(txn.Change(store.STATE_PATH, "state", store.dumps(state), owns=tuple(owns)))
    return changes + _aux_changes(prot, holds, prof, with_profile, country_candidate)


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


@dataclass
class _Plan:
    """What a locked step wants committed. `context` is handed back to the caller."""
    changes: list
    actor: str
    source: str
    audit_events: list
    force_reload: bool = False
    context: object = None


@dataclass(frozen=True)
class _Refused:
    """A gate of the shared write path refused before anything was written."""
    gate: str                       # unavailable | degraded | corrupt | allowlist_corrupt
    message: str
    reason: object = None


def _locked_transaction(prepare, *, background=False, allow_corrupt=False):
    """The one write path (module docstring): availability() ->
    caddyfile_lock() -> txn.resolve_pending() -> store.load() -> prepare() ->
    txn.apply_locked() -> _after_commit(), all between load and apply under the lock.

    prepare(state, corrupt) edits state in place and returns a _Plan to commit,
    or any other value to stop without writing. corrupt is the StateCorrupt
    replaced by an empty state (allow_corrupt only), else None. Returns
    (refused, value, outcome): a _Refused or None, what prepare returned, and
    the txn Outcome (None when nothing was applied)."""
    avail = availability(background=background)
    if not avail.ok:
        return _Refused("unavailable", avail.message, avail.code), None, None
    with caddyfile_lock():
        pending = txn.resolve_pending()
        if pending is not None:
            return _Refused("degraded", pending.message), None, None
        corrupt = None
        try:
            state = store.load()
        except store.StateCorrupt as e:
            store.quarantine(e.raw, str(e))
            if not allow_corrupt:
                return _Refused("corrupt", str(e)), None, None
            corrupt, state = e, store.State()
        problem = allowlist_problem()
        if problem is not None:
            return _Refused("allowlist_corrupt", problem), None, None
        plan = prepare(state, corrupt)
        if not isinstance(plan, _Plan):
            return None, plan, None
        state_change = next((c for c in plan.changes if c.path == store.STATE_PATH), None)
        state_before = fsio.read_bytes(store.STATE_PATH)
        outcome = txn.apply_locked(plan.changes, actor=plan.actor, source=plan.source,
                                   audit_events=plan.audit_events, force_reload=plan.force_reload)
        # Only a transaction that actually rewrote bans.json with its candidate
        # may snapshot it or clear a corrupt-state report: a profile or country
        # change on a corrupt state leaves bans.json (and its degraded mode)
        # exactly as they were, and so does one whose state bytes were unchanged.
        if (outcome.ok and state_change is not None and state_before != state_change.data
                and fsio.read_bytes(store.STATE_PATH) == state_change.data):
            _after_commit(corrupt)
    return None, plan, outcome


def allowlist_problem():
    """Why allowlist.json cannot be used, or None. While it is corrupt the last
    generated policies stay in place: every policy write is refused."""
    try:
        allowlist.load()
    except allowlist.Corrupt as e:
        return f"{e}. The last generated policies stay enforced; fix or remove the file to resume changes"
    return None


def _transact(actor, client, mutate, *, source="manual", force=(), allow_corrupt=False, force_reload=False,
              affects=("manual",)):
    """mutate(state, now, version) edits state in place and returns a Mutation,
    or raises BanError. Everything between load and apply runs under the lock.
    The mutation's audit events travel in the transaction journal, so txn
    writes them exactly when (and if) the change commits."""
    def prepare(state, corrupt):
        version = _corrupt_version(corrupt) if corrupt else state.version
        holds = {} if corrupt else {k: v for k, v in _holds(state).items() if k not in force}
        now = store.utc_now()
        expired = store.prune_expired(state, now, sources=[n for n in render.active_sources(state) if n not in holds])
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
            parts = ", ".join(f"{n} {c}" for n, c in e.by_source.items())
            return _error("capacity_exceeded", f"This would render {e.count} prefixes ({parts}); the limit "
                          f"(BANS_MAX) is {e.limit}. Remove or merge bans first.", 409, count=e.count,
                          limit=e.limit, by_source=e.by_source)
        return _Plan(changes, actor, source, _expired_events(expired) + result.audit,
                     force_reload=force_reload, context=(result, holds))

    refused, plan, outcome = _locked_transaction(prepare, allow_corrupt=allow_corrupt)
    if refused is not None:
        if refused.gate == "allowlist_corrupt":
            return _refused_error(refused)
        if refused.gate == "unavailable":
            return _error("bans_unavailable", refused.message, 503, reason=refused.reason)
        if refused.gate == "corrupt":
            return _error("state_degraded", f"{refused.message}. The last generated policy stays enforced; "
                          "open Security to recover.", 503, recovery=True)
        return _error("state_degraded", refused.message, 503, recovery=True)
    if outcome is None:
        return plan                         # an error response from prepare
    result, holds = plan.context
    body = {**_outcome_body(outcome), **result.body}
    if outcome.ok and set(holds) & set(affects):
        body["enforcement"] = "held"
        body["message"] = ("Stored. The ban file differs from the stored state, so it was not regenerated; "
                           "use Re-apply in Security.")
    return body, (result.status if outcome.ok else outcome.http_status)


def _public(r, now, prot) -> dict:
    out = {k: getattr(r, k) for k in ("id", "source", "scope", "value", "reason", "actor",
                                      "created_at", "expires_at", "scenario", "origin", "source_id")}
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


def delete_crowdsec_decision(decision_id, actor, remote_addr):
    """Delete one CrowdSec decision in LAPI (machine login), then drop its
    stored record through the shared transaction so bans-crowdsec.caddy
    updates now instead of at the next sync. Only the id of a currently synced
    record is accepted, never an address. No lock is held during the LAPI call."""
    if not lapimachine.valid_decision_id(decision_id):
        return _error("invalid_decision_id", "A CrowdSec decision ID is a positive integer.", 400)
    if not lapi.enabled():
        return _error("crowdsec_not_enabled", "CrowdSec sync is not enabled.", 409)
    creds, problem = lapimachine.read_credentials()
    if creds is None:
        return _error("crowdsec_write_not_configured", problem or "Add CrowdSec machine credentials "
                      "(CROWDSEC_MACHINE_ID and CROWDSEC_MACHINE_PASSWORD) to unban here.", 409)
    try:
        state = store.load()
    except store.StateCorrupt as e:
        return _error("state_degraded", f"{e}. Open Security to recover.", 503, recovery=True)
    if not any(r.source == "crowdsec" and r.source_id == decision_id for r in state.records):
        return _error("decision_not_found", "No synced CrowdSec decision with that ID.", 404)
    gone = False
    try:
        lapimachine.delete_decision(decision_id, creds)
    except lapimachine.DecisionGone:
        gone = True
    except lapi.LapiAuthError as e:
        return _error("crowdsec_auth_failed", f"CrowdSec refused the machine credentials ({e}).", 502)
    except lapi.LapiMalformed as e:
        return _error("crowdsec_bad_response", f"CrowdSec sent an unusable response ({e}).", 502)
    except lapi.LapiUnavailable as e:
        return _error("crowdsec_unreachable", f"CrowdSec is unreachable ({e}).", 503)
    detail = f"id={decision_id}"

    def mutate(st, now, version):
        r = next((x for x in st.records if x.source == "crowdsec" and x.source_id == decision_id), None)
        if r is not None:
            st.records.remove(r)
        return Mutation({"deleted": decision_id, "already_gone": gone}, 200, [("crowdsec_decision_deleted", detail)])
    body, status = _transact(actor, _verified_client(remote_addr), mutate, source="crowdsec_unban",
                             affects=("crowdsec",))
    if status >= 400:                       # deleted in CrowdSec; the sync drops the stored copy
        audit.log_action("crowdsec_decision_deleted", actor, detail)
        return {"ok": True, "code": "deleted_pending_sync", "deleted": decision_id, "already_gone": gone,
                "message": f"Deleted in CrowdSec. The console removes it within {config.BANS_SYNC_INTERVAL} "
                           "seconds."}, 200
    return body, status


def _aux_active(name) -> bool:
    return {"plugin": _plugin_active, "cloudflare": _profile_active, "country": _country_active}[name]()


def reapply(payload, actor, remote_addr):
    source = payload.get("source", "manual") if isinstance(payload, dict) else None
    if source not in render.SOURCES and source not in AUX_FILES:
        return _error("invalid_source", "Unknown policy source.", 400)

    def mutate(state, now, version):
        active = _aux_active(source) if source in AUX_FILES else source in render.active_sources(state)
        if not active:
            raise BanError("source_not_enabled", f"The {source} source is not in use.", 400)
        return Mutation({"source": source}, 200, [("bans_reapply", source)])
    # Re-apply also reloads unchanged files: Caddy may never have loaded the
    # policy (an import in an included file, added before the file existed).
    return _transact(actor, _verified_client(remote_addr), mutate, force=(source,), source="reapply",
                     force_reload=True, affects=(source,))


def reset(payload, actor, remote_addr):
    if not isinstance(payload, dict):
        return _error("invalid_request", "Send a JSON object.", 400)
    source = payload.get("source")
    if source not in RESET_SOURCES:
        return _error("invalid_source", "source must be manual, crowdsec, country or cloudflare.", 400)
    if source in AUX_FILES:
        return _reset_aux(source, payload, actor)
    what = "manual ban" if source == "manual" else "stored CrowdSec decision"
    if payload.get("confirm") is not True:
        return _error("confirmation_required", f"Resetting deletes every {what}; send confirm: true.", 400)
    expected = payload.get("version")

    def mutate(state, now, version):
        if source not in render.active_sources(state):
            raise BanError("source_not_enabled", f"The {source} source is not in use.", 400)
        if expected != version:
            raise BanError("version_conflict", "The ban list changed since you loaded it; reload the Security view.", 409)
        removed = [r for r in state.records if r.source == source]
        state.records = [r for r in state.records if r.source != source]
        body = {"removed": len(removed)}
        if source == "crowdsec":
            body["message"] = (f"Removed {len(removed)} stored CrowdSec decisions. They return within "
                               f"{config.BANS_SYNC_INTERVAL} seconds unless they are removed in CrowdSec "
                               "(cscli decisions delete).")
        return Mutation(body, 200, [("bans_reset", f"{source}: removed {len(removed)} records")])
    return _transact(actor, _verified_client(remote_addr), mutate, force=(source,), allow_corrupt=True,
                     source="reset", affects=(source,))


# --- Phase 4: client-IP profile, Cloudflare ranges, country policy ------------------------

def _country_active() -> bool:
    """Render geo.caddy once a country policy is saved or once it left something behind. BANS_ENABLED=false
    disables it with everything else."""
    return (config.BANS_ENABLED and (country.exists() or os.path.exists(render.COUNTRY.path)))


def _refused_error(refused):
    if refused.gate == "allowlist_corrupt":
        return _error("allowlist_degraded", refused.message + ".", 503)
    if refused.gate == "unavailable":
        return _error("bans_unavailable", refused.message, 503, reason=refused.reason)
    if refused.gate == "corrupt":
        return _error("state_degraded", f"{refused.message}. The last generated policy stays enforced; "
                      "open Security to recover.", 503, recovery=True)
    return _error("state_degraded", refused.message, 503, recovery=True)


def _policy_transaction(actor, source, events, *, prof=None, check=None, force=(), background=False,
                        allow_corrupt=False, country_candidate=None, strict_country_shape=False):
    """A profile, range or country change: the candidate profile (and the
    country candidate) expanded through every dependent
    file, committed by one journal under caddyfile_lock() (spec 4.2).
    check(state) runs under the lock and returns an error response to stop."""
    def prepare(state, corrupt):
        if check is not None:
            stop = check(state)
            if stop is not None:
                return stop
        holds = {} if corrupt else {k: v for k, v in _holds(state).items() if k not in force}
        candidate = prof(profile.load_or_default()) if callable(prof) else (
            prof if prof is not None else profile.load_or_default())
        prot = protected_for(state, prof=candidate)
        country_cand = country_candidate
        if strict_country_shape and country_cand is None:
            # An enabled country policy follows the profile's shape: render the new shape
            # strictly (policy re-read under the lock), so a refused render (dataset
            # missing, over the cap) refuses the change instead of leaving a geo.caddy
            # that does not fit the profile and denies every public client.
            policy = country.load_or_default()
            shape = lambda mode: "direct" if mode == "direct" else "cloudflare"
            if country.effective_enabled(policy) and config.BANS_ENABLED and shape(policy.profile) != shape(candidate.mode):
                country_cand = policy
        try:
            # A corrupt bans.json is never rewritten here: the operator recovers it.
            changes = _candidates(state, prot, holds, store.utc_now(), prof=candidate,
                                  bans=corrupt is None and _bans_present(state), with_profile=prof is not None,
                                  country_candidate=country_cand)
        except country.CountryError as e:
            return _error(e.code, str(e), e.status, **e.extra)
        except render.CapacityError as e:
            return _error("capacity_exceeded", f"The ban files would render {e.count} prefixes; the limit "
                          f"(BANS_MAX) is {e.limit}. Remove bans first.", 409, count=e.count, limit=e.limit)
        return _Plan(changes, actor, source, list(events), context=holds)

    refused, plan, outcome = _locked_transaction(prepare, background=background, allow_corrupt=allow_corrupt)
    if refused is not None:
        return _refused_error(refused)
    if outcome is None:
        return plan
    return _outcome_body(outcome), (200 if outcome.ok else outcome.http_status)


def allowlist_info() -> dict:
    """GET /api/security/allowlist: the operator's never-ban entries."""
    problem = allowlist_problem()
    entries = [] if problem else allowlist.load()
    return {"entries": [dataclasses.asdict(e) for e in entries], "max_entries": allowlist.MAX_ENTRIES,
            "note_max": allowlist.NOTE_MAX, "corrupt": problem, "file": allowlist.PATH}


def _allowlist_transaction(actor, change, event):
    """Add or remove a never-ban entry: change(entries) -> (new_entries, detail)
    runs under the lock on the entries read there, and the new list is expanded
    through every policy file repeating the protected set (the ban sources, the
    plugin route, the country policy) in one journal and one reload."""
    def prepare(state, corrupt):
        try:
            entries, body = change(allowlist.load())
        except allowlist.InputError as e:
            return _error(e.code, str(e), e.status)
        holds = {k: v for k, v in _holds(state).items()}
        prot = protected_for(state, allow=entries)
        try:
            changes = _candidates(state, prot, holds, store.utc_now(), bans=_bans_present(state))
        except country.CountryError as e:
            return _error(e.code, str(e), e.status, **e.extra)
        except render.CapacityError as e:
            return _error("capacity_exceeded", f"The ban files would render {e.count} prefixes; the limit "
                          f"(BANS_MAX) is {e.limit}. Remove bans first.", 409, count=e.count, limit=e.limit)
        changes.append(txn.Change(allowlist.PATH, "state", allowlist.dumps(entries)))
        return _Plan(changes, actor, "allowlist", [(event, body["entry"]["value"])],
                     context=(body, holds))

    refused, plan, outcome = _locked_transaction(prepare)
    if refused is not None:
        return _refused_error(refused)
    if outcome is None:
        return plan
    body, holds = plan.context
    out = {**_outcome_body(outcome), **body}
    if outcome.ok and holds:
        out["held"] = sorted(holds)
    return out, ((201 if event == "allowlist_added" else 200) if outcome.ok else outcome.http_status)


def add_allowlist(payload, actor):
    if not isinstance(payload, dict):
        return _error("invalid_request", "Send a JSON object.", 400)
    try:
        net = allowlist.validate_value(payload.get("value"))
        note = allowlist.validate_note(payload.get("note"))
    except (addr.AddressError, allowlist.InputError) as e:
        return _error(e.code, str(e), getattr(e, "status", 400))

    def change(entries):
        entries, entry = allowlist.add(entries, net, note, actor, store.iso(store.utc_now()))
        return entries, {"entry": dataclasses.asdict(entry)}
    return _allowlist_transaction(actor, change, "allowlist_added")


def remove_allowlist(entry_id, actor):
    def change(entries):
        found = next((e for e in entries if e.id == entry_id), None)
        if found is None:
            raise allowlist.InputError("not_found", "That never-ban entry no longer exists.", 404)
        return [e for e in entries if e.id != entry_id], {"entry": dataclasses.asdict(found)}
    return _allowlist_transaction(actor, change, "allowlist_removed")


def _reset_aux(source, payload, actor):
    if source == "country" and not _country_active() or source == "cloudflare" and not _profile_active():
        return _error("source_not_enabled", f"The {source} policy is not in use.", 400)
    if source == "plugin":
        return _error("invalid_source", "The plugin route has no state to reset; use Re-apply.", 400)
    if payload.get("confirm") is not True:
        return _error("confirmation_required", f"Resetting returns the {source} policy to its defaults; "
                      "send confirm: true.", 400)
    if source == "cloudflare":
        prof = profile.Profile(mode="direct", stored=True)
        return _policy_transaction(actor, "reset", [("bans_reset", "cloudflare: direct profile, bundled ranges")],
                                   prof=prof, force=("cloudflare",), allow_corrupt=True, strict_country_shape=True)
    return _reset_country(actor)


def client_ip_profile_info() -> dict:
    corrupt = None
    try:
        prof = profile.load()
    except profile.Corrupt as e:
        prof, corrupt = profile.default(), str(e)
    data = fsio.read_bytes(render.PROFILE.path)
    check = _ranges_check_meta()
    return {
        "mode": prof.mode, "env_mode": profile.parse_mode(config.CLIENT_IP_MODE), "stored": prof.stored,
        "modes": list(profile.MODES), "tunnel_peers": prof.tunnel_peers, "tunnel_only": prof.tunnel_only,
        "trusted_peers": prof.peers(), "corrupt": corrupt,
        "file": render.PROFILE.path, "import_line": render.PROFILE.import_line,
        "present": data is not None, "current": data is not None and data == profile.render(prof),
        "hash": fsio.sha256_tag(data)[7:19] if data is not None else None,
        "ranges": {"v4": prof.ranges.get("v4", []), "v6": prof.ranges.get("v6", []), "source": prof.ranges_source,
                   "fetched_at": prof.ranges_fetched_at, "auto_update": config.CLOUDFLARE_RANGES_AUTO_UPDATE,
                   "checked_at": check.get("checked_at"), "last_error": check.get("last_error")},
    }


def set_client_ip_profile(payload, actor):
    """PUT /api/security/client-ip-profile: validate the mode and every peer
    before anything is generated, then regenerate the trusted proxies file and
    everything that repeats the protected set or the Cloudflare peers."""
    try:
        candidate = profile.from_payload(payload, profile.load_or_default())
    except profile.InputError as e:
        return _error(e.code, str(e), 400)

    def under_lock(current):
        # Ranges, their source and the recorded hashes are re-read under the lock, so a
        # refresh that landed since validation is never undone by this save.
        return dataclasses.replace(candidate, ranges={k: list(v) for k, v in current.ranges.items()},
                                   ranges_source=current.ranges_source, ranges_fetched_at=current.ranges_fetched_at,
                                   last_rendered_hashes=dict(current.last_rendered_hashes))
    detail = candidate.mode + (f" peers={' '.join(candidate.tunnel_peers)}" if candidate.tunnel_peers else "")
    return _policy_transaction(actor, "profile", [("client_ip_profile_changed", detail)], prof=under_lock,
                               force=("cloudflare",), strict_country_shape=True)


RANGES_CHECK_PATH = os.path.join(config.BACKUP_DIR, "cloudflare-ranges-check.json")
RANGES_LOCK_PATH = os.path.join(config.BACKUP_DIR, "cloudflare-ranges.lock")
RANGES_LOCK_NAME = "cloudflare-ranges.lock"
_ranges_thread_lock = threading.Lock()
RANGES_CHECK_INTERVAL = 24 * 3600
RANGES_RETRY_INTERVAL = 3600
RANGES_MANUAL_INTERVAL = 60          # POST /api/security/cloudflare-ranges/refresh


def _ranges_check_meta() -> dict:
    """Health metadata of the last range check. Not transaction state: it owns
    no policy, and a lost or damaged copy only makes the next check run early."""
    try:
        with open(RANGES_CHECK_PATH, "rb") as f:
            doc = json.loads(f.read(16 * 1024).decode("utf-8"))
        return doc if isinstance(doc, dict) else {}
    except (OSError, ValueError, RecursionError):
        return {}


def _write_ranges_check(result, error=None) -> None:
    doc = {"checked_at": store.iso(store.utc_now()), "result": result, "last_error": (str(error)[:300] if error else None)}
    try:
        fsio.atomic_write(RANGES_CHECK_PATH, json.dumps(doc, sort_keys=True).encode(), 0o600)
    except OSError as e:
        log.warning("Could not record the Cloudflare range check: %s", e)


def _seconds_since_check(meta) -> float:
    try:
        return (store.utc_now() - store.parse_iso(meta["checked_at"])).total_seconds()
    except (KeyError, TypeError, ValueError):
        return float("inf")


def ranges_due() -> bool:
    meta = _ranges_check_meta()
    wait = RANGES_RETRY_INTERVAL if meta.get("last_error") else RANGES_CHECK_INTERVAL
    return _seconds_since_check(meta) >= wait


def refresh_cloudflare_ranges(actor="system", *, manual=False, session=None):
    """Fetch the official lists (outside caddyfile_lock()), validate them and,
    when they changed, commit the new list with every dependent file in one
    journaled transaction (spec 4.2). A failure keeps the last good list."""
    if manual and _seconds_since_check(_ranges_check_meta()) < RANGES_MANUAL_INTERVAL:
        return _error("rate_limited", f"The ranges were checked less than {RANGES_MANUAL_INTERVAL} seconds ago; "
                      "try again shortly.", 429)
    try:
        before = profile.load()
    except profile.Corrupt as e:
        return _error("state_degraded", f"{e}. Reset the Cloudflare profile in Security.", 503, recovery=True)
    try:
        fetched = cfranges.fetch(session or http_client.Session())
        problem = cfranges.plausible(before.ranges, fetched)
        if problem:
            raise cfranges.RangeError(f"refusing the new list: {problem}")
    except (cfranges.RangeError, http_client.RequestException) as e:
        _write_ranges_check("failed", e)
        audit.log_action("cloudflare_ranges_refused", actor, str(e)[:200])
        return _error("ranges_refused", f"The Cloudflare ranges were not updated ({e}); the last good list stays.", 502)
    if fetched == before.ranges and before.ranges_source == "cloudflare":
        _write_ranges_check("unchanged")
        return {"ok": True, "code": None, "message": "The Cloudflare ranges are current.", "reload_status": "not_required",
                "enforcement": "unchanged", "changed": False}, 200
    candidate = dataclasses.replace(before, ranges=fetched, ranges_source="cloudflare",
                                    ranges_fetched_at=store.iso(store.utc_now()), stored=True)
    added = sum(len(set(fetched[f]) - set(before.ranges.get(f, ()))) for f in ("v4", "v6"))
    removed = sum(len(set(before.ranges.get(f, ())) - set(fetched[f])) for f in ("v4", "v6"))

    def unchanged_since(state):
        # Under the lock: the candidate was built from `before`, read before the
        # fetch. Any concurrent profile change (mode, tunnel peers, tunnel_only,
        # ranges) wins; this refresh never overwrites it.
        try:
            now = profile.load() if profile.exists() else None
        except profile.Corrupt as e:
            return _error("state_degraded", f"{e}. Reset the Cloudflare profile in Security.", 503, recovery=True)
        if now is not None and now.mode != "cloudflare-proxied" and before.mode == "cloudflare-proxied":
            return _error("version_conflict", "The client-IP profile left Cloudflare proxied mode during the "
                          "refresh; the ranges were not applied.", 409)
        if (now is None) != (not before.stored) or (now is not None and profile.dumps(now) != profile.dumps(before)):
            return _error("version_conflict", "The Cloudflare profile changed during the refresh; try again.", 409)
        return None
    body, status = _policy_transaction(actor, "cloudflare-ranges",
                                       [("cloudflare_ranges_updated", f"{added} added, {removed} removed")],
                                       prof=candidate, check=unchanged_since, background=not manual)
    _write_ranges_check("updated" if body.get("ok") else "failed", None if body.get("ok") else body.get("message"))
    return {**body, "changed": bool(body.get("ok"))}, status


def ranges_tick(session=None) -> str:
    """The daily background refresh: proxied mode only (direct mode never
    contacts Cloudflare), one worker at a time, never under caddyfile_lock()."""
    if not (config.BANS_ENABLED and config.CLOUDFLARE_RANGES_AUTO_UPDATE):
        return "disabled"
    if profile.load_or_default().mode != "cloudflare-proxied":
        return "not_needed"
    if not ranges_due():
        return "current"
    # Container-local lock first, then the best-effort BACKUP_DIR one (src/locks.py);
    # caddyfile_lock() is taken only later, inside the refresh, never around the fetch.
    with locks.try_lock(RANGES_LOCK_NAME, RANGES_LOCK_PATH, _ranges_thread_lock) as held:
        if not held:
            return "busy"
        if not ranges_due():
            return "current"
        body, _ = refresh_cloudflare_ranges(session=session)
        return "updated" if body.get("changed") else ("current" if body.get("ok") else "failed")


def _reset_country(actor):
    return _policy_transaction(actor, "reset", [("bans_reset", "country: policy off")],
                               country_candidate=country.Policy(stored=True), force=("country",), allow_corrupt=True)


def _country_facts():
    """(policy, corrupt, data, facts, error, prof): the stored policy rendered
    against the current profile and protected set, without writing anything."""
    corrupt = None
    try:
        policy = country.load()
    except country.Corrupt as e:
        policy, corrupt = country.Policy(), str(e)
    prof = profile.load_or_default()
    try:
        state = store.load()
    except store.StateCorrupt:
        state = store.State()
    try:
        data, facts = country.render(policy, prof.mode, prof.peers(), protected_for(state, prof=prof).exclusion_tokens())
        return policy, corrupt, data, facts, None, prof
    except country.CountryError as e:
        return policy, corrupt, None, None, e, prof


_FETCH = object()


def country_policy_info(country_facts=None, live=_FETCH) -> dict:
    """`country_facts`: a _country_facts() result already read for this request.
    `live`: the running Caddy config (None when unreachable); read here if omitted."""
    policy, corrupt, data, facts, error, prof = country_facts or _country_facts()
    if live is _FETCH:
        try:
            live = caddy_admin.live_config()
        except caddy_admin.CaddyUnavailable:
            live = None
    # The header and range trust only hold when the live Caddy runs the selected
    # profile's trusted proxies; without the import client_ip is the edge peer.
    trust = _live_trust(live, prof) if live is not None else None
    trust_ok = None if trust is None else bool(trust) and all(t["matches"] for t in trust)
    on_disk = fsio.read_bytes(render.COUNTRY.path)
    current = data is not None and on_disk == data
    facts = facts or {"profile": None, "prefixes": policy.dataset.get("prefixes") or {}, "month": None, "warnings": []}
    shape = facts["profile"]
    enforcing = country.effective_enabled(policy)
    return {
        "enabled": policy.enabled, "effective": enforcing, "env_enabled": True,
        "stored": policy.stored, "countries": policy.countries, "corrupt": corrupt,
        "cloudflare_geolocation_confirmed": policy.cloudflare_geolocation_confirmed,
        "shape": shape, "client_ip_mode": prof.mode, "updated_at": policy.updated_at,
        "iso_codes": sorted(country.ISO), "special_codes": list(country.SPECIAL),
        "prefixes": facts["prefixes"], "limits": {"max": country.max_prefixes(), "warn": country.warn_prefixes()},
        "dataset": {**countrydata.info(), "used_month": facts["month"]},
        "warnings": facts["warnings"], "error": ({"code": error.code, "message": str(error)} if error else None),
        "file": render.COUNTRY.path, "import_line": render.COUNTRY.import_line,
        "present": on_disk is not None, "current": current,
        "hash": fsio.sha256_tag(on_disk)[7:19] if on_disk is not None else None,
        "trust_ok": trust_ok,
        "healthy": bool(enforcing and current and error is None and trust_ok is not False
                        and (shape != "cloudflare" or policy.cloudflare_geolocation_confirmed)),
    }


def set_country_policy(payload, actor):
    """PUT /api/security/country-policy: validate the codes and render the
    candidate (cap, dataset, Cloudflare peers) before anything is written; a
    refused candidate leaves geo.caddy and country-policy.json untouched."""
    try:
        candidate = country.from_payload(payload, country.load_or_default())
    except country.CountryError as e:
        return _error(e.code, str(e), e.status)
    candidate.updated_at = store.iso(store.utc_now())
    detail = f"enabled={str(candidate.enabled).lower()} countries={' '.join(candidate.countries)}"
    return _policy_transaction(actor, "country", [("country_policy_changed", detail)], country_candidate=candidate,
                               force=("country",))


def country_tick() -> str:
    """Regenerate geo.caddy after a new dataset arrived, only when the selected
    countries' output changes (spec 4.3). Direct policy only; reads local files."""
    if not config.BANS_ENABLED:
        return "disabled"
    policy = country.load_or_default()
    if not country.effective_enabled(policy) or profile.load_or_default().mode != "direct":
        return "not_needed"
    _, _, data, _, error, _ = _country_facts()
    if error is not None:
        return error.code
    if data == fsio.read_bytes(render.COUNTRY.path):
        return "current"
    seen = country.dumps(policy)

    def unchanged(_state):
        # The policy was read before the lock: a PUT that landed since wins.
        if country.dumps(country.load_or_default()) != seen:
            return _error("version_conflict", "The country policy changed while the dataset update was prepared.", 409)
        return None

    body, _ = _policy_transaction("system", "country-data", [("country_policy_rendered", "dataset update")],
                                  country_candidate=policy, background=True, check=unchanged)
    return "applied" if body.get("ok") else str(body.get("code") or "failed")


def _live_trust(live, prof) -> list:
    """Per live server: the trusted proxies and client-IP headers Caddy runs,
    and whether they are what the selected profile renders."""
    servers = (((live or {}).get("apps") or {}).get("http") or {}).get("servers") or {}
    want = {ipaddress.ip_network(x, strict=False) for x in detect.expand_tokens(prof.peers())}
    out = []
    for name, srv in sorted(servers.items()):
        if not isinstance(srv, dict):
            continue
        tp = srv.get("trusted_proxies") or {}
        ranges = [str(r) for r in tp.get("ranges") or []] if isinstance(tp, dict) else []
        headers = [str(h) for h in srv.get("client_ip_headers") or []]
        try:
            have = {ipaddress.ip_network(r, strict=False) for r in ranges}
        except ValueError:
            have = None
        if prof.mode == "direct":
            ok = not ranges
        else:
            ok = have == want and any(h.lower() == "cf-connecting-ip" for h in headers)
        out.append({"server": name, "listen": srv.get("listen") or [], "trusted_proxies": ranges[:64],
                    "client_ip_headers": headers[:8], "matches": ok})
    return out


# --- CrowdSec file sync (spec 2.4-2.6) ---------------------------------------------------

REFRESH_TOLERANCE = timedelta(minutes=2)
PROTECTED_SAMPLE_MAX = 10
COUNTS_TEXT_MAX = 12
_SYNC_OK = ("applied", "stored", "unchanged")


@dataclass
class SyncApply:
    code: str
    message: str = ""
    added: int = 0
    removed: int = 0
    active: int = 0
    protected: dict = field(default_factory=dict)
    protected_sample: list = field(default_factory=list)
    by_origin: dict = field(default_factory=dict)
    capacity: object = None

    @property
    def ok(self) -> bool:
        return self.code in _SYNC_OK


def _counts_text(counts) -> str:
    """A bounded "name count, ..." summary for audit details and messages."""
    items = sorted((str(k)[:40], v) for k, v in counts.items() if v)
    text = ", ".join(f"{k} {v}" for k, v in items[:COUNTS_TEXT_MAX])
    if len(items) > COUNTS_TEXT_MAX:
        text += f", and {len(items) - COUNTS_TEXT_MAX} more"
    return text or "none"


def _reconcile_crowdsec(state, wanted) -> tuple:
    """Replace the crowdsec records with `wanted` (decision id -> Accepted).
    A record whose decision, value and expiry (within REFRESH_TOLERANCE) are
    unchanged is kept as it is, so a repeated snapshot changes no byte."""
    old = {r.source_id: r for r in state.records if r.source == "crowdsec"}
    keep, added = [], 0
    for did, a in wanted.items():
        r = old.get(did)
        if (r is not None and r.value == addr.token(a.net) and r.expires_at
                and abs(store.parse_iso(r.expires_at) - a.expires_at) <= REFRESH_TOLERANCE):
            keep.append(r)
            continue
        added += r is None
        keep.append(store.new_crowdsec_record(did, a.net, a.origin, a.scenario, a.fetched_at, a.expires_at))
    removed = sum(1 for did in old if did not in wanted)
    keep.sort(key=lambda r: int(r.source_id))
    state.records = [r for r in state.records if r.source != "crowdsec"] + keep
    return keep, added, removed


def _total_counts(records, now) -> dict:
    """Every prefix rendered into stock Caddy, whatever its origin: the sync
    gate (spec 2.5). Manual changes use render.capacity_counts instead."""
    return {name: len(render.effective_prefixes(records, now, name)) for name in ("manual", "crowdsec")}


def apply_crowdsec(desired, *, snapshot=False, ignored=None, now=None) -> SyncApply:
    """Make the stored crowdsec records equal the sync leader's accepted
    decisions and render bans-crowdsec.caddy through the Phase 1 transaction.
    Called only by the sync leader, with decisions already fetched: never
    while caddyfile_lock() is held and never with an LAPI request in flight.

    Only the crowdsec source is pruned and rendered: manual records, the
    management registry and bans-manual.caddy belong to the manual path and
    expire_tick (spec 2.4). Every decision gets the manual checks (canonical
    value, width, protected overlap). Every failure keeps the last loaded
    policy (spec 2.6): a corrupt state, a pending journal, a held file or a
    capacity overflow returns before any write."""
    ignored = collections.Counter(ignored or {})

    def prepare(state, corrupt):
        at = now or store.utc_now()
        holds = _holds(state)
        if "crowdsec" in holds:
            return SyncApply("held", "bans-crowdsec.caddy differs from the stored state (for example after host "
                             "recovery). CrowdSec sync is paused for that file until you Re-apply it in Security.")
        expired = store.prune_expired(state, at, sources=["crowdsec"])
        prot = protected_for(state)
        wanted, prot_counts, sample = {}, collections.Counter(), []
        for a in desired:
            if a.expires_at <= at:
                ignored["expired"] += 1
                continue
            try:
                net = addr.canonical(addr.token(a.net))
                addr.check_width(net)
            except addr.AddressError as e:
                ignored["too_wide" if e.code == "range_too_wide" else "invalid_value"] += 1
                continue
            category = prot.overlap(net)
            if category:
                prot_counts[category] += 1
                if len(sample) < PROTECTED_SAMPLE_MAX:
                    sample.append({"value": addr.token(net), "category": category,
                                   "scenario": a.scenario, "origin": a.origin})
                continue
            wanted[a.decision_id] = dataclasses.replace(a, net=net)
        keep, added, removed = _reconcile_crowdsec(state, wanted)
        result = SyncApply("unchanged", added=added, removed=removed, active=len(keep),
                           protected=dict(prot_counts), protected_sample=sample,
                           by_origin=dict(collections.Counter(r.origin for r in keep)))
        try:
            render.check_capacity(_total_counts(state.records, at), config.BANS_MAX)
            # The manual policy is never regenerated here: treat it as held.
            changes = _candidates(state, prot, {**holds, "manual": "sync"}, at)
        except render.CapacityError as e:
            result.code = "capacity_exceeded"
            result.capacity = {"count": e.count, "limit": e.limit, "by_source": e.by_source}
            result.message = (f"CrowdSec decisions would render {e.count} prefixes in total "
                              f"({_counts_text(e.by_source)}; CrowdSec by origin: {_counts_text(result.by_origin)}); "
                              f"the limit (BANS_MAX) is {e.limit}. The last applied CrowdSec policy stays enforced "
                              "and automatic apply is paused. Restrict CROWDSEC_ORIGINS, raise BANS_MAX after "
                              "measuring (docs/security.md#capacity), or use plugin mode (docs/security.md#crowdsec-plugin).")
            return result
        events = _expired_events(expired)
        all_ignored = ignored + collections.Counter({f"protected:{k}": v for k, v in prot_counts.items()})
        # A sync that changes nothing is silent in both modes: no audit line,
        # and txn writes no file and reloads nothing for unchanged bytes.
        if snapshot and (added or removed or expired):
            events.append(("crowdsec_snapshot", f"{len(keep)} active, {added} added, {removed} removed; "
                           f"ignored: {_counts_text(all_ignored)}"))
        elif added or removed:
            events.append(("crowdsec_sync", f"{len(keep)} active, {added} added, {removed} removed"))
        return _Plan(changes, "system", "crowdsec", events, context=result)

    refused, value, outcome = _locked_transaction(prepare, background=True)
    if refused is not None:
        if refused.gate == "corrupt":
            return SyncApply("corrupt", f"{refused.message}. CrowdSec sync is paused until the ban state is "
                             "recovered in Security.")
        return SyncApply(refused.gate, refused.message)
    if outcome is None:
        return value                        # held or capacity_exceeded: nothing was written
    result = value.context
    if not outcome.ok:
        result.code = outcome.code or "apply_failed"
    elif outcome.reload_status == "applied":
        result.code = "applied"
    elif outcome.enforcement != "unchanged":
        result.code = "stored"
    result.message = outcome.message
    return result


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
    by_source = {n: len(render.effective_prefixes(state.records, now, n)) for n in render.active_sources(state)}
    return {"records": [_public(r, now, prot) for r in records], "state_version": state.version,
            "rendered_prefixes": by_source["manual"], "rendered_by_source": by_source,
            "max_prefixes": config.BANS_MAX}, 200


def _rid(*parts) -> str:
    return fsio.sha256_tag("|".join(str(p) for p in parts).encode())[7:23]


def _recovery_info_locked() -> dict:
    base = {"required": True, "phase": None, "backups": [], "reapply": False, "reset": False, "state_version": None,
            "held_sources": []}
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
                "reason": "policy_differs", "files": [_policy_filename(n) for n in sorted(holds)],
                "held_sources": sorted(holds), "actions": [],
                "summary": "A managed ban file differs from the stored state, for example after host recovery. "
                           "It is not regenerated, and its expiry and CrowdSec sync are paused, until you fix "
                           "the records and Re-apply.",
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


def _site_rows(live, text, state, now, holds, country_facts=None) -> list:
    """One row per site: the manual policy's result at the top level (the Phase 1
    shape) plus `policies` for every active source. `state` None means the
    stored records are unknown (corrupt), so any managed ban route counts."""
    sources = render.active_sources(state)
    after = {n: tuple(render.SOURCES[a].path for a in names) for n, names in render.AFTER.items()}
    blocks = scan.site_blocks(text)
    management = scan.management_hosts(text, scan.console_host())
    detected = {}
    if live is not None:
        for name, src in sources.items():
            prefixes = None if state is None else render.effective_prefixes(state.records, now, name)
            expected = None if name in holds or prefixes is None else [addr.token(p) for p in prefixes]
            detected[name] = detect.site_statuses(live, src, bool(prefixes), expected_ranges=expected)
    show_plugin = _plugin_rows_wanted(live)
    names = list(sources) + (["plugin"] if show_plugin else [])
    if live is not None and show_plugin:
        expected = None
        if "plugin" not in holds:
            expected = detect.expand_tokens(protected_for(state or store.State()).exclusion_tokens())
        detected["plugin"] = detect.plugin_site_statuses(live, expected_exclusions=expected)
    plugin_after = tuple(render.SOURCES[n].path for n in render.SOURCES)
    if _country_rows_wanted(live):
        names.append("country")
        if live is not None:
            detected["country"] = detect.country_site_statuses(
                live, expected_shape=None if "country" in holds else _country_expected_shape(country_facts))
    country_after = tuple(render.SOURCES[n].path for n in render.COUNTRY_AFTER if n in render.SOURCES)

    def policy(name, status, block, mgmt, found=None):
        imp = None
        if block is not None:
            imp = (scan.block_import_state(text, block, None, after=plugin_after, snippet=render.PLUGIN.snippet)
                   if name == "plugin" else
                   scan.block_import_state(text, block, render.COUNTRY.path, after=country_after)
                   if name == "country" else
                   scan.block_import_state(text, block, sources[name].path, after=after.get(name, ())))
        return {"status": _management_status(status, imp) if mgmt else status,
                "pre_handlers": found.pre_handlers if found else [], "detail": found.detail if found else "",
                "import": imp}

    rows, seen = [], set()
    for i, s in enumerate(detected.get("manual", [])):
        block = next((b for b in blocks if set(b.hosts) & set(s.hosts)), None) if s.hosts \
            else next((b for b in blocks if s.label in b.addresses), None)
        if block is not None:
            seen.add(block.start)
        mgmt = bool(set(s.hosts) & management)
        policies = {name: policy(name, found[i].status, block, mgmt, found[i]) for name, found in detected.items()}
        rows.append({"label": s.label, "hosts": s.hosts, "source": "main" if block else "external",
                     "line": block.start if block else None, **policies["manual"], "policies": policies})
    unreachable = live is None
    fallback = "caddy_unreachable" if unreachable else "not_loaded"
    fallback_detail = ("The Caddy admin API is unreachable, so whether this site enforces the ban list "
                       "cannot be checked." if unreachable
                       else "This site block is not in Caddy's running configuration.")
    for b in blocks:
        if b.start in seen:
            continue
        mgmt = bool(set(b.hosts) & management)
        policies = {name: {**policy(name, fallback, b, mgmt), "detail": fallback_detail} for name in names}
        rows.append({"label": b.hosts[0] if b.hosts else b.addresses[0], "hosts": b.hosts,
                     "source": "main", "line": b.start, **policies["manual"], "policies": policies})
    return rows


def _country_rows_wanted(live) -> bool:
    return _country_active() or (live is not None and bool(detect.country_shapes(live)))


def _country_expected_shape(country_facts=None):
    """The marker value the current settings render, or None while the policy
    cannot be rendered (the live value is then not compared)."""
    policy, _, _, facts, error, _ = country_facts or _country_facts()
    if not country.effective_enabled(policy):
        return "off"
    return None if error is not None or facts is None else facts["profile"]


def _plugin_rows_wanted(live) -> bool:
    if _plugin_active():
        return True
    return live is not None and any(s.status != "not_imported" for s in detect.plugin_site_statuses(live))


def _management_status(live_status, imp) -> str:
    """A console site is only "never banned" while it neither enforces the ban
    list (live) nor imports it (on disk, applied by the next reload). The
    snippet guard is advisory, so a hand-typed import is reported as the
    lockout risk it is, never as safe."""
    if live_status in ("not_imported", "not_loaded", "caddy_unreachable") and not (imp and imp.get("present")):
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


def _pid_alive(pid) -> bool:
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True                  # exists, but not ours to signal
    return True


def _scrub(value, secret):
    """The sync report is data from outside this process: whatever it carries,
    the bouncer key never leaves in an API response."""
    if isinstance(value, str):
        return value.replace(secret, "[redacted]") if secret else value
    if isinstance(value, dict):
        return {k: _scrub(v, secret) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v, secret) for v in value]
    return value


def _crowdsec_status(now) -> dict:
    """CrowdSec health for the Security view. The report is only shown while
    CrowdSec is enabled (a file left behind after disabling is ignored), and it
    is stale when its updated_at is old or its leader process is gone."""
    enabled = lapi.enabled()
    origins = list(lapi.origins()) if enabled else []
    doc = syncstate.read() if enabled else None
    stale = enabled
    if doc is not None:
        try:
            age = (now - store.parse_iso(doc["updated_at"])).total_seconds()
            limit = STALE_POLLS * config.CROWDSEC_POLL_INTERVAL + config.BANS_SYNC_INTERVAL
            stale = age > limit or not _pid_alive(doc.get("leader_pid"))
        except (KeyError, TypeError, ValueError):
            stale = True
        key, _ = lapi.read_key()
        doc = _scrub(doc, key)
    creds, write_problem = lapimachine.read_credentials() if enabled else (None, None)
    return {"enabled": enabled, "origins": origins, "write_configured": creds is not None,
            "write_problem": write_problem,
            "list_origins": [o for o in origins if o in lapi.LIST_ORIGINS], "sync": doc, "stale": stale}


ISOLATION_CHECK = ("crowdsec/check-plugin-isolation.sh -- -f docker-compose.prod.yaml -f docker-compose.crowdsec.yaml "
                   "-f docker-compose.crowdsec-plugin.yaml")


def _plugin_status(live, state, holds, text) -> dict:
    """The plugin block of GET /api/security. Never probes Caddy: status()
    already ran availability(), which refreshed the module cache."""
    module = plugin.cached_module() if lapi.enabled() else None
    app = plugin.live_app(live) if live is not None else None
    if not (_plugin_active() or module or app):
        return {"enabled": False}
    problem = plugin.admin_problem(live) if live is not None else None
    data = fsio.read_bytes(render.PLUGIN.path)
    static = protected.build(never=never_networks(), allowlist=allowlist.networks(allowlist.load_or_default()),
                             docker=protected.read_docker_networks())
    return {
        "enabled": True, "module": module, "refused": problem is not None,
        "admin": None if problem is None else {"code": problem.code, "message": problem.message},
        "app": app, "key_mode": plugin.key_mode(), "key_file": plugin.key_file() or None,
        "placeholder": plugin.api_key_placeholder(),
        "ticker_interval": app["ticker_interval"] if app else plugin.TICKER_INTERVAL,
        "definition": {
            "file": render.PLUGIN.path, "import_line": render.PLUGIN.import_line,
            "site_import": render.PLUGIN.site_import, "present": data is not None,
            "hash": fsio.sha256_tag(data)[7:19] if data is not None else None,
            "current": data is not None and state is not None and plugin_route_current(state),
            "hold": "plugin" in holds, "hold_reason": holds.get("plugin"),
            "imported": scan.mentions_import(text, render.PLUGIN.path),
        },
        "allowlist": plugin.allowlist_commands(static),
        "check_command": ISOLATION_CHECK,
    }


def _profile_status(live, holds, text) -> dict:
    info = client_ip_profile_info()
    prof = profile.load_or_default()
    deps = []
    for path in (render.PROFILE.path, *(s.path for s in render.SOURCES.values()), render.COUNTRY.path,
                 render.PLUGIN.path):
        data = fsio.read_bytes(path)
        if data is not None:
            deps.append({"file": os.path.basename(path), "hash": fsio.sha256_tag(data)[7:19]})
    info["ranges"]["age_seconds"] = _age_seconds(info["ranges"].get("fetched_at"))
    return {**info, "active": _profile_active(), "hold": holds.get("cloudflare"), "dependencies": deps,
            "imported": scan.mentions_import(text, render.PROFILE.path),
            "live": _live_trust(live, prof) if live is not None else None}


def _age_seconds(stamp):
    try:
        return max(0, int((store.utc_now() - store.parse_iso(stamp)).total_seconds()))
    except (TypeError, ValueError, KeyError):
        return None


def _country_status(live, holds, country_facts=None) -> dict:
    info = country_policy_info(country_facts, live)
    shapes = detect.country_shapes(live) if live is not None else None
    # Healthy needs the rendered file, the confirmation (Cloudflare) and, when
    # Caddy answers, the same shape running live.
    live_ok = None if shapes is None else bool(shapes) and set(shapes) == {info["shape"] or "off"}
    trust_ok = info["trust_ok"]
    prefixes = info["prefixes"] if isinstance(info["prefixes"], dict) else {}
    summary = {"mode": info["shape"], "countries": info["countries"], "prefixes": prefixes,
               "cap": info["limits"]["max"], "warn": info["limits"]["warn"], "warnings": info["warnings"],
               "healthy": bool(info["healthy"] and live_ok is not False and trust_ok is not False),
               "live_ok": live_ok, "trust_ok": trust_ok}
    return {**info, "active": _country_active(), "hold": holds.get("country"), "live_shapes": shapes,
            "healthy": summary["healthy"], "trust_ok": trust_ok, "summary": summary}


def status(remote_addr) -> dict:
    avail = availability()
    info = recovery_info()
    try:
        state = store.load()
    except store.StateCorrupt:
        state = None
    now = store.utc_now()
    holds = _holds(state) if state else {}
    sources = {}
    for name, src in render.active_sources(state).items():
        rendered = len(render.effective_prefixes(state.records, now, name)) if state else 0
        sources[name] = {
            "file": src.path, "import_line": src.import_line, "hold": name in holds,
            "hold_reason": holds.get(name), "rendered_prefixes": rendered,
            "active_records": sum(1 for r in (state.records if state else [])
                                  if r.source == name and not r.expired(now)),
        }
    if "crowdsec" in sources:
        sources["crowdsec"].update(_crowdsec_status(now))
    try:
        live, caddy = caddy_admin.live_config(), {"reachable": True, "message": None}
    except caddy_admin.CaddyUnavailable as e:
        live, caddy = None, {"reachable": False, "message": f"The Caddy admin API is unreachable ({e})."}
    degraded = None
    if info["required"] and info["kind"] in ("journal", "state_corrupt"):
        degraded = {"kind": info["kind"], "reason": info["reason"], "phase": info["phase"], "message": info["summary"]}
    by_source = {name: s["rendered_prefixes"] for name, s in sources.items()}
    text = _read_caddyfile()
    country_facts = _country_facts()               # the dataset is read once per request
    return {
        "enabled": True, "available": avail.ok,
        "unavailable": None if avail.ok else {"code": avail.code, "message": avail.message},
        "state_version": info["state_version"], "degraded": degraded, "recovery": info,
        "sources": sources,
        "protected": protected_for(state or store.State(), _verified_client(remote_addr)).summary(),
        "allowlist": allowlist_info(),
        "sites": _site_rows(live, text, state, now, holds, country_facts),
        "plugin": _plugin_status(live, state, holds, text),
        "client_ip_profile": _profile_status(live, holds, text),
        "country_policy": _country_status(live, holds, country_facts),
        "caddy": caddy,
        "limits": {"max_prefixes": config.BANS_MAX, "used": sum(by_source.values()), "by_source": by_source},
        "last_apply": _last_apply(),
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
        if allowlist_problem() is not None:
            return "allowlist_corrupt"
        now = now or store.utc_now()
        holds = _holds(state)
        removed = store.prune_expired(state, now, sources=[n for n in render.active_sources(state) if n not in holds])
        aged = store.prune_management(state, now)
        if not removed and not aged:
            # Only a record-less policy may be out of date (first start, a
            # CLIENT_IP_MODE default, BANS_NEVER or Docker networks changed):
            # render those alone, writing no ban state.
            changes = [c for c in _aux_changes(protected_for(state), holds) if fsio.read_bytes(c.path) != c.data]
            if not changes:
                return "idle"
            events = [("plugin_route_rendered", _route_detail(c.data)) for c in changes if c.path == render.PLUGIN.path]
            events += [("client_ip_profile_rendered", profile.load_or_default().mode)
                       for c in changes if c.path == render.PROFILE.path]
            events += [("country_policy_rendered", "shape follows the client-IP profile")
                       for c in changes if c.path == render.COUNTRY.path]
            source = "plugin" if any(c.path == render.PLUGIN.path for c in changes) else "profile"
            outcome = txn.apply_locked(changes, actor="system", source=source, audit_events=events)
            return "applied" if outcome.ok else outcome.code
        try:
            changes = _candidates(state, protected_for(state), holds, now)
        except render.CapacityError:
            return "capacity_exceeded"      # BANS_MAX was lowered below the stored bans; never drop one to fit
        outcome = txn.apply_locked(changes, actor="system", source="expiry", audit_events=_expired_events(removed))
        if outcome.ok:
            _after_commit(None)
    return "applied" if outcome.ok else outcome.code


def client_ip_snippet_context() -> dict:
    """What the Cloudflare snippets need before they may be inserted: the saved
    profile mode, whether its trusted proxies file is current, the trusted peers
    and the Cloudflare ranges to put into the origin guard."""
    info = client_ip_profile_info()
    ranges = info["ranges"]
    return {"mode": info["mode"], "current": bool(info["current"] and not info["corrupt"]),
            "peers": info["trusted_peers"], "tunnel_only": info["tunnel_only"],
            "ranges": list(ranges["v4"]) + list(ranges["v6"])}


def plugin_snippet_context(text):
    """What the editor needs to place the plugin snippets (spec 3.6), or None
    when they are not offered (CrowdSec off, or a build without the module)."""
    if not lapi.enabled():
        return None
    module = plugin.module_available()
    if module is False:
        return None
    try:
        live = caddy_admin.live_config()
    except caddy_admin.CaddyUnavailable:
        live = None
    problem = plugin.admin_problem(live) if live is not None else None
    try:
        state = store.load()
    except store.StateCorrupt:
        state = None
    data = fsio.read_bytes(render.PLUGIN.path)
    return {
        "module": module, "blocked": problem.message if problem else "",
        "key_mode": plugin.key_mode(),
        "app_live": plugin.live_app(live) is not None,
        "app_on_disk": bool(re.search(r"(?m)^\s*crowdsec\s*\{", text or "")),
        "definition_target": render.PLUGIN.path,
        "definition_import": scan.mentions_import(text, render.PLUGIN.path),
        "definition_current": data is not None and state is not None and plugin_route_current(state),
        "definition_hash": fsio.sha256_tag(data)[7:19] if data is not None else None,
        "snippet": render.PLUGIN.snippet,
    }
