"""One journaled transaction for console-managed state and policy files (spec 1.5).

Manual bans use it now; CrowdSec sync, country policy and Cloudflare ranges
(Phases 2-4) pass their own Change lists to the same functions. The caller
always holds caddyfile_lock() and has run resolve_pending(), so exactly one
transaction is ever in flight. Nothing here takes that lock.

On disk, in order:
  1. hidden temp files beside each target (".<name>.<random>.tmp", never *.caddy)
  2. BACKUP_DIR/.policy-transactions/<id>/NN-<name>.prev.bak and .cand.bak
  3. BACKUP_DIR/bans-transaction.json, phase "prepared"
  4. os.replace() of every policy, then every state file; journal flushed after each
  5. adapt, /load, verify live == adapted; commit marks the journal, emits the
     mutation's audit events, then deletes it

The journal carries the mutation's audit events, so they are written exactly
when the change commits: here, or later by recovery when Caddy is found running
the candidate. A change that rolls back is never audited as made.
"""
import json
import logging
import os
import re
import shutil
import uuid
from dataclasses import dataclass

from .. import audit, config
from ..caddy_api import invalidate_servers_cache
from ..config import BACKUP_DIR, CADDYFILE
from . import caddy as caddy_admin
from . import fsio
from .detect import marker_present
from .scan import imports_files, mentions_import
from .store import iso, utc_now

JOURNAL_PATH = os.path.join(BACKUP_DIR, "bans-transaction.json")
TXN_ROOT = os.path.join(BACKUP_DIR, ".policy-transactions")
JOURNAL_VERSION = 1
STATE_MODE = 0o600
POLICY_MODE = 0o644
MAX_ENTRIES = 16
MAX_AUDIT_EVENTS = 64

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Change:
    """One file to replace. A state file names the policy files it owns; their
    candidate hashes must already be embedded in its last_rendered_hashes."""
    path: str
    kind: str                       # "state" | "policy"
    data: bytes
    marker: object = None           # policy: its live vars marker, for reload need
    owns: tuple = ()                # state: basenames of the policies it owns


@dataclass
class Outcome:
    ok: bool
    code: object
    reload_status: str              # applied | not_required | not_attempted | rejected | failed | unknown
    enforcement: str                # enforced | not_enabled | unchanged | unknown
    message: str
    http_status: int = 200


class JournalCorrupt(Exception):
    pass


def _checkpoint(name: str) -> None:
    """Crash-injection seam for tests. Does nothing in production."""


def read_journal():
    try:
        with open(JOURNAL_PATH, "rb") as f:
            raw = f.read(1024 * 1024)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise JournalCorrupt(f"Cannot read the transaction journal ({e.strerror or e})") from None
    try:
        doc = json.loads(raw.decode("utf-8"))
        if doc.get("version") != JOURNAL_VERSION or not isinstance(doc.get("entries"), list):
            raise ValueError("unknown journal format")
    except (ValueError, AttributeError, UnicodeDecodeError, RecursionError) as e:
        raise JournalCorrupt(f"The transaction journal is unreadable ({e})") from None
    return doc


def _write_journal(journal) -> None:
    fsio.atomic_write(JOURNAL_PATH, json.dumps(journal, sort_keys=True, indent=1).encode("utf-8"), STATE_MODE)


def _remove_quietly(path) -> None:
    if path:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass


def _check_embedded_hashes(changes) -> None:
    """Spec step 5: every candidate state already embeds the candidate hash of
    each policy it owns, and every changed policy has an owner."""
    policies = {os.path.basename(c.path): c for c in changes if c.kind == "policy"}
    owned = set()
    for c in changes:
        if c.kind not in ("state", "policy"):
            raise ValueError(f"unknown change kind {c.kind!r}")
        if c.kind != "state":
            continue
        hashes = json.loads(c.data.decode("utf-8")).get("last_rendered_hashes", {})
        for name in c.owns:
            owned.add(name)
            if name in policies and hashes.get(name) != fsio.sha256_tag(policies[name].data):
                raise ValueError(f"{os.path.basename(c.path)} does not embed the candidate hash of {name}")
    if set(policies) - owned:
        raise ValueError(f"no state file in this transaction owns {sorted(set(policies) - owned)}")


def _restore_files(journal) -> None:
    """Put every entry back to its previous bytes (or absence), state first. Idempotent."""
    for e in sorted(journal["entries"], key=lambda e: e["kind"] == "policy"):
        name = os.path.basename(e["path"])
        current = fsio.sha256_tag(fsio.read_bytes(e["path"]))
        if current == e["candidate_hash"]:
            if e["backup_path"] is None:
                os.remove(e["path"])
                fsio.fsync_dir(os.path.dirname(e["path"]))
            else:
                data = fsio.read_bytes(e["backup_path"])
                if fsio.sha256_tag(data) != e["previous_hash"]:
                    raise ValueError(f"the backup of {name} does not match its recorded hash")
                fsio.atomic_write(e["path"], data, e["mode"])
        elif current != e["previous_hash"]:
            raise ValueError(f"{name} changed outside this transaction")
        _remove_quietly(e["temp_path"])


def _finish_candidate(journal) -> None:
    """Put every entry at its candidate bytes, policies first. Idempotent."""
    for e in sorted(journal["entries"], key=lambda e: e["kind"] != "policy"):
        name = os.path.basename(e["path"])
        current = fsio.sha256_tag(fsio.read_bytes(e["path"]))
        if current != e["candidate_hash"]:
            if current != e["previous_hash"]:
                raise ValueError(f"{name} changed outside this transaction")
            data = fsio.read_bytes(e["candidate_path"])
            if fsio.sha256_tag(data) != e["candidate_hash"]:
                raise ValueError(f"the saved new version of {name} does not match its recorded hash")
            fsio.atomic_write(e["path"], data, e["mode"])
        _remove_quietly(e["temp_path"])


def _remove_debris(journal) -> None:
    """Temps and the transaction directory. Called only once the journal is
    gone: a journal must never name backups that no longer exist, while
    orphaned backups and hidden temps are harmless (the sweep removes them)."""
    for e in journal.get("entries", []):
        _remove_quietly(e.get("temp_path"))
    shutil.rmtree(os.path.join(TXN_ROOT, journal.get("id", "")), ignore_errors=True)


def _cleanup(journal) -> None:
    _remove_quietly(JOURNAL_PATH)
    fsio.fsync_dir(BACKUP_DIR)
    _remove_debris(journal)


def _audit_quietly(action, actor, detail) -> None:
    """Post-commit audit: a failing audit log must not undo a committed change."""
    try:
        audit.log_action(action, actor, detail)
    except OSError as e:
        log.warning("Could not write audit event %s: %s", action, e)


def _commit(journal) -> bool:
    """Verify every final file is the candidate, mark the journal committed,
    emit the mutation's audit events, then clean up. Shared by apply_locked
    and the recovery paths, so audit events appear wherever a change commits.

    Only an OSError from writing the committed journal means "not committed";
    it propagates and the journal stays pending for recovery. After that write
    the change is committed: audit and cleanup failures are logged, never raised."""
    if any(fsio.sha256_tag(fsio.read_bytes(e["path"])) != e["candidate_hash"] for e in journal["entries"]):
        return False
    journal["phase"] = "committed"
    _write_journal(journal)
    for action, detail in journal.get("audit") or []:
        _audit_quietly(action, journal["actor"], detail)
    try:
        _cleanup(journal)
    except OSError as e:
        log.warning("Could not clean up committed ban transaction %s: %s", journal.get("id"), e)
    return True


def _discard(journal) -> None:
    """Undo a preparation that never replaced a final path."""
    current = None
    try:
        current = read_journal()
    except JournalCorrupt:
        pass
    if current and current.get("id") == journal["id"]:
        _remove_quietly(JOURNAL_PATH)
        fsio.fsync_dir(BACKUP_DIR)
    _remove_debris(journal)


def _rollback(journal, code, message, http_status, reload_status) -> Outcome:
    try:
        _restore_files(journal)
        _cleanup(journal)
        return Outcome(False, code, reload_status, "unchanged",
                       message + " The previous files were restored.", http_status)
    except (OSError, ValueError) as e:
        journal["phase"] = "rollback_failed"
        try:
            _write_journal(journal)
        except OSError:
            pass
        audit.log_action("bans_rollback_failed", journal["actor"], f"{journal['source']}: {type(e).__name__}: {e}")
        return Outcome(False, "rollback_failed", reload_status, "unknown",
                       f"{message} Restoring the previous files also failed ({e}); open Security to recover.", 500)


def _hold_ambiguous(journal, outcome: Outcome) -> Outcome:
    """Spec step 15: never claim rollback. Keep the candidate files and journal."""
    status = outcome.reload_status                    # failed | unknown
    journal["phase"] = f"reload_{status}"
    try:
        _write_journal(journal)
    except OSError:
        pass
    audit.log_action(f"bans_reload_{status}", journal["actor"], journal["source"])
    return Outcome(False, outcome.code, status, "unknown",
                   f"{outcome.message} The new files stay on disk and further changes wait until the running "
                   "configuration is verified.", outcome.http_status)


def _adapt_load_verify(text: str, on_adapted=None):
    """Adapt the on-disk Caddyfile, POST it to /load and verify live /config/
    equals the adapted result. Returns (None, expected_hash) on success, else
    (failure Outcome, expected_hash or None). Failure codes: caddy_unreachable,
    adaptation_failed (both before /load), reload_rejected, reload_failed,
    reload_unknown. on_adapted(expected_hash), if given, runs between adapt and
    /load; a non-None Outcome it returns aborts before /load."""
    try:
        adapted = caddy_admin.adapt(text)
    except caddy_admin.CaddyUnavailable as e:
        return Outcome(False, "caddy_unreachable", "not_attempted", "unknown",
                       f"Caddy could not adapt the configuration ({e}).", 503), None
    if not adapted.ok:
        return Outcome(False, "adaptation_failed", "not_attempted", "unknown",
                       f"Caddy rejected the configuration: {adapted.message[:2000]}.", 422), None
    expected = caddy_admin.config_hash(adapted.config)
    if on_adapted is not None:
        abort = on_adapted(expected)
        if abort is not None:
            return abort, expected

    result = caddy_admin.load(text)
    invalidate_servers_cache()
    _checkpoint("loaded")
    if result.status == "rejected":
        return Outcome(False, "reload_rejected", "rejected", "unknown",
                       f"Caddy rejected the reload and keeps its running configuration: {result.message}",
                       502), expected
    if result.status == "failed":
        return Outcome(False, "reload_failed", "failed", "unknown", result.message, 503), expected
    if result.status != "applied":
        return Outcome(False, "reload_unknown", "unknown", "unknown", result.message, 504), expected
    try:
        live_after = caddy_admin.config_hash(caddy_admin.live_config())
    except caddy_admin.CaddyUnavailable:
        live_after = None
    if live_after != expected:
        return Outcome(False, "reload_unknown", "unknown", "unknown",
                       "Caddy accepted the reload, but its running configuration does not match "
                       "the adapted configuration.", 504), expected
    return None, expected


def _could_import(live, caddyfile_text, change, created) -> bool:
    """Whether Caddy may load this policy, so the change needs a reload. The
    console only reads the main Caddyfile: an import in an included file is
    invisible to it, and the live config has no marker while the policy file
    did not exist at the last load. Creating the file therefore reloads once
    whenever the Caddyfile imports any file."""
    return (marker_present(live, change.marker) or mentions_import(caddyfile_text, change.path)
            or (created and imports_files(caddyfile_text)))


def _reload_unchanged(changes, actor, source, audit_events) -> Outcome:
    """Re-apply with nothing to write: adapt, /load and verify the unchanged
    files, so Caddy picks up a policy it never loaded. No journal is needed,
    because no file changes; a failed or ambiguous /load leaves the files as
    they were and the next change or status check reads Caddy again."""
    try:
        live = caddy_admin.live_config()
        with open(CADDYFILE, encoding="utf-8", newline="") as f:
            caddyfile_text = f.read()
    except caddy_admin.CaddyUnavailable as e:
        return Outcome(False, "caddy_unreachable", "not_attempted", "unknown",
                       f"The Caddy admin API is unreachable ({e}); nothing was changed.", 503)
    except FileNotFoundError:
        caddyfile_text = ""
    except (OSError, UnicodeError) as e:
        return Outcome(False, "write_failed", "not_attempted", "unchanged", f"Cannot read the Caddyfile: {e}", 500)
    if not any(_could_import(live, caddyfile_text, c, True) for c in changes if c.kind == "policy"):
        for action, detail in audit_events:
            audit.log_action(action, actor, detail)
        return Outcome(True, None, "not_required", "not_enabled",
                       "Nothing to change, and no site imports this policy, so Caddy was not reloaded.")
    failure, _ = _adapt_load_verify(caddyfile_text)
    if failure is not None:
        if failure.code == "adaptation_failed":
            audit.log_action("bans_adapt_rejected", actor, f"{source}: {failure.message[:200]}")
        elif failure.code == "reload_rejected":
            audit.log_action("bans_reload_rejected", actor, f"{source}: {failure.message[:200]}")
        return failure
    for action, detail in audit_events:
        _audit_quietly(action, actor, detail)
    _audit_quietly("bans_policy_applied", actor, f"{source}: reloaded unchanged files")
    return Outcome(True, None, "applied", "enforced", "Re-applied; Caddy reloaded.")


def apply_locked(changes, *, actor: str, source: str, audit_events=(), force_reload=False) -> Outcome:
    """Spec 1.5 steps 5-15. audit_events is a sequence of (action, detail) pairs
    for this mutation, written to the audit log only when the change commits.
    force_reload (Re-apply) reloads Caddy even when no file changes, as long as
    the Caddyfile could import a managed policy."""
    if read_journal() is not None:
        raise RuntimeError("apply_locked() needs resolve_pending() to clear the journal first")
    if len(changes) > MAX_ENTRIES:
        raise ValueError("too many files in one transaction")
    if len(audit_events) > MAX_AUDIT_EVENTS:
        raise ValueError("too many audit events in one transaction")
    _check_embedded_hashes(changes)
    all_changes = changes
    changes = [c for c in changes if fsio.read_bytes(c.path) != c.data]
    if not changes and force_reload:
        return _reload_unchanged(all_changes, actor, source, audit_events)
    if not changes:
        for action, detail in audit_events:
            audit.log_action(action, actor, detail)
        return Outcome(True, None, "not_required", "unchanged", "Nothing to change.")

    try:
        live = caddy_admin.live_config()
    except caddy_admin.CaddyUnavailable as e:
        return Outcome(False, "caddy_unreachable", "not_attempted", "unknown",
                       f"The Caddy admin API is unreachable ({e}); nothing was changed.", 503)
    try:
        with open(CADDYFILE, encoding="utf-8", newline="") as f:
            caddyfile_text = f.read()
    except FileNotFoundError:
        caddyfile_text = ""
    except (OSError, UnicodeError) as e:
        return Outcome(False, "write_failed", "not_attempted", "unchanged", f"Cannot read the Caddyfile: {e}", 500)

    txid = uuid.uuid4().hex
    txdir = os.path.join(TXN_ROOT, txid)
    journal = {
        "version": JOURNAL_VERSION, "id": txid, "phase": "preparing", "actor": actor, "source": source,
        "created_at": iso(utc_now()), "entries": [], "replaced_paths": [],
        "previous_live_hash": caddy_admin.config_hash(live), "candidate_live_hash": None,
        "reload_required": any(_could_import(live, caddyfile_text, c, force_reload or fsio.read_bytes(c.path) is None)
                               for c in changes if c.kind == "policy"),
        "audit": [[str(action), str(detail)] for action, detail in audit_events],
    }

    # Steps 6-8: temps, backups and candidate copies, then the journal.
    try:
        os.makedirs(TXN_ROOT, mode=0o700, exist_ok=True)
        os.makedirs(txdir, mode=0o700)
        previous = []
        for i, c in enumerate(changes):
            prev = fsio.read_bytes(c.path)
            previous.append(prev)
            stem = os.path.join(txdir, f"{i:02d}-{os.path.basename(c.path)}")
            entry = {"path": c.path, "kind": c.kind,
                     "mode": POLICY_MODE if c.kind == "policy" else STATE_MODE,
                     "previous_hash": fsio.sha256_tag(prev), "candidate_hash": fsio.sha256_tag(c.data),
                     "temp_path": None, "backup_path": None if prev is None else stem + ".prev.bak",
                     "candidate_path": stem + ".cand.bak"}
            journal["entries"].append(entry)
            entry["temp_path"] = fsio.write_temp(os.path.dirname(c.path), os.path.basename(c.path),
                                                 c.data, entry["mode"])
        _checkpoint("temps_written")
        for c, prev, e in zip(changes, previous, journal["entries"]):
            if prev is not None:
                fsio.atomic_write(e["backup_path"], prev, STATE_MODE)
            fsio.atomic_write(e["candidate_path"], c.data, STATE_MODE)
        fsio.fsync_dir(txdir)
        fsio.fsync_dir(TXN_ROOT)
        _checkpoint("backups_written")
        journal["phase"] = "prepared"
        _write_journal(journal)
        _checkpoint("journal_prepared")
    except OSError as e:
        _discard(journal)
        return Outcome(False, "write_failed", "not_attempted", "unchanged", f"Could not prepare the change: {e}", 500)

    # Step 9: policies first, then state; the journal records each replace.
    try:
        for e in sorted(journal["entries"], key=lambda e: e["kind"] != "policy"):
            os.replace(e["temp_path"], e["path"])
            fsio.fsync_dir(os.path.dirname(e["path"]))
            journal["replaced_paths"].append(e["path"])
            _write_journal(journal)
            _checkpoint("replaced:" + os.path.basename(e["path"]))
    except OSError as e:
        return _rollback(journal, "write_failed", f"Could not replace the managed files: {e}.", 500, "not_attempted")

    # Step 10: nothing imports a changed policy, so Caddy has nothing to reload.
    # Caddy still runs the previous live hash, so a journal left behind by a
    # failed commit would be restored by recovery: roll back now to match.
    if not journal["reload_required"]:
        try:
            committed = _commit(journal)
        except OSError as e:               # the committed journal was never written
            return _rollback(journal, "write_failed", f"Could not commit the change: {e}.", 500, "not_attempted")
        if not committed:
            return _rollback(journal, "write_failed", "A managed file changed during the update.", 500, "not_attempted")
        return Outcome(True, None, "not_required", "not_enabled",
                       "Stored. No site imports this policy yet, so Caddy was not reloaded.")

    # Steps 11-13: adapt the unchanged on-disk Caddyfile with the candidates
    # present, record the adapted hash, then /load and verify.
    def record_adapted(expected):
        journal["candidate_live_hash"] = expected
        journal["phase"] = "adapted"
        try:
            _write_journal(journal)
        except OSError as e:
            return Outcome(False, "write_failed", "not_attempted", "unknown", f"Could not update the journal: {e}.", 500)
        _checkpoint("adapted")
        return None

    failure, _ = _adapt_load_verify(caddyfile_text, on_adapted=record_adapted)
    if failure is not None:
        if failure.code == "adaptation_failed":
            audit.log_action("bans_adapt_rejected", actor, f"{source}: {failure.message[:200]}")
        elif failure.code == "reload_rejected":
            audit.log_action("bans_reload_rejected", actor, f"{source}: {failure.message[:200]}")
        if failure.code in ("reload_failed", "reload_unknown"):
            return _hold_ambiguous(journal, failure)
        # Spec steps 11 and 14: nothing new is running, so restore every entry.
        return _rollback(journal, failure.code, failure.message, failure.http_status, failure.reload_status)

    applied_detail = f"{source}: " + ", ".join(os.path.basename(e["path"]) for e in journal["entries"])
    try:
        committed = _commit(journal)
    except OSError as e:
        # The committed journal was never written. Caddy runs the candidate and
        # the files are the candidate; the journal still says "adapted" with a
        # matching hash, so recovery commits it (and emits its audit events).
        _audit_quietly("bans_policy_applied", actor, applied_detail)
        return Outcome(True, None, "applied", "enforced",
                       f"Applied; Caddy reloaded. Recording the commit failed ({e}); "
                       "it is settled before the next change.")
    if not committed:
        return _hold_ambiguous(journal, Outcome(False, "reload_unknown", "unknown", "unknown",
                                                "A managed file changed during the reload.", 504))
    _audit_quietly("bans_policy_applied", actor, applied_detail)
    return Outcome(True, None, "applied", "enforced", "Applied; Caddy reloaded.")


# ---------------------------------------------------------------------------
# Recovery (spec 1.5 "At startup", 1.6). The caller holds caddyfile_lock().

# Hidden temps, plus the availability probe (service._probe) left by a crash.
_ORPHAN_BANS_DIR = re.compile(r"^(\..+\.caddy\.[A-Za-z0-9_]+\.tmp|\.console-probe-[0-9a-z]+\.probe)$")
_ORPHAN_BACKUP_DIR = re.compile(
    r"^\.(bans\.json|bans-transaction\.json|plugin-policy\.json|cloudflare-ranges\.json|country-policy\.json|allowlist\.json)"
    r"\.[A-Za-z0-9_]+\.tmp$")


@dataclass
class Pending:
    reason: str           # journal_corrupt | hash_mismatch | caddy_unreachable | live_mismatch | rollback_failed
    message: str
    journal: object = None


def _sweep_orphans(journal=None) -> None:
    """Remove hidden temps and transaction directories the current journal (if
    any) does not reference: debris from a crash before a journal was written.
    Only files written under caddyfile_lock() match, and none of them can match
    an import glob, so removing them never changes what Caddy loads."""
    keep_temps = {e.get("temp_path") for e in (journal or {}).get("entries", [])}
    keep_dir = (journal or {}).get("id")
    for directory, pattern in ((config.BANS_DIR, _ORPHAN_BANS_DIR), (BACKUP_DIR, _ORPHAN_BACKUP_DIR)):
        try:
            names = os.listdir(directory)
        except OSError:
            continue
        for name in names:
            path = os.path.join(directory, name)
            if pattern.match(name) and path not in keep_temps:
                try:
                    _remove_quietly(path)
                except OSError as e:
                    log.warning("Could not remove leftover temp file %s: %s", path, e)
    try:
        names = os.listdir(TXN_ROOT)
    except OSError:
        return
    for name in names:
        if name != keep_dir:
            shutil.rmtree(os.path.join(TXN_ROOT, name), ignore_errors=True)


def _verify_files(journal):
    """Spec startup step 1. Returns a problem message, or None if every current,
    backup and candidate hash named by the journal checks out."""
    try:
        for e in journal["entries"]:
            name = os.path.basename(e["path"])
            if fsio.sha256_tag(fsio.read_bytes(e["path"])) not in (e["previous_hash"], e["candidate_hash"]):
                return f"{name} changed outside the console while a transaction was pending."
            if e["backup_path"] and fsio.sha256_tag(fsio.read_bytes(e["backup_path"])) != e["previous_hash"]:
                return f"The backup of {name} is missing or damaged."
            if fsio.sha256_tag(fsio.read_bytes(e["candidate_path"])) != e["candidate_hash"]:
                return f"The saved new version of {name} is missing or damaged."
    except (OSError, KeyError, TypeError) as e:
        return f"The files named by the transaction journal cannot be checked ({e})."
    return None


def _recovered(journal, how: str) -> None:
    _audit_quietly("bans_recovered", "system", f"{journal['source']}: {how}")


def resolve_pending():
    """Settle an unfinished journal from what Caddy is actually running.

    Runs before every mutation and on every expiry tick, so the first tick after
    a restart is the startup recovery. Never POSTs /load and never guesses:
    live == candidate finishes, live == previous restores, anything else waits
    for an operator action. A journal already marked committed is only cleaned
    up: its audit events were emitted when it was marked.
    """
    try:
        journal = read_journal()
    except JournalCorrupt as e:
        return Pending("journal_corrupt", f"{e}. Restore the managed files by hand; see docs/security.md.")
    _sweep_orphans(journal)
    if journal is None:
        return None
    if journal.get("phase") == "committed":
        _cleanup(journal)
        return None
    problem = _verify_files(journal)
    if problem:
        return Pending("hash_mismatch", problem, journal)
    try:
        live_hash = caddy_admin.config_hash(caddy_admin.live_config())
    except caddy_admin.CaddyUnavailable as e:
        return Pending("caddy_unreachable",
                       f"A {journal['source']} change is pending and the Caddy admin API is unreachable ({e}). "
                       "It is settled automatically once Caddy answers.", journal)
    try:
        if journal.get("candidate_live_hash") and live_hash == journal["candidate_live_hash"]:
            _finish_candidate(journal)
            if not _commit(journal):
                return Pending("hash_mismatch", "A managed file changed while finishing the pending change.", journal)
            _recovered(journal, "Caddy runs the new policy; finished it")
            return None
        if live_hash == journal["previous_live_hash"]:
            _restore_files(journal)
            _cleanup(journal)
            _recovered(journal, "Caddy runs the previous policy; restored it")
            return None
    except (OSError, ValueError) as e:
        return Pending("rollback_failed", f"Settling the pending change failed: {e}", journal)
    return Pending("live_mismatch",
                   "Caddy's running configuration matches neither the previous nor the new policy. "
                   "Choose which files to keep; the console then reloads Caddy.", journal)


RECOVERY_ACTIONS = ("use_candidate", "use_previous")


def recovery_action(action: str, actor: str) -> Outcome:
    """Operator choice for a pending journal: keep the candidate or the previous
    files, then adapt, /load and verify the on-disk Caddyfile. The journal is
    removed only after Caddy confirms; the caller audits the action itself.

    Before /load the journal records the adapted hash as the chosen side's live
    hash, so a crash after /load is settled by the next resolve_pending()."""
    if action not in RECOVERY_ACTIONS:
        return Outcome(False, "invalid_action", "not_attempted", "unknown",
                       f"Unknown recovery action {action!r}.", 400)
    try:
        journal = read_journal()
    except JournalCorrupt as e:
        return Outcome(False, "recovery_blocked", "not_attempted", "unknown",
                       f"{e}. Restore the managed files by hand; see docs/security.md.", 409)
    if journal is None:
        return Outcome(True, None, "not_required", "unchanged", "Nothing to recover.")
    if journal.get("phase") == "committed":
        _cleanup(journal)
        return Outcome(True, None, "not_required", "unchanged", "Nothing to recover.")
    problem = _verify_files(journal)
    if problem:
        return Outcome(False, "recovery_blocked", "not_attempted", "unknown",
                       problem + " Restore the files by hand; see docs/security.md.", 409)
    try:
        if action == "use_candidate":
            _finish_candidate(journal)
        else:
            _restore_files(journal)
        with open(CADDYFILE, encoding="utf-8", newline="") as f:
            text = f.read()
    except (OSError, UnicodeError, ValueError) as e:
        return Outcome(False, "write_failed", "not_attempted", "unknown", f"Could not prepare the files: {e}", 500)

    hash_key = "candidate_live_hash" if action == "use_candidate" else "previous_live_hash"

    def record_adapted(expected):
        journal[hash_key] = expected
        journal["phase"] = f"recovery_{action}"
        try:
            _write_journal(journal)
        except OSError as e:
            return Outcome(False, "write_failed", "not_attempted", "unknown", f"Could not update the journal: {e}.", 500)
        return None

    failure, _ = _adapt_load_verify(text, on_adapted=record_adapted)
    if failure is not None:
        return failure
    if action == "use_previous":
        _cleanup(journal)
        return Outcome(True, None, "applied", "unchanged", "Recovered the previous files; Caddy reloaded.")
    try:
        committed = _commit(journal)
    except OSError as e:
        return Outcome(True, None, "applied", "enforced",
                       f"Recovered; Caddy reloaded. Recording the commit failed ({e}); "
                       "it is settled before the next change.")
    if not committed:
        return Outcome(False, "reload_unknown", "unknown", "unknown",
                       "A managed file changed during the recovery reload.", 504)
    return Outcome(True, None, "applied", "enforced", "Recovered the new files; Caddy reloaded.")


def reconcile_after_external_reload() -> None:
    """The editor just loaded the on-disk Caddyfile successfully, which also
    loaded whatever managed policy is on disk. Settle a pending journal to match
    so Security is not left degraded. Mixed states wait for the operator."""
    try:
        journal = read_journal()
    except JournalCorrupt:
        return
    if journal is None:
        return
    if journal.get("phase") == "committed":
        _cleanup(journal)
        return
    if _verify_files(journal):
        return
    policies = [e for e in journal["entries"] if e["kind"] == "policy"]
    current = {e["path"]: fsio.sha256_tag(fsio.read_bytes(e["path"])) for e in policies}
    try:
        if all(current[e["path"]] == e["candidate_hash"] for e in policies):
            _finish_candidate(journal)
            if _commit(journal):
                _recovered(journal, "a Caddyfile reload loaded the new policy")
        elif all(current[e["path"]] == e["previous_hash"] for e in policies):
            _restore_files(journal)
            _cleanup(journal)
            _recovered(journal, "a Caddyfile reload kept the previous policy")
    except (OSError, ValueError) as e:
        log.warning("Could not settle ban transaction %s after a reload: %s", journal.get("id"), e)
