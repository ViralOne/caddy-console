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
import os
import shutil
import uuid
from dataclasses import dataclass

from .. import audit
from ..caddy_api import invalidate_servers_cache
from ..config import BACKUP_DIR, CADDYFILE
from . import caddy as caddy_admin
from . import fsio
from .detect import marker_present
from .scan import mentions_import
from .store import iso, utc_now

JOURNAL_PATH = os.path.join(BACKUP_DIR, "bans-transaction.json")
TXN_ROOT = os.path.join(BACKUP_DIR, ".policy-transactions")
JOURNAL_VERSION = 1
STATE_MODE = 0o600
POLICY_MODE = 0o644
MAX_ENTRIES = 16
MAX_AUDIT_EVENTS = 64


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


def _cleanup(journal) -> None:
    for e in journal.get("entries", []):
        _remove_quietly(e.get("temp_path"))
    shutil.rmtree(os.path.join(TXN_ROOT, journal.get("id", "")), ignore_errors=True)
    _remove_quietly(JOURNAL_PATH)
    fsio.fsync_dir(BACKUP_DIR)


def _commit(journal) -> bool:
    """Verify every final file is the candidate, mark the journal committed,
    emit the mutation's audit events, then clean up. Shared by apply_locked
    and the recovery paths, so audit events appear wherever a change commits.
    Raises OSError if the committed journal cannot be written; the journal is
    then still pending and recovery commits it later."""
    if any(fsio.sha256_tag(fsio.read_bytes(e["path"])) != e["candidate_hash"] for e in journal["entries"]):
        return False
    journal["phase"] = "committed"
    _write_journal(journal)
    for action, detail in journal.get("audit") or []:
        audit.log_action(action, journal["actor"], detail)
    _cleanup(journal)
    return True


def _discard(journal) -> None:
    """Undo a preparation that never replaced a final path."""
    for e in journal["entries"]:
        _remove_quietly(e["temp_path"])
    shutil.rmtree(os.path.join(TXN_ROOT, journal["id"]), ignore_errors=True)
    current = None
    try:
        current = read_journal()
    except JournalCorrupt:
        pass
    if current and current.get("id") == journal["id"]:
        _remove_quietly(JOURNAL_PATH)


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


def apply_locked(changes, *, actor: str, source: str, audit_events=()) -> Outcome:
    """Spec 1.5 steps 5-15. audit_events is a sequence of (action, detail) pairs
    for this mutation, written to the audit log only when the change commits."""
    if read_journal() is not None:
        raise RuntimeError("apply_locked() needs resolve_pending() to clear the journal first")
    if len(changes) > MAX_ENTRIES:
        raise ValueError("too many files in one transaction")
    if len(audit_events) > MAX_AUDIT_EVENTS:
        raise ValueError("too many audit events in one transaction")
    _check_embedded_hashes(changes)
    changes = [c for c in changes if fsio.read_bytes(c.path) != c.data]
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
        "reload_required": any(marker_present(live, c.marker) or mentions_import(caddyfile_text, c.path)
                               for c in changes if c.kind == "policy"),
        "audit": [[str(action), str(detail)] for action, detail in audit_events],
    }

    # Steps 6-8: temps, backups and candidate copies, then the journal.
    try:
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
        except OSError as e:
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

    try:
        committed = _commit(journal)
    except OSError as e:
        # Caddy runs the candidate and the files are the candidate; the journal
        # still says "adapted" with a matching hash, so recovery commits it.
        return Outcome(True, None, "applied", "enforced",
                       f"Applied; Caddy reloaded. Clearing the transaction journal failed ({e}); "
                       "it is settled before the next change.")
    if not committed:
        return _hold_ambiguous(journal, Outcome(False, "reload_unknown", "unknown", "unknown",
                                                "A managed file changed during the reload.", 504))
    audit.log_action("bans_policy_applied", actor,
                     f"{source}: " + ", ".join(os.path.basename(e["path"]) for e in journal["entries"]))
    return Outcome(True, None, "applied", "enforced", "Applied; Caddy reloaded.")
