"""CrowdSec decision-stream synchronizer and its leader lock (spec 2.4, 2.6).

Exactly one process leads: it holds a non-blocking flock on
BACKUP_DIR/bans-sync.lock for as long as it lives, polls LAPI and applies the
result through service.apply_crowdsec(). Every gunicorn worker runs a sync
thread that retries the lock once per poll interval, so a dead leader is
replaced within one interval, and a new leader always starts with
startup=true. flock locks belong to an open file description, so two workers
(or two Leadership objects in one process) never both hold it, and the kernel
releases it when the leader exits.

Lock order: bans-sync.lock, then caddyfile_lock() inside apply_crowdsec().
Nothing takes bans-sync.lock while holding caddyfile_lock(), and fetch_stream()
runs before apply_crowdsec(), never inside it.
"""
import collections
import fcntl
import logging
import os
import time

from .. import audit, config
from ..config import BACKUP_DIR
from . import lapi, store, syncstate

LOCK_PATH = os.path.join(BACKUP_DIR, "bans-sync.lock")
AUTH_RETRY_SECONDS = 60
log = logging.getLogger(__name__)
_APPLY_STATES = {"capacity_exceeded": "capacity_exceeded", "held": "held",
                 "corrupt": "degraded", "degraded": "degraded", "unavailable": "degraded"}


class Leadership:
    def __init__(self, path=None):
        self.path, self.fd = path or LOCK_PATH, None

    def try_acquire(self) -> bool:
        if self.fd is not None:
            return True
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return False
        except OSError:
            os.close(fd)
            raise
        self.fd = fd
        return True

    def release(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def _audit(action, detail) -> None:
    try:
        audit.log_action(action, "system", detail)
    except OSError as e:
        log.warning("IP bans: could not write audit event %s: %s", action, e)


class Synchronizer:
    def __init__(self, *, monotonic=time.monotonic, wall=store.utc_now):
        self._mono, self._wall = monotonic, wall
        self.desired = {}                         # decision id -> lapi.Accepted
        self.ignored = collections.Counter()
        self.need_snapshot = True                 # first poll of every leader is startup=true
        self.snapshot_audit = False
        self.key = None
        self.lapi_state, self.lapi_message = "starting", ""
        self.apply_state, self.apply_message = "pending", ""
        self.last_attempt = None                  # monotonic seconds
        self.last_apply = None
        self.last_result = None
        self.times = dict.fromkeys(("last_poll_at", "last_success_at", "last_snapshot_at", "last_apply_at"))

    def _set(self, kind, state, message="") -> None:
        before = getattr(self, kind + "_state")
        setattr(self, kind + "_state", state)
        setattr(self, kind + "_message", message)
        if state == before:
            return                                    # audited and logged once per change, not every poll
        if state == "ok":
            if before not in ("starting", "pending"):
                log.info("IP bans: CrowdSec %s is ok again (was %s)", kind, before)
                _audit("crowdsec_recovered", f"{kind}: ok")
        else:
            log.warning("IP bans: CrowdSec %s %s: %s", kind, state, message)
            _audit("crowdsec_degraded", f"{kind} {state}: {message}")

    def step(self) -> str:
        """One poll, and at most one apply per BANS_SYNC_INTERVAL. Never raises
        for LAPI problems: they become the LAPI state, and enforcement stays."""
        now_m = self._mono()
        key, problem = lapi.read_key()
        if key is None:
            self.need_snapshot = True
            self._set("lapi", "missing_key", problem)
            self._write()
            return self.lapi_state
        rotated = key != self.key
        if rotated:
            self.key, self.need_snapshot = key, True        # first key, or a rotated one
        if (self.lapi_state == "auth_failed" and not rotated and self.last_attempt is not None
                and now_m - self.last_attempt < AUTH_RETRY_SECONDS):
            self._write()                                   # spec 2.6: no delta polling while refused
            return self.lapi_state
        startup = self.need_snapshot
        self.last_attempt = now_m
        fetched_at = self._wall()
        self.times["last_poll_at"] = store.iso(fetched_at)
        try:
            # The query carries the origins as the operator wrote them (LAPI
            # compares case-sensitively); classify() uses the lowercased set.
            stream = lapi.fetch_stream(lapi.url(), key, startup=startup,
                                       origins=lapi.wire_origins(config.CROWDSEC_ORIGINS))
        except lapi.LapiAuthError as e:
            self.need_snapshot = True
            self._set("lapi", "auth_failed", f"LAPI refused the console's bouncer key ({e}). Enforcement is "
                      f"unchanged; a full snapshot follows once the key works (retried every {AUTH_RETRY_SECONDS} s).")
        except lapi.LapiMalformed as e:
            self.need_snapshot = True
            self._set("lapi", "malformed", f"LAPI sent an unusable response ({e}); it was ignored and "
                      "enforcement is unchanged.")
        except lapi.LapiUnavailable as e:
            self.need_snapshot = True
            self._set("lapi", "unreachable", f"LAPI is unreachable ({e}). The last synced list stays enforced.")
        else:
            self._merge(stream, startup, fetched_at)
            self.need_snapshot = False
            self.times["last_success_at"] = store.iso(fetched_at)
            if startup:
                self.times["last_snapshot_at"] = store.iso(fetched_at)
                self.snapshot_audit = True
            self._set("lapi", "ok")
            self._maybe_apply(now_m)
        self._write()
        return self.lapi_state

    def _merge(self, stream, startup, fetched_at) -> None:
        if startup:                                   # reconciliation: the snapshot is the whole truth
            self.desired, self.ignored = {}, collections.Counter()
        for did in stream.deleted:
            self.desired.pop(did, None)               # an unknown id is a no-op
        origins = lapi.origins()
        for d in stream.new:
            accepted, reason = lapi.classify(d, origins, fetched_at)
            if accepted is None:
                self.ignored[reason] += 1
                self.desired.pop(d.id, None)
            else:
                self.desired[d.id] = accepted

    def _maybe_apply(self, now_m) -> None:
        """Every BANS_SYNC_INTERVAL, whether or not a delta arrived: a full
        reconcile is cheap when nothing changed (no write, no reload), and it
        restores records an operator Reset until CrowdSec itself drops them."""
        if self.last_apply is not None and now_m - self.last_apply < config.BANS_SYNC_INTERVAL:
            return
        from . import service                        # service imports the editor routes; keep this lazy
        result = service.apply_crowdsec(list(self.desired.values()), snapshot=self.snapshot_audit,
                                        ignored=dict(self.ignored))
        self.last_apply, self.last_result = now_m, result
        self.times["last_apply_at"] = store.iso(self._wall())
        if result.ok:
            self.snapshot_audit = False
            self._set("apply", "ok")
        else:
            self._set("apply", _APPLY_STATES.get(result.code, "failed"), result.message)

    def _write(self) -> None:
        result = self.last_result
        ignored = dict(self.ignored)
        if result is not None:
            ignored.update({f"protected:{k}": v for k, v in result.protected.items()})
        doc = {"version": syncstate.VERSION, "leader_pid": os.getpid(), "updated_at": store.iso(self._wall()),
               "lapi_state": self.lapi_state, "lapi_message": self.lapi_message,
               "apply_state": self.apply_state, "apply_message": self.apply_message, **self.times,
               "decisions": len(self.desired),
               "by_origin": dict(collections.Counter(a.origin for a in self.desired.values())),
               "ignored": ignored, "protected_sample": result.protected_sample if result else [],
               "capacity": result.capacity if result else None, "origins": list(lapi.origins()),
               "poll_interval": config.CROWDSEC_POLL_INTERVAL, "sync_interval": config.BANS_SYNC_INTERVAL}
        try:
            syncstate.write(doc)
        except OSError as e:
            log.warning("IP bans: could not write the CrowdSec status file: %s", e)
