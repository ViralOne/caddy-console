"""Expiry cleanup at least once per minute, in every gunicorn worker.

Started from gunicorn's post_worker_init, never in the master: the master
would fork workers while its thread could hold caddyfile_lock(), and the
inherited fd would keep that flock held. Ticks from several workers are
serialized by the lock; an idle tick only reads files. The first tick runs
immediately, which is the startup recovery of an unfinished journal. A tick
that cannot complete is logged when that starts or changes, not every tick.

When CrowdSec is configured, every worker also runs a "bans-sync" thread. Only
the worker holding BACKUP_DIR/bans-sync.lock polls LAPI (src/bans/sync.py);
the others retry the lock each poll interval and take over when it exits.
"""
import logging
import os
import threading

from .. import config
from . import lapi

log = logging.getLogger(__name__)
TICK_SECONDS = 30
_started = False
_OK = ("idle", "applied")


def _loop(stop) -> None:
    from . import service
    last = "idle"
    while True:
        try:
            result = service.expire_tick()
            # Persistent states (unavailable, capacity_exceeded, degraded: stuck
            # until an operator acts) are logged when they start or change,
            # not every tick, and once more when ticks complete again.
            if result not in _OK and result != last:
                log.warning("IP bans: expiry tick did not complete (%s)", result)
            elif result in _OK and last not in _OK:
                log.info("IP bans: expiry tick completes again (%s)", result)
            last = result
        except Exception:  # noqa: BLE001 - the thread must survive anything
            log.exception("IP bans: expiry tick crashed")
        if stop.wait(TICK_SECONDS):
            return


def _sync_loop(stop) -> None:
    from . import sync
    leader, synchronizer, crashed, stood_down = sync.Leadership(), None, None, None
    while True:
        try:
            if stood_down and sync.foreign_leader_live(stood_down):
                pass                                 # the other leader still reports: stay a follower
            elif not sync.foreign_host_live() and leader.try_acquire():
                stood_down = None
                if synchronizer is None:
                    synchronizer = sync.Synchronizer()
                    log.info("IP bans: worker %d leads CrowdSec sync", os.getpid())
                if synchronizer.second_leader():
                    # The locks did not exclude (for example two containers on
                    # one BACKUP_DIR whose flock does not work). Two leaders
                    # would flap bans, so this one yields while the other reports.
                    log.error("IP bans: a second CrowdSec sync leader wrote the status file; worker %d steps "
                              "down until that leader stops reporting. Check that BACKUP_DIR is a local "
                              "filesystem and that only one console container uses it.", os.getpid())
                    leader.stand_down()
                    synchronizer, stood_down = None, synchronizer.nonce
                else:
                    synchronizer.step()
            if crashed is not None:
                log.info("IP bans: CrowdSec sync steps complete again")
            crashed = None
        except Exception as e:  # noqa: BLE001 - the thread must survive anything
            # A repeating crash (for example an unwritable BACKUP_DIR) is
            # logged when it starts or changes, not every poll.
            kind = f"{type(e).__name__}: {e}"
            if kind != crashed:
                log.exception("IP bans: CrowdSec sync step crashed")
            crashed = kind
        if stop.wait(config.CROWDSEC_POLL_INTERVAL):
            leader.release()
            return


RANGES_TICK_SECONDS = 3600


def _ranges_loop(stop) -> None:
    """Daily Cloudflare range refresh (spec 4.2); ranges_tick decides whether one is due."""
    from . import service
    while True:
        try:
            result = service.ranges_tick()
            if result == "failed":
                log.warning("IP bans: Cloudflare range refresh failed; the last good list stays")
        except Exception:  # noqa: BLE001 - the thread must survive anything
            log.exception("IP bans: Cloudflare range refresh crashed")
        if stop.wait(RANGES_TICK_SECONDS):
            return


COUNTRY_TICK_SECONDS = 3600


def _country_loop(stop) -> None:
    """Regenerate geo.caddy after a new country dataset (spec 4.3)."""
    from . import service
    while True:
        try:
            result = service.country_tick()
            if result not in ("disabled", "not_needed", "current", "applied"):
                log.warning("IP bans: country policy refresh did not complete (%s); the last good file stays", result)
        except Exception:  # noqa: BLE001 - the thread must survive anything
            log.exception("IP bans: country policy refresh crashed")
        if stop.wait(COUNTRY_TICK_SECONDS):
            return


def start_background():
    global _started
    if _started or not config.BANS_ENABLED:
        return None
    _started = True
    stop = threading.Event()
    threading.Thread(target=_loop, args=(stop,), name="bans-expiry", daemon=True).start()
    if config.CLOUDFLARE_RANGES_AUTO_UPDATE:
        threading.Thread(target=_ranges_loop, args=(stop,), name="cloudflare-ranges", daemon=True).start()
    threading.Thread(target=_country_loop, args=(stop,), name="country-policy", daemon=True).start()
    if lapi.enabled():
        threading.Thread(target=_sync_loop, args=(stop,), name="bans-sync", daemon=True).start()
    return stop
