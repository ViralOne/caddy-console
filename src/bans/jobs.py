"""Expiry cleanup at least once per minute, in every gunicorn worker.

Started from gunicorn's post_worker_init, never in the master: the master
would fork workers while its thread could hold caddyfile_lock(), and the
inherited fd would keep that flock held. Ticks from several workers are
serialized by the lock; an idle tick only reads files. The first tick runs
immediately, which is the startup recovery of an unfinished journal.
"""
import logging
import threading

from .. import config

log = logging.getLogger(__name__)
TICK_SECONDS = 30
_started = False


def _loop(stop) -> None:
    from . import service
    while True:
        try:
            result = service.expire_tick()
            if result not in ("idle", "applied"):
                # e.g. capacity_exceeded or degraded: expiries are stuck until an operator acts.
                log.warning("IP bans: expiry tick did not complete (%s)", result)
        except Exception:  # noqa: BLE001 - the thread must survive anything
            log.exception("IP bans: expiry tick crashed")
        if stop.wait(TICK_SECONDS):
            return


def start_background():
    global _started
    if _started or not config.BANS_ENABLED:
        return None
    _started = True
    stop = threading.Event()
    threading.Thread(target=_loop, args=(stop,), name="bans-expiry", daemon=True).start()
    return stop
