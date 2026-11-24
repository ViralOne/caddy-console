"""Expiry cleanup at least once per minute, in every gunicorn worker.

Started from gunicorn's post_worker_init, never in the master: the master
would fork workers while its thread could hold caddyfile_lock(), and the
inherited fd would keep that flock held. Ticks from several workers are
serialized by the lock; an idle tick only reads files. The first tick runs
immediately, which is the startup recovery of an unfinished journal. A tick
that cannot complete is logged when that starts or changes, not every tick.
"""
import logging
import threading

from .. import config

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


def start_background():
    global _started
    if _started or not config.BANS_ENABLED:
        return None
    _started = True
    stop = threading.Event()
    threading.Thread(target=_loop, args=(stop,), name="bans-expiry", daemon=True).start()
    return stop
