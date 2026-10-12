import os

import gunicorn

gunicorn.SERVER = "Microsoft-IIS/10.0"

workers = int(os.environ.get("GUNICORN_WORKERS", "2"))
threads = int(os.environ.get("GUNICORN_THREADS", "4"))

timeout = int(os.environ.get("GUNICORN_TIMEOUT", "90"))
graceful_timeout = 30

# Load the app once in the master so every worker shares the same generated
# session key. Incompatible with --reload (workers would be forked with the
# already-imported code), so the dev stack turns it off via GUNICORN_PRELOAD=false.
preload_app = os.environ.get("GUNICORN_PRELOAD", "true").lower() != "false"


def when_ready(server):
    # In the master, so there is one GeoIP updater however many workers run;
    # workers are forked without this thread and just reopen the files it swaps.
    import logging
    from src.geoip_update import start_background
    # Its messages go to gunicorn's error log, next to everything else.
    updater_log = logging.getLogger("src.geoip_update")
    updater_log.handlers = server.log.error_log.handlers
    updater_log.setLevel(logging.INFO)
    updater_log.propagate = False
    start_background()
