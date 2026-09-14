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
