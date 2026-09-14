import os

import gunicorn

gunicorn.SERVER = "Microsoft-IIS/10.0"

workers = int(os.environ.get("GUNICORN_WORKERS", "2"))
threads = int(os.environ.get("GUNICORN_THREADS", "4"))

timeout = int(os.environ.get("GUNICORN_TIMEOUT", "90"))
graceful_timeout = 30

preload_app = True
