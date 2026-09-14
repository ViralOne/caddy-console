"""Test environment. Import this before anything from `src`.

src.config reads its settings at import time, so every test module must agree
on them; this is the one place they are set. Everything lives in one temp dir
so the tests never touch /etc/caddy or /backups.
"""
import os
import tempfile

ROOT = tempfile.mkdtemp(prefix="caddy-editor-test-")
BACKUP_DIR = os.path.join(ROOT, "backups")
CADDYFILE = os.path.join(ROOT, "Caddyfile")
AUDIT_LOG = os.path.join(BACKUP_DIR, "audit.log")
LOG_FILE = os.path.join(ROOT, "access.log")

os.environ.update({
    "BACKUP_DIR": BACKUP_DIR,
    "CADDYFILE_PATH": CADDYFILE,
    "AUDIT_LOG": AUDIT_LOG,
    "CADDY_LOG_FILE": LOG_FILE,
    "AUTH_MODE": "cloudflare",
    "ALLOWED_EMAILS": "admin@example.com",
    "SESSION_COOKIE_SECURE": "false",
    "BACKUP_KEEP": "3",
    "AUDIT_LOG_MAX_BYTES": "400",
    "CADDY_API_URL": "http://caddy.invalid:2019",
})
