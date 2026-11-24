"""Test environment. Import this before anything from `src`.

src.config reads its settings at import time, so every test module must agree
on them; this is the one place they are set. Everything lives in one temp dir
so the tests never touch /etc/caddy or /backups.
"""
import os
import tempfile

ROOT = tempfile.mkdtemp(prefix="caddy-console-test-")
BACKUP_DIR = os.path.join(ROOT, "backups")
CADDYFILE = os.path.join(ROOT, "Caddyfile")
AUDIT_LOG = os.path.join(BACKUP_DIR, "audit.log")
LOG_FILE = os.path.join(ROOT, "access.log")
GEOIP_DIR = os.path.join(ROOT, "geoip")
BANS_DIR = os.path.join(ROOT, "console")
LOCK_DIR = os.path.join(ROOT, "locks")

os.environ.update({
    "BACKUP_DIR": BACKUP_DIR,
    "CADDYFILE_PATH": CADDYFILE,
    "AUDIT_LOG": AUDIT_LOG,
    "CADDY_LOG_FILE": LOG_FILE,
    "AUTH_MODE": "cloudflare",
    # Tests exercise the temporary synthetic-header mode explicitly. Production
    # Cloudflare mode is covered separately and must verify signed Access JWTs.
    "UNSAFE_ALLOW_UNVERIFIED_CF_HEADER": "true",
    "ALLOWED_EMAILS": "admin@example.com",
    "SESSION_COOKIE_SECURE": "false",
    "BACKUP_KEEP": "3",
    "AUDIT_LOG_MAX_BYTES": "400",
    "CADDY_API_URL": "http://caddy.invalid:2019",
    "GEOIP_DIR": GEOIP_DIR,
    # Tests must never download anything.
    "GEOIP_AUTO_UPDATE": "false",
    "BANS_ENABLED": "true",
    "BANS_DIR": BANS_DIR,
    "BANS_NEVER": "",
    "LOCK_DIR": LOCK_DIR,
})
