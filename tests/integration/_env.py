"""Environment for the stock-Caddy suite. Import before anything from src."""
import os

ROOT = "/etc/caddy/itest"
BACKUP_DIR = "/tmp/bans-itest/backups"
BANS_DIR = f"{ROOT}/console"
API = os.environ.get("CADDY_API_URL", "http://caddy-target:2019")
DATA_URL = os.environ.get("CADDY_DATA_URL", "http://caddy-target:80")
for d in (ROOT, BACKUP_DIR, BANS_DIR, "/tmp/bans-itest/geoip"):
    os.makedirs(d, exist_ok=True)
os.environ.update({
    "BACKUP_DIR": BACKUP_DIR, "CADDYFILE_PATH": f"{ROOT}/Caddyfile", "BANS_DIR": BANS_DIR,
    "AUDIT_LOG": f"{BACKUP_DIR}/audit.log", "CADDY_API_URL": API, "AUTH_MODE": "cloudflare",
    "UNSAFE_ALLOW_UNVERIFIED_CF_HEADER": "true", "ALLOWED_EMAILS": "it@example.com",
    "SESSION_COOKIE_SECURE": "false", "GEOIP_AUTO_UPDATE": "false", "GEOIP_DIR": "/tmp/bans-itest/geoip",
    "BANS_ENABLED": "true", "BANS_NEVER": "", "SERVER_URL": "http://console.it.example.com",
})
