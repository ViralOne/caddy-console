import os

CADDYFILE = os.environ.get("CADDYFILE_PATH", "/etc/caddy/Caddyfile")
BACKUP_DIR = os.environ.get("BACKUP_DIR", "/backups")
AUDIT_LOG = os.environ.get("AUDIT_LOG", "/backups/audit.log")
ALLOWED_DOMAIN = os.environ.get("ALLOWED_DOMAIN", "")
ALLOWED_EMAILS = [
    e.strip()
    for e in os.environ.get("ALLOWED_EMAILS", "").split(",")
    if e.strip()
]
SESSION_TIMEOUT_HOURS = int(os.environ.get("SESSION_TIMEOUT_HOURS", "8"))
SERVER_URL = os.environ.get("SERVER_URL", "http://localhost:9090")
AUTH_MODE = os.environ.get("AUTH_MODE", "google").lower()
CADDY_API_URL = os.environ.get("CADDY_API_URL", "http://caddy:2019")
CADDY_LOG_FILE = os.environ.get("CADDY_LOG_FILE", "/var/log/caddy/access.log")

# Cloudflare Access JWT validation (AUTH_MODE=cloudflare). When both are set the
# Cf-Access-Jwt-Assertion header is verified against the team's public keys and
# the identity is taken from the token. When unset the app falls back to
# trusting the Cf-Access-Authenticated-User-Email header, which is only safe if
# nothing but the tunnel can reach the editor.
CF_ACCESS_TEAM_DOMAIN = os.environ.get("CF_ACCESS_TEAM_DOMAIN", "").strip().rstrip("/")
CF_ACCESS_AUD = os.environ.get("CF_ACCESS_AUD", "").strip()

# How many pre-save backups to keep on disk (oldest are pruned after each save).
BACKUP_KEEP = int(os.environ.get("BACKUP_KEEP", "50"))

# Rotate the audit log once it grows past this size; one rotated file is kept.
AUDIT_LOG_MAX_BYTES = int(os.environ.get("AUDIT_LOG_MAX_BYTES", str(5 * 1024 * 1024)))

# Only files with this prefix in BACKUP_DIR are backups; everything else in
# that directory (secret key, audit log, lock file) must never be served.
BACKUP_PREFIX = "Caddyfile."

os.makedirs(BACKUP_DIR, exist_ok=True)
