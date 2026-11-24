import os

# Shown in the account menu. Duplicated in pyproject.toml and package.json since
# the app runs from source, so importlib.metadata has nothing to read;
# test_version.py keeps the three in step.
APP_VERSION = "0.7.0"

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
# Whether SERVER_URL was set explicitly (the default above is only a dev
# fallback). The sign-in page names that host, else the request's own.
SERVER_URL_CONFIGURED = bool(os.environ.get("SERVER_URL", "").strip())
AUTH_MODE = os.environ.get("AUTH_MODE", "google").lower()
CADDY_API_URL = os.environ.get("CADDY_API_URL", "http://caddy:2019")
CADDY_LOG_FILE = os.environ.get("CADDY_LOG_FILE", "/var/log/caddy/access.log")

# Cloudflare Access JWT validation (AUTH_MODE=cloudflare). With both values,
# identity comes only from a verified Cf-Access-Jwt-Assertion. Without them the
# app refuses to start unless the explicit internal/dev escape hatch below is on.
CF_ACCESS_TEAM_DOMAIN = os.environ.get("CF_ACCESS_TEAM_DOMAIN", "").strip().rstrip("/")
CF_ACCESS_AUD = os.environ.get("CF_ACCESS_AUD", "").strip()
# Explicit escape hatch for the temporary, loopback-only development/internal
# proxy that injects a synthetic identity. Production Cloudflare mode fails
# closed unless a signed Access JWT can be verified.
UNSAFE_ALLOW_UNVERIFIED_CF_HEADER = os.environ.get(
    "UNSAFE_ALLOW_UNVERIFIED_CF_HEADER", "false"
).lower() in ("1", "true", "yes")

# How many pre-save backups to keep on disk (oldest are pruned after each save).
BACKUP_KEEP = int(os.environ.get("BACKUP_KEEP", "50"))

# Loading is bounded by the requested time range, not by a byte budget: the log
# is append-ordered, so the start of a range is found by bisection, and rolled
# archives are opened only when a range predates the live file. How far back you
# can look is therefore Caddy's retention (roll_keep / roll_keep_for), not a
# setting here.

# Rotate the audit log once it grows past this size; one rotated file is kept.
AUDIT_LOG_MAX_BYTES = int(os.environ.get("AUDIT_LOG_MAX_BYTES", str(5 * 1024 * 1024)))

# Only files with this prefix in BACKUP_DIR are backups; everything else in
# that directory (secret key, audit log, lock file) must never be served.
BACKUP_PREFIX = "Caddyfile."

os.makedirs(BACKUP_DIR, exist_ok=True)

# Events the explorer keeps in memory from the scanned window. Columnar storage
# costs roughly 30 bytes each, so the default is about 6 MB. Past this the oldest
# are dropped and the response reports how many, rather than quietly under-counting.
EXPLORE_MAX_EVENTS = int(os.environ.get("CADDY_EXPLORE_MAX_EVENTS", "200000"))

# IP location and network owner for the Explore IP popover, from DB-IP's free
# Lite databases (CC-BY 4.0). Read offline, so no visitor IP leaves the server.
# The updater fetches a new release monthly; set GEOIP_AUTO_UPDATE=false on a
# host without egress and drop the .mmdb files into GEOIP_DIR by hand.
GEOIP_DIR = os.environ.get("GEOIP_DIR", "/data/geoip")
GEOIP_AUTO_UPDATE = os.environ.get("GEOIP_AUTO_UPDATE", "true").lower() not in ("0", "false", "no")


def bounded_int(name: str, default: int, low: int, high: int) -> int:
    """An integer setting with server-side bounds; anything else stops startup."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise RuntimeError(f"{name} must be an integer between {low} and {high}, got {raw!r}") from None
    if not low <= value <= high:
        raise RuntimeError(f"{name} must be between {low} and {high}, got {value}")
    return value


# IP bans (docs/security.md). Sites are unchanged until one imports the managed
# file, so this defaults on. BANS_DIR must be inside the Caddyfile directory and
# visible at the same absolute path in the Caddy container.
BANS_ENABLED = os.environ.get("BANS_ENABLED", "true").lower() not in ("0", "false", "no")
BANS_DIR = os.environ.get("BANS_DIR", "/etc/caddy/console").rstrip("/") or "/etc/caddy/console"
# Measured by tests/integration/bans_benchmark.py; see docs/security.md.
BANS_MAX = bounded_int("BANS_MAX", 10000, 1, 100000)
# Extra protected IPs/CIDRs, comma or space separated. Parsed by src/bans/protected.py
# at app start; one invalid token refuses startup.
BANS_NEVER = os.environ.get("BANS_NEVER", "")

# CrowdSec file sync (docs/security.md#crowdsec-file-sync). Only the optional
# docker-compose.crowdsec.yaml sets CROWDSEC_URL; empty means no CrowdSec at all.
# src/bans/lapi.py validates the URL and origins; service.init_config() refuses
# startup on an invalid value. The key is read at poll time, never logged.
BANS_SYNC_INTERVAL = bounded_int("BANS_SYNC_INTERVAL", 30, 10, 3600)
CROWDSEC_URL = os.environ.get("CROWDSEC_URL", "")
CROWDSEC_CONSOLE_BOUNCER_KEY = os.environ.get("CROWDSEC_CONSOLE_BOUNCER_KEY", "")
CROWDSEC_CONSOLE_BOUNCER_KEY_FILE = os.environ.get("CROWDSEC_CONSOLE_BOUNCER_KEY_FILE", "").strip()
CROWDSEC_ORIGINS = os.environ.get("CROWDSEC_ORIGINS", "crowdsec,cscli")
CROWDSEC_POLL_INTERVAL = bounded_int("CROWDSEC_POLL_INTERVAL", 10, 5, 300)

# Phase 3, CrowdSec plugin mode (docs/security.md#crowdsec-plugin). The plugin's
# own key (CROWDSEC_PLUGIN_BOUNCER_KEY) belongs to the Caddy container and is
# never read here: the console only needs the secret's path, if one is used, to
# offer the matching {file.<path>} placeholder. CADDY_ADMIN_ADDRESS is the admin
# bind health checks and recovery use; the plugin overlay sets the fixed
# caddy-admin address. Both are validated by src/bans/plugin.py at startup.
CROWDSEC_PLUGIN_BOUNCER_KEY_FILE = os.environ.get("CROWDSEC_PLUGIN_BOUNCER_KEY_FILE", "").strip()
CADDY_ADMIN_ADDRESS = os.environ.get("CADDY_ADMIN_ADDRESS", "").strip() or "0.0.0.0:2019"

# Phase 4, Cloudflare trust profiles (docs/security.md#client-ip-profiles).
# CLIENT_IP_MODE is the default profile until an operator saves one in Security;
# src/bans/profile.py validates it at startup. Direct mode never contacts Cloudflare.
CLIENT_IP_MODE = os.environ.get("CLIENT_IP_MODE", "direct").strip().lower() or "direct"
CLOUDFLARE_RANGES_AUTO_UPDATE = os.environ.get(
    "CLOUDFLARE_RANGES_AUTO_UPDATE", "true").lower() not in ("0", "false", "no")

# Phase 4 country allowlist (docs/security.md, spec 4.3). Off until configured.
# PROVISIONAL cap: 20000 is a placeholder until the Phase 4 benchmark measures
# adaptation time, reload memory and request latency; the warning threshold
# (10000) lives in src/bans/country.py.
COUNTRY_POLICY_ENABLED = os.environ.get("COUNTRY_POLICY_ENABLED", "false").lower() in ("1", "true", "yes")
COUNTRY_MAX_PREFIXES = bounded_int("COUNTRY_MAX_PREFIXES", 20000, 1, 200000)
