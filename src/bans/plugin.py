"""CrowdSec plugin mode from the console's side (spec 3.1-3.6).

The console never holds the plugin's bouncer key. It knows only whether the
key comes from the environment or a file, and that file's path, so it can offer
the matching placeholder. Everything else is read from Caddy: whether the
running build has the module (an /adapt probe, which provisions nothing and so
contacts no LAPI), where the admin API listens and whether the global crowdsec
app is loaded (GET /config/).
"""
import ipaddress
import re
import socket
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from .. import config
from . import caddy as caddy_admin
from . import protected

DEFAULT_KEY_FILE = "/run/secrets/crowdsec_plugin_bouncer_key"
ENV_PLACEHOLDER = "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}"
API_URL = "http://crowdsec:8080"
TICKER_INTERVAL = "10s"
# Same rule as caddy-plugin/preflight/check.go keyPath.
_KEY_PATH = re.compile(r"^/(?:[A-Za-z0-9_][A-Za-z0-9._-]*/)*[A-Za-z0-9_][A-Za-z0-9._-]*\Z")
_ADMIN = re.compile(r"^(?:\[([0-9A-Fa-f:.]+)\]|([0-9.]+)|([A-Za-z0-9.-]*)):([0-9]{1,5})\Z")
# A value that is exactly one placeholder and nothing else; only such a value
# is ever shown. Same rule as caddy-plugin/preflight/check.go placeholder.
_PLACEHOLDER = re.compile(r"^\{(?:env|file)\.[A-Za-z0-9_./-]{1,255}\}\Z")


def is_placeholder(value) -> bool:
    """Exactly one {env.*}/{file.*} placeholder: the only key form ever shown."""
    return isinstance(value, str) and bool(_PLACEHOLDER.match(value))


_UNRECOGNIZED = re.compile(r"unrecognized global option:?\s*crowdsec", re.I)
PROBE_TEXT = ("{\n\tcrowdsec {\n\t\tapi_url http://crowdsec.invalid:8080\n"
              "\t\tapi_key caddy-console-module-probe\n\t}\n}\n")
MODULE_TTL = 300.0
MODULE_UNKNOWN_TTL = 30.0
LAPI_TTL = 60.0

_lock = threading.Lock()
_cache = {}


class ConfigError(ValueError):
    pass


def parse_key_file(raw) -> str:
    text = (raw or "").strip()
    if not text:
        return ""
    if len(text) > 255 or not _KEY_PATH.match(text) or any(s in (".", "..") for s in text[1:].split("/")):
        raise ConfigError("CROWDSEC_PLUGIN_BOUNCER_KEY_FILE must be an absolute path such as "
                          f"{DEFAULT_KEY_FILE} (letters, digits, '.', '_', '-' and '/')")
    return text


@dataclass(frozen=True)
class AdminAddress:
    host: str
    port: int
    fixed: bool

    def __str__(self) -> str:
        return f"[{self.host}]:{self.port}" if ":" in self.host else f"{self.host}:{self.port}"


def parse_admin_address(raw) -> AdminAddress:
    text = (raw or "").strip() or "0.0.0.0:2019"
    m = _ADMIN.match(text)
    if not m or not 0 < int(m.group(4)) < 65536:
        raise ConfigError("CADDY_ADMIN_ADDRESS must be host:port, for example 172.30.250.2:2019")
    port = int(m.group(4))
    if m.group(3) is not None:
        return AdminAddress(m.group(3), port, False)          # a name, or "" for ":2019"
    try:
        ip = ipaddress.ip_address(m.group(1) or m.group(2))
    except ValueError:
        raise ConfigError("CADDY_ADMIN_ADDRESS must be host:port, for example 172.30.250.2:2019") from None
    fixed = not (ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local)
    return AdminAddress(str(ip), port, fixed)


def admin_address() -> AdminAddress:
    return parse_admin_address(config.CADDY_ADMIN_ADDRESS)


def key_file() -> str:
    return parse_key_file(config.CROWDSEC_PLUGIN_BOUNCER_KEY_FILE)


def key_mode() -> str:
    return "file" if key_file() else "env"


def api_key_placeholder() -> str:
    path = key_file()
    return f"{{file.{path}}}" if path else ENV_PLACEHOLDER


# --- module probe -------------------------------------------------------------------

def reset_cache() -> None:
    with _lock:
        _cache.clear()


def cached_module():
    """The last probe result without probing: for code under caddyfile_lock()."""
    with _lock:
        hit = _cache.get("module")
    return hit[0] if hit else None


def module_available(force=False):
    """True/False: does the running Caddy build have the crowdsec module? None
    when that cannot be told (Caddy unreachable or an unrelated adapt error).
    Never call this while holding caddyfile_lock(): it talks to Caddy."""
    now = time.monotonic()
    with _lock:
        hit = _cache.get("module")
        if hit and not force and now - hit[1] < (MODULE_TTL if hit[0] is not None else MODULE_UNKNOWN_TTL):
            return hit[0]
    try:
        result = caddy_admin.adapt(PROBE_TEXT)
        value = True if result.ok else (False if _UNRECOGNIZED.search(result.message or "") else None)
    except caddy_admin.CaddyUnavailable:
        value = None
    with _lock:
        _cache["module"] = (value, time.monotonic())
    return value


# --- admin exposure (spec 3.1) ----------------------------------------------------------

@dataclass(frozen=True)
class AdminProblem:
    code: str
    message: str


def _lapi_addresses() -> list:
    """CrowdSec's addresses as the console resolves CROWDSEC_URL, cached briefly."""
    host = urlsplit(config.CROWDSEC_URL or "").hostname
    if not host:
        return []
    with _lock:
        hit = _cache.get("lapi")
        if hit and hit[0] == host and time.monotonic() - hit[2] < LAPI_TTL:
            return hit[1]
    try:
        found = sorted({ipaddress.ip_address(i[4][0]) for i in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)},
                       key=str)
    except (OSError, ValueError):
        found = []
    with _lock:
        _cache["lapi"] = (host, found, time.monotonic())
    return found


def _listen(live):
    admin = (live or {}).get("admin")
    if not isinstance(admin, dict):
        return "", []
    if admin.get("disabled"):
        return "off", []
    origins = admin.get("origins") if isinstance(admin.get("origins"), list) else []
    return str(admin.get("listen") or "").removeprefix("tcp/"), [str(o) for o in origins]


def admin_problem(live):
    """None when Caddy's running admin bind is the fixed caddy-admin address,
    lists it in origins and shares no network with CrowdSec; otherwise what is
    wrong and the bind to use. Plugin activation is refused while this is set."""
    want = admin_address()
    if not want.fixed:
        return AdminProblem("admin_not_fixed",
                            f"The console's CADDY_ADMIN_ADDRESS is {want}, not Caddy's fixed caddy-admin address. "
                            "Start it with docker-compose.crowdsec-plugin.yaml, which sets 172.30.250.2:2019.")
    hint = f"Use admin {want} {{ origins caddy:2019 {want} }} in the global options, then Save & Reload."
    listen, origins = _listen(live)
    if listen == "":
        return AdminProblem("admin_missing", "Caddy's running config has no admin listener, so it listens on "
                            f"localhost:2019 only. {hint}")
    if listen == "off":
        return AdminProblem("admin_off", f"Caddy's admin API is turned off. {hint}")
    if listen.startswith("unix/"):
        return AdminProblem("admin_unix", f"Caddy's admin API is a unix socket. {hint}")
    host, _, port = listen.rpartition(":")
    host = host.strip("[]")
    if host == "":
        return AdminProblem("admin_wildcard", f"Caddy's admin API listens on every interface ({listen}), "
                            f"so CrowdSec could reach it. {hint}")
    if host == "localhost":
        return AdminProblem("admin_loopback", f"Caddy's admin API listens on loopback only ({listen}). {hint}")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return AdminProblem("admin_mismatch", f"Caddy's admin API listens on {listen}, not {want}. {hint}")
    if ip.is_unspecified:
        return AdminProblem("admin_wildcard", f"Caddy's admin API listens on every interface ({listen}), "
                            f"so CrowdSec could reach it. {hint}")
    if ip.is_loopback:
        return AdminProblem("admin_loopback", f"Caddy's admin API listens on loopback only ({listen}). {hint}")
    if str(ip) != want.host or port != str(want.port):
        return AdminProblem("admin_mismatch", f"Caddy's admin API listens on {listen}, not {want}. {hint}")
    if str(want) not in origins:
        return AdminProblem("admin_origins", f"Caddy's admin origins do not list {want}. {hint}")
    for net in protected.read_docker_networks():
        if ip in net and any(a in net for a in _lapi_addresses()):
            return AdminProblem("admin_shared", f"Caddy's admin address {want} is on a network CrowdSec also "
                                f"joins ({net}). caddy-admin must be shared only with the console.")
    return None


def live_app(live):
    """The running global crowdsec app, without its key: only whether the key
    is the expected placeholder, another placeholder, missing, or written in."""
    app = ((live or {}).get("apps") or {}).get("crowdsec")
    if not isinstance(app, dict):
        return None
    key = app.get("api_key")
    expected = api_key_placeholder()
    if not key:
        form = "missing"
    elif key == expected:
        form = "expected"
    elif is_placeholder(key):
        form = "placeholder"
    else:
        form = "literal"
    return {"api_url": str(app.get("api_url") or "")[:200],
            "ticker_interval": str(app.get("ticker_interval") or "60s")[:20],
            "streaming": app.get("enable_streaming") is not False,
            "hard_fails": app.get("enable_hard_fails") is True,
            "key_form": form, "key_placeholder": key if form == "placeholder" else None}


ALLOWLIST = "caddy_console_protected"


def allowlist_commands(prot) -> str:
    """Copy-only commands for a CrowdSec LAPI allowlist with the static
    protected set (core ranges, BANS_NEVER, Docker networks). Defense in depth
    only (spec 3.4): allowlists stop new decisions but keep existing ones, and
    verified console addresses change at runtime, so they are left out."""
    from . import addr
    values = [addr.token(n) for cat, n in prot.entries if cat not in ("operator", "profile")]
    seen = list(dict.fromkeys(values))
    return "\n".join([
        f"cscli allowlists delete {ALLOWLIST} || true",
        f"cscli allowlists create {ALLOWLIST} -d 'Caddy Console protected ranges'",
        f"cscli allowlists add {ALLOWLIST} " + " ".join(seen),
    ]) + "\n"


def admin_guard(content: str):
    """While the console runs with a fixed CADDY_ADMIN_ADDRESS (the plugin
    overlay), refuse to save a Caddyfile whose admin bind would expose port
    2019 or lose the console. None means "save may go on"; an unreachable
    Caddy or an adapt error is left to the save path, which fails anyway."""
    if not config.BANS_ENABLED or not admin_address().fixed:
        return None
    try:
        result = caddy_admin.adapt(content)
    except caddy_admin.CaddyUnavailable:
        return None
    if not result.ok:
        return None
    problem = admin_problem(result.config)
    return problem.message if problem else None
