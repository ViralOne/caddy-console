import difflib
import hashlib
import functools
import ipaddress
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, wait

import requests as http_client

from .config import CADDY_API_URL

DOMAIN_RE = re.compile(
    r'^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

CADDY_TIMEOUT = float(os.environ.get("CADDY_CMD_TIMEOUT", "20"))

_CACHE_TTL = float(os.environ.get("CADDY_CACHE_TTL", "60"))
_CACHE_MAX = 8
_cache: dict[str, tuple[float, object]] = {}
_cache_lock = threading.Lock()

TIMED_OUT = -1
NOT_FOUND = -2


def _cache_key(kind: str, content: str) -> str:
    return f"{kind}:{hashlib.sha256(content.encode()).hexdigest()}"


def _cache_get(key: str):
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and hit[0] > now:
            return hit[1]
        if hit:
            del _cache[key]
    return None


def _cache_put(key: str, value) -> None:
    with _cache_lock:
        if len(_cache) >= _CACHE_MAX:
            for stale in [k for k, (exp, _) in _cache.items() if exp <= time.monotonic()]:
                del _cache[stale]
            while len(_cache) >= _CACHE_MAX:
                del _cache[next(iter(_cache))]
        _cache[key] = (time.monotonic() + _CACHE_TTL, value)


def run_caddy(argv: list[str], timeout: float | None = None) -> tuple[int, str, str]:
    """Run a caddy command. Returns (returncode, stdout, stderr).

    Returns TIMED_OUT if the process had to be killed and NOT_FOUND if the caddy
    binary is missing, rather than raising, so callers can report either as a
    normal validation failure.
    """
    limit = CADDY_TIMEOUT if timeout is None else timeout
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=limit)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return TIMED_OUT, "", f"caddy did not finish within {limit:g}s and was stopped"
    except FileNotFoundError:
        return NOT_FOUND, "", "the caddy binary was not found on PATH"


def _run_on_temp_config(content: str, argv_for: callable) -> tuple[int, str, str]:
    """Write content to a temp file and run caddy against it, always cleaning up."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".caddyfile", delete=False
    ) as tmp:
        tmp.write(content)
        tmp_path = tmp.name
    try:
        return run_caddy(argv_for(tmp_path))
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


def caddy_fmt(content: str) -> str:
    """Format Caddyfile content using caddy fmt.

    Formatting is best-effort: if caddy fails, times out, or is missing, the
    content is returned unchanged and validation reports the real problem.
    """
    key = _cache_key("fmt", content)
    cached = _cache_get(key)
    if cached is not None:
        return cached

    rc, stdout, stderr = _run_on_temp_config(content, lambda p: ["caddy", "fmt", p])
    # Caddy 2.11 exits 1 when the input is not formatted, yet still prints the
    # formatted text: that is the case this function exists for.
    unformatted = rc == 1 and "input is not formatted" in stderr
    formatted = stdout if (rc == 0 or unformatted) and stdout else content
    if rc >= 0:
        _cache_put(key, formatted)
    return formatted


def _adapt_via_admin_api(content: str):
    """Adapt with the running Caddy without loading the result.

    This verifies Caddyfile syntax and module availability against the exact
    running build. It is not a runtime validation; POST /load performs that
    transactional check when the user saves.

    Returns (accepted, message, "adapted"), or None if the API was unreachable.
    """
    try:
        resp = http_client.post(
            f"{CADDY_API_URL}/adapt",
            data=content.encode(),
            headers={"Content-Type": "text/caddyfile"},
            timeout=CADDY_TIMEOUT,
        )
    except Exception:
        return None
    if resp.status_code == 200:
        return (True, "Caddyfile syntax and modules were accepted by the running Caddy", "adapted")
    return (False, _admin_error(resp), "adapted")


def _admin_error(resp) -> str:
    """The admin API reports errors as {"error": "..."}; show just the message."""
    try:
        message = resp.json().get("error")
    except Exception:
        message = None
    return (message or resp.text or "").strip() or f"caddy rejected the config (HTTP {resp.status_code})"


def caddy_check(content: str) -> tuple[bool, str, str]:
    """Return (accepted, message, check_level) for one Caddyfile.

    The preferred `adapted` path asks the running Caddy, so custom modules match,
    but proves syntax/module availability only. The `validated` fallback uses the
    bundled binary for a full local validation when the admin API is unreachable.
    """
    key = _cache_key("validate", content)
    cached = _cache_get(key)
    if cached is not None:
        return cached

    remote = _adapt_via_admin_api(content)
    if remote is not None:
        _cache_put(key, remote)
        return remote

    rc, stdout, stderr = _run_on_temp_config(
        content,
        lambda p: ["caddy", "validate", "--config", p, "--adapter", "caddyfile"],
    )
    if rc == 0:
        result = (True, "Config passed local Caddy validation", "validated")
    elif rc < 0:
        result = (False, stderr or stdout or "Caddy validation unavailable", "unavailable")
    else:
        result = (False, stderr or stdout or f"caddy validate failed (exit {rc})", "validated")

    # Timeouts and a missing binary are transient/environmental, so do not cache.
    if rc >= 0:
        _cache_put(key, result)
    return result


def caddy_validate(content: str) -> tuple[bool, str]:
    """Compatibility wrapper for save/restore callers."""
    accepted, message, _ = caddy_check(content)
    return accepted, message


def _is_local_address(addr: str) -> bool:
    """Site addresses that are valid without a dot: localhost, *.localhost, [ipv6]."""
    host = addr.split(",")[0].strip()
    if host.startswith("["):
        return True  # bracketed IPv6 literal, e.g. [::1]:8080
    host = host.rsplit(":", 1)[0] if ":" in host else host
    return host == "localhost" or host.endswith(".localhost")


def _has_access_log_directive(content: str) -> bool:
    """Best-effort detection of a site/snippet `log` directive.

    A `log` inside the top-level global options block is Caddy's runtime log,
    not an HTTP access log. Site blocks and reusable snippets are both relevant.
    """
    depth = 0
    root_is_global = False
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if depth == 0 and "{" in stripped:
            root_is_global = stripped == "{"
            if (not root_is_global
                    and re.search(r"(?:^|[;\s])log(?:\s|\{|$)", stripped.split("{", 1)[1])):
                return True
        if depth > 0 and not root_is_global and re.match(r"^log(?:\s|\{|$)", stripped):
            return True
        depth += stripped.count("{") - stripped.count("}")
        if depth <= 0:
            depth = 0
            root_is_global = False
    return False


def _access_log_warnings(content: str) -> list[str]:
    if not _has_access_log_directive(content):
        return []
    warnings = []
    if not re.search(r"(?m)^\s*format\s+filter\s*\{", content):
        warnings.append(
            "Access logging is enabled without 'format filter'; request headers can contain "
            "session tokens and API keys. Use the filtered logging snippet from docs/setup.md."
        )
        return warnings

    if re.search(r"(?m)^\s*output\s+file\s+\S+", content):
        modes = re.findall(r"(?m)^\s*mode\s+(0?[0-7]{3})\s*(?:#.*)?$", content)
        if not any(int(mode, 8) & 0o004 for mode in modes):
            warnings.append(
                "The non-root console cannot read Caddy's default 0600 log files; set "
                "'mode 0644' in the access-log output file block."
            )
    has_request_delete = bool(re.search(
        r"(?m)^\s*request>headers\s+delete\s*(?:#.*)?$", content
    ))
    has_response_delete = bool(re.search(
        r"(?m)^\s*resp_headers\s+delete\s*(?:#.*)?$", content
    ))
    if not has_request_delete:
        warnings.append(
            "Access-log filtering does not delete request>headers; remove the header map to "
            "avoid storing credentials."
        )
    if not has_response_delete:
        warnings.append(
            "Access-log filtering does not delete resp_headers; remove the response header map."
        )
    if (not has_request_delete or not has_response_delete) and re.search(
        r"(?m)^\s*log_credentials(?:\s|$)", content
    ):
        warnings.append(
            "The global log_credentials option disables Caddy's default credential redaction; "
            "do not use it while any access-log header map is retained."
        )
    return warnings


def smart_validate(content: str) -> list[str]:
    """Check site addresses look like real domains (caddy is too permissive)."""
    warnings = []
    brace_depth = 0

    for i, line in enumerate(content.split("\n"), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        opens = stripped.count("{")
        closes = stripped.count("}")

        if brace_depth == 0 and stripped == "{":
            brace_depth += 1
            continue

        if brace_depth == 0 and not stripped.startswith("}") and not stripped.startswith("import "):
            addr = stripped.rstrip(" {")
            if addr and not DOMAIN_RE.match(addr) and not addr.startswith(":") and not addr.startswith("http") and not re.match(r'^\([a-zA-Z0-9_-]+\)$', addr):
                if not addr.startswith("*.") and "." not in addr and not _is_local_address(addr):
                    warnings.append(f"Line {i}: '{addr}' doesn't look like a valid domain")

        brace_depth += opens - closes
        if brace_depth < 0:
            brace_depth = 0

    warnings.extend(_access_log_warnings(content))
    return warnings


def fmt_warning(content: str, formatted: str) -> str | None:
    """'Line N: not formatted …' when `caddy fmt` would change `content`, else None.

    N is a line in `content` (what the editor shows), so the strip can link it.
    """
    if formatted == content:
        return None
    a, b = content.split("\n"), formatted.split("\n")
    first, changed = None, 0
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        if first is None:
            first = i1 + 1
        changed += max(i2 - i1, j2 - j1)
    first = min(max(first or 1, 1), max(len(a), 1))
    return f"Line {first}: not formatted — Check will fix whitespace on {changed} line{'' if changed == 1 else 's'}"


# --- Upstream DNS check (warning only, never blocks a save) ----------------------
#
# "could not be resolved from the console container": the console and Caddy may
# sit on different networks, so this is evidence, not proof. Unknown answers
# (timeouts, transient resolver errors) produce no warning at all.

_DNS_TTL = 60.0
_DNS_TIMEOUT = 1.0
_DNS_CACHE_MAX = 256
_dns_cache: dict[str, tuple[float, bool | None]] = {}
_dns_lock = threading.Lock()
_dns_inflight: dict[str, Future] = {}
_DNS_MAX_HOSTS = 64
_dns_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="dns-check")
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_PLACEHOLDER_RE = re.compile(r"\{[^{}\s]*\}")
_NOT_FOUND = {getattr(socket, n) for n in ("EAI_NONAME", "EAI_NODATA") if hasattr(socket, n)}


def _upstream_tokens(content: str) -> list[tuple[int, str]]:
    """(line, token) for each upstream in reverse_proxy lines and their `to` lines."""
    out = []
    stack = []   # one entry per open brace: True if it opened a reverse_proxy block
    for number, raw in enumerate(content.split("\n"), 1):
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()
        if not line:
            continue
        words = line.split()
        if words[0] == "reverse_proxy":
            args = [w for w in words[1:] if w != "{"]
            if args and args[0][0] in "@/*":
                args = args[1:]
            out += [(number, a) for a in args]
        elif words[0] == "to" and stack and stack[-1]:
            out += [(number, a) for a in words[1:] if a != "{"]
        bare = _PLACEHOLDER_RE.sub("", line)
        for _ in range(bare.count("}")):
            if stack:
                stack.pop()
        for _ in range(bare.count("{")):
            stack.append(words[0] == "reverse_proxy")
    return out


def _dial_host(token: str) -> str | None:
    """The DNS name an upstream token dials, or None when there is nothing to resolve."""
    if "{" in token or token.startswith("unix/"):
        return None
    token = _SCHEME_RE.sub("", token).split("/", 1)[0]
    if not token or token.startswith("["):
        return None
    host = token.rsplit(":", 1)[0] if token.count(":") == 1 else token
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        return host.lower()


def _check_host(host, lookup):
    try:
        lookup(host, None)
        return True
    except socket.gaierror as e:
        return False if e.errno in _NOT_FOUND else None
    except Exception:  # noqa: BLE001 - a DNS hiccup must never break /api/validate
        return None


def _dns_store(host, ok):
    """Cache an answer; an unknown (None) never replaces a fresh known one."""
    now = time.monotonic()
    with _dns_lock:
        hit = _dns_cache.get(host)
        if ok is None and hit and hit[0] > now and hit[1] is not None:
            return
        _dns_cache[host] = (now + _DNS_TTL, ok)
        while len(_dns_cache) > _DNS_CACHE_MAX:
            del _dns_cache[next(iter(_dns_cache))]


def _dns_done(host, fut):
    with _dns_lock:
        if _dns_inflight.get(host) is fut:
            del _dns_inflight[host]
    if not fut.cancelled():
        _dns_store(host, fut.result())


def resolve_hosts(hosts, lookup=socket.getaddrinfo, timeout=_DNS_TIMEOUT) -> dict:
    """host -> True (resolves), False (no such name) or None (unknown).

    At most _DNS_MAX_HOSTS hosts are looked up per call; the rest stay unknown.
    A lookup that outlives the timeout keeps running in the background, is
    shared by later calls, and fills the cache when it finishes.
    """
    hosts = list(dict.fromkeys(hosts))
    result = {h: None for h in hosts}
    now = time.monotonic()
    futs, own = {}, {}
    with _dns_lock:
        for h in hosts[:_DNS_MAX_HOSTS]:
            hit = _dns_cache.get(h)
            if hit and hit[0] > now:
                result[h] = hit[1]
            elif h in _dns_inflight:
                futs[h] = _dns_inflight[h]
            else:
                futs[h] = own[h] = _dns_inflight[h] = _dns_pool.submit(_check_host, h, lookup)
    for h, fut in own.items():
        fut.add_done_callback(functools.partial(_dns_done, h))
    if futs:
        done, _ = wait(list(futs.values()), timeout=timeout)
        for h, fut in futs.items():
            if fut in done and not fut.cancelled():
                result[h] = fut.result()
            else:
                if h in own:
                    fut.cancel()   # no-op once it is running
                _dns_store(h, None)
    return result


def upstream_resolve_warnings(content: str, lookup=socket.getaddrinfo, timeout=_DNS_TIMEOUT) -> list[str]:
    found = [(line, token, host) for line, token in _upstream_tokens(content)
             if (host := _dial_host(token))]
    if not found:
        return []
    status = resolve_hosts(sorted({h for _, _, h in found}), lookup=lookup, timeout=timeout)
    warnings, seen = [], set()
    for line, token, host in found:
        if status.get(host) is False and (line, token) not in seen:
            seen.add((line, token))
            warnings.append(f"Line {line}: upstream {token} could not be resolved from the console container")
    return warnings
