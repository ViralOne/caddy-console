import hashlib
import os
import re
import subprocess
import tempfile
import threading
import time

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

    rc, stdout, _ = _run_on_temp_config(content, lambda p: ["caddy", "fmt", p])
    formatted = stdout if rc == 0 and stdout else content
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
