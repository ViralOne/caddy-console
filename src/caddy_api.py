"""Small helpers for talking to the Caddy admin API."""
import threading
import time

import requests as http_client

from .config import CADDY_API_URL

# /api/traffic and /api/upstreams are requested together by the Metrics tab and
# both need the running config, so remember it briefly instead of fetching twice.
_SERVERS_TTL = 2.0
_servers_lock = threading.Lock()
_servers_cache: dict = {"value": None, "at": 0.0}


def get_servers() -> dict:
    """Return apps.http.servers from the running config, or {} on any failure."""
    now = time.monotonic()
    with _servers_lock:
        if _servers_cache["value"] is not None and now - _servers_cache["at"] < _SERVERS_TTL:
            return _servers_cache["value"]
    try:
        resp = http_client.get(f"{CADDY_API_URL}/config/apps/http/servers", timeout=3)
        servers = resp.json() if resp.status_code == 200 else {}
        if not isinstance(servers, dict):
            servers = {}
    except Exception:
        servers = {}
    with _servers_lock:
        _servers_cache["value"] = servers
        _servers_cache["at"] = time.monotonic()
    return servers


def invalidate_servers_cache() -> None:
    with _servers_lock:
        _servers_cache["value"] = None
