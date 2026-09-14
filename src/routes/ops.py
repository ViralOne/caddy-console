import json
import os
import re
import threading
from datetime import datetime

import requests as http_client
from flask import Blueprint, jsonify

from ..audit import iter_entries, tail_lines
from ..auth import login_required
from ..caddy_api import get_servers
from ..config import AUDIT_LOG, BACKUP_DIR, BACKUP_PREFIX, CADDY_API_URL, CADDYFILE
from ..validator import run_caddy

ops_bp = Blueprint("ops", __name__)


@ops_bp.route("/api/audit", methods=["GET"])
@login_required
def get_audit():
    entries = []
    for line in reversed(tail_lines(AUDIT_LOG, 50)):
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return jsonify({"entries": entries})


# --- /api/status ------------------------------------------------------------------
#
# Both subprocesses here used to run on every open of the Status panel. The
# binary can't change while the container runs, and the on-disk file only needs
# re-validating when it changes.

_status_lock = threading.Lock()
_status_cache: dict = {"version": None, "file_key": None, "config_valid": None}


def _caddy_version() -> str:
    with _status_lock:
        if _status_cache["version"] is not None:
            return _status_cache["version"]
    rc, stdout, _ = run_caddy(["caddy", "version"], timeout=5)
    version = stdout.strip() if rc == 0 else "unknown"
    if rc == 0:
        with _status_lock:
            _status_cache["version"] = version
    return version


def _config_valid_on_disk() -> bool:
    try:
        st = os.stat(CADDYFILE)
        key = (st.st_mtime_ns, st.st_size)
    except OSError:
        return False
    with _status_lock:
        if _status_cache["file_key"] == key:
            return _status_cache["config_valid"]
    rc, _, _ = run_caddy(["caddy", "validate", "--config", CADDYFILE, "--adapter", "caddyfile"])
    valid = rc == 0
    if rc >= 0:  # don't remember timeouts / missing binary
        with _status_lock:
            _status_cache["file_key"] = key
            _status_cache["config_valid"] = valid
    return valid


@ops_bp.route("/api/status", methods=["GET"])
@login_required
def caddy_status():
    try:
        mtime = os.path.getmtime(CADDYFILE)
        last_modified = datetime.fromtimestamp(mtime).isoformat()
    except OSError:
        last_modified = "unknown"

    return jsonify({
        "caddy_version": _caddy_version(),
        "config_valid": _config_valid_on_disk(),
        "config_path": CADDYFILE,
        "last_modified": last_modified,
    })


@ops_bp.route("/api/metrics", methods=["GET"])
@login_required
def metrics():
    total_saves = 0
    total_logins = 0
    users = set()
    saves_today = 0
    today = datetime.now().strftime("%Y-%m-%d")

    for entry in iter_entries():
        action = entry.get("action", "")
        if "save" in action:
            total_saves += 1
            if entry.get("time", "").startswith(today):
                saves_today += 1
        if action == "login":
            total_logins += 1
        if entry.get("user"):
            users.add(entry["user"])

    try:
        with open(CADDYFILE) as f:
            content = f.read()
    except OSError:
        content = ""
    site_count = content.count("reverse_proxy")
    config_lines = len(content.split("\n")) if content else 0

    try:
        backup_count = len([f for f in os.listdir(BACKUP_DIR) if f.startswith(BACKUP_PREFIX)])
    except OSError:
        backup_count = 0

    try:
        mtime = os.path.getmtime(CADDYFILE)
        last_modified = datetime.fromtimestamp(mtime).isoformat()
    except OSError:
        last_modified = None

    return jsonify({
        "total_saves": total_saves,
        "saves_today": saves_today,
        "total_logins": total_logins,
        "unique_users": len(users),
        "site_count": site_count,
        "backup_count": backup_count,
        "last_modified": last_modified,
        "config_lines": config_lines,
    })


@ops_bp.route("/api/upstreams", methods=["GET"])
@login_required
def upstreams():
    try:
        resp = http_client.get(f"{CADDY_API_URL}/reverse_proxy/upstreams", timeout=5)
        if resp.status_code != 200:
            return jsonify({"upstreams": [], "error": f"Caddy returned {resp.status_code}"})
        rows = resp.json()
    except http_client.ConnectionError:
        return jsonify({"upstreams": [], "error": "Caddy admin API not reachable"})
    except Exception as e:
        return jsonify({"upstreams": [], "error": str(e)})

    # Caddy's upstreams endpoint only reports the dial address, so join it with
    # the running config to say which sites proxy there and which kinds of
    # health check are configured.
    detail = _get_upstream_detail()
    enriched = []
    for row in rows if isinstance(rows, list) else []:
        info = detail.get(row.get("address"), {})
        enriched.append({
            **row,
            "domains": info.get("domains", []),
            # `fails` is only ever populated when passive health checking is on,
            # which requires fail_duration > 0 (Caddy's default is 0 = off).
            "passive_health": info.get("passive", False),
            "active_health": info.get("active", False),
        })
    enriched.sort(key=lambda u: (not u["domains"], u["domains"][:1], u.get("address", "")))
    return jsonify({"upstreams": enriched})


def _get_upstream_detail():
    """Map each upstream dial address to its sites and health-check config."""
    detail = {}
    for srv_config in get_servers().values():
        if isinstance(srv_config, dict):
            _walk_routes(srv_config.get("routes", []), [], detail)
    for info in detail.values():
        info["domains"] = sorted(info["domains"])
    return detail


def _walk_routes(routes, hosts, detail):
    """Recursively collect reverse_proxy upstreams, carrying host matchers down.

    reverse_proxy handlers are normally nested inside a subroute handler, so the
    host matcher lives on an outer route.
    """
    if not isinstance(routes, list):
        return
    for route in routes:
        if not isinstance(route, dict):
            continue
        route_hosts = list(hosts)
        for match_set in route.get("match", []) or []:
            if isinstance(match_set, dict):
                route_hosts.extend(match_set.get("host", []) or [])
        for handler in route.get("handle", []) or []:
            if not isinstance(handler, dict):
                continue
            if handler.get("handler") == "reverse_proxy":
                checks = handler.get("health_checks") or {}
                passive = bool((checks.get("passive") or {}).get("fail_duration"))
                active = bool(checks.get("active"))
                for upstream in handler.get("upstreams", []) or []:
                    dial = (upstream or {}).get("dial")
                    if not dial:
                        continue
                    info = detail.setdefault(dial, {"domains": set(), "passive": False, "active": False})
                    info["domains"].update(route_hosts)
                    info["passive"] = info["passive"] or passive
                    info["active"] = info["active"] or active
            # subroute (and similar wrappers) nest another route list.
            _walk_routes(handler.get("routes", []), route_hosts, detail)


@ops_bp.route("/api/traffic", methods=["GET"])
@login_required
def traffic():
    try:
        resp = http_client.get(f"{CADDY_API_URL}/metrics", timeout=5)
        if resp.status_code == 404:
            return jsonify({"error": "Metrics endpoint not found (404). Add to global block: servers { metrics }", "sites": {}})
        if resp.status_code != 200:
            return jsonify({"error": f"Caddy returned HTTP {resp.status_code}: {resp.text[:200]}", "sites": {}})
        if "caddy_" not in resp.text:
            return jsonify({"error": "Response doesn't contain Caddy metrics. Check Caddy version supports metrics.", "sites": {}})
        result = parse_prometheus_metrics(resp.text)
        domains, listen = _server_maps()
        result["server_domains"] = domains
        result["server_listen"] = listen
        return jsonify(result)
    except http_client.ConnectionError as e:
        return jsonify({"error": f"Connection failed to {CADDY_API_URL}/metrics: {e}", "sites": {}})
    except Exception as e:
        return jsonify({"error": f"{type(e).__name__}: {e}", "sites": {}})


def _server_maps():
    """Map server names (srv0, srv1) to their host matchers and listen addresses."""
    domains_map, listen_map = {}, {}
    for srv_name, srv_config in get_servers().items():
        if not isinstance(srv_config, dict):
            continue
        domains = []
        for route in srv_config.get("routes", []) or []:
            if not isinstance(route, dict):
                continue
            for match_set in route.get("match", []) or []:
                if isinstance(match_set, dict):
                    domains.extend(match_set.get("host", []) or [])
        if domains:
            domains_map[srv_name] = sorted(set(domains))
        listen = srv_config.get("listen", []) or []
        if listen:
            listen_map[srv_name] = [str(l) for l in listen]
    return domains_map, listen_map


# Backwards-compatible name used by older callers/tests.
def _get_server_domain_map():
    return _server_maps()[0]


_METRIC_LINE = re.compile(r'^(caddy_[A-Za-z0-9_]+)\{([^}]*)\}\s+(\S+)')


def _num(text: str) -> float:
    try:
        return float(text)
    except ValueError:
        return 0.0


def _empty_series():
    return {"requests": 0, "in_flight": 0, "errors": 0, "latency_sum": 0.0, "latency_count": 0,
            "bytes_in": 0.0, "bytes_out": 0.0}


def parse_prometheus_metrics(text):
    """Aggregate Caddy's per-handler HTTP metrics into per-server figures.

    Every middleware handler in a route is instrumented separately, so a single
    request shows up once per handler (subroute, headers, reverse_proxy, ...).
    Summing across handlers would overcount by that factor. Instead, for each
    server we take the handler that saw the most requests: that is the
    outermost one, and every request that reached any handler passed through it.

    caddy_http_requests_total has no `code` label; 5xx counts come from
    caddy_http_request_duration_seconds_count, which does.
    """
    series = {}  # (server, handler) -> figures
    upstreams_healthy = {}

    def bucket(labels):
        key = (labels.get("server", "unknown"), labels.get("handler", ""))
        return series.setdefault(key, _empty_series())

    for line in text.split("\n"):
        if not line or line[0] == "#":
            continue
        m = _METRIC_LINE.match(line)
        if not m:
            continue
        name, label_str, raw = m.groups()
        if not name.startswith(("caddy_http_", "caddy_reverse_proxy_upstreams_healthy")):
            continue
        labels = _parse_labels(label_str)
        value = _num(raw)

        if name == "caddy_http_requests_total":
            bucket(labels)["requests"] += int(value)
        elif name == "caddy_http_requests_in_flight":
            bucket(labels)["in_flight"] += int(value)
        elif name == "caddy_http_request_duration_seconds_sum":
            bucket(labels)["latency_sum"] += value
        elif name == "caddy_http_request_duration_seconds_count":
            b = bucket(labels)
            b["latency_count"] += int(value)
            if labels.get("code", "").startswith("5"):
                b["errors"] += int(value)
        elif name == "caddy_http_request_size_bytes_sum":
            bucket(labels)["bytes_in"] += value
        elif name == "caddy_http_response_size_bytes_sum":
            bucket(labels)["bytes_out"] += value
        elif name == "caddy_reverse_proxy_upstreams_healthy":
            upstreams_healthy[labels.get("upstream", "unknown")] = int(value)

    # Pick one representative handler per server.
    chosen = {}
    for (server, handler), data in series.items():
        rank = (data["requests"], data["latency_count"], handler)
        if server not in chosen or rank > chosen[server][0]:
            chosen[server] = (rank, data)

    totals = {"requests": 0, "errors": 0, "in_flight": 0, "bytes_in": 0, "bytes_out": 0}
    site_list = {}
    for server, (_, data) in chosen.items():
        avg_latency = (data["latency_sum"] / data["latency_count"] * 1000) if data["latency_count"] > 0 else 0
        error_rate = (data["errors"] / data["requests"] * 100) if data["requests"] > 0 else 0
        site_list[server] = {
            "requests": data["requests"],
            "errors": data["errors"],
            "error_rate": round(error_rate, 2),
            "avg_latency_ms": round(avg_latency, 1),
            "bytes_in": int(data["bytes_in"]),
            "bytes_out": int(data["bytes_out"]),
        }
        totals["requests"] += data["requests"]
        totals["errors"] += data["errors"]
        totals["in_flight"] += data["in_flight"]
        totals["bytes_in"] += int(data["bytes_in"])
        totals["bytes_out"] += int(data["bytes_out"])

    return {
        "sites": site_list,
        "totals": totals,
        "upstreams_healthy": upstreams_healthy,
    }


def _parse_labels(label_str):
    labels = {}
    for m in re.finditer(r'(\w+)="([^"]*)"', label_str):
        labels[m.group(1)] = m.group(2)
    return labels
