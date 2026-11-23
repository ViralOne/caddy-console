"""Is a source's policy enforced on each site of the live config? (spec "Mode
detection and health"). Source identity comes from the vars marker; effective
blocking from the client_ip matcher route with a 403 that follows it; anything
that can act on the request before that route is reported, never assumed away.
"""
import ipaddress
from dataclasses import dataclass, field

BENIGN = {"vars", "map", "log_append", "encode", "push", "tracing", "request_body",
          "intercept", "templates", "copy_response_headers"}


@dataclass
class SiteStatus:
    label: str
    hosts: list
    server: str
    status: str
    pre_handlers: list = field(default_factory=list)
    detail: str = ""


def _is_marker(node, marker) -> bool:
    return isinstance(node, dict) and node.get("handler") == "vars" and str(node.get(marker, "")) == "1"


def marker_present(config, marker) -> bool:
    stack = [config]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if _is_marker(node, marker):
                return True
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return False


def _has_403(node) -> bool:
    if isinstance(node, dict):
        if node.get("handler") == "static_response" and str(node.get("status_code", "")) == "403":
            return True
        return any(_has_403(v) for v in node.values())
    if isinstance(node, list):
        return any(_has_403(v) for v in node)
    return False


REQUIRED_PROTECTED = ("100.64.0.0/10", "169.254.0.0/16")


def _nets(ranges):
    """Ranges as a set of networks (strict=False: Caddy emits e.g. 127.0.0.1/8); None if any is unparsable."""
    try:
        return {ipaddress.ip_network(str(r), strict=False) for r in ranges}
    except ValueError:
        return None


def _client_ip_ranges(node):
    ci = node.get("client_ip") if isinstance(node, dict) else None
    ranges = ci.get("ranges") if isinstance(ci, dict) else None
    return _nets(ranges) if isinstance(ranges, list) else None


def _is_ban_route(route, expected=None) -> bool:
    """The managed shape: client_ip ranges, a `not client_ip` covering the core
    protected ranges, and a 403. A user's own client_ip/403 route fails this."""
    if not _has_403(route.get("handle")):
        return False
    required = _nets(REQUIRED_PROTECTED)
    for m in route.get("match") or []:
        banned = _client_ip_ranges(m)
        if not banned:
            continue
        protected = set()
        for n in m.get("not") or []:
            protected |= _client_ip_ranges(n) or set()
        if not required <= protected:
            continue
        if expected is not None and banned != expected:
            continue
        return True
    return False


def classify(h):
    name = h.get("handler")
    if name in BENIGN:
        return "benign", None
    if name == "headers":
        return ("pre", "request_header") if h.get("request") else ("benign", None)
    if name == "rewrite":
        return "pre", "rewrite"
    if name == "authentication":
        return "pre", "basic_auth"
    if name == "reverse_proxy" and h.get("handle_response") and h.get("rewrite"):
        return "pre", "forward_auth"
    if name == "static_response":
        if str(h.get("status_code", "")).startswith("3") and (h.get("headers") or {}).get("Location"):
            return "pre", "redir"
        return "unknown", "respond"
    return "unknown", name or "unnamed handler"


def _events(route, out, scope) -> None:
    """Routes and handlers in execution order, descending into subroutes.
    `scope` identifies the route list a route belongs to."""
    out.append(("route", route, scope))
    for h in route.get("handle") or []:
        if not isinstance(h, dict):
            continue
        if h.get("handler") == "subroute":
            inner = id(h)
            for r in h.get("routes") or []:
                if isinstance(r, dict):
                    _events(r, out, inner)
        else:
            out.append(("handler", h, scope))


def _status(route, source, active, label, hosts, server, expected=None) -> SiteStatus:
    events = []
    _events(route, events, id(route))
    s = SiteStatus(label, hosts, server, "not_imported")
    marker_at = next((i for i, (k, v, _) in enumerate(events) if k == "handler" and _is_marker(v, source.marker)), None)
    if marker_at is None:
        return s
    scope = events[marker_at][2]
    # Only a sibling route after the marker's own can be this source's ban route.
    ban_at = next((i for i, (k, v, sc) in enumerate(events)
                   if i > marker_at and k == "route" and sc == scope and _is_ban_route(v, expected)), None)
    if ban_at is None:
        if active:
            s.status = "unknown"
            s.detail = ("The ban list is imported, but the running configuration has no ban matcher yet. "
                        "Check the reload state.")
        else:
            s.status = "imported_empty"
        return s
    pre, unknown = [], []
    for kind, h, _ in events[:ban_at]:
        if kind != "handler" or _is_marker(h, source.marker):
            continue
        verdict, name = classify(h)
        bucket = pre if verdict == "pre" else unknown if verdict == "unknown" else None
        if bucket is not None and name not in bucket:
            bucket.append(name)
    if unknown:
        s.status, s.pre_handlers = "unknown", pre + unknown
        s.detail = ("Handlers run before the ban check that could answer the request first: "
                    + ", ".join(unknown) + ".")
    elif pre:
        s.status, s.pre_handlers = "enforced_pre_handler", pre
    else:
        s.status = "enforced"
    return s


def site_statuses(config, source, active: bool, *, expected_ranges=None) -> list:
    """`expected_ranges` (optional, keyword-only): CIDR strings the source's
    rendered policy bans; when given, a ban route only counts if its client_ip
    ranges equal that set (networks compared with strict=False)."""
    expected = None if expected_ranges is None else _nets(expected_ranges)
    servers = (((config or {}).get("apps") or {}).get("http") or {}).get("servers") or {}
    out = []
    for name, srv in sorted(servers.items()):
        if not isinstance(srv, dict):
            continue
        listen = (srv.get("listen") or [""])[0]
        for route in srv.get("routes") or []:
            if not isinstance(route, dict):
                continue
            hosts = [h for m in route.get("match") or [] if isinstance(m, dict) for h in (m.get("host") or [])]
            out.append(_status(route, source, active, hosts[0] if hosts else (listen or name), hosts, name, expected))
    return out
