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


COUNTRY_MARKER = "caddy_console_country_policy"
COUNTRY_SHAPES = ("off", "direct", "cloudflare")


def _is_country_marker(node) -> bool:
    return (isinstance(node, dict) and node.get("handler") == "vars"
            and str(node.get(COUNTRY_MARKER, "")) in COUNTRY_SHAPES)


def country_shapes(config) -> list:
    """Every country policy shape (off, direct, cloudflare) a live config's
    vars handlers carry. The marker's value is the shape, not "1", and
    matcher names do not survive adaptation, so this is how the live config
    shows which shape Caddy loaded."""
    found, stack = [], [config]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if _is_country_marker(node):
                found.append(str(node[COUNTRY_MARKER]))
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return found


def marker_present(config, marker) -> bool:
    if marker == COUNTRY_MARKER:
        return bool(country_shapes(config))
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
# Caddy's `private_ranges` shortcut as it appears in adapted JSON
# (caddyhttp.PrivateRangesCIDR in Caddy 2.11.9).
PRIVATE_RANGES = ("192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8", "127.0.0.1/8", "fd00::/8", "::1")


def expand_tokens(tokens) -> list:
    out = []
    for t in tokens:
        out.extend(PRIVATE_RANGES if t == "private_ranges" else (t,))
    return out


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
    if name == "crowdsec":
        # The plugin only blocks banned clients (spec 3.5): never an application
        # pre-handler for a file policy, wherever `order crowdsec first` puts it.
        return "benign", None
    return "unknown", name or "unnamed handler"


def _events(route, out, scope, shielded=False) -> None:
    """Routes and handlers in execution order, descending into subroutes.
    `scope` identifies the route list a route belongs to; `shielded` marks a
    managed ban route (any source) and everything inside it: it only answers
    403 to clients it bans, so it is never a pre-handler for another source."""
    shielded = shielded or _is_ban_route(route)
    out.append(("route", route, scope, shielded))
    for h in route.get("handle") or []:
        if not isinstance(h, dict):
            continue
        if h.get("handler") == "subroute":
            inner = id(h)
            for r in h.get("routes") or []:
                if isinstance(r, dict):
                    _events(r, out, inner, shielded)
        else:
            out.append(("handler", h, scope, shielded))


def _status(route, source, active, label, hosts, server, expected=None) -> SiteStatus:
    events = []
    _events(route, events, id(route))
    s = SiteStatus(label, hosts, server, "not_imported")
    marker_at = next((i for i, (k, v, _, _) in enumerate(events) if k == "handler" and _is_marker(v, source.marker)), None)
    if marker_at is None:
        return s
    scope = events[marker_at][2]
    # Only a sibling route after the marker's own can be this source's ban route.
    ban_at = next((i for i, (k, v, sc, _) in enumerate(events)
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
    for kind, h, _, shielded in events[:ban_at]:
        if kind != "handler" or shielded or _is_marker(h, source.marker):
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


PLUGIN_UNPROTECTED = ("The crowdsec handler runs here without import protect_crowdsec, so private, Docker and "
                      "BANS_NEVER addresses reach the plugin. Replace the crowdsec line with import protect_crowdsec.")
PLUGIN_OUTDATED = ("The running protected route is older than the current protected set. Use Re-apply for the "
                   "plugin route in Security.")


def _protect_ranges(route):
    """The union of `not client_ip` ranges in the route's matchers, or None."""
    found = None
    for m in route.get("match") or []:
        if not isinstance(m, dict):
            continue
        for n in m.get("not") or []:
            nets = _client_ip_ranges(n)
            if nets:
                found = (found or set()) | nets
    return found


def _plugin_status(route, label, hosts, server, expected=None) -> SiteStatus:
    events = []
    _events(route, events, id(route))
    s = SiteStatus(label, hosts, server, "not_imported")
    found = [i for i, (k, v, _, _) in enumerate(events) if k == "handler" and v.get("handler") == "crowdsec"]
    if not found:
        return s
    # Every crowdsec handler in the site must sit behind the protected matcher:
    # one bare handler (say in a nested handle) blocks protected clients.
    owners = []
    for at in found:
        handler = events[at][1]
        # _events records each route before its handlers, so the owner is earlier.
        owner_at = max(i for i, (k, v, _, _) in enumerate(events[:at])
                       if k == "route" and any(h is handler for h in v.get("handle") or []))
        ranges = _protect_ranges(events[owner_at][1])
        if ranges is None or not _nets(REQUIRED_PROTECTED) <= ranges:
            s.status, s.detail = "plugin_unprotected", PLUGIN_UNPROTECTED
            return s
        owners.append((owner_at, ranges))
    if expected is not None and any(ranges != expected for _, ranges in owners):
        s.status, s.detail = "unknown", PLUGIN_OUTDATED
        return s
    owner_at = owners[0][0]
    pre, unknown = [], []
    for kind, h, _, shielded in events[:owner_at]:
        if kind != "handler" or shielded:
            continue
        verdict, name = classify(h)
        bucket = pre if verdict == "pre" else unknown if verdict == "unknown" else None
        if bucket is not None and name not in bucket:
            bucket.append(name)
    if unknown:
        s.status, s.pre_handlers = "unknown", pre + unknown
        s.detail = "Handlers run before the plugin check that could answer the request first: " + ", ".join(unknown) + "."
    elif pre:
        s.status, s.pre_handlers = "enforced_pre_handler", pre
    else:
        s.status = "enforced"
    return s


def plugin_site_statuses(config, *, expected_exclusions=None) -> list:
    """Per site, is the crowdsec handler in effective order behind the
    protected matcher? Same iteration as site_statuses, so rows align.
    `expected_exclusions`: the current protected tokens (expand_tokens form);
    a running route with another set is reported as out of date."""
    expected = None if expected_exclusions is None else _nets(expected_exclusions)
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
            out.append(_plugin_status(route, hosts[0] if hosts else (listen or name), hosts, name, expected))
    return out


COUNTRY_UNMATCHED = ("The running configuration has the country policy marker but not the denial handler that "
                     "belongs to it. Check the reload state.")


def _is_country_denial(route) -> bool:
    """geo.caddy's denial: a 403 behind a `not` matcher. Matcher names do not
    survive adaptation, so this is the shape the file always renders."""
    return _has_403(route.get("handle")) and any(isinstance(m, dict) and m.get("not") for m in route.get("match") or [])


def _country_status(route, label, hosts, server, expected) -> SiteStatus:
    events = []
    _events(route, events, id(route))
    s = SiteStatus(label, hosts, server, "not_imported")
    at = next((i for i, (k, v, _, _) in enumerate(events) if k == "handler" and _is_country_marker(v)), None)
    if at is None:
        return s
    shape = str(events[at][1][COUNTRY_MARKER])
    if expected is not None and shape != expected:
        s.status = "unknown"
        s.detail = (f"The running configuration has the {shape} country policy, but the current settings render "
                    f"{expected}. Save and reload to apply them.")
        return s
    if shape == "off":
        s.status = "imported_empty"
        return s
    scope = events[at][2]
    deny_at = next((i for i, (k, v, sc, _) in enumerate(events)
                    if i > at and k == "route" and sc == scope and _is_country_denial(v)), None)
    if deny_at is None:
        s.status, s.detail = "unknown", COUNTRY_UNMATCHED
        return s
    pre, unknown = [], []
    for kind, h, _, shielded in events[:deny_at]:
        if kind != "handler" or shielded or _is_country_marker(h):
            continue
        verdict, name = classify(h)
        bucket = pre if verdict == "pre" else unknown if verdict == "unknown" else None
        if bucket is not None and name not in bucket:
            bucket.append(name)
    if unknown:
        s.status, s.pre_handlers = "unknown", pre + unknown
        s.detail = ("Handlers run before the country check that could answer the request first: "
                    + ", ".join(unknown) + ".")
    elif pre:
        s.status, s.pre_handlers = "enforced_pre_handler", pre
    else:
        s.status = "enforced"
    return s


def country_site_statuses(config, *, expected_shape=None) -> list:
    """Per site, is the country policy marker live with its denial handler?
    Same iteration as site_statuses, so rows align. `expected_shape`: the shape
    the current settings render (off, direct, cloudflare)."""
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
            out.append(_country_status(route, hosts[0] if hosts else (listen or name), hosts, name, expected_shape))
    return out
