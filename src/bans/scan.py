"""On-disk Caddyfile facts the live config cannot give: which block a site is
in, whether it imports a managed policy first, and which site is the console's
own. A brace counter, not a parser, mirroring static/js/app/caddyfile-sites.js.
"""
import os
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .. import config
from . import plugin

MANAGEMENT_MARK = "caddy-console: management"
_COMMENT = re.compile(r"(^|\s)#.*$")
_PLACEHOLDER = re.compile(r"\{[^{}\s]*\}")
_IMPORT = re.compile(r"^import\s+(\S+)")
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://")
_USER_MATCHER = re.compile(r"^@caddy_console_\w*")
_ROUTE = re.compile(r"^route(\s|\{|$)")
FIRST_MSG = "put the ban import first in the site block (or first inside its top-level route) so nothing runs before the ban check."



@dataclass
class SiteBlock:
    addresses: list
    hosts: list
    start: int
    end: int
    management: bool = False


def host_of(address) -> str:
    a = _SCHEME.sub("", str(address).lower())
    return re.sub(r":\d+$", "", re.sub(r"/.*$", "", a))


def _strip(raw: str) -> str:
    return _COMMENT.sub("", raw).strip()


def site_blocks(text) -> list:
    blocks, depth, current = [], 0, None
    for i, raw in enumerate(str(text).split("\n"), 1):
        line = _strip(raw)
        if line and depth == 0 and line.endswith("{") and line != "{" and not line.startswith(("(", "&(")):
            addresses = [a for a in re.split(r"[\s,]+", line[:-1]) if a]
            current = SiteBlock(addresses, [h for h in map(host_of, addresses) if h], i, i)
            blocks.append(current)
        if current is not None and MANAGEMENT_MARK in raw:
            current.management = True
        if not line:
            continue
        bare = _PLACEHOLDER.sub("", line)
        depth = max(0, depth + bare.count("{") - bare.count("}"))
        if current is not None:
            current.end = i
        if depth == 0:
            current = None
    return blocks


def _glob_regex(glob: str):
    out, i = [], 0
    while i < len(glob):
        c = glob[i]
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[" and glob.find("]", i + 1) > i:
            end = glob.find("]", i + 1)
            out.append(glob[i:end + 1])
            i = end
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("".join(out) + r"\Z")


def glob_matches(pattern: str, path: str) -> bool:
    if pattern.startswith("/"):
        return bool(_glob_regex(pattern).match(path))
    if "/" not in pattern and "." not in pattern:
        return False            # a snippet or named-route name, not a file
    # Relative to Caddy's working directory, which the console cannot know.
    return bool(_glob_regex(os.path.basename(pattern)).match(os.path.basename(path)))


def import_targets(text) -> list:
    out = []
    for i, raw in enumerate(str(text).split("\n"), 1):
        m = _IMPORT.match(_strip(raw))
        if m:
            out.append((i, m.group(1)))
    return out


def mentions_import(text, path) -> bool:
    return any(glob_matches(token, path) for _, token in import_targets(text))


def imports_files(text) -> bool:
    """True when the Caddyfile imports any file, which may in turn import a
    managed policy: the console cannot follow those includes."""
    return any(token.startswith("/") or "/" in token or "." in token for _, token in import_targets(text))


def _is_policy_import(line, path) -> bool:
    m = _IMPORT.match(line)
    return bool(m and glob_matches(m.group(1), path))


def _is_snippet_import(line, snippet) -> bool:
    m = _IMPORT.match(line)
    return bool(m and m.group(1) == snippet)


def block_import_state(text, block, path, after=(), snippet=None) -> dict:
    """`after`: other managed policy paths that may come before this import
    (the CrowdSec import goes directly after the manual one). `snippet`: match
    `import <snippet>` (a Caddyfile snippet such as protect_crowdsec) instead
    of a file glob covering `path`."""
    mine = (lambda line: _is_snippet_import(line, snippet)) if snippet else (lambda line: _is_policy_import(line, path))
    lines = str(text).split("\n")
    children, depth = [], 1
    for n in range(block.start, block.end - 1):        # interior lines; n + 1 is the line number
        line = _strip(lines[n])
        if not line:
            continue
        children.append((n + 1, line, depth))
        bare = _PLACEHOLDER.sub("", line)
        depth += bare.count("{") - bare.count("}")
    matches = [ln for ln, line, _ in children if mine(line)]
    state = {"present": bool(matches), "count": len(matches),
             "line": matches[0] if matches else None, "first_child": False, "layout": None}

    def leads(seq) -> bool:
        for _, line in seq:
            if mine(line):
                return True
            if not any(_is_policy_import(line, p) for p in after):
                return False
        return False
    top = [(ln, line) for ln, line, d in children if d == 1]
    if leads(top):
        state.update(first_child=True, layout="site")
    elif top and _ROUTE.match(top[0][1]):
        route_ln = top[0][0]
        inner = [(ln, line) for ln, line, d in children if d == 2 and ln > route_ln]
        if leads(inner):
            state.update(first_child=True, layout="strict")
    return state


def console_host():
    """The console's own host from SERVER_URL, or None when it was not set explicitly.

    The one place that decides this; the other way a site is recognised as the
    console's is the `# caddy-console: management` comment (see site_blocks).
    """
    if not config.SERVER_URL_CONFIGURED:
        return None
    return (urlsplit(config.SERVER_URL).hostname or "").lower() or None


def management_hosts(text, server_host=None) -> set:
    hosts = {h for b in site_blocks(text) if b.management for h in b.hosts}
    if server_host:
        hosts.add(server_host.lower())
    return hosts


def _after_msg(label, after) -> str:
    own = label.removesuffix(" ban list")
    prior = " or ".join(os.path.basename(p).removeprefix("bans-").removesuffix(".caddy") for p in after)
    return (f"put the {own} import first in the site block, or directly after the {prior} ban import, "
            "so nothing runs before the ban check.")


def bans_warnings(text, path, management=frozenset(), *, label="manual ban list", short="the ban list",
                  after=(), reserved=True) -> list:
    out = []
    if reserved:
        for i, raw in enumerate(str(text).split("\n"), 1):
            if _USER_MATCHER.match(_strip(raw)):
                out.append(f"Line {i}: matcher names starting with @caddy_console_ are reserved for "
                           "Caddy Console's generated policy; rename this matcher.")
    for block in site_blocks(text):
        st = block_import_state(text, block, path, after=after)
        if not st["present"]:
            continue
        if set(block.hosts) & set(management):
            out.append(f"Line {st['line']}: this is the console's own site; importing {short} "
                       "here could lock you out of the console.")
        if st["count"] > 1:
            out.append(f"Line {st['line']}: this site imports the {label} {st['count']} times; keep one import.")
        if not st["first_child"]:
            out.append(f"Line {st['line']}: {_after_msg(label, after) if after else FIRST_MSG}")
    return out


_CROWDSEC_LINE = re.compile(r"^crowdsec(\s|$)")
_API_KEY = re.compile(r"^api_key\s+(\S+)")


def _depth_lines(text):
    """(line number, stripped line, depth before the line) for every non-empty line."""
    out, depth = [], 0
    for i, raw in enumerate(str(text).split("\n"), 1):
        line = _strip(raw)
        if not line:
            continue
        out.append((i, line, depth))
        bare = _PLACEHOLDER.sub("", line)
        depth = max(0, depth + bare.count("{") - bare.count("}"))
    return out


def _global_block(lines):
    """The global options block: the first top-level line, when it is a bare "{"."""
    if not lines or lines[0][1] != "{" or lines[0][2] != 0:
        return []
    inner = []
    for ln, line, depth in lines[1:]:
        if depth == 0:
            break
        inner.append((ln, line, depth))
    return inner


def plugin_warnings(text, definition_path, management=frozenset(), *, snippet="protect_crowdsec",
                    placeholder=None, crowdsec_path=None) -> list:
    out = []
    lines = _depth_lines(text)
    glob_line = f"import {os.path.join(os.path.dirname(definition_path), os.path.basename(definition_path)[:-len('.caddy')] + '*.caddy')}"
    top = [(ln, line) for ln, line, d in lines if d == 0]
    definition_top = any(_is_policy_import(line, definition_path) for _, line in top)
    g = _global_block(lines)
    app_at = next((ln for ln, line, d in g if d == 1 and line.startswith("crowdsec") and line.endswith("{")), None)
    if app_at is not None:
        if not any(d == 1 and re.match(r"^order\s+crowdsec\s", line) for _, line, d in g):
            out.append(f"Line {app_at}: add `order crowdsec first` to the global options, or Caddy cannot place the "
                       "crowdsec handler.")
        for ln, line, d in g:
            m = _API_KEY.match(line)
            if d != 2 or not m:
                continue
            value = m.group(1)
            if not plugin.is_placeholder(value):
                out.append(f"Line {ln}: the bouncer key is written into the Caddyfile, where anyone who can read "
                           f"Caddy's config sees it; use api_key {placeholder or '{env.CROWDSEC_PLUGIN_BOUNCER_KEY}'}.")
            elif placeholder and value != placeholder:
                out.append(f"Line {ln}: api_key is {value}, but this deployment's Caddy expects {placeholder} "
                           "(set by CROWDSEC_PLUGIN_BOUNCER_KEY_FILE).")
    for block in site_blocks(text):
        inner = [(ln, line) for ln, line, d in lines if block.start < ln < block.end and d >= 1]
        uses = [ln for ln, line in inner if _is_snippet_import(line, snippet)]
        for ln, line in inner:
            if _is_policy_import(line, definition_path):
                out.append(f"Line {ln}: the protected route definition is a top-level import; move it outside every "
                           "site block, below the global options.")
            elif _CROWDSEC_LINE.match(line) and not line.endswith("{"):
                out.append(f"Line {ln}: the crowdsec handler without import {snippet} also runs for private, Docker "
                           f"and BANS_NEVER addresses; use import {snippet} instead.")
        if not uses:
            continue
        if not definition_top:
            out.append(f"Line {uses[0]}: import {snippet} needs the protected route definition at top level "
                       f"first: {glob_line}")
        if set(block.hosts) & set(management):
            out.append(f"Line {uses[0]}: this is the console's own site; the CrowdSec plugin here could lock you "
                       "out of the console.")
        if len(uses) > 1:
            out.append(f"Line {uses[0]}: this site imports {snippet} {len(uses)} times; keep one import.")
        if crowdsec_path and any(_is_policy_import(line, crowdsec_path) for _, line in inner):
            out.append(f"Line {uses[0]}: this site enforces CrowdSec decisions twice, through bans-crowdsec.caddy "
                       "and the plugin; plugin sites do not need the CrowdSec file import.")
    return out


_TRUSTED = re.compile(r"^trusted_proxies\s+static\s+(.+)$")
_BROAD = {"private_ranges", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fd00::/8"}


def trust_warnings(text, mode: str, tunnel_only: bool = False) -> list:
    """Spec 4.1: a broad private-range trust lets any LAN or published-port peer
    forge CF-Connecting-IP. Accepted only for a confirmed tunnel-only listener."""
    out = []
    for ln, line, depth in _global_block(_depth_lines(text)):
        m = _TRUSTED.match(line)
        if not m or depth < 2:
            continue
        broad = sorted(set(m.group(1).split()) & _BROAD)
        if broad and not (mode == "cloudflare-tunnel" and tunnel_only):
            out.append(f"Line {ln}: trusted_proxies {' '.join(broad)} lets any peer in those ranges, including LAN "
                       "and published-port clients, forge the client IP. Trust the fixed cloudflared address, or "
                       "import cloudflare-trusted-proxies*.caddy and select the profile in Security.")
    return out
