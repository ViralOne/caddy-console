"""On-disk Caddyfile facts the live config cannot give: which block a site is
in, whether it imports a managed policy first, and which site is the console's
own. A brace counter, not a parser, mirroring static/js/app/caddyfile-sites.js.
"""
import os
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .. import config

MANAGEMENT_MARK = "caddy-console: management"
_COMMENT = re.compile(r"(^|\s)#.*$")
_PLACEHOLDER = re.compile(r"\{[^{}\s]*\}")
_IMPORT = re.compile(r"^import\s+(\S+)")
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://")
_USER_MATCHER = re.compile(r"^@caddy_console_\w*")
_ROUTE = re.compile(r"^route(\s|\{|$)")
FIRST_MSG = "put the ban import first in the site block (or first inside its top-level route) so nothing runs before the ban check."

AFTER_MSG = ("put the CrowdSec import first in the site block, or directly after the manual ban import, "
             "so nothing runs before the ban check.")


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


def block_import_state(text, block, path, after=()) -> dict:
    """`after`: other managed policy paths that may come before this import
    (the CrowdSec import goes directly after the manual one)."""
    lines = str(text).split("\n")
    children, depth = [], 1
    for n in range(block.start, block.end - 1):        # interior lines; n + 1 is the line number
        line = _strip(lines[n])
        if not line:
            continue
        children.append((n + 1, line, depth))
        bare = _PLACEHOLDER.sub("", line)
        depth += bare.count("{") - bare.count("}")
    matches = [ln for ln, line, _ in children if _is_policy_import(line, path)]
    state = {"present": bool(matches), "count": len(matches),
             "line": matches[0] if matches else None, "first_child": False, "layout": None}

    def leads(seq) -> bool:
        for _, line in seq:
            if _is_policy_import(line, path):
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
            out.append(f"Line {st['line']}: {AFTER_MSG if after else FIRST_MSG}")
    return out
