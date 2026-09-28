#!/usr/bin/env python3
"""Print a large but valid Caddyfile, for exercising the editor's diff and save
paths at sizes where the old O(lines^2) diff used to freeze the browser.

    python3 dev/gen-caddyfile.py 600 > /tmp/big-Caddyfile
"""
import sys

HEADER = """{
\tadmin 0.0.0.0:2019
\tmetrics
}

(access_log) {
\tlog {
\t\toutput file /var/log/caddy/access.log {
\t\t\troll_size 10mb
\t\t\troll_keep 3
\t\t\troll_keep_for 168h
\t\t}
\t\tformat filter {
\t\t\twrap json
\t\t\trequest>headers delete
\t\t\tresp_headers delete
\t\t}
\t}
}
"""

SITE = """
http://site{i}.example.com {{
\timport access_log
\treverse_proxy 127.0.0.1:{port}
}}
"""


def main() -> int:
    sites = int(sys.argv[1]) if len(sys.argv) > 1 else 600
    out = [HEADER]
    for i in range(sites):
        out.append(SITE.format(i=i, port=10000 + (i % 40000)))
    text = "".join(out)
    sys.stdout.write(text)
    print(
        f"# {sites} sites, {len(text.splitlines())} lines, {len(text)} bytes",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
