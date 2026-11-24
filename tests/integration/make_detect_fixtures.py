"""Adapt representative site layouts with the running Caddy and print the JSON.

  docker compose -f docker-compose.dev.yaml exec -T caddy-console \
    /app/.venv/bin/python - < tests/integration/make_detect_fixtures.py \
    > tests/fixtures/bans/adapted-layouts.json

Only POST /adapt is used, so the running dev configuration never changes.
"""
import json
import os
import sys

import requests

API = os.environ.get("CADDY_API_URL", "http://caddy-target:2019")
DIR = "/etc/caddy/console-fixtures"
ACTIVE = (
    "# Managed by Caddy Console. Do not edit; changes are overwritten.\n"
    "vars caddy_console_manual_policy 1\n"
    "@caddy_console_manual_banned {\n"
    "\tclient_ip 198.51.100.0/24 203.0.113.7\n"
    "\tnot client_ip private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10\n"
    "}\n"
    "handle @caddy_console_manual_banned {\n"
    "\trespond 403\n"
    "}\n"
)
EMPTY = ("# Managed by Caddy Console. Do not edit; changes are overwritten.\n"
         "vars caddy_console_manual_policy 1\n")
CS_ACTIVE = (
    "# Managed by Caddy Console. Do not edit; changes are overwritten.\n"
    "vars caddy_console_crowdsec_policy 1\n"
    "@caddy_console_crowdsec_banned {\n"
    "\tclient_ip 192.0.2.0/24 203.0.113.9\n"
    "\tnot client_ip private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10\n"
    "}\n"
    "handle @caddy_console_crowdsec_banned {\n"
    "\trespond 403\n"
    "}\n"
)
IMP = f"import {DIR}/active/bans-manual*.caddy"
IMP_CS = f"import {DIR}/active/bans-crowdsec*.caddy"
IMP_EMPTY = f"import {DIR}/empty/bans-manual*.caddy"
G = "{\n\tadmin 0.0.0.0:2019\n}\n"
HASH = "$2a$14$Zkx19XLiW6VYouLHR5NmfOFU0z2GTNmpkT/5qqR7hx4IjWJPDhjvG"


def site(body, imp=IMP, global_block=G, before=""):
    return f"{global_block}{before}a.example.com {{\n{body.format(imp=imp)}}}\n"


LAYOUTS = {
    "simple_proxy": site("\t{imp}\n\treverse_proxy 127.0.0.1:9\n"),
    "handle_catchall": site("\t{imp}\n\thandle {{\n\t\treverse_proxy 127.0.0.1:9\n\t}}\n"),
    "handle_path_specific": site("\t{imp}\n\thandle /api/* {{\n\t\trespond \"api\"\n\t}}\n\thandle {{\n\t\trespond \"app\"\n\t}}\n"),
    "handle_before_import": site("\thandle /x/* {{\n\t\trespond \"x\"\n\t}}\n\t{imp}\n\thandle {{\n\t\trespond \"app\"\n\t}}\n"),
    "handle_path": site("\t{imp}\n\thandle_path /static/* {{\n\t\trespond \"static\"\n\t}}\n\thandle {{\n\t\trespond \"app\"\n\t}}\n"),
    "route_strict": site("\troute {{\n\t\t{imp}\n\t\tredir /old /new\n\t\treverse_proxy 127.0.0.1:9\n\t}}\n"),
    "redir_before": site("\t{imp}\n\tredir /old /new\n\treverse_proxy 127.0.0.1:9\n"),
    "rewrite_before": site("\t{imp}\n\trewrite /old /new\n\treverse_proxy 127.0.0.1:9\n"),
    "basic_auth_before": site("\t{imp}\n\tbasic_auth {{\n\t\tbob " + HASH.replace("{", "{{").replace("}", "}}") + "\n\t}}\n\treverse_proxy 127.0.0.1:9\n"),
    "forward_auth_before": site("\t{imp}\n\tforward_auth 127.0.0.1:9 {{\n\t\turi /verify\n\t}}\n\treverse_proxy 127.0.0.1:9\n"),
    "request_header_before": site("\t{imp}\n\trequest_header X-Test 1\n\treverse_proxy 127.0.0.1:9\n"),
    "invoke_before": site("\t{imp}\n\tinvoke app\n", before="&(app) {\n\trespond \"named\" 200\n}\n"),
    "custom_order_first": site("\t{imp}\n\trespond \"hi\" 200\n", global_block="{\n\tadmin 0.0.0.0:2019\n\torder respond first\n}\n"),
    "empty_policy": site("\t{imp}\n\treverse_proxy 127.0.0.1:9\n", imp=IMP_EMPTY),
    "manual_and_crowdsec": site("\t{imp}\n\t" + IMP_CS + "\n\treverse_proxy 127.0.0.1:9\n"),
    "crowdsec_only": site("\t" + IMP_CS + "\n\treverse_proxy 127.0.0.1:9\n"),
    "not_imported": site("\treverse_proxy 127.0.0.1:9\n"),
}


def main():
    for sub, body in (("active", ACTIVE), ("empty", EMPTY)):
        os.makedirs(f"{DIR}/{sub}", exist_ok=True)
        with open(f"{DIR}/{sub}/bans-manual.caddy", "w", encoding="utf-8") as f:
            f.write(body)
    with open(f"{DIR}/active/bans-crowdsec.caddy", "w", encoding="utf-8") as f:
        f.write(CS_ACTIVE)
    out = {}
    for name, text in LAYOUTS.items():
        resp = requests.post(f"{API}/adapt", data=text.encode(), timeout=20,
                             headers={"Content-Type": "text/caddyfile"})
        if resp.status_code != 200:
            sys.exit(f"{name}: adapt failed: {resp.text}")
        out[name] = resp.json()["result"]
    json.dump(out, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")


main()
