"""CrowdSec plugin mode end to end (spec "Run the optional plugin overlay").

Runs inside the console container of tests/integration/plugin/compose.yaml, one
step per call; dev/crowdsec-plugin-it.sh drives the steps that need the host or
another container. It uses the console only through its HTTP API and files,
and the Caddyfiles it writes use the shipped snippet code verbatim, so every
successful start is also the "documented snippets adapt and run" check.

  python -m tests.integration.plugin_it <command> [args]
"""
import ipaddress
import json
import os
import re
import sys
import time

import requests

CADDYFILE = "/etc/caddy/Caddyfile"
BANS_DIR = "/etc/caddy/console"
ROUTE = f"{BANS_DIR}/crowdsec-plugin-protect.caddy"
CONSOLE = "http://127.0.0.1:9090"
LAPI = "http://crowdsec:8080"
CONTROL = {"X-Control": os.environ.get("FAKE_LAPI_CONTROL", "")}
AUTH = {"Cf-Access-Authenticated-User-Email": "it@example.com"}
FIXED = "172.30.250.2:2019"
ADMIN = {
    "fixed": f"\tadmin {FIXED} {{\n\t\torigins caddy:2019 {FIXED}\n\t}}\n",
    "wildcard": "\tadmin 0.0.0.0:2019\n",
    "loopback": "\tadmin localhost:2019\n",
    "missing": "",
}
SERVERS = ("\tservers :8001 {\n\t\ttrusted_proxies static 192.0.2.0/24\n\t\tclient_ip_headers Cf-Connecting-Ip\n\t}\n"
           "\tservers :8002 {\n\t\ttrusted_proxies static 172.30.252.3/32\n\t\tclient_ip_headers Cf-Connecting-Ip\n\t}\n")


def fail(message):
    sys.exit(f"plugin_it: {message}")


def wait(pred, seconds, what):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            if pred():
                return
        except (requests.RequestException, OSError, ValueError, KeyError, TypeError):
            pass
        time.sleep(1)
    fail(f"timed out after {seconds}s waiting for {what}")


def shipped():
    with open("/app/src/snippets.json", encoding="utf-8") as f:
        return {s["id"]: s["code"].replace("/etc/caddy/console/", BANS_DIR + "/") for s in json.load(f) if "id" in s}


def indent(code, prefix):
    return "".join(prefix + line + "\n" for line in code.splitlines())


def caddyfile(mode, admin="fixed", stage="full", key_path=None):
    s = shipped()
    glob = s[f"crowdsec-plugin-global-{mode}"]
    if key_path:
        glob = glob.replace("/run/secrets/crowdsec_plugin_bouncer_key", key_path)
    site = indent(s["crowdsec-plugin-site"], "\t") if stage == "full" else ""
    hosts = lambda h: f"http://{h}, http://{h}:8001, http://{h}:8002"
    return ("{\n" + ADMIN[admin] + SERVERS + indent(glob, "\t") + "}\n\n" + s["crowdsec-plugin-definition"] + "\n"
            + hosts("plugin.it.example.com") + " {\n\timport " + BANS_DIR + "/bans-manual*.caddy\n" + site
            + "\trespond \"plugin ok\" 200\n}\n\n"
            + hosts("file.it.example.com") + " {\n\timport " + BANS_DIR + "/bans-manual*.caddy\n\timport "
            + BANS_DIR + "/bans-crowdsec*.caddy\n\trespond \"file ok\" 200\n}\n")


def session():
    s = requests.Session()
    s.headers.update(AUTH)
    page = s.get(CONSOLE + "/", timeout=10).text
    s.headers["X-CSRF-Token"] = re.search(r'name="csrf-token" content="([^"]+)"', page).group(1)
    return s


def security():
    r = session().get(CONSOLE + "/api/security", timeout=20)
    r.raise_for_status()
    return r.json()


def row(status, host):
    return next(x for x in status["sites"] if host in x["hosts"])


def cmd_write_caddyfile(mode, admin="fixed", stage="full", key_path=None):
    with open(CADDYFILE, "w", encoding="utf-8") as f:
        f.write(caddyfile(mode, admin, stage, key_path))


def cmd_wait_definition():
    wait(lambda: security()["plugin"]["module"] is True, 60, "the console to see the crowdsec module")
    wait(lambda: security()["plugin"]["definition"]["current"], 90, "the protected route definition")
    with open(ROUTE, encoding="utf-8") as f:
        text = f.read()
    if "\t\tnot client_ip private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10 " not in text \
            or " 203.0.113.99" not in text:
        fail(f"the route lacks the protected set or BANS_NEVER:\n{text}")
    p = security()["plugin"]
    if p["refused"] or p["admin"] is not None:
        fail(f"plugin mode refused: {p['admin']}")
    print(f"definition current ({p['definition']['hash']}); admin bind accepted")


def cmd_save(mode):
    s = session()
    version = s.get(CONSOLE + "/api/caddyfile", timeout=10).json().get("version")
    bad = caddyfile(mode, admin="wildcard")
    r = s.post(CONSOLE + "/api/save", json={"content": bad, "version": version}, timeout=30)
    if r.status_code != 409 or r.json().get("code") != "admin_exposed":
        fail(f"a wildcard admin save was not refused: {r.status_code} {r.text[:300]}")
    r = s.post(CONSOLE + "/api/save", json={"content": caddyfile(mode), "version": version}, timeout=60)
    if r.status_code != 200 or not r.json().get("ok"):
        fail(f"saving the protected sites failed: {r.status_code} {r.text[:500]}")
    print("wildcard save refused; protected sites saved and loaded")


def cmd_check_paths():
    def ready():
        st = security()
        p, f = row(st, "plugin.it.example.com")["policies"], row(st, "file.it.example.com")["policies"]
        return (p["plugin"]["status"] == "enforced" and p["crowdsec"]["status"] == "not_imported"
                and f["plugin"]["status"] == "not_imported" and f["crowdsec"]["status"] in ("enforced", "imported_empty"))
    wait(ready, 60, "plugin site on the plugin path and file site on the file path")
    print("per-site CrowdSec paths: plugin site -> plugin, file site -> file sync")


def cmd_lapi_add(value, origin="lists:it"):
    r = requests.post(LAPI + "/it/add", json={"value": value, "origin": origin}, headers=CONTROL, timeout=5)
    r.raise_for_status()
    print(r.json()["id"])


def cmd_check_keys():
    calls = requests.get(LAPI + "/it/calls", headers=CONTROL, timeout=5).json()
    stream = [c for c in calls if c["path"] == "/v1/decisions/stream"]
    plugin = {c["ua"].split("/")[0] for c in stream if c["name"] == "plugin"}
    console = {c["ua"].split("/")[0] for c in stream if c["name"] == "console"}
    if not plugin or not console or "caddy-console" in plugin or console != {"caddy-console"}:
        fail(f"bouncer identities are mixed up: plugin UAs {plugin}, console UAs {console}")
    if any(c["name"] is None for c in calls):
        fail("a request used an unknown key")
    print(f"plugin polls with its own key ({sorted(plugin)}); the console with its own")


def covers(path, value):
    """True when a prefix in the policy file contains value (the renderer collapses
    adjacent prefixes, so 203.0.113.84 and .85 become 203.0.113.84/31)."""
    ip = ipaddress.ip_address(value)
    with open(path, encoding="utf-8") as f:
        for token in f.read().split():
            try:
                if ip in ipaddress.ip_network(token, strict=False):
                    return True
            except ValueError:
                continue
    return False


def cmd_manual_ban(value):
    r = session().post(CONSOLE + "/api/bans", json={"value": value, "duration": "4h", "reason": "plugin it"}, timeout=60)
    if r.status_code != 201 or r.json().get("enforcement") != "enforced":
        fail(f"manual ban failed: {r.status_code} {r.text[:300]}")
    if not covers(f"{BANS_DIR}/bans-manual.caddy", value):
        fail("the manual ban is not in bans-manual.caddy")
    if covers(ROUTE, value):
        fail("a manual ban leaked into the plugin route")
    print(f"manual ban {value} rendered to bans-manual.caddy only")


def cmd_wait_file_record(value):
    def stored():
        with open("/backups/bans.json", encoding="utf-8") as f:
            return any(r["source"] == "crowdsec" and r["value"] == value for r in json.load(f)["records"])
    try:
        wait(stored, 45, f"the console's file sync to store {value}")
    except SystemExit:
        try:
            print(json.dumps(security()["sources"].get("crowdsec"), indent=1), file=sys.stderr)
        except (requests.RequestException, ValueError, KeyError):
            pass
        raise


def cmd_check_ignored(value):
    with open("/backups/bans.json", encoding="utf-8") as f:
        if any(r["value"] == value for r in json.load(f)["records"]):
            fail(f"{value} (lists:it origin) was synced into the file; only the plugin should enforce it")


COMMANDS = {name[4:].replace("_", "-"): fn for name, fn in globals().items() if name.startswith("cmd_")}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        fail(f"usage: plugin_it {{{'|'.join(sorted(COMMANDS))}}} [args]")
    COMMANDS[sys.argv[1]](*sys.argv[2:])
