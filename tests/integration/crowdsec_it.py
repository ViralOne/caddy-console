"""CrowdSec file sync end to end (spec "Run the optional CrowdSec overlay").

Runs inside caddy-console of the dev stack started with docker-compose.crowdsec.yaml,
one step per call; dev/crowdsec-it.sh drives the steps that need the host or the
crowdsec container. It talks to the real console only through its files and
Caddy's data plane, so it proves what the gunicorn workers actually do.

  python -m tests.integration.crowdsec_it <command> [args]
"""
import json
import os
import re
import signal
import sys
import time

import requests

CADDYFILE = os.environ.get("CADDYFILE_PATH", "/etc/caddy/Caddyfile")
SAVED = os.path.join(os.path.dirname(CADDYFILE), ".crowdsec-it.Caddyfile.orig")
API = os.environ.get("CADDY_API_URL", "http://caddy-target:2019")
DATA = os.environ.get("CADDY_DATA_URL", "http://caddy-target:80")
LAPI = os.environ.get("CROWDSEC_URL", "http://crowdsec:8080")
BANS_DIR = os.environ.get("BANS_DIR", "/etc/caddy/console")
BACKUP_DIR = os.environ.get("BACKUP_DIR", "/backups")
STATUS = os.path.join(BACKUP_DIR, "bans-crowdsec-sync.json")
STATE = os.path.join(BACKUP_DIR, "bans.json")
POLICY = os.path.join(BANS_DIR, "bans-crowdsec.caddy")
MARK = "/tmp/crowdsec-it.json"
EXPLAIN_LOG = "/var/log/caddy/explain-it.log"
HASH = "$2a$14$Zkx19XLiW6VYouLHR5NmfOFU0z2GTNmpkT/5qqR7hx4IjWJPDhjvG"
UA = "caddy-console-it/1.0"
# Nikto's own User-Agent. The pinned hub list matches case-sensitively (\bSqlmap\b,
# \bNikto\b), so the real lowercase "sqlmap/..." agent never triggers http-bad-user-agent.
BAD_UA = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)"
CS, AUTH, EXPLAIN = "cs.it.example.com", "auth.cs.it.example.com", "explain.cs.it.example.com"
EXPECT = {"203.0.113.61": "crowdsecurity/http-probing",
          "203.0.113.62": "crowdsecurity/http-bad-user-agent",
          "203.0.113.63": "crowdsecurity/http-generic-bf"}

FIELDS = ("\tlog_append <user_agent {http.request.header.User-Agent}\n"
          "\tlog_append auth_challenge {http.response.header.Www-Authenticate}\n")
IMPORTS = f"\timport {BANS_DIR}/bans-manual*.caddy\n\timport {BANS_DIR}/bans-crowdsec*.caddy\n"


def log_block(path):
    return ("\tlog {\n\t\toutput file " + path + " {\n\t\t\tmode 0644\n\t\t}\n"
            "\t\tformat filter {\n\t\t\twrap json\n\t\t\trequest>headers delete\n\t\t\tresp_headers delete\n\t\t}\n\t}\n")


TEXT = ("{\n\tadmin 0.0.0.0:2019\n\tservers {\n\t\ttrusted_proxies static private_ranges\n"
        "\t\tclient_ip_headers X-Forwarded-For\n\t}\n}\n\n"
        f"http://{CS} {{\n" + IMPORTS + FIELDS + log_block("/var/log/caddy/access.log")
        + "\trespond /ok \"ok\" 200\n\trespond 404\n}\n\n"
        f"http://{AUTH} {{\n" + IMPORTS + FIELDS + log_block("/var/log/caddy/access.log")
        + "\tbasic_auth {\n\t\tit " + HASH + "\n\t}\n\trespond \"secret\" 200\n}\n\n"
        f"http://{EXPLAIN} {{\n" + FIELDS + log_block(EXPLAIN_LOG)
        + "\tbasic_auth /private/* {\n\t\tit " + HASH + "\n\t}\n\trespond /ok \"ok\" 200\n\trespond 404\n}\n")


def fail(message):
    sys.exit(f"crowdsec_it: {message}")


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


def load(text):
    r = requests.post(f"{API}/load", data=text.encode("utf-8"), headers={"Content-Type": "text/caddyfile"}, timeout=20)
    if r.status_code != 200:
        fail(f"/load answered {r.status_code}: {r.text[:500]}")


def get(host, path="/ok", ip="203.0.113.60", ua=UA, auth=None):
    return requests.get(DATA + path, headers={"Host": host, "X-Forwarded-For": ip, "User-Agent": ua},
                        auth=auth, timeout=5, allow_redirects=False)


def status():
    with open(STATUS, encoding="utf-8") as f:
        return json.load(f)


def policy_bytes():
    with open(POLICY, "rb") as f:
        return f.read()


def decisions(ip):
    key = os.environ["CROWDSEC_CONSOLE_BOUNCER_KEY"]
    r = requests.get(f"{LAPI}/v1/decisions", params={"ip": ip}, headers={"X-Api-Key": key}, timeout=5)
    r.raise_for_status()
    return r.json() or []


def utc_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def cmd_prepare():
    # The Caddyfile must use the shipped snippet lines verbatim, so a successful
    # /load below is also the "every shipped snippet adapts" check (spec Testing).
    with open("/app/src/snippets.json", encoding="utf-8") as f:
        shipped = {s["id"]: s["code"] for s in json.load(f) if "id" in s}
    for sid in ("crowdsec-bans-site", "crowdsec-log-fields"):
        for line in shipped[sid].replace("/etc/caddy/console/", BANS_DIR + "/").splitlines():
            if "\t" + line + "\n" not in TEXT:
                fail(f"the integration Caddyfile does not use the shipped {sid} line {line!r}")
    if not os.path.exists(SAVED):
        with open(CADDYFILE, "rb") as f, open(SAVED, "wb") as out:
            out.write(f.read())
    with open(CADDYFILE, "w", encoding="utf-8") as f:
        f.write(TEXT)
    load(TEXT)
    wait(lambda: get(CS).status_code == 200, 30, "the integration site")


def cmd_restore():
    if os.path.exists(SAVED):
        with open(SAVED, "rb") as f:
            data = f.read()
        with open(CADDYFILE, "wb") as f:
            f.write(data)
        os.remove(SAVED)
        load(data.decode("utf-8"))


def cmd_explain_traffic():
    codes = [get(EXPLAIN, "/ok").status_code, get(EXPLAIN, "/missing").status_code,
             get(EXPLAIN, "/private/x", auth=("it", "wrong-password")).status_code]
    if codes != [200, 404, 401]:
        fail(f"explain site answered {codes}")

    def logged():
        with open(EXPLAIN_LOG, encoding="utf-8") as f:
            return f.read().count("\n") >= 3
    wait(logged, 20, "three lines in the explain log")
    with open(EXPLAIN_LOG, encoding="utf-8") as f:
        text = f.read()
    for leak in ('"headers"', '"resp_headers"', "Authorization", "wrong-password"):
        if leak in text:
            fail(f"the filtered log contains {leak}")
    if '"user_agent"' not in text or '"auth_challenge":"Basic' not in text:
        fail("the log lacks the user_agent or auth_challenge field (is log_append ordered before basic_auth?)")


def cmd_check_explain(ip):
    out = sys.stdin.read()
    value = r"(?:.* -> )?"
    need = [rf"evt\.Meta\.source_ip : {value}{re.escape(ip)}\s*$", rf"evt\.Meta\.http_path : {value}/missing\s*$",
            rf"evt\.Meta\.http_verb : {value}GET\s*$", rf"evt\.Meta\.http_status : {value}404\s*$",
            rf"evt\.Parsed\.http_user_agent : {value}{re.escape(UA)}\s*$", rf"evt\.Meta\.sub_type : {value}auth_fail\s*$"]
    missing = [p for p in need if not re.search(p, out, re.M)]
    seen = set(re.findall(rf"evt\.Meta\.source_ip : {value}(\S+)\s*$", out, re.M))
    if missing or seen != {ip}:
        fail(f"cscli explain: missing {missing}; source_ip values {sorted(seen)} (expected only {ip})\n{out[-3000:]}")
    print(f"cscli explain: source_ip is the visitor {ip}; path, verb, status, User-Agent and auth_fail present")


def cmd_scenario_traffic():
    for i in range(20):
        get(CS, f"/probe-{i}/admin.php", ip="203.0.113.61")
    for _ in range(3):
        get(CS, "/ok", ip="203.0.113.62", ua=BAD_UA)
    for _ in range(8):
        get(AUTH, "/", ip="203.0.113.63", auth=("it", "wrong-password"))


def cmd_wait_decisions():
    for ip, scenario in EXPECT.items():
        wait(lambda: scenario in {d.get("scenario") for d in decisions(ip)}, 180, f"{scenario} for {ip}")
        print(f"{ip}: {scenario}")
    for ip in EXPECT:
        wait(lambda: get(CS, ip=ip).status_code == 403, 90, f"file enforcement for {ip}")


def cmd_wait_enforced(ip, t0, seconds, expect):
    wait(lambda: get(CS, ip=ip).status_code == int(expect), int(seconds) + 10, f"HTTP {expect} for {ip}")
    elapsed = time.time() - float(t0)
    if elapsed > float(seconds):
        fail(f"{ip} reached HTTP {expect} after {elapsed:.0f}s; the objective is {seconds}s")
    print(f"{ip}: HTTP {expect} after {elapsed:.0f}s")


def cmd_check_records(ip, origin):
    with open(STATE, encoding="utf-8") as f:
        records = json.load(f)["records"]
    hits = [r for r in records if r["source"] == "crowdsec" and r["value"] == ip]
    if not hits or any(r["origin"] != origin or r["actor"] != "system" or not r["source_id"].isdigit() for r in hits):
        fail(f"unexpected crowdsec records for {ip}: {hits}")


def cmd_outage_start(ip):
    if get(CS, ip=ip).status_code != 403:
        fail(f"{ip} is not enforced before the outage")
    with open(MARK, "w", encoding="utf-8") as f:
        json.dump({"policy": policy_bytes().decode(), "snapshot": status()["last_snapshot_at"], "ip": ip}, f)


def cmd_outage_check(ip):
    with open(MARK, encoding="utf-8") as f:
        mark = json.load(f)
    wait(lambda: status()["lapi_state"] == "unreachable", 3 * status()["poll_interval"] + 20, "lapi_state unreachable")
    time.sleep(status()["sync_interval"])
    if policy_bytes().decode() != mark["policy"] or get(CS, ip=ip).status_code != 403:
        fail("the outage changed the CrowdSec policy or dropped enforcement")


def cmd_outage_recovered():
    with open(MARK, encoding="utf-8") as f:
        mark = json.load(f)
    wait(lambda: status()["lapi_state"] == "ok" and status()["last_snapshot_at"] > mark["snapshot"], 90,
         "a startup=true snapshot after LAPI recovered")


def sync_workers():
    out = []
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                if b"gunicorn" not in f.read():
                    continue
            names = []
            for tid in os.listdir(f"/proc/{pid}/task"):
                with open(f"/proc/{pid}/task/{tid}/comm", encoding="utf-8") as f:
                    names.append(f.read().strip())
        except OSError:
            continue
        if "bans-sync" in names:
            out.append(int(pid))
    return out


def cmd_failover():
    workers = sync_workers()
    if len(workers) < 2:
        fail(f"expected a bans-sync thread in every worker, found {workers}")
    doc = status()
    old = doc["leader_pid"]
    if old not in workers:
        fail(f"leader {old} is not one of the workers {workers}")
    t0 = utc_iso()
    os.kill(old, signal.SIGTERM)
    wait(lambda: status()["leader_pid"] not in (None, old) and status()["last_snapshot_at"] >= t0,
         3 * doc["poll_interval"] + 30, "a new leader that starts with a snapshot")
    print(f"sync leader {old} -> {status()['leader_pid']}, snapshot {status()['last_snapshot_at']}")


COMMANDS = {name[4:].replace("_", "-"): fn for name, fn in list(globals().items()) if name.startswith("cmd_")}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        fail(f"usage: python -m tests.integration.crowdsec_it {{{','.join(COMMANDS)}}} [args]")
    COMMANDS[sys.argv[1]](*sys.argv[2:])
