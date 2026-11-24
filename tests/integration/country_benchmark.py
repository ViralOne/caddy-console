"""Direct country policy at 1,000 / 10,000 / 20,000 prefixes (spec Phase 4 gate).

  docker compose -f docker-compose.dev.yaml restart caddy-target   # a clean Caddy heap is the RSS baseline
  docker compose -f docker-compose.dev.yaml exec -T caddy-console \
    /app/.venv/bin/python -m tests.integration.country_benchmark

Generated benchmark prefixes (80 % IPv4, 20 % IPv6, nothing collapses) in a
throwaway dataset, rendered by country.render() into geo.caddy and imported by
EIGHT sites on stock caddy-target (the Phase 1 bans benchmark imports its file
in a similar number of sites). Adaptation and /load time, Caddy's resident
memory, and p95 latency for the worst allowed client (the last prefix in the
list, so Caddy scans all of it) and for a denied client. The baseline is the
policy switched off. Prints a Markdown table and the cap the budget supports.
"""
import tests.integration._env as itenv  # noqa: I001  (must precede src imports)

import os

os.environ["COUNTRY_POLICY_ENABLED"] = "true"

import ipaddress
import re
import shutil
import statistics
import tempfile
import time

import requests

from src import config
from src.bans import caddy as caddy_admin, country, countrydata, fsio, protected

config.COUNTRY_MAX_PREFIXES = 200000       # measure sizes beyond any shipped cap
SITES = 8
SIZES = (0, 1000, 10000, 20000)
BUDGET = {"adapt_s": 2.0, "load_s": 3.0, "rss_delta_mib": 150.0, "p95_delta_ms": 2.0}
REQUESTS = 600
RUNS = 3                 # each size is measured RUNS times; the table shows medians (Go GC and a shared host are noisy)
D = itenv.BANS_DIR
GEO = os.path.join(D, "geo.caddy")
CADDYFILE = ("{\n\tadmin 0.0.0.0:2019\n\tservers {\n\t\ttrusted_proxies static private_ranges\n"
             "\t\tclient_ip_headers X-Forwarded-For\n\t}\n}\n" + "".join(
                 f"\nhttp://s{i}.it.example.com {{\n\timport {D}/geo*.caddy\n\trespond \"ok\" 200\n}}\n"
                 for i in range(SITES)))


def dataset(n):
    v4 = int(n * 0.8)
    base4 = int(ipaddress.ip_address("198.18.0.0"))
    rows = [(str(ipaddress.ip_network((base4 + 2 * i, 32))), "DE") for i in range(v4)]
    rows += [(f"2001:db8:{2 * i:x}::/48", "DE") for i in range(n - v4)]
    return rows


def rss_mib():
    text = requests.get(f"{itenv.API}/metrics", timeout=5).text
    return float(re.search(r"^process_resident_memory_bytes (\S+)$", text, re.M).group(1)) / 2 ** 20


def latency(ip, expect):
    samples = []
    for i in range(REQUESTS):
        t = time.perf_counter()
        r = requests.get(itenv.DATA_URL + "/", headers={"Host": f"s{i % SITES}.it.example.com", "X-Forwarded-For": ip},
                         allow_redirects=False, timeout=5)
        samples.append((time.perf_counter() - t) * 1000)
        assert r.status_code == expect, (ip, r.status_code)
    samples.sort()
    return statistics.median(samples), samples[int(len(samples) * 0.95) - 1]


def measure(n, workdir):
    if n:
        rows = dataset(n)
        with open(countrydata.path(workdir), "wb") as f:
            f.write(countrydata.dumps(rows, "2099-01"))
        data, facts = country.render(country.Policy(enabled=True, countries=["DE"]), "direct", [],
                                     protected.build().exclusion_tokens(), workdir)
        assert facts["prefixes"]["total"] == n, facts["prefixes"]
        last_allowed = str(ipaddress.ip_network(rows[-1][0]).network_address)
    else:
        data, _ = country.render(country.Policy(), "direct", [], [])
        last_allowed = "198.18.0.0"
    fsio.atomic_write(GEO, data, 0o644)
    t = time.perf_counter()
    adapted = caddy_admin.adapt(CADDYFILE)
    adapt_s = time.perf_counter() - t
    assert adapted.ok, adapted.message
    t = time.perf_counter()
    loaded = caddy_admin.load(CADDYFILE)
    load_s = time.perf_counter() - t
    assert loaded.status == "applied", loaded.message
    time.sleep(2)
    _, p95_allowed = latency(last_allowed, 200)
    _, p95_denied = latency("192.0.2.77", 403 if n else 200)
    return {"n": n, "kib": len(data) / 1024, "adapt_s": adapt_s, "load_s": load_s, "rss": rss_mib(),
            "p95": max(p95_allowed, p95_denied), "p95_allowed": p95_allowed, "p95_denied": p95_denied}


def main():
    shutil.rmtree(D, ignore_errors=True)
    os.makedirs(D)
    with open(f"{itenv.ROOT}/Caddyfile", "w", encoding="utf-8") as f:
        f.write(CADDYFILE)
    workdir = tempfile.mkdtemp(prefix="country-bench-")
    try:
        runs = [[measure(n, workdir) for n in SIZES] for _ in range(RUNS)]
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
        with open("/etc/caddy/Caddyfile", encoding="utf-8") as f:
            caddy_admin.load(f.read())
    rows = [{k: statistics.median(run[i][k] for run in runs) for k in runs[0][i]} for i in range(len(SIZES))]
    # Caddy's heap is not returned between runs: the clean baseline is the smallest one seen.
    rows[0]["rss"] = min(run[0]["rss"] for run in runs)
    base, best = rows[0], None
    print("| Prefixes | File | Adapt | Reload | Caddy RSS | p95 allowed (last prefix) | p95 denied | Within budget |")
    print("|---:|---:|---:|---:|---:|---:|---:|:---|")
    for r in rows:
        r["ok"] = (r["adapt_s"] <= BUDGET["adapt_s"] and r["load_s"] <= BUDGET["load_s"]
                   and r["rss"] - base["rss"] <= BUDGET["rss_delta_mib"]
                   and r["p95"] - base["p95"] <= BUDGET["p95_delta_ms"])
        print(f"| {r['n']:,} | {r['kib']:.0f} KiB | {r['adapt_s']:.2f} s | {r['load_s']:.2f} s | "
              f"{r['rss']:.0f} MiB | {r['p95_allowed']:.2f} ms | {r['p95_denied']:.2f} ms | {'yes' if r['ok'] else 'no'} |")
    for r in rows[1:]:
        if not r["ok"]:
            break
        best = r["n"]
    print(f"\nLargest size within budget: {best if best else 'none: stop and report'}")


main()
