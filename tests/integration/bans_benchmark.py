"""Manual file mode at 1,000 / 10,000 / 20,000 prefixes (spec Phase 1 gate).

  docker compose -f docker-compose.dev.yaml exec -T caddy-console \
    /app/.venv/bin/python -m tests.integration.bans_benchmark

Adaptation and reload time through the admin API, Caddy's resident memory from
its /metrics, and allowed-client latency, against stock caddy-target. Prints a
Markdown table and the BANS_MAX it supports.
"""
import tests.integration._env as itenv  # noqa: I001  (must precede src imports)

import ipaddress
import re
import statistics
import time

import requests

from src.bans import caddy as caddy_admin, fsio, protected, render
from tests.integration.bans_caddy_it import CADDYFILE, get, reset_itest

SIZES = (0, 1000, 10000, 20000)
BUDGET = {"adapt_s": 2.0, "load_s": 3.0, "rss_delta_mib": 150.0, "p95_delta_ms": 2.0}
REQUESTS = 300


def prefixes(n):
    base = int(ipaddress.ip_address("198.18.0.0"))         # benchmark range, not protected
    return [ipaddress.ip_network(base + 2 * i) for i in range(n)]   # gaps, so nothing collapses


def rss_mib():
    text = requests.get(f"{itenv.API}/metrics", timeout=5).text
    return float(re.search(r"^process_resident_memory_bytes (\S+)$", text, re.M).group(1)) / 2 ** 20


def latency():
    samples = []
    for _ in range(REQUESTS):
        t = time.perf_counter()
        assert get("proxy.it.example.com", ip="203.0.113.200").status_code == 200
        samples.append((time.perf_counter() - t) * 1000)
    samples.sort()
    return statistics.median(samples), samples[int(len(samples) * 0.95) - 1]


def measure(n):
    src = render.SOURCES["manual"]
    data = render.render_policy(src, prefixes(n), protected.build().exclusion_tokens(), 100000)
    fsio.atomic_write(src.path, data, 0o644)
    t = time.perf_counter()
    adapted = caddy_admin.adapt(CADDYFILE)
    adapt_s = time.perf_counter() - t
    assert adapted.ok, adapted.message
    t = time.perf_counter()
    loaded = caddy_admin.load(CADDYFILE)
    load_s = time.perf_counter() - t
    assert loaded.status == "applied", loaded.message
    time.sleep(2)
    if n:
        assert get("proxy.it.example.com", ip="198.18.0.0").status_code == 403
    p50, p95 = latency()
    return {"n": n, "kib": len(data) / 1024, "adapt_s": adapt_s, "load_s": load_s, "rss": rss_mib(), "p50": p50, "p95": p95}


def main():
    reset_itest()
    rows = [measure(n) for n in SIZES]
    base, best = rows[0], None
    print("| Prefixes | File | Adapt | Reload | Caddy RSS | p50 | p95 | Within budget |")
    print("|---:|---:|---:|---:|---:|---:|---:|:---|")
    for r in rows:
        r["ok"] = (r["adapt_s"] <= BUDGET["adapt_s"] and r["load_s"] <= BUDGET["load_s"]
                   and r["rss"] - base["rss"] <= BUDGET["rss_delta_mib"]
                   and r["p95"] - base["p95"] <= BUDGET["p95_delta_ms"])
        print(f"| {r['n']:,} | {r['kib']:.0f} KiB | {r['adapt_s']:.2f} s | {r['load_s']:.2f} s | "
              f"{r['rss']:.0f} MiB | {r['p50']:.2f} ms | {r['p95']:.2f} ms | {'yes' if r['ok'] else 'no'} |")
    for r in rows[1:]:
        if not r["ok"]:
            break
        best = r["n"]
    print(f"\nLargest size within budget: {best if best else 'none: stop and report'}")
    print(f"Released BANS_MAX: {min(10000, best) if best else 'none'}")
    with open("/etc/caddy/Caddyfile", encoding="utf-8") as f:
        caddy_admin.load(f.read())


main()
