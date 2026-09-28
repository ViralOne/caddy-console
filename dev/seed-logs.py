#!/usr/bin/env python3
"""Write believable access-log data into the dev stack, for screenshots and for
trying the explorer with something that looks like real traffic.

    ./dev/run.sh up
    python3 dev/seed-logs.py | docker compose -f docker-compose.dev.yaml \
        exec -T caddy-target sh -c 'cat >> /var/log/caddy/access.log'

Entries are emitted oldest-first so the file is time-ordered, which is what lets
the explorer bisect it.
"""
import json
import random
import sys
import time

SITES = [
    # host, weight, paths, p50 latency, error rate
    ("nas.example.com",      30, ["/ugreen/v1/desktop/list", "/ugreen/v1/docker/container/list", "/favicon.ico"], 0.09, 0.01),
    ("photos.example.com",   22, ["/api/albums", "/api/assets/thumbnail", "/api/server-info"], 0.04, 0.00),
    ("watch.example.com",    18, ["/api/v1/items", "/api/v1/sessions", "/web/index.html"], 0.12, 0.02),
    ("grafana.example.com",  10, ["/api/ds/query", "/api/dashboards/home", "/public/build/app.js"], 0.18, 0.01),
    ("torrent.example.com",   8, ["/api/v2/sync/maindata", "/api/v2/torrents/info"], 0.35, 0.14),
    ("ha.example.com",        7, ["/api/websocket", "/api/states", "/manifest.json"], 0.06, 0.00),
    ("radarr.example.com",    5, ["/api/v3/queue", "/api/v3/movie"], 0.22, 0.03),
]
METHODS = ["GET"] * 8 + ["POST"] * 2
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) "
      "Gecko/20100101 Firefox/142.0")


def entry(ts, host, uri, method, status, duration, size):
    return {
        "level": "info" if status < 500 else "error",
        "ts": ts,
        "logger": "http.log.access.log0",
        "msg": "handled request",
        "request": {
            "remote_ip": "172.71.98.14", "remote_port": str(random.randrange(40000, 65000)),
            "client_ip": "82.77.14.203", "proto": "HTTP/2.0",
            "method": method, "host": host, "uri": uri,
        },
        "bytes_read": 0,
        "user_id": "",
        "duration": duration,
        "size": size,
        "status": status,
    }


def generate(minutes, rate_per_min, end_ts, burst_host=None, burst_window=None):
    hosts = [s for s in SITES for _ in range(s[1])]
    rows = []
    for i in range(int(minutes * rate_per_min)):
        age = random.random() * minutes * 60
        ts = end_ts - age
        host, _, paths, p50, err = random.choice(hosts)
        # A believable burst: one site's upstream struggling for a few minutes.
        bursting = (burst_host == host and burst_window
                    and burst_window[0] <= age <= burst_window[1])
        rate = 0.85 if bursting else err
        if random.random() < rate:
            status = random.choice([502, 502, 503, 504])
            duration = p50 * random.uniform(8, 40)
            size = 0
        else:
            status = random.choice([200] * 18 + [204, 304, 304, 404])
            duration = max(0.001, random.gauss(p50, p50 / 3))
            size = 0 if status in (204, 304) else random.randrange(280, 90000)
        rows.append(entry(ts, host, random.choice(paths), random.choice(METHODS),
                          status, round(duration, 6), size))
    rows.sort(key=lambda r: r["ts"])
    return rows


def main():
    random.seed(int(sys.argv[1]) if len(sys.argv) > 1 else 42)
    now = time.time()
    # Two hours of traffic, with torrent.example.com failing 20-28 minutes ago.
    for row in generate(120, 26, now, burst_host="torrent.example.com",
                        burst_window=(20 * 60, 28 * 60)):
        print(json.dumps(row))


if __name__ == "__main__":
    main()
