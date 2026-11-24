"""One HTTP request from a client container, retried until the expected status.

  python -m tests.integration.plugin_client URL HOST EXPECT [--within S] [--header 'Name: value' ...]
"""
import argparse
import sys
import time

import requests


def main():
    p = argparse.ArgumentParser()
    p.add_argument("url")
    p.add_argument("host")
    p.add_argument("expect", type=int)
    p.add_argument("--within", type=float, default=0)
    p.add_argument("--header", action="append", default=[])
    a = p.parse_args()
    headers = {"Host": a.host, **dict(h.split(": ", 1) for h in a.header)}
    end = time.monotonic() + a.within
    while True:
        try:
            code = requests.get(a.url, headers=headers, timeout=5, allow_redirects=False).status_code
        except requests.RequestException as e:
            code = f"error {type(e).__name__}"
        if code == a.expect:
            print(f"{a.host} {a.url} {' '.join(a.header)} -> {code}")
            return
        if time.monotonic() >= end:
            sys.exit(f"plugin_client: {a.host} {a.url} {a.header} answered {code}, expected {a.expect}")
        time.sleep(1)


main()
