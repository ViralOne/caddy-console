"""Does GET /config/ after POST /load equal the POST /adapt result, byte for byte
after key sorting? Also prints the adapted marker and matcher shapes.

  docker compose -f docker-compose.dev.yaml exec -T caddy-console \
    /app/.venv/bin/python - < tests/integration/spike_load_roundtrip.py
"""
import hashlib
import json
import os

import requests

API = os.environ.get("CADDY_API_URL", "http://caddy-target:2019")
H = {"Content-Type": "text/caddyfile"}
DIR = "/etc/caddy/console-fixtures/active"
norm = lambda c: hashlib.sha256(json.dumps(c, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

original = open("/etc/caddy/Caddyfile", encoding="utf-8").read()
text = original + f"\nhttp://spike.example.com {{\n\timport {DIR}/bans-manual*.caddy\n\trespond \"ok\" 200\n}}\n"
adapted = requests.post(f"{API}/adapt", data=text.encode(), headers=H, timeout=20).json()["result"]
try:
    load = requests.post(f"{API}/load", data=text.encode(), headers=H, timeout=20)
    live = requests.get(f"{API}/config/", timeout=5).json()
    print("load-status:", load.status_code)
    print("roundtrip-equal:", norm(adapted) == norm(live))

    def find(node, pred, out):
        if isinstance(node, dict):
            if pred(node):
                out.append(node)
            for v in node.values():
                find(v, pred, out)
        elif isinstance(node, list):
            for v in node:
                find(v, pred, out)
        return out

    print("marker:", find(live, lambda d: "caddy_console_manual_policy" in d, [])[:1])
    print("matcher:", json.dumps(find(live, lambda d: "client_ip" in d and "not" in d, [])[:1]))
finally:
    requests.post(f"{API}/load", data=original.encode(), headers=H, timeout=20)
