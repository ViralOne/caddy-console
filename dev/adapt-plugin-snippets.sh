#!/usr/bin/env bash
# Adapt the exact code of every shipped plugin snippet with a built plugin image,
# in both secret modes (spec 3.6 and "Testing"). tests/test_plugin_snippets.py and
# tests/snippet-insert.test.mjs pin the fixtures to src/snippets.json.
#   ./dev/adapt-plugin-snippets.sh caddy-crowdsec:local
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE="${1:?usage: dev/adapt-plugin-snippets.sh IMAGE}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/console"
cp tests/fixtures/plugin/crowdsec-plugin-protect.caddy "$tmp/console/"
for mode in env file; do
  cp "tests/fixtures/plugin/$mode.Caddyfile" "$tmp/Caddyfile"
  docker run --rm -v "$tmp:/etc/caddy:ro" "$IMAGE" caddy adapt --config /etc/caddy/Caddyfile --adapter caddyfile \
    > "$tmp/$mode.json"
  python3 - "$tmp/$mode.json" "$mode" <<'PY'
import json, sys
cfg, mode = json.load(open(sys.argv[1])), sys.argv[2]
want = {"env": "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}", "file": "{file./run/secrets/crowdsec_plugin_bouncer_key}"}[mode]
app = cfg.get("apps", {}).get("crowdsec") or {}
assert app.get("api_key") == want, f"api_key is {app.get('api_key')!r}"
# The adapter writes api_url with a trailing slash. Stream mode stays on and hard
# fails stay off (spec 3.3), so a LAPI outage keeps the decisions in memory.
assert app.get("ticker_interval") == "10s" and app.get("api_url", "").rstrip("/") == "http://crowdsec:8080", app
assert app.get("enable_streaming") is not False and not app.get("enable_hard_fails"), app

def has(node, pred):
    if isinstance(node, dict):
        return pred(node) or any(has(v, pred) for v in node.values())
    if isinstance(node, list):
        return any(has(v, pred) for v in node)
    return False

sites = {}
for srv in cfg["apps"]["http"]["servers"].values():
    for route in srv["routes"]:
        hosts = [h for m in route.get("match", []) for h in m.get("host", [])]
        for h in hosts:
            sites[h] = route
plugin = lambda n: n.get("handler") == "crowdsec"
guarded = lambda n: plugin_in(n) and any("not" in m for m in n.get("match", []))
plugin_in = lambda n: any(isinstance(h, dict) and h.get("handler") == "crowdsec" for h in n.get("handle", []) or [])
assert has(sites["plugin.example.com"], guarded), "plugin.example.com has no protected crowdsec route"
assert has(sites["plugin.example.com"], lambda n: n.get("caddy_console_plugin_protect") in (1, "1")), "no plugin marker"
assert not has(sites["file.example.com"], plugin), "file.example.com runs the plugin"
print(f"{mode}: every shipped plugin snippet adapts; plugin site protected, file site file-only")
PY
done
