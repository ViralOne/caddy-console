#!/usr/bin/env bash
# Phase 1 gate: every baseline Compose file renders, passes BANS_* through and
# needs nothing from CrowdSec.
set -euo pipefail
cd "$(dirname "$0")/.."
export CADDY_CONSOLE_IMAGE=ghcr.io/example/caddy-console:sha-0000000 CLOUDFLARE_TUNNEL_TOKEN=dummy \
  SERVER_URL=https://console.example.com SECRET_KEY=dummy GOOGLE_CLIENT_ID=dummy \
  GOOGLE_CLIENT_SECRET=dummy ALLOWED_EMAILS=a@example.com BANS_ENABLED=true
for f in docker-compose.prod.yaml docker-compose.tunnel.yaml docker-compose.internal.yaml \
         docker-compose.nas.yaml docker-compose.dev.yaml; do
  out=$(docker compose -f "$f" config 2>/dev/null)
  if grep -qi crowdsec <<<"$out"; then echo "$f mentions CrowdSec" >&2; exit 1; fi
  # The dev stack pins its own BANS_ENABLED/BANS_DIR; the baseline stacks pass all four.
  names="BANS_ENABLED BANS_DIR BANS_MAX BANS_NEVER CLIENT_IP_MODE COUNTRY_MAX_PREFIXES CLOUDFLARE_RANGES_AUTO_UPDATE"
  if [ "$f" = docker-compose.dev.yaml ]; then names="BANS_ENABLED BANS_DIR"; fi
  for name in $names; do
    grep -q "$name" <<<"$out" || { echo "$f does not pass $name" >&2; exit 1; }
  done
  echo "$f: ok"
done

# Phase 2 gate: the optional overlay is the only change needed to start CrowdSec,
# and it keeps Caddy off the CrowdSec network.
export CROWDSEC_CONSOLE_BOUNCER_KEY=dummy-check-key
for combo in "docker-compose.prod.yaml docker-compose.crowdsec.yaml caddy caddy-console" \
             "docker-compose.internal.yaml docker-compose.crowdsec.yaml caddy caddy-console" \
             "docker-compose.tunnel.yaml docker-compose.crowdsec.yaml caddy caddy-console" \
             "docker-compose.dev.yaml docker-compose.crowdsec.yaml caddy-target caddy-console"; do
  read -r base overlay caddy console <<<"$combo"
  docker compose -f "$base" -f "$overlay" config --format json | python3 dev/check-crowdsec-overlay.py "$caddy" "$console" \
    || { echo "$base + $overlay: CrowdSec overlay check failed" >&2; exit 1; }
  echo "$base + $overlay: ok"
done

# Phase 3 gate: the plugin overlay keeps CrowdSec and cloudflared off caddy-admin,
# pins the fixed admin address and uses a key of its own. It is checked on top
# of the CrowdSec overlay, as it is used.
export CROWDSEC_PLUGIN_BOUNCER_KEY=dummy-plugin-key
export CADDY_PLUGIN_IMAGE=ghcr.io/viralone/caddy-crowdsec:sha-0000000
for combo in "docker-compose.prod.yaml docker-compose.crowdsec.yaml docker-compose.crowdsec-plugin.yaml caddy caddy-console crowdsec" \
             "docker-compose.internal.yaml docker-compose.crowdsec.yaml docker-compose.crowdsec-plugin.yaml caddy caddy-console crowdsec" \
             "docker-compose.tunnel.yaml docker-compose.crowdsec.yaml docker-compose.crowdsec-plugin.yaml caddy caddy-console crowdsec"; do
  read -r base cs plug caddy console variant <<<"$combo"
  image="ghcr.io/viralone/caddy-$variant:sha-0000000"
  out=$(CADDY_PLUGIN_IMAGE="$image" docker compose -f "$base" -f "$cs" -f "$plug" config --format json)
  python3 dev/check-crowdsec-overlay.py "$caddy" "$console" --plugin <<<"$out" \
    || { echo "$base + $plug: CrowdSec overlay check failed" >&2; exit 1; }
  python3 dev/check-plugin-overlay.py "$caddy" "$console" "$variant" <<<"$out" \
    || { echo "$base + $plug: plugin overlay check failed" >&2; exit 1; }
  # The same key for both bouncers must be caught.
  if CADDY_PLUGIN_IMAGE="$image" CROWDSEC_PLUGIN_BOUNCER_KEY="$CROWDSEC_CONSOLE_BOUNCER_KEY" \
      docker compose -f "$base" -f "$cs" -f "$plug" config --format json \
      | python3 dev/check-plugin-overlay.py "$caddy" "$console" "$variant" 2>/dev/null; then
    echo "$base + $plug: a shared bouncer key was not detected" >&2; exit 1
  fi
  echo "$base + $plug: ok"
done
# The baseline files still render without any plugin variable.
unset CROWDSEC_PLUGIN_BOUNCER_KEY CADDY_PLUGIN_IMAGE

# NAS single-file stacks: self-contained (no repo bind mounts), same checks as the overlays.
export CADDY_CONSOLE_IMAGE=ghcr.io/example/caddy-console:sha-0000000 CROWDSEC_CONSOLE_BOUNCER_KEY=dummy-check-key \
  CROWDSEC_PLUGIN_BOUNCER_KEY=dummy-plugin-key
for combo in "docker-compose.nas.crowdsec.yaml crowdsec" \
             "docker-compose.nas.crowdsec-plugin.yaml crowdsec-cloudflare"; do
  read -r f variant <<<"$combo"
  image="ghcr.io/viralone/caddy-$variant:sha-0000000"
  out=$(CADDY_PLUGIN_IMAGE="$image" docker compose -f "$f" config --format json 2>/dev/null)
  if grep -q '"extends"' "$f" || grep -Eq '^\s*- \./|^\s*- \.\./' "$f"; then
    echo "$f is not self-contained" >&2; exit 1
  fi
  if [ "$variant" = crowdsec ]; then
    python3 dev/check-crowdsec-overlay.py caddy caddy-editor <<<"$out" || { echo "$f: check failed" >&2; exit 1; }
  else
    python3 dev/check-crowdsec-overlay.py caddy caddy-editor --plugin <<<"$out" || { echo "$f: check failed" >&2; exit 1; }
    python3 dev/check-plugin-overlay.py caddy caddy-editor "$variant" <<<"$out" || { echo "$f: plugin check failed" >&2; exit 1; }
  fi
  python3 -c '
import json,sys
c=json.loads(sys.stdin.read())
bad=[p for s in c["services"].values() for p in (s.get("ports") or []) if str(p.get("target")) in ("8080","2019") or str(p.get("published")) in ("8080","2019")]
sys.exit("published 8080/2019: %s" % bad if bad else 0)' <<<"$out" || { echo "$f: published 8080/2019" >&2; exit 1; }
  echo "$f: ok"
done
unset CROWDSEC_PLUGIN_BOUNCER_KEY CADDY_PLUGIN_IMAGE
