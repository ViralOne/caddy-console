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
  names="BANS_ENABLED BANS_DIR BANS_MAX BANS_NEVER"
  if [ "$f" = docker-compose.dev.yaml ]; then names="BANS_ENABLED BANS_DIR"; fi
  for name in $names; do
    grep -q "$name" <<<"$out" || { echo "$f does not pass $name" >&2; exit 1; }
  done
  echo "$f: ok"
done

# Phase 2 gate: the optional overlay is the only change needed to start CrowdSec,
# and it keeps Caddy off the CrowdSec network. NAS uses its companion file
# because its console service is named caddy-editor.
export CROWDSEC_CONSOLE_BOUNCER_KEY=dummy-check-key
for combo in "docker-compose.prod.yaml docker-compose.crowdsec.yaml caddy caddy-console" \
             "docker-compose.internal.yaml docker-compose.crowdsec.yaml caddy caddy-console" \
             "docker-compose.tunnel.yaml docker-compose.crowdsec.yaml caddy caddy-console" \
             "docker-compose.dev.yaml docker-compose.crowdsec.yaml caddy-target caddy-console" \
             "docker-compose.nas.yaml docker-compose.crowdsec.nas.yaml caddy caddy-editor"; do
  read -r base overlay caddy console <<<"$combo"
  docker compose -f "$base" -f "$overlay" config --format json | python3 dev/check-crowdsec-overlay.py "$caddy" "$console" \
    || { echo "$base + $overlay: CrowdSec overlay check failed" >&2; exit 1; }
  echo "$base + $overlay: ok"
done
