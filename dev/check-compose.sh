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
