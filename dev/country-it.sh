#!/usr/bin/env bash
# Stock-Caddy integration suite for the client-IP profiles and the country policy
# (spec Phase 4 gate). Needs Docker. Leaves the dev stack running with its own
# Caddyfile and the wildcard admin listener (admin 0.0.0.0:2019) restored.
set -euo pipefail
cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f docker-compose.dev.yaml)
PY=(/app/.venv/bin/python)

restore() {
  status=$?
  "${COMPOSE[@]}" exec -T caddy-target caddy reload --config /etc/caddy/Caddyfile \
    --adapter caddyfile --address 0.0.0.0:2019 >/dev/null 2>&1 || true
  if [ "$status" -ne 0 ]; then echo "country integration: FAILED (exit $status)" >&2; fi
  exit "$status"
}
trap restore EXIT

./dev/run.sh up
"${COMPOSE[@]}" exec -T caddy-console "${PY[@]}" -m unittest tests.integration.country_caddy_it -v
echo "country integration: all passed"
