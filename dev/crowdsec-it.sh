#!/usr/bin/env bash
# CrowdSec file-sync overlay, end to end (spec "Run the optional CrowdSec
# overlay", Phase 2 gate). Needs Docker and network access to the CrowdSec Hub.
# Uses a throwaway bouncer key, so CI needs no secret. Hands the dev stack back
# without CrowdSec and with its own Caddyfile.
set -euo pipefail
cd "$(dirname "$0")/.."
export CADDY_CONSOLE_UID="$(id -u)" CADDY_CONSOLE_GID="$(id -g)" BUILDX_BUILDER="${BUILDX_BUILDER:-default}"
# One key for the whole run: every compose call below renders the same value.
export CROWDSEC_CONSOLE_BOUNCER_KEY="${CROWDSEC_CONSOLE_BOUNCER_KEY:-$(python3 -c 'import secrets; print(secrets.token_hex(24))')}"
BASE=(docker compose -f docker-compose.dev.yaml)
COMPOSE=(docker compose -f docker-compose.dev.yaml -f docker-compose.crowdsec.yaml)
IPS="203.0.113.60 203.0.113.61 203.0.113.62 203.0.113.63 203.0.113.70 203.0.113.71"
it() { "${COMPOSE[@]}" exec -T caddy-console /app/.venv/bin/python -m tests.integration.crowdsec_it "$@"; }
cscli() { "${COMPOSE[@]}" exec -T crowdsec cscli "$@"; }
forget() { for ip in $IPS; do cscli decisions delete --ip "$ip" >/dev/null 2>&1 || true; done; }

restore() {
  status=$?
  if [ "$status" -ne 0 ]; then "${COMPOSE[@]}" logs --tail 200 crowdsec caddy-console >&2 || true; fi
  "${COMPOSE[@]}" up -d crowdsec >/dev/null 2>&1 || true
  forget
  it restore >/dev/null 2>&1 || true
  "${COMPOSE[@]}" rm -sf crowdsec >/dev/null 2>&1 || true
  "${BASE[@]}" up -d caddy-console >/dev/null 2>&1 || true    # back to the baseline environment
  # Whatever happened above, Caddy ends on the dev Caddyfile with the wildcard
  # admin listener (admin 0.0.0.0:2019), or the console loses Caddy.
  "${BASE[@]}" exec -T caddy-target caddy reload --config /etc/caddy/Caddyfile \
    --adapter caddyfile --address 0.0.0.0:2019 >/dev/null 2>&1 || true
  if [ "$status" -ne 0 ]; then echo "crowdsec integration: FAILED (exit $status)" >&2; fi
  exit "$status"
}
trap restore EXIT

./dev/run.sh up
# The image registers BOUNCER_KEY_caddy_console only once per crowdsec-config
# volume, so a volume left by an earlier run still holds an older key. Drop the
# bouncer and restart: the entrypoint registers this run's key again.
"${COMPOSE[@]}" up -d --wait --wait-timeout 300 crowdsec
cscli bouncers delete caddy_console >/dev/null 2>&1 || true
"${COMPOSE[@]}" restart crowdsec >/dev/null
"${COMPOSE[@]}" up -d --wait --wait-timeout 300 crowdsec caddy-console
cscli bouncers list -o json | grep -q '"caddy_console"'
forget
it prepare

# Isolation: no published CrowdSec port, Caddy off crowdsec-lapi, no route from CrowdSec to 2019.
CS_ID="$("${COMPOSE[@]}" ps -q crowdsec)"
docker inspect "$CS_ID" | python3 -c 'import json,sys; p=json.load(sys.stdin)[0]["NetworkSettings"]["Ports"] or {}; sys.exit(1 if any(p.values()) else 0)'
CADDY_NETS="$(docker inspect -f '{{json .NetworkSettings.Networks}}' "$("${COMPOSE[@]}" ps -q caddy-target)")"
if grep -q crowdsec-lapi <<<"$CADDY_NETS"; then echo "Caddy joined crowdsec-lapi" >&2; exit 1; fi
"${COMPOSE[@]}" exec -T crowdsec sh -c 'command -v wget' >/dev/null
ADMIN_IP="$("${COMPOSE[@]}" exec -T caddy-console getent hosts caddy-target | awk 'NR == 1 {print $1}')"
test -n "$ADMIN_IP"
for target in caddy-target "$ADMIN_IP"; do
  if "${COMPOSE[@]}" exec -T crowdsec wget -q -T 3 -O /dev/null "http://$target:2019/config/"; then
    echo "CrowdSec reached the Caddy admin API at $target:2019" >&2; exit 1
  fi
done
echo "isolation: ok"

# Parsing of the real filtered log: source_ip must be the synthetic visitor, not the proxy peer.
# The log volume outlives runs, so start the explain log empty.
"${COMPOSE[@]}" exec -T caddy-target sh -c ': > /var/log/caddy/explain-it.log'
it explain-traffic
cscli explain --file /var/log/caddy/explain-it.log --type caddy -v | it check-explain 203.0.113.60

# Scenarios: 404 path probe, bad User-Agent, Basic auth brute force, each enforced by the file.
it scenario-traffic
it wait-decisions

# One local decision reaches file enforcement within 60 s, and its deletion too.
t0=$(date +%s); cscli decisions add --ip 203.0.113.70 --duration 1h --reason caddy-console-it >/dev/null
it wait-enforced 203.0.113.70 "$t0" 60 403
it check-records 203.0.113.70 cscli
t0=$(date +%s); cscli decisions delete --ip 203.0.113.70 >/dev/null
it wait-enforced 203.0.113.70 "$t0" 60 200

# LAPI outage keeps the last list; recovery starts with startup=true.
cscli decisions add --ip 203.0.113.71 --duration 1h --reason caddy-console-it >/dev/null
it wait-enforced 203.0.113.71 "$(date +%s)" 60 403
it outage-start 203.0.113.71
"${COMPOSE[@]}" stop crowdsec
it outage-check 203.0.113.71
"${COMPOSE[@]}" up -d --wait --wait-timeout 300 crowdsec
it outage-recovered

# Leader failover across gunicorn workers.
it failover

echo "crowdsec integration: all passed"
