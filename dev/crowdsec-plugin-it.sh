#!/usr/bin/env bash
# CrowdSec plugin mode end to end (spec "Run the optional plugin overlay", Phase 3 gate).
# Needs Docker. Builds caddy-crowdsec:local unless PLUGIN_IMAGE names an image.
# Throwaway keys, so CI needs no secret. Removes its project and files on exit.
set -euo pipefail
cd "$(dirname "$0")/.."
# Compose builds the console with the docker driver's "default" builder, like dev/run.sh;
# dev/build-plugin-image.sh picks its own builder unless the caller chose one.
CALLER_BUILDX_BUILDER="${BUILDX_BUILDER:-}"
export CADDY_CONSOLE_UID="$(id -u)" CADDY_CONSOLE_GID="$(id -g)" BUILDX_BUILDER="${BUILDX_BUILDER:-default}"
rand() { python3 -c 'import secrets; print(secrets.token_hex(24))'; }
export IT_CONSOLE_KEY="$(rand)" IT_PLUGIN_KEY="$(rand)" IT_CONTROL="$(rand)"
export PLUGIN_IMAGE="${PLUGIN_IMAGE:-caddy-crowdsec:local}"
F=tests/integration/plugin
P=(docker compose -f "$F/compose.yaml")
PF=(docker compose -f "$F/compose.yaml" -f "$F/compose.file-secret.yaml")
it() { "${P[@]}" exec -T console /app/.venv/bin/python -m tests.integration.plugin_it "$@"; }
req() { local svc="$1"; shift; "${P[@]}" exec -T "$svc" /app/.venv/bin/python -m tests.integration.plugin_client "$@"; }
lapi_add() { it lapi-add "$@" | tail -n 1; }
refused() {  # $@: compose command prefix; Caddy must exit before launch with $MSG
  local out
  if out="$("$@" run --rm --no-deps caddy 2>&1)"; then echo "Caddy started but should have been refused" >&2; return 1; fi
  grep -q "refusing to start Caddy" <<<"$out" && grep -q "$MSG" <<<"$out" || { echo "$out" >&2; return 1; }
  echo "refused before launch: $MSG"
}
cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then "${P[@]}" logs --tail 200 >&2 || true; fi
  "${P[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf dev/run/plugin-it dev/run/plugin-it-backups dev/run/plugin-it-secret
  if [ "$status" -ne 0 ]; then echo "plugin integration: FAILED (exit $status)" >&2; fi
  exit "$status"
}
trap cleanup EXIT

docker image inspect "$PLUGIN_IMAGE" >/dev/null 2>&1 || BUILDX_BUILDER="$CALLER_BUILDX_BUILDER" ./dev/build-plugin-image.sh crowdsec
docker run --rm "$PLUGIN_IMAGE" caddy list-modules --json --skip-standard | python3 dev/check-plugin-modules.py crowdsec
mkdir -p dev/run/plugin-it/console dev/run/plugin-it-backups dev/run/plugin-it-secret
# Written like `echo key > file`: Caddy trims the trailing newline (Review Focus 5).
printf '%s\n' "$IT_PLUGIN_KEY" > dev/run/plugin-it-secret/crowdsec_plugin_bouncer_key
"${P[@]}" build console
"${P[@]}" up -d --wait --wait-timeout 120 crowdsec console client-direct edge-proxy cloudflared

# 1. The admin bind is checked before Caddy listens.
for admin in wildcard loopback missing; do
  it write-caddyfile env "$admin" bootstrap
  case "$admin" in wildcard) MSG="wildcard address" ;; loopback) MSG="loopback only" ;; missing) MSG="no admin line" ;; esac
  refused "${P[@]}"
done

# 2. Environment-key mode, in the operator's order.
it write-caddyfile env fixed bootstrap
"${P[@]}" up -d --wait --wait-timeout 120 caddy
it wait-definition
it save env
it check-paths
crowdsec/check-plugin-isolation.sh --caddy caddy --console console -- -f "$F/compose.yaml"

# 3. The plugin uses Caddy's resolved client IP, never RemoteAddr or a forged header, without a reload.
t0="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
lapi_add 198.51.100.10 >/dev/null      # the direct client itself
lapi_add 203.0.113.80 >/dev/null       # a visitor behind the trusted edge
lapi_add 203.0.113.81 >/dev/null       # a visitor behind the tunnel
lapi_add 192.0.2.10 >/dev/null         # the edge peer's own address: must not block its visitors
lapi_add 10.1.2.3 >/dev/null           # protected (private): never reaches the plugin
lapi_add 203.0.113.99 >/dev/null       # protected (BANS_NEVER)
lapi_add 203.0.113.86 >/dev/null       # enforced, added with the protected ones
D=http://198.51.100.2/ E=http://192.0.2.2:8001/ T=http://172.30.252.2:8002/
req edge-proxy "$E" plugin.it.example.com 403 --within 30 --header 'Cf-Connecting-Ip: 203.0.113.80'
req edge-proxy "$E" plugin.it.example.com 403 --within 30 --header 'Cf-Connecting-Ip: 203.0.113.86'
req client-direct "$D" plugin.it.example.com 403 --within 30
req client-direct "$D" file.it.example.com 200                                   # file site: no plugin there
req cloudflared "$T" plugin.it.example.com 403 --within 30 --header 'Cf-Connecting-Ip: 203.0.113.81'
req edge-proxy "$E" plugin.it.example.com 200 --header 'Cf-Connecting-Ip: 203.0.113.82'   # peer banned, visitor not
req edge-proxy "$E" plugin.it.example.com 200 --header 'Cf-Connecting-Ip: 10.1.2.3'
req edge-proxy "$E" plugin.it.example.com 200 --header 'Cf-Connecting-Ip: 203.0.113.99'
it check-ignored 203.0.113.80                                                     # lists:it origin: not file-synced
if "${P[@]}" logs --since "$t0" caddy | grep -q '"uri":"/load"'; then echo "Caddy was reloaded during plugin enforcement" >&2; exit 1; fi
echo "plugin enforcement without reload: ok"
# A forged header from a peer the listener does not trust is ignored: port 80 trusts no proxy, so the
# resolved address is the (protected) tunnel peer itself, not the banned 203.0.113.80 it claims.
req cloudflared http://172.30.252.2/ plugin.it.example.com 200 --header 'Cf-Connecting-Ip: 203.0.113.80'
it check-keys

# 4. Manual bans keep file mode; mixed sites keep their CrowdSec path.
it manual-ban 203.0.113.84
req edge-proxy "$E" plugin.it.example.com 403 --header 'Cf-Connecting-Ip: 203.0.113.84'
req edge-proxy "$E" file.it.example.com 403 --header 'Cf-Connecting-Ip: 203.0.113.84'
lapi_add 203.0.113.87 cscli >/dev/null
it wait-file-record 203.0.113.87
req edge-proxy "$E" file.it.example.com 403 --within 30 --header 'Cf-Connecting-Ip: 203.0.113.87'
req edge-proxy "$E" plugin.it.example.com 403 --within 30 --header 'Cf-Connecting-Ip: 203.0.113.87'
it check-paths

# 5. LAPI outage: decisions in memory stay enforced; a Caddy start with LAPI down still serves.
lapi_add 203.0.113.88 >/dev/null
req edge-proxy "$E" plugin.it.example.com 403 --within 30 --header 'Cf-Connecting-Ip: 203.0.113.88'
"${P[@]}" stop crowdsec
sleep 25
req edge-proxy "$E" plugin.it.example.com 403 --header 'Cf-Connecting-Ip: 203.0.113.88'
"${P[@]}" restart caddy
"${P[@]}" up -d --wait --wait-timeout 180 caddy
req edge-proxy "$E" plugin.it.example.com 200 --within 30 --header 'Cf-Connecting-Ip: 203.0.113.85'
"${P[@]}" up -d --wait crowdsec      # the fake restarts empty: add the decision again
lapi_add 203.0.113.88 >/dev/null
req edge-proxy "$E" plugin.it.example.com 403 --within 60 --header 'Cf-Connecting-Ip: 203.0.113.88'
echo "outage and recovery: ok"

# 6. Host recovery through the fixed admin address.
it manual-ban 203.0.113.85
req edge-proxy "$E" plugin.it.example.com 403 --header 'Cf-Connecting-Ip: 203.0.113.85'
"${P[@]}" stop console
: > dev/run/plugin-it/console/bans-manual.caddy
"${P[@]}" exec -T -e CADDY_ADMIN_ADDRESS=172.30.250.2:2019 caddy sh -c \
  'caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --address "${CADDY_ADMIN_ADDRESS:-0.0.0.0:2019}"'
req edge-proxy "$E" plugin.it.example.com 200 --header 'Cf-Connecting-Ip: 203.0.113.85'
"${P[@]}" start console
echo "host recovery via 172.30.250.2:2019: ok"

# 7. File-secret mode: enforced with the mounted key; mismatched paths stop Caddy before launch.
it write-caddyfile file fixed full
"${PF[@]}" up -d --wait --wait-timeout 120 --force-recreate caddy console
lapi_add 203.0.113.91 >/dev/null
req edge-proxy "$E" plugin.it.example.com 403 --within 30 --header 'Cf-Connecting-Ip: 203.0.113.91'
echo "file-secret mode: ok"
# The one-off containers below take Caddy's fixed address, so the service must be stopped first.
"${PF[@]}" stop caddy
( export MSG="is not mounted" IT_KEY_FILE=/run/secrets/other; refused "${PF[@]}" )
it write-caddyfile file fixed full /run/secrets/other
( export MSG="but this container expects"; refused "${PF[@]}" )
it write-caddyfile env fixed full
( export MSG="but this container expects"; refused "${PF[@]}" )
echo "plugin integration: all passed"
