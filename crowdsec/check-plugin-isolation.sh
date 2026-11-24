#!/usr/bin/env bash
# Deployment check for CrowdSec plugin mode (docs/security.md#crowdsec-plugin, spec 3.1).
# Run it on the Docker host after every start; plugin mode is not started
# successfully until it passes. It needs no published port: each probe runs in
# the network namespace of the CrowdSec or cloudflared container itself. It also
# checks that those containers have no CAP_NET_RAW or CAP_NET_ADMIN.
#
#   crowdsec/check-plugin-isolation.sh [--caddy caddy] [--console caddy-console] [--data-port 80] \
#     -- -f docker-compose.prod.yaml -f docker-compose.crowdsec.yaml -f docker-compose.crowdsec-plugin.yaml
set -euo pipefail
CADDY=caddy CONSOLE=caddy-console DATA_PORT=80 ADMIN_IP=172.30.250.2
while [ $# -gt 0 ]; do
  case "$1" in
    --caddy) CADDY="$2"; shift 2 ;;
    --console) CONSOLE="$2"; shift 2 ;;
    --data-port) DATA_PORT="$2"; shift 2 ;;
    --) shift; break ;;
    *) echo "usage: $0 [--caddy NAME] [--console NAME] [--data-port N] -- <docker compose -f ...>" >&2; exit 2 ;;
  esac
done
[ $# -gt 0 ] || { echo "pass the Compose files after --" >&2; exit 2; }
COMPOSE=(docker compose "$@")
fail() { echo "plugin isolation: FAILED: $*" >&2; exit 1; }

caddy_id="$("${COMPOSE[@]}" ps -q "$CADDY")"; [ -n "$caddy_id" ] || fail "$CADDY is not running"
console_id="$("${COMPOSE[@]}" ps -q "$CONSOLE")"; [ -n "$console_id" ] || fail "$CONSOLE is not running"
probe_image="$(docker inspect -f '{{.Config.Image}}' "$console_id")"

# Exit 0 when a TCP connection to $2:$3 succeeds from inside container $1.
reach() {
  docker run --rm --cap-drop ALL --security-opt no-new-privileges:true --network "container:$1" \
    --entrypoint /app/.venv/bin/python "$probe_image" -c '
import socket, sys
try:
    socket.create_connection((sys.argv[1], int(sys.argv[2])), 3).close()
except OSError:
    sys.exit(1)' "$2" "$3"
}
# Exit 0 when the main process of container $1 has neither CAP_NET_ADMIN (12) nor
# CAP_NET_RAW (13) in its bounding set (what cap_drop removes; a process can never
# gain a capability outside it, not even through a setuid or file-capability binary). Caddy accepts a packet for 172.30.250.2
# on any of its interfaces, so a peer able to write raw frames or routes could
# address the admin port through a network it shares with Caddy.
no_net_caps() {
  docker run --rm --cap-drop ALL --security-opt no-new-privileges:true --network none --pid "container:$1" \
    --entrypoint /app/.venv/bin/python "$probe_image" -c '
import sys
with open("/proc/1/status") as f:
    bnd = next(int(line.split()[1], 16) for line in f if line.startswith("CapBnd:"))
sys.exit(1 if bnd & (1 << 12 | 1 << 13) else 0)'
}
networks_of() { docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}} {{end}}' "$1"; }

caddy_nets="$(networks_of "$caddy_id")"
peers="$("${COMPOSE[@]}" ps --format '{{.Service}}' | grep -E '^(crowdsec|cloudflared)' || true)"
[ -n "$peers" ] || fail "no crowdsec or cloudflared container is running"
for peer in $peers; do
  peer_id="$("${COMPOSE[@]}" ps -q "$peer")"
  peer_nets="$(networks_of "$peer_id")"
  no_net_caps "$peer_id" || fail "$peer has CAP_NET_RAW or CAP_NET_ADMIN; give it cap_drop: [ALL]"
  targets="$ADMIN_IP"
  for entry in $caddy_nets; do targets="$targets ${entry#*=}"; done
  for ip in $targets; do
    [ -n "$ip" ] || continue
    if reach "$peer_id" "$ip" 2019; then fail "$peer reached the Caddy admin API at $ip:2019"; fi
  done
  shared=""
  for entry in $caddy_nets; do
    case " $peer_nets " in *" ${entry%%=*}="*) shared="$shared ${entry#*=}" ;; esac
  done
  if [ -n "$shared" ]; then
    answered=""
    for ip in $shared; do if reach "$peer_id" "$ip" "$DATA_PORT"; then answered="$ip"; break; fi; done
    [ -n "$answered" ] || fail "$peer cannot reach Caddy's data plane on port $DATA_PORT ($shared)"
    echo "$peer: no NET_RAW/NET_ADMIN; 2019 refused on $(echo "$targets" | wc -w | tr -d ' ') addresses; data plane answers at $answered:$DATA_PORT"
  else
    echo "$peer: no NET_RAW/NET_ADMIN; 2019 refused on $(echo "$targets" | wc -w | tr -d ' ') addresses; shares no network with Caddy"
  fi
done

# The two bouncers must not share a key (compares the rendered environment; file secrets are not read).
"${COMPOSE[@]}" config --format json | python3 -c '
import json, sys
env = (json.load(sys.stdin)["services"].get("crowdsec") or {}).get("environment") or {}
p, c = env.get("BOUNCER_KEY_caddy_plugin"), env.get("BOUNCER_KEY_caddy_console")
sys.exit("the plugin and the console share one bouncer key" if p and p == c else 0)' || fail "shared bouncer key"
echo "plugin isolation: ok"
