#!/usr/bin/env bash
# Stock-Caddy integration suite for IP bans (spec Phase 1 gate). Needs Docker.
# Leaves the dev stack running with its own Caddyfile restored.
set -euo pipefail
cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f docker-compose.dev.yaml)
PY=(/app/.venv/bin/python)
PRELOAD_NAME=caddy-console-preload-it
ADMIN_IP=""
code() { curl -s -o /dev/null -w '%{http_code}' -H 'Host: proxy.it.example.com' -H 'X-Forwarded-For: 203.0.113.7' http://127.0.0.1:8081/; }

# Whatever happens, hand the dev stack back with its own Caddyfile and the
# wildcard admin listener (admin 0.0.0.0:2019), or the console loses Caddy.
restore() {
  status=$?
  docker rm -f "$PRELOAD_NAME" >/dev/null 2>&1 || true
  "${COMPOSE[@]}" start caddy-console >/dev/null 2>&1 || true
  for address in 0.0.0.0:2019 ${ADMIN_IP:+"$ADMIN_IP:2019"}; do
    if "${COMPOSE[@]}" exec -T caddy-target caddy reload --config /etc/caddy/Caddyfile \
        --adapter caddyfile --address "$address" >/dev/null 2>&1; then
      break
    fi
  done
  if [ "$status" -ne 0 ]; then echo "bans integration: FAILED (exit $status)" >&2; fi
  exit "$status"
}
trap restore EXIT

./dev/run.sh up
"${COMPOSE[@]}" exec -T caddy-console "${PY[@]}" -m unittest tests.integration.bans_caddy_it -v

# Host recovery exactly as documented: stop the console, truncate the policy,
# reload through the admin address inside the Caddy container, start again.
# A wildcard bind accepts only its own listen address as the CLI origin, so
# localhost:2019 would get 403. The last pass binds admin to caddy-target's own IP on the admin network (as a
# fixed-bind deployment would), then puts the wildcard listener back.
ADMIN_IP="$("${COMPOSE[@]}" exec -T caddy-console getent hosts caddy-target | awk 'NR == 1 {print $1}')"
test -n "$ADMIN_IP"
for address in 0.0.0.0:2019 "$ADMIN_IP:2019"; do
  if [ "$address" = "$ADMIN_IP:2019" ]; then
    "${COMPOSE[@]}" exec -T caddy-console "${PY[@]}" -m tests.integration.bans_recovery_prep "$address"
  else
    "${COMPOSE[@]}" exec -T caddy-console "${PY[@]}" -m tests.integration.bans_recovery_prep
  fi
  test "$(code)" = 403
  "${COMPOSE[@]}" stop caddy-console
  : > dev/run/itest/console/bans-manual.caddy
  "${COMPOSE[@]}" exec -T -e CADDY_ADMIN_ADDRESS="$address" caddy-target sh -c \
    'caddy reload --config /etc/caddy/itest/Caddyfile --adapter caddyfile \
     --address "${CADDY_ADMIN_ADDRESS:-0.0.0.0:2019}"'
  test "$(code)" = 200
  if [ "$address" = "$ADMIN_IP:2019" ]; then
    # Back to the wildcard listener through the fixed one; prove loopback answers again.
    "${COMPOSE[@]}" exec -T caddy-target caddy reload --config /etc/caddy/Caddyfile \
      --adapter caddyfile --address "$address"
    "${COMPOSE[@]}" exec -T caddy-target wget -qO /dev/null http://127.0.0.1:2019/config/
  fi
  "${COMPOSE[@]}" start caddy-console
  for _ in $(seq 1 30); do curl -sf -o /dev/null http://localhost:8888/health && break; sleep 1; done
  echo "host recovery via $address: ok"
done

# Caddy accepts only the listen address itself as the CLI's origin on a wildcard bind.
"${COMPOSE[@]}" exec -T caddy-target caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --address 0.0.0.0:2019

# The production CMD (gunicorn.conf.py, GUNICORN_PRELOAD defaulting to true):
# the "bans-expiry" thread must run in every worker and never in the master,
# whose fork would otherwise copy a thread that may hold caddyfile_lock().
IMAGE="$(docker inspect -f '{{.Image}}' "$("${COMPOSE[@]}" ps -q caddy-console)")"
read -r -a CMD <<< "$(docker image inspect -f '{{range .Config.Cmd}}{{.}} {{end}}' "$IMAGE")"
# The dev service sets GUNICORN_PRELOAD=false for --reload; put the image default back.
"${COMPOSE[@]}" run -d --rm --no-deps --name "$PRELOAD_NAME" -e GUNICORN_PRELOAD=true caddy-console "${CMD[@]}" >/dev/null
threads_ok=""
for _ in $(seq 1 30); do
  # One line per gunicorn process: "<pid> <ppid> <bans-expiry threads>".
  report="$(docker exec "$PRELOAD_NAME" sh -c '
    for p in /proc/[0-9]*; do
      [ "${p#/proc/}" = "$$" ] && continue
      grep -q gunicorn "$p/cmdline" 2>/dev/null || continue
      n=$(cat "$p"/task/*/comm 2>/dev/null | grep -cx bans-expiry || true)
      echo "${p#/proc/} $(awk "{print \$4}" "$p/stat") $n"
    done' 2>/dev/null || true)"
  master="$(awk '$1 == 1' <<< "$report")"
  workers="$(awk '$2 == 1' <<< "$report")"
  if [ -n "$master" ] && [ "$(wc -l <<< "$workers")" -ge 2 ] && ! awk '$3 != 1 {bad=1} END {exit !bad}' <<< "$workers"; then
    threads_ok=1
    break
  fi
  sleep 1
done
echo "$report" | sed 's/^/  gunicorn pid ppid bans-expiry: /'
test -n "$threads_ok"
test "$(awk '{print $3}' <<< "$master")" = 0
docker rm -f "$PRELOAD_NAME" >/dev/null
echo "preload: bans-expiry in every worker, not in the master: ok"

echo "bans integration: all passed"
