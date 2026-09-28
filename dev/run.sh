#!/usr/bin/env bash
# Local dev stack helper. See docker-compose.dev.yaml for what it starts.
set -euo pipefail

cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f docker-compose.dev.yaml)
URL="http://localhost:8888"

seed() {
  mkdir -p dev/run/backups
  if [ ! -f dev/run/Caddyfile ]; then
    cp dev/Caddyfile.seed dev/run/Caddyfile
    echo "seeded dev/run/Caddyfile from dev/Caddyfile.seed"
  fi
}

case "${1:-up}" in
  up)
    seed
    "${COMPOSE[@]}" up -d --build
    printf 'waiting for the console to come up'
    for _ in $(seq 1 60); do
      if curl -sf -o /dev/null "$URL/health"; then
        echo " ok"
        echo
        echo "  console     $URL"
        echo "  dev target  http://localhost:8081  (try: curl -H 'Host: hello.example.com' http://localhost:8081)"
        echo "  config      dev/run/Caddyfile"
        echo
        echo "signed in as dev@local via an injected header - no real auth, localhost only"
        exit 0
      fi
      printf '.'
      sleep 1
    done
    echo " timed out"
    "${COMPOSE[@]}" logs --tail 40 caddy-console
    exit 1
    ;;
  down)
    "${COMPOSE[@]}" down -v
    rm -rf dev/run
    ;;
  logs)
    shift
    "${COMPOSE[@]}" logs -f "${@:-}"
    ;;
  reset)
    seed
    # Rewrite in place. Deleting the file would break the bind mount: the
    # containers keep the old inode and then see a missing Caddyfile.
    cat dev/Caddyfile.seed > dev/run/Caddyfile
    "${COMPOSE[@]}" restart caddy-target
    echo "dev/run/Caddyfile reset to the seed"
    ;;
  big)
    # Write an N-site Caddyfile to stdout, for exercising the diff/save path.
    python3 dev/gen-caddyfile.py "${2:-600}"
    ;;
  *)
    echo "usage: dev/run.sh [up|down|logs|reset|big [sites]]" >&2
    exit 2
    ;;
esac
