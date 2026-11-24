#!/usr/bin/env bash
# Run Go from the pinned Caddy builder image, so no local Go install is needed.
#   ./dev/plugin-go.sh test                          vet and test the preflight
#   ./dev/plugin-go.sh tidy crowdsec                 refresh caddy-plugin/crowdsec/go.sum
#   ./dev/plugin-go.sh tidy crowdsec-cloudflare
set -euo pipefail
cd "$(dirname "$0")/.."
# Keep in step with the FROM line in caddy-plugin/Dockerfile (Dependabot updates that one).
BUILDER=caddy:2.11.9-builder@sha256:cda07fe9d82728c7ac44d844306d435e98131423dc7b114f05a8a8ecfff94707
RUN=(docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e GOPATH=/tmp/go -e GOCACHE=/tmp/gocache
     -e GOTOOLCHAIN=local -e CGO_ENABLED=0)
case "${1:-}" in
  test)
    "${RUN[@]}" -v "$PWD/caddy-plugin/preflight:/src:ro" -w /src "$BUILDER" \
      sh -c 'go vet ./... && go test -count=1 ./...'
    ;;
  tidy)
    variant="${2:?usage: dev/plugin-go.sh tidy <crowdsec|crowdsec-cloudflare>}"
    test -f "caddy-plugin/$variant/go.mod"
    "${RUN[@]}" -e GOFLAGS=-mod=mod -v "$PWD/caddy-plugin/$variant:/src" -w /src "$BUILDER" \
      sh -c 'go mod tidy && go mod verify'
    ;;
  *)
    echo "usage: dev/plugin-go.sh test | tidy <crowdsec|crowdsec-cloudflare>" >&2
    exit 2
    ;;
esac
