#!/usr/bin/env bash
# Build one plugin image locally and check its modules (docs/development.md).
#   ./dev/build-plugin-image.sh crowdsec              -> caddy-crowdsec:local
#   ./dev/build-plugin-image.sh crowdsec-cloudflare   -> caddy-crowdsec-cloudflare:local
set -euo pipefail
cd "$(dirname "$0")/.."
variant="${1:?usage: dev/build-plugin-image.sh <crowdsec|crowdsec-cloudflare>}"
image="caddy-$variant:local"
# The docker-driver builder of the current context, so the image lands in the local store.
export BUILDX_BUILDER="${BUILDX_BUILDER:-$(docker context show)}"
docker build -f caddy-plugin/Dockerfile --build-arg VARIANT="$variant" ${GOPROXY:+--build-arg GOPROXY="$GOPROXY"} \
  -t "$image" caddy-plugin
docker run --rm "$image" caddy list-modules --json --skip-standard | python3 dev/check-plugin-modules.py "$variant"
# The module record baked into the image is the one this build produced.
docker run --rm "$image" cat /usr/share/caddy-console/modules.json | python3 dev/check-plugin-modules.py "$variant"
version="$(docker run --rm "$image" caddy version)"
case "$version" in v2.11.9*) ;; *) echo "unexpected Caddy version: $version" >&2; exit 1 ;; esac
echo "$image: Caddy $version"
