# syntax=docker/dockerfile:1
# Optional Caddy images for CrowdSec plugin mode (docs/security.md#crowdsec-plugin).
# Build context is this directory; VARIANT is crowdsec or crowdsec-cloudflare:
#   docker build -f caddy-plugin/Dockerfile --build-arg VARIANT=crowdsec -t caddy-crowdsec:local caddy-plugin
# Both FROM lines are literal tag@digest pins so Dependabot (docker) can update them;
# dev/plugin-go.sh uses the same builder pin.
FROM caddy:2.11.9-builder@sha256:cda07fe9d82728c7ac44d844306d435e98131423dc7b114f05a8a8ecfff94707 AS build
ARG VARIANT=crowdsec
# Optional module proxy override (for example direct); go.sum still pins every module.
ARG GOPROXY
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /src/preflight
COPY preflight/ ./
RUN go vet ./... && go test -count=1 ./... \
 && go build -trimpath -ldflags='-s -w' -o /out/caddy-console-preflight .
WORKDIR /src/caddy
COPY ${VARIANT}/ ./
# go.sum pins the whole graph; -mod=readonly fails the build if go.mod/go.sum are stale.
RUN go mod verify \
 && go build -trimpath -ldflags='-s -w' -o /out/caddy . \
 && /out/caddy list-modules --json --skip-standard > /out/modules.json

FROM caddy:2.11.9-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0
ARG VARIANT=crowdsec
COPY --from=build /out/caddy /usr/bin/caddy
COPY --from=build /out/caddy-console-preflight /usr/bin/caddy-console-preflight
COPY --from=build /out/modules.json /usr/share/caddy-console/modules.json
LABEL org.opencontainers.image.title="caddy-${VARIANT}" \
      org.opencontainers.image.description="Caddy 2.11.9 with the CrowdSec HTTP bouncer v0.15.0 for Caddy Console plugin mode" \
      org.opencontainers.image.licenses="Apache-2.0"
# Caddy runs as root in the official image and the Compose files grant only
# NET_BIND_SERVICE, so no file capability is needed on the replaced binary.
ENTRYPOINT ["/usr/bin/caddy-console-preflight"]
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
