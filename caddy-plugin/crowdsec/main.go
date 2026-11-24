// Caddy 2.11.9 with the CrowdSec HTTP bouncer, for docker-compose.crowdsec-plugin.yaml.
// Equivalent to `xcaddy build --with github.com/hslatman/caddy-crowdsec-bouncer/http`,
// with every dependency pinned by go.sum.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/hslatman/caddy-crowdsec-bouncer/http"
)

func main() {
	caddycmd.Main()
}
