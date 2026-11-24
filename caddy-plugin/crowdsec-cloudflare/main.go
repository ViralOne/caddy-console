// Caddy 2.11.9 with the CrowdSec HTTP bouncer and the Cloudflare DNS provider
// (DNS-01), for the NAS plugin overlay. Cloudflare as a proxy or Tunnel does
// not need this variant.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddy-dns/cloudflare"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/hslatman/caddy-crowdsec-bouncer/http"
)

func main() {
	caddycmd.Main()
}
