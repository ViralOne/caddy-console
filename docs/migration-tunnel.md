# Migration: nginx + port forwarding → Caddy + Cloudflare Tunnel

Goal: serve the same apps through Caddy without the server IP appearing in public
DNS or having any open ports, with the admin console on its own domain behind
Google login.

## At a glance

| | Today | After |
|---|---|---|
| Reverse proxy | nginx | Caddy (+ web console for the Caddyfile) |
| How traffic gets in | router port forward 80/443 → server IP | one Cloudflare Tunnel (an **outbound** connection from the server) |
| Open ports on the server's public IP | 80, 443 | **none** |
| Server IP in public DNS | yes (A records) | no |
| HTTPS | nginx / certificates on the server | Cloudflare (at the edge) |
| Old domain (Route53) | A → IP | CNAME → Cloudflare (Cloudflare for SaaS) |
| New domain | — | on Cloudflare, proxied |
| Console | — | `https://console.new-domain.com`, Google login |

## Target architecture

```
visitor
   │  app.new-domain.com            (Cloudflare DNS, proxied)
   │  app.old-domain.com            (Route53: CNAME → fallback origin, Cloudflare for SaaS)
   ▼
Cloudflare  ── HTTPS, WAF, server IP hidden
   │
   ▼  one tunnel (cloudflared runs on the server and dials out to Cloudflare)
┌──────────────── server (docker-compose.tunnel.yaml) ─────────────────┐
│ cloudflared ──► caddy:80 ──► the apps (192.168.x.x:port)             │
│      └───────► caddy-console:9090  (Google login)                     │
│                     └── Caddy admin API caddy:2019 (internal network) │
└───────────────────────────────────────────────────────────────────────┘
```

**One tunnel for every app.** The tunnel sends all traffic to Caddy, and Caddy
picks the app by hostname (the `Host` header), exactly as nginx does today. A new
app is a new block in the Caddyfile; nothing changes in the tunnel or DNS.

## Why this design

- **Why not just a CNAME from Route53 to Cloudflare?** Cloudflare only serves
  hostnames it knows. A plain CNAME from a domain on another DNS provider to a
  Cloudflare host returns **error 1001**. Cloudflare for SaaS (*custom hostnames*)
  is the supported way to serve a domain whose DNS lives elsewhere, and it is
  available on the Free plan with a number of hostnames included (check the
  current limit on the Cloudflare for SaaS plans page).
- **Why a tunnel instead of port forwarding + proxy?** The Cloudflare proxy only
  hides the IP in DNS. With a port forward open, anyone who scans the IP reaches
  the server directly and bypasses Cloudflare. The old domain's DNS history also
  already shows the IP. With a tunnel there is no open port to find.
- **Why no `caddy-cloudflare` image / `CLOUDFLARE_API_TOKEN`?** Those exist to
  issue certificates on the server (DNS-01). Through the tunnel, Cloudflare does
  HTTPS and Caddy receives plain HTTP on the internal Docker network. The stock
  `caddy` image is enough.

## Steps

### Phase 0 — now (in progress)

Caddy runs side by side with nginx on 8080/8443 (`docker-compose.internal.yaml`).
Move the sites from nginx into the Caddyfile and test them directly on 8080.

### Phase 1 — new domain and tunnel

1. Add the new domain to Cloudflare (Free is enough).
2. **Zero Trust → Networks → Tunnels → Create tunnel** (type *Cloudflared*). Copy
   the token into the stack variable `CLOUDFLARE_TUNNEL_TOKEN`.
3. In the tunnel, add **Public hostnames**:

   | Hostname | Service |
   |---|---|
   | `console.new-domain.com` | `http://caddy-console:9090` |
   | `*.new-domain.com` | `http://caddy:80` |

   If the dashboard does not create the DNS record for the wildcard, add
   `*` CNAME `<tunnel-id>.cfargotunnel.com` (proxied) by hand.
4. **SSL/TLS → Edge Certificates**: turn on *Always Use HTTPS*.

### Phase 2 — Caddyfile for the tunnel

Sites are served over **HTTP** (Cloudflare does HTTPS). Without the `http://`
prefix, Caddy tries to obtain certificates and redirects to HTTPS, which loops.

```caddyfile
{
	# Only on the internal caddy-admin network (fixed IP in the compose file).
	# 0.0.0.0 would also expose this unauthenticated API to cloudflared.
	admin 172.30.250.2:2019 {
		origins caddy:2019 172.30.250.2:2019
	}
	servers {
		# Through the tunnel every request comes from the cloudflared container.
		# This makes Caddy (and the console's dashboard/Explore, including GeoIP)
		# see the visitor's real IP.
		trusted_proxies static private_ranges
		client_ip_headers Cf-Connecting-IP
	}
}

(access_log) {
	log {
		output file /var/log/caddy/access.log
		format filter {
			wrap json
			request>headers delete
			resp_headers delete
		}
	}
}

http://app.new-domain.com, http://app.old-domain.com {
	import access_log
	reverse_proxy 192.168.0.x:port
}
```

The same app is served on both domains from one block.

### Phase 3 — Google login for the console

1. Google Cloud Console → **APIs & Services → Credentials → OAuth client ID**
   (Web application). *Authorized redirect URI*:
   `https://console.new-domain.com/auth/callback`.
2. Stack variables (Portainer):

   | Variable | Value |
   |---|---|
   | `CADDY_CONSOLE_IMAGE` | `ghcr.io/viralone/caddy-console:sha-<commit>` (pinned, not `latest`) |
   | `SERVER_URL` | `https://console.new-domain.com` |
   | `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | from step 1 |
   | `ALLOWED_EMAILS` | admin emails, comma-separated |
   | `SECRET_KEY` | `python -c "import secrets; print(secrets.token_hex(32))"` |
   | `CLOUDFLARE_TUNNEL_TOKEN` | from Phase 1 |

   The stack refuses to start if any of them is missing.

### Phase 4 — switch to the tunnel

1. Stop the `internal` stack and start `docker-compose.tunnel.yaml`.
2. Test: `https://app.new-domain.com` works, `https://console.new-domain.com`
   asks for Google, and an email that is not allowed is refused.
3. From outside (e.g. mobile data): `curl -I http://<public-ip>:8080` must no
   longer get an answer from Caddy.

### Phase 5 — old domain through Cloudflare for SaaS

1. On the new zone, create an explicit record `origin` CNAME
   `<tunnel-id>.cfargotunnel.com` (proxied), then set **SSL/TLS → Custom
   Hostnames → Fallback origin** to `origin.new-domain.com`.
2. **Tunnel rule for the old hostnames.** The tunnel picks a service by the
   `Host` header, and requests for `app.old-domain.com` do not match
   `*.new-domain.com`. Without a rule they hit the tunnel's final rule, which
   returns 404 by default. Either add a public hostname per old hostname →
   `http://caddy:80`, or set the final (*catch-all*) rule to `http://caddy:80`
   through the tunnel configuration API. **Verify this with the first migrated
   hostname** before doing the rest.
3. **Add Custom Hostname**: `app.old-domain.com`. Cloudflare asks for validation
   (TXT or HTTP); add the requested records in Route53.
4. In Route53: `app.old-domain.com CNAME origin.new-domain.com`.
   **One hostname at a time.** Rollback = restore the old A record.
5. Check in Cloudflare that the hostname and its certificate are *Active*.

### Phase 6 — cleanup

1. Stop nginx.
2. Remove the router port forwards for 80/443 (and 8080/8443).
3. Remove any remaining Route53 A records that point at the server IP.

## Limitations and caveats

- **The old domain's apex** (`old-domain.com` without `www`) cannot be a CNAME in
  Route53 (ALIAS only targets AWS resources). Options: redirect it to `www` with
  an S3 bucket + CloudFront, or leave it on the IP (which keeps the IP exposed).
- **DNS history**: the IP has been public on the old domain for a long time. After
  the migration that no longer matters because no port is open, so do not
  re-enable port forwards "temporarily".
- **Other records on the same IP** (mail, VPN, SSH) still expose it. Review the
  whole Route53 zone.
- **Caddy's admin API** (`:2019`) has no authentication. It must be bound to
  Caddy's fixed IP on the internal `caddy-admin` network (the `admin` line in the
  Phase 2 Caddyfile), not `0.0.0.0`. With `0.0.0.0`, `cloudflared` on `caddy-edge`
  could reach it. Check after deploying: from the `cloudflared` side, port 2019
  must refuse connections while port 80 answers.
- **A broken Caddyfile does not lock you out of the console**: the console has its
  own tunnel hostname that goes straight to `caddy-console:9090`, not through Caddy.
- **Later (optional)**: Cloudflare Access in front of the console as a second
  login layer (`AUTH_MODE=cloudflare` + `CF_ACCESS_TEAM_DOMAIN` + `CF_ACCESS_AUD`).

## Rollback

| Phase | How to roll back |
|---|---|
| 1–3 | nothing to undo; nginx still serves everything |
| 4 | stop the tunnel stack, start `internal` |
| 5 | in Route53, replace the CNAME with the old A record |
| 6 | re-enable the router rules (use **Pause**, not **Remove**, until you are sure) |
