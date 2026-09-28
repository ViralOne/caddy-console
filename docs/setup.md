# Setup

How to get Caddy Console running against a real Caddy instance. If you just want
to poke at it locally, see [development.md](development.md) instead.

## What you end up with

```
internet → Cloudflare Access (auth) → cloudflared tunnel → caddy-console:9090
internet → Cloudflare proxy (SSL)  → caddy:80/443       → your services
```

Three containers:

- **caddy** — the reverse proxy serving your sites (ports 80/443)
- **caddy-console** — the web UI (no port published; reached through the tunnel)
- **cloudflared** — the tunnel that exposes the console without opening a port

All three share the same `./Caddyfile` through volume mounts. Saving in the UI
rewrites that file and reloads Caddy through its admin API
(`POST http://caddy:2019/load`), so there is no downtime and no container restart.

`docker-compose.prod.yaml` puts the console and the tunnel on their own `console`
network. Caddy sits on both `console` and `default`, so the containers you proxy to
can live on `default` and be reachable by Caddy **without** being able to reach the
console or Caddy's admin API.

## 1. Start it

```bash
mkdir caddy && cd caddy

cat > Caddyfile << 'EOF'
{
    admin 0.0.0.0:2019
    metrics
}

app.yourdomain.com {
    reverse_proxy 10.0.0.1:8080
}
EOF

cp .env.example .env
# Set at minimum: AUTH_MODE, SECRET_KEY, ALLOWED_EMAILS, CLOUDFLARE_TUNNEL_TOKEN

docker compose -f docker-compose.prod.yaml up -d
```

## 2. Choose how people sign in

Set `AUTH_MODE` in `.env`:

| Mode | How it works | Session length |
|------|--------------|----------------|
| `google` | Google OAuth login page (needs `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`) | `SESSION_TIMEOUT_HOURS`, default 8h |
| `cloudflare` | Cloudflare Access authenticates before traffic reaches the app | Set in Cloudflare Zero Trust, default 24h |

Both honour `ALLOWED_DOMAIN` and `ALLOWED_EMAILS` as extra filters.

> **In `cloudflare` mode, set `CF_ACCESS_TEAM_DOMAIN` and `CF_ACCESS_AUD`.**
> With both set, every request's signed `Cf-Access-Jwt-Assertion` token is verified
> (signature, issuer, audience, expiry) and the identity is taken from it. Without
> them the app falls back to trusting the `Cf-Access-Authenticated-User-Email`
> header and warns at startup. That fallback is only safe if nothing but the tunnel
> can reach port 9090 — any other container on the same Docker network could set
> that header and get full control of your reverse proxy config.

## 3. Turn on access logging

The dashboard and the explorer both read Caddy's access log, so it needs a `log`
directive **inside each site block**. Define a snippet once and import it:

```caddyfile
(access_log) {
    log {
        output file /var/log/caddy/access.log {
            roll_size 10mb
            roll_keep 6
            roll_keep_for 168h
        }
        format filter {
            wrap json
            request>headers delete
            resp_headers delete
        }
    }
}

app.yourdomain.com {
    import access_log
    reverse_proxy 10.0.0.1:8080
}
```

The `caddy-logs` volume is shared between the Caddy and console containers, which
both compose files already configure. To use a different path, set
`CADDY_LOG_FILE` in `.env` to match your Caddyfile.

### Strip the headers — this is not optional

`format filter` with `wrap json` keeps every field the UI uses (`ts`, host, method,
uri, status, duration, size, client_ip) and drops the header maps. Two reasons:

- **Request headers carry session tokens and API keys in plaintext.** Caddy redacts
  `Cookie` automatically but nothing else, so a bare `format json` writes live
  credentials to disk and then renders them in your browser.
- **Headers are roughly 90% of each entry.** Dropping them takes an entry from
  ~4 KB to ~300 bytes, so the same `roll_size` covers more than ten times the
  history.

To keep one specific header, delete the others individually instead of the whole
map — `request>headers>Authorization delete`. The filter encoder also supports
`ip_mask` if you would rather not store full client IPs.

### Two things that catch people out

- **Every entry needs `ts`.** The explorer indexes events by timestamp, so entries
  without one are counted as skipped rather than shown. Caddy includes `ts` by
  default; only a custom `time_key` could remove it.
- **A global `log default` block is not enough.** It captures Caddy's runtime log
  (startup, TLS, shutdown), not HTTP access logs. Per-site `log` directives are
  what produce request entries.

Changes to an existing `output file` block need a **full restart** of the Caddy
container — a reload will not pick them up.

## 4. How far back you can look

History is whatever Caddy has kept. `roll_size × roll_keep` caps the disk used and
`roll_keep_for` caps the age; whichever comes first wins. The example above keeps
about 60 MB or 7 days. The explorer reads rolled `.gz` archives too, so raising
`roll_keep` directly extends how far back you can search.

## Running a custom Caddy build

Plugin builds work as-is. If your Caddyfile uses a DNS provider for DNS-01 —

```
tls {
	dns cloudflare {env.CLOUDFLARE_API_TOKEN}
}
```

— point the `caddy` service at a build that carries the module and nothing else
changes:

```yaml
image: ghcr.io/caddybuilds/caddy-cloudflare:2.11.4-alpine
```

Validation is done by that container, through its admin API (`POST /adapt`), so
whatever modules it has are the modules your config is checked against. The
console also ships a plain Caddy binary, but only for `caddy fmt` and as a
fallback when the admin API is unreachable.

If you rely on that fallback and your config needs a plugin, build the console
image against a matching Caddy:

```bash
docker build --build-arg CADDY_IMAGE=ghcr.io/caddybuilds/caddy-cloudflare:2.11.4-alpine .
```

Without it, the fallback reports `module not registered: dns.providers.cloudflare`
for a config that loads fine.

## Upstream health checks

Health status on the dashboard comes from Caddy's active health checks. Without
them a site shows "not checked" rather than a state:

```caddyfile
app.yourdomain.com {
    reverse_proxy 10.0.0.1:8080 {
        health_uri /
        health_interval 30s
    }
}
```

For the **Fails** count, passive checks are also needed (`fail_duration` defaults
to 0, meaning off):

```caddyfile
reverse_proxy 10.0.0.1:8080 {
    fail_duration 30s
    max_fails 3
    unhealthy_status 5xx
}
```

## Prometheus metrics (optional)

Add `metrics` to the global block to expose Caddy's Prometheus endpoint, which the
dashboard uses for server-level counters:

```caddyfile
{
    admin 0.0.0.0:2019
    metrics
}
```

## Cloudflare setup

1. Add your domain to Cloudflare (nameservers must point to CF)
2. SSL/TLS mode → **Full** (Caddy uses local certs, CF handles public SSL)
3. Zero Trust → Tunnels → create tunnel, copy token to `CLOUDFLARE_TUNNEL_TOKEN`
4. Tunnel public hostname: `caddy-console.yourdomain.com` → `http://caddy-console:9090`
5. Zero Trust → Access → Applications → add policy (email OTP for your allowed emails)
6. Open the application, click on Application settings (tab) -> AUD tag into `CF_ACCESS_TEAM_DOMAIN`

## Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AUTH_MODE` | yes | `google` | Auth mode: `google` or `cloudflare` |
| `SECRET_KEY` | yes | — | Flask session secret |
| `GOOGLE_CLIENT_ID` | google mode | — | OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | google mode | — | OAuth client secret |
| `CLOUDFLARE_TUNNEL_TOKEN` | cloudflare mode | — | Tunnel token |
| `CF_ACCESS_TEAM_DOMAIN` | recommended (cloudflare mode) | — | `<team>.cloudflareaccess.com`; enables JWT verification together with `CF_ACCESS_AUD` |
| `CF_ACCESS_AUD` | recommended (cloudflare mode) | — | Access application AUD tag |
| `ALLOWED_DOMAIN` | no | — | Restrict to email domain |
| `ALLOWED_EMAILS` | no | — | Comma-separated allowed emails |
| `SESSION_TIMEOUT_HOURS` | no | `8` | Session lifetime (google mode) |
| `SERVER_URL` | no | `http://localhost:9090` | OAuth callback base URL |
| `CADDY_API_URL` | no | `http://caddy:2019` | Caddy admin API address |
| `CADDYFILE_PATH` | no | `/etc/caddy/Caddyfile` | Path to Caddyfile |
| `BACKUP_DIR` | no | `/backups` | Backup storage directory |
| `BACKUP_KEEP` | no | `50` | Pre-save backups to keep; oldest are pruned after each save (`0` = keep all) |
| `AUDIT_LOG_MAX_BYTES` | no | `5242880` | Rotate the audit log past this size; one rotated file is kept |
| `CADDY_LOG_FILE` | no | `/var/log/caddy/access.log` | Path to Caddy access log (must match Caddyfile) |
| `CADDY_EXPLORE_MAX_EVENTS` | no | `200000` | Events held in memory per range; ~38 B each |
| `GUNICORN_WORKERS` / `GUNICORN_THREADS` | no | `2` / `4` | Server process/thread counts |
| `GUNICORN_PRELOAD` | no | `true` | Load the app once in the master. Set `false` when using `--reload` (the dev stack does) |

## Day-to-day commands

```bash
# Start
docker compose -f docker-compose.prod.yaml up -d

# Logs
docker compose -f docker-compose.prod.yaml logs -f

# Update (pull new image from GHCR)
docker compose -f docker-compose.prod.yaml pull caddy-console
docker compose -f docker-compose.prod.yaml up -d caddy-console

# Restart caddy (only needed for admin address changes or image upgrades)
docker compose -f docker-compose.prod.yaml restart caddy
```
