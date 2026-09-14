# Caddy Editor

Web UI to manage your Caddyfile — edit, validate, format, save & reload with zero downtime. Includes traffic metrics from Caddy's Prometheus endpoint, upstream health monitoring, backup/restore with diff, and audit log.

## Features

- **Editor Tab** — CodeMirror 6 with Caddyfile syntax highlighting, find/replace, Cmd+S to save, validate & format
- **Metrics Tab** — total requests, error rate, in-flight, bandwidth, upstream health (requires `metrics` in global block)
- **Logs Tab** — live-tailing Caddy access logs (requires global `log default` writing to shared volume)
- **Save & Reload** — writes Caddyfile and reloads Caddy via admin API (zero downtime)
- **Backups** — automatic pre-save backups with preview, inline diff, and one-click restore
- **Audit Log** — who saved what and when
- **Snippets** — common Caddyfile patterns (reverse proxy, headers, rate limiting, etc.)

## Architecture

```
internet → Cloudflare Access (auth) → cloudflared tunnel → caddy-editor:9090
internet → Cloudflare proxy (SSL)  → caddy:80/443       → your services
```

Three containers:
- **caddy** — the reverse proxy serving your sites (ports 80/443)
- **caddy-editor** — web UI to edit the Caddyfile (no port exposed, accessed via tunnel)
- **cloudflared** — Cloudflare Tunnel connecting the editor to the internet securely

All three share the same `./Caddyfile` via volume mounts. When you save in the editor, it reloads Caddy via its admin API (`POST http://caddy:2019/load`).

`docker-compose.prod.yaml` puts the editor and the tunnel on their own `editor` network. Caddy is on both `editor` and `default`, so containers you proxy to can sit on `default` and reach Caddy without being able to reach the editor or Caddy's admin API.

## Auth Modes

Set `AUTH_MODE` in `.env`:

| Mode | How it works | Session duration |
|------|-------------|-----------------|
| `google` | Google OAuth login page (needs `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`) | `SESSION_TIMEOUT_HOURS` (default 8h) |
| `cloudflare` | Cloudflare Access handles auth before traffic reaches the app (email OTP) | Configured in CF Zero Trust dashboard (default 24h) |

Both modes support `ALLOWED_DOMAIN` and `ALLOWED_EMAILS` as additional filters.

**Cloudflare mode: set `CF_ACCESS_TEAM_DOMAIN` and `CF_ACCESS_AUD`.** With both set, the app verifies the signed `Cf-Access-Jwt-Assertion` token (signature, issuer, audience, expiry) on every request and takes the identity from it. Without them it falls back to trusting the `Cf-Access-Authenticated-User-Email` header and logs a warning at startup. Header trust is only safe if literally nothing except the tunnel can reach port 9090; any other container on the same Docker network could set that header and get full access to your reverse proxy config.

## Production Deploy

```bash
mkdir caddy && cd caddy

# Create your Caddyfile
cat > Caddyfile << 'EOF'
{
    admin 0.0.0.0:2019
    metrics
}

app.yourdomain.com {
    reverse_proxy 10.0.0.1:8080
}
EOF

# Create .env from example
cp .env.example .env
# Edit: set AUTH_MODE, CLOUDFLARE_TUNNEL_TOKEN, ALLOWED_EMAILS, SECRET_KEY

# Start
docker compose -f docker-compose.prod.yaml up -d
```

**Important:**
- The global block must include `admin 0.0.0.0:2019` so the editor can reload Caddy over the Docker network
- Add `metrics` to the global block to enable traffic metrics in the Metrics tab

## Feature Requirements

Each tab beyond the Editor requires specific Caddyfile configuration:

### Metrics Tab

Add `metrics` to your Caddyfile global block:

```caddyfile
{
    admin 0.0.0.0:2019
    metrics
}
```

Shows request counts, latency, error rates, and bandwidth per server group.

### Logs Tab

Access logs require a `log` directive **inside each site block**. Define a snippet once and import it in every site:

```caddyfile
(access_log) {
    log {
        output file /var/log/caddy/access.log {
            roll_size 10mb
            roll_keep 3
        }
        format json
    }
}

app.yourdomain.com {
    import access_log
    reverse_proxy 10.0.0.1:8080
}
```

The `caddy-logs` volume is shared between the Caddy and editor containers (already configured in both compose files). Every site that imports `access_log` will write HTTP request entries to the shared file.

To change the log path, set `CADDY_LOG_FILE` in `.env` (default: `/var/log/caddy/access.log`).

**Note:** A global `log default` block only captures Caddy runtime logs (startup, TLS, shutdown) — not HTTP access logs. You must use per-site `log` directives for access logging.

## Upstream Health Checks

To get health status for a backend, add `health_uri` inside the `reverse_proxy` block:

```caddyfile
app.yourdomain.com {
    reverse_proxy 10.0.0.1:8080 {
        health_uri /
        health_interval 30s
    }
}
```

Without this, upstreams show as `n/a` in the health column (passive fail counts still work).

## Cloudflare Setup

1. Add your domain to Cloudflare (nameservers must point to CF)
2. SSL/TLS mode → **Full** (Caddy uses local certs, CF handles public SSL)
3. Zero Trust → Tunnels → create tunnel, copy token to `CLOUDFLARE_TUNNEL_TOKEN`
4. Tunnel public hostname: `ceditor.yourdomain.com` → `http://caddy-editor:9090`
5. Zero Trust → Access → Applications → add policy (email OTP for your allowed emails)
6. On that application's Overview page copy the **Application Audience (AUD) Tag** into `CF_ACCESS_AUD`, and put your team domain (`<team>.cloudflareaccess.com`, shown under Zero Trust → Settings) into `CF_ACCESS_TEAM_DOMAIN`

## Local Dev

```bash
cp .env.example .env   # fill in GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, ALLOWED_DOMAIN
docker compose up -d --build
# open http://localhost:9090
```

### No-OAuth dev stack

To click through the UI without setting up Google OAuth:

```bash
./dev/run.sh up      # http://localhost:8888, signed in as dev@local
./dev/run.sh down    # stop and remove volumes
./dev/run.sh reset   # restore dev/run/Caddyfile from the seed
./dev/run.sh big 600 # print a 600-site Caddyfile to stdout
```

`docker-compose.dev.yaml` starts three containers: a front Caddy that injects the
`Cf-Access-Authenticated-User-Email` header the app's `AUTH_MODE=cloudflare`
expects, the editor, and a second Caddy whose config the editor edits and
reloads. The editor works on `dev/run/Caddyfile`, so your real Caddyfile is never
touched.

There is no authentication in this stack — every published port is bound to
`127.0.0.1` for that reason. Never use it off localhost.

### Tests

```bash
node tests/diff.test.mjs                        # diff correctness + performance
python3 -m unittest discover -s tests -t .      # caddy wrapper, cache, session key
```

## How Save & Reload Works

1. Formats config with `caddy fmt`
2. Validates with `caddy validate`
3. Under a file lock (saves from different workers can't interleave): re-checks that the file on disk is still the version you loaded, backs it up to `/backups/`, writes the new content, prunes backups beyond `BACKUP_KEEP`
4. Sends `POST http://caddy:2019/load` to reload Caddy live (zero downtime)
5. If Caddy rejects the config (runtime-only problems `caddy validate` can't see, like a port already in use), the on-disk file is rolled back to the backup so disk and running config never diverge

The editor validates with the Caddy binary baked into its image; keep that version in step with the `caddy` service in your compose file (both are `2.11.4` here).

## JS Editor (CodeMirror)

The editor uses CodeMirror 6, bundled locally. To rebuild after changing `src/static/js/editor-src.js`:

```bash
npm install
npm run build
```

The bundle (`editor.bundle.js`) is committed — no build step needed on the server.

## Environment Variables

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
| `GUNICORN_WORKERS` / `GUNICORN_THREADS` | no | `2` / `4` | Server process/thread counts |
| `GUNICORN_PRELOAD` | no | `true` | Load the app once in the master. Set `false` when using `--reload` (the dev stack does) |

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check (no auth) |
| `GET /api/caddyfile` | Get current Caddyfile content |
| `POST /api/validate` | Validate + format config |
| `POST /api/save` | Save and reload Caddy |
| `GET /api/backups` | List backups |
| `GET /api/backups/:name` | Get backup content |
| `DELETE /api/backups/:name` | Delete a backup |
| `GET /api/snippets` | Get snippet templates |
| `GET /api/metrics` | Editor activity metrics |
| `GET /api/traffic` | Caddy Prometheus metrics (parsed) |
| `GET /api/upstreams` | Upstream backend status |
| `GET /api/status` | Caddy version and config validity |
| `GET /api/logs` | Tail Caddy access log (supports `?pos=` for incremental) |
| `POST /api/logs/ping` | Generate a test log entry by hitting Caddy |
| `GET /api/audit` | Audit log entries |

## Commands

```bash
# Start
docker compose -f docker-compose.prod.yaml up -d

# Logs
docker compose -f docker-compose.prod.yaml logs -f

# Update (pull new image from GHCR)
docker compose -f docker-compose.prod.yaml pull caddy-editor
docker compose -f docker-compose.prod.yaml up -d caddy-editor

# Restart caddy (only needed for admin address changes or image upgrades)
docker compose -f docker-compose.prod.yaml restart caddy
```
