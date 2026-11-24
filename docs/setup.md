# Setup

How to get Caddy Console running against a real Caddy instance. If you just want
to poke at it locally, see [development.md](development.md) instead.

## What you end up with

The production stack supports two authentication layouts:

```text
Google mode:
internet → cloudflared tunnel → caddy-console:9090 → Google OAuth

Cloudflare mode:
internet → Cloudflare Access → cloudflared tunnel → caddy-console:9090

Public sites in either mode:
internet → Caddy :80/:443 → your services
```

Three containers run in production:

- **caddy** publishes host ports 80/443 after the Nginx cutover.
- **caddy-console** has no published port and is reached only through cloudflared.
- **cloudflared** provides the outbound tunnel.

Caddy and the console alone share the internal `caddy-admin` network. Cloudflared
and the console share a separate `console-ui` network, so cloudflared cannot reach
Caddy's unauthenticated admin API. Caddy has its own `caddy-public` network for
ACME egress. Do not attach other services to `caddy-admin`.

The host directory `/opt/caddy` is mounted read-only into Caddy and read-write
into the console. Directory mounting is required: the console writes a temporary
file, flushes it, and atomically replaces `/etc/caddy/Caddyfile`, then holds one
cross-process lock until Caddy's blocking `POST /load` succeeds or rollback is
complete.

The temporary `docker-compose.internal.yaml` stack instead publishes Caddy on
8080/8443 so it can run beside Nginx. Its console uses Google OAuth, has no
published port, and is served by that Caddy on a LAN-only hostname; see the
README's "Internal stack" section for the Caddyfile site and DNS.
Do not run the internal and production stacks simultaneously. While Nginx still
owns public 80/443, Caddy cannot complete HTTP-01 or TLS-ALPN certificate
challenges through 8080/8443. Use DNS-01 for pre-cutover certificates, or expect
certificate issuance only after traffic moves to Caddy.

Compose volumes remain project-scoped. Keep the same Compose project or Portainer
stack name when switching files. A different name creates new empty certificate,
backup, log and GeoIP volumes; migrate or declare those volumes external before
changing the stack name.

## 1. Prepare the host and image reference

The console image runs as UID/GID 10001 and must be able to atomically replace
files inside `/opt/caddy`:

```bash
sudo mkdir -p /opt/caddy

sudo tee /opt/caddy/Caddyfile > /dev/null << 'EOF'
{
    # Unpublished and reachable only on the caddy-admin Docker network.
    admin 0.0.0.0:2019
    metrics
}

app.yourdomain.com {
    reverse_proxy 10.0.0.1:8080
}
EOF
sudo chown -R 10001:10001 /opt/caddy
sudo chmod 0755 /opt/caddy
sudo chmod 0644 /opt/caddy/Caddyfile

cp .env.example .env
chmod 600 .env
# Set CADDY_CONSOLE_IMAGE to the immutable sha-* tag or digest published by CI.
# Then configure one authentication mode below.

docker compose -f docker-compose.prod.yaml up -d
```

In Portainer, set the same values as stack environment variables. The production
Compose file deliberately has no `latest` image fallback and refuses to render
until `CADDY_CONSOLE_IMAGE` and `CLOUDFLARE_TUNNEL_TOKEN` are set.


### One-time permissions when upgrading an existing stack

Earlier images ran as root, so existing backup and GeoIP volumes may still be
root-owned. Keep the same Compose project/Portainer stack name and, before the
first non-root start, change only those two data directories to UID/GID 10001.
For plain Compose:

```bash
docker compose -f docker-compose.internal.yaml run --rm --no-deps --user 0 \
  --cap-add CHOWN --entrypoint chown caddy-console \
  -R 10001:10001 /backups /data/geoip
```

Use `docker-compose.prod.yaml` instead if that is the existing stack. Also apply
the `/opt/caddy` ownership command above. Do not rename or recreate the volumes.

## 2. Choose exactly one authentication mode

Both modes also honor `ALLOWED_DOMAIN` and `ALLOWED_EMAILS`. Keep at least one
restriction configured.

### Google OAuth

Use this when the application itself should own the login session:

1. Set `AUTH_MODE=google`.
2. Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` and a strong `SECRET_KEY`.
3. Set `SERVER_URL` to the public HTTPS console origin, for example
   `https://caddy-console.example.com`.
4. Register exactly `${SERVER_URL}/auth/callback` as an authorized redirect URI.
5. Configure the Cloudflare Tunnel hostname, but do **not** add a Cloudflare
   Access application in front unless you intentionally want two login gates.

The application session defaults to eight hours (`SESSION_TIMEOUT_HOURS`).

### Cloudflare Access

Use this when Cloudflare Access should authenticate every request before it reaches
the tunnel:

1. Set `AUTH_MODE=cloudflare`.
2. Set `CF_ACCESS_TEAM_DOMAIN` to `<team>.cloudflareaccess.com`.
3. Set `CF_ACCESS_AUD` to the application's AUD tag.
4. Create an Access application and policy for the tunnel hostname.

Both values are mandatory. The application verifies the signed Access JWT's
signature, issuer, audience and expiry and refuses to start if verification is not
configured. Production has no unsigned-header fallback.

`UNSAFE_ALLOW_UNVERIFIED_CF_HEADER` exists only inside the committed dev Compose
file for its loopback-bound synthetic login. Never pass it to the internal or
production service.

## 3. Turn on access logging

The dashboard and the explorer both read Caddy's access log, so it needs a `log`
directive **inside each site block**. Define a snippet once and import it:

```caddyfile
(access_log) {
    log {
        output file /var/log/caddy/access.log {
            mode 0644
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
both compose files already configure. The console mounts that volume read-only and
runs as UID 10001, while Caddy creates files as its own user. The `mode 0644`
setting is therefore required for the console to read them; the volume is not
published or shared with unrelated containers. To use a different path, set
`CADDY_LOG_FILE` in `.env` to match your Caddyfile.

When upgrading an existing log volume, update current files once before starting
the non-root console:

```bash
docker compose -f docker-compose.internal.yaml exec caddy \
  find /var/log/caddy -maxdepth 1 -type f -name 'access*.log*' \
  -exec chmod 0644 {} +
```

### Strip the headers — this is not optional

`format filter` with `wrap json` keeps every field the UI uses (`ts`, host, method,
uri, status, duration, size, client_ip) and drops the header maps. Two reasons:

- **Request headers can carry session tokens, API keys and personal data.** Caddy
  redacts common credential headers by default unless `log_credentials` is set,
  but dropping the complete maps prevents less common secrets and identifying
  metadata from being written and rendered.
- **Headers are roughly 90% of each entry.** Dropping them takes an entry from
  ~4 KB to ~300 bytes, so the same `roll_size` covers more than ten times the
  history.

The editor's **Check** action warns when it sees site/snippet access logging without
`format filter`, or when the filter does not delete both header maps. This is a
warning rather than a parser-level block because Caddyfiles can import external
files, but production deployment should not proceed until the effective config is
verified.

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

## 5. IP location (optional, automatic)

Click a client IP in an expanded event to see where it is from (city, country,
network/ASN) and what else it did in the range on screen. Location comes from
[DB-IP](https://db-ip.com)'s free Lite databases (CC-BY 4.0), read locally — no
visitor IP is ever sent anywhere to look it up.

You do not need to do anything: on startup, and then once a day, the console
checks whether the installed release is older than the current month and, if so,
downloads the new one (~65 MB, about 135 MB on disk) into `GEOIP_DIR`. The
compose files mount a `caddy-geoip` volume there so a rebuild does not
re-download. Downloads are rejected above 512 MiB compressed or 512 MiB
uncompressed per database. A failed, oversized or partial download never replaces
the working files.

On a host without internet egress, set `GEOIP_AUTO_UPDATE=false` and drop
`dbip-city-lite.mmdb` and `dbip-asn-lite.mmdb` (decompressed, from
<https://db-ip.com/db/lite.php>) into `GEOIP_DIR` yourself; they are picked up
within ten minutes without a restart. Without the files the popover still works —
it just shows the IP's type and its requests, not its location.

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
image: ghcr.io/caddybuilds/caddy-cloudflare:2.11.9-alpine
```

The **Check** action first asks the running container to adapt the Caddyfile through
`POST /adapt`, so syntax and module availability are checked against the exact
custom build. Adaptation does not provision or run the configuration; the full
transactional check happens during `POST /load` after **Save & Reload**. The UI
labels these states separately.

The console also ships a plain Caddy binary for `caddy fmt` and for full local
validation when the admin API is unreachable. If that fallback must understand a
plugin, build the console image against the same Caddy distribution:

```bash
docker build --build-arg CADDY_IMAGE=ghcr.io/caddybuilds/caddy-cloudflare:2.11.9-alpine .
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

## Wildcard subdomains without DNS credentials (on-demand TLS)

A wildcard certificate (`*.apps.yourdomain.com`) needs a DNS-01 challenge, which
means a Caddy build with a DNS provider module plus API credentials. When the
subdomains are created by another app and there are only a handful of them,
on-demand TLS is simpler: Caddy gets a normal HTTP-01 certificate for each
hostname the first time it is requested, with the stock image.

It needs WAN ports 80 and 443 forwarded to Caddy, a wildcard DNS record pointing
at them, and an **`ask` endpoint** that approves each hostname. Without a strict
`ask`, anyone can request `random123.apps.yourdomain.com` and spend your Let's
Encrypt quota (50 certificates per registered domain per week, shared with every
other site on that domain).

```caddyfile
{
    on_demand_tls {
        ask http://10.0.0.5:8081/__caddy_ask   # returns 200 only for real hostnames
    }
}

*.apps.yourdomain.com {
    tls {
        on_demand
    }
    respond /__caddy_ask 404                  # keep the approval endpoint internal
    reverse_proxy 10.0.0.5:8081
}
```

Caddy calls `ask` with `?domain=<hostname>`. The endpoint can live in the app
that creates the subdomains, or in a backend Caddy that checks the site exists:

```caddyfile
@ask path /__caddy_ask
handle @ask {
    map {query.domain} {project} {
        ~^([a-z0-9-]+)\.apps\.yourdomain\.com$ "${1}"
        default "__none__"
    }
    @published file {
        root /var/www/sites
        try_files /{project}/index.html
    }
    respond @published 200
    respond 404
}
```

`on_demand_tls` is a global option, so restart Caddy after adding it. The first
request to a new hostname waits a few seconds for its certificate. With many
subdomains, or frequent new ones, use a DNS-01 wildcard instead (see
[Running a custom Caddy build](#running-a-custom-caddy-build)).

## Prometheus metrics (optional)

Add `metrics` to the global block to expose Caddy's Prometheus endpoint, which the
dashboard uses for server-level counters:

```caddyfile
{
    admin 0.0.0.0:2019
    metrics
}
```

## Cloudflare Tunnel and Access setup

Both authentication modes use Tunnel as the private transport:

1. Add the domain to Cloudflare and choose the required SSL/TLS mode for the
   public Caddy sites.
2. Create a remotely managed tunnel and set its token as
   `CLOUDFLARE_TUNNEL_TOKEN`. Compose passes it through `TUNNEL_TOKEN`, not the
   process command line. Platforms with file secrets may use cloudflared's
   `TUNNEL_TOKEN_FILE` instead.
3. Route `caddy-console.yourdomain.com` to `http://caddy-console:9090`.

For `AUTH_MODE=cloudflare` only:

4. Zero Trust → Access → Applications → create an application and policy for the
   console hostname.
5. Copy the team domain into `CF_ACCESS_TEAM_DOMAIN`.
6. Open that Access application → Application settings → copy the AUD tag into
   `CF_ACCESS_AUD`.

For `AUTH_MODE=google`, skip steps 4–6 and configure Google's callback as described
in the authentication section.

## Behind a proxy or tunnel: real client IPs

When Caddy sits behind Cloudflare Tunnel, another proxy, or Docker's
port-forwarding proxy, every request can appear to come from one private
address. Client IPs, IP locations and `client:` filters in Explore are then
wrong, and the dashboard shows a "Visitors' real IPs are not being logged"
notice: at least 50 requests in the last hour, 95% or more from one IP in
Docker's `172.16.0.0/12` range. A home network browsing from one PC
(`192.168.x` / `10.x`) does not trigger it.

Behind Cloudflare (tunnel or proxied DNS), tell Caddy which header carries the
visitor's IP:

```caddyfile
{
	servers {
		trusted_proxies static private_ranges
		client_ip_headers Cf-Connecting-IP
	}
}
```

`private_ranges` fits a tunnel, where `cloudflared` reaches Caddy over a Docker
network. With proxied DNS and published ports instead, trust Cloudflare's
published ranges (<https://www.cloudflare.com/ips/>), not private ranges.

If no proxy is involved and the address is a Docker network gateway (such as
`172.17.0.1`), Docker itself is rewriting the source address. That is normal for
Docker Desktop, rootless Docker and requests from the host itself; on a Linux
server with published ports it points at the daemon's `userland-proxy`. Running
Caddy with `network_mode: host` avoids it.

The notice can be dismissed per IP; that is stored in the browser only.

### Cloudflare request fields (optional)

Cloudflare adds the visitor's country and a Ray ID to each request. The
recommended `format filter` drops all headers, so add the two you want back as
separate log fields, in each site block (or in the `(access_log)` snippet):

```caddyfile
log_append cf_country {header.Cf-IPCountry}
log_append cf_ray {header.Cf-Ray}
```

Explore then shows a **Country (Cloudflare)** facet, a `country:` filter (e.g.
`country:RO`, `-country:US`), the country in each event, and the Ray ID (with
copy) when you open an event's original line. Paste the Ray ID into the
Cloudflare dashboard to see what Cloudflare did with that request. Without these
lines nothing changes: no facet, no extra fields.

## IP bans (optional)

Ban an IP or range from the **Security** view or the Explore IP popover; stock
Caddy enforces it on the sites that import the managed file. Setup, the
protected ranges, capacity and host recovery are in
[docs/security.md](security.md). No extra service is required. For automatic
bans from CrowdSec, add the optional overlay described in
[CrowdSec file sync](security.md#crowdsec-file-sync-optional); the quick start
above needs nothing from it. For enforcement without reloads, see
[CrowdSec plugin](security.md#crowdsec-plugin).

## Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CADDY_CONSOLE_IMAGE` | production/internal | — | Immutable `sha-*` tag or image digest; no `latest` fallback |
| `AUTH_MODE` | yes | `google` | Auth mode: `google` or `cloudflare` |
| `SECRET_KEY` | google mode | — | Strong Flask session secret; Cloudflare mode persists a generated key if omitted |
| `GOOGLE_CLIENT_ID` | google mode | — | OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | google mode | — | OAuth client secret |
| `SERVER_URL` | google mode outside localhost | `http://localhost:9090` | Public HTTPS origin used for the exact OAuth callback URI |
| `CLOUDFLARE_TUNNEL_TOKEN` | production stack | — | Remotely managed Tunnel token; passed to cloudflared outside argv |
| `CF_ACCESS_TEAM_DOMAIN` | cloudflare mode | — | `<team>.cloudflareaccess.com`; mandatory for JWT issuer and JWKS validation |
| `CF_ACCESS_AUD` | cloudflare mode | — | Access application AUD tag; mandatory for JWT audience validation |
| `UNSAFE_ALLOW_UNVERIFIED_CF_HEADER` | never in production | `false` | Explicit synthetic-login escape hatch used only by dev Compose |
| `ALLOWED_DOMAIN` | no | — | Restrict to an email domain |
| `ALLOWED_EMAILS` | no | — | Comma-separated allowed emails |
| `SESSION_TIMEOUT_HOURS` | no | `8` | Session lifetime in Google mode |
| `CADDY_API_URL` | no | `http://caddy:2019` | Caddy admin API address |
| `CADDYFILE_PATH` | no | `/etc/caddy/Caddyfile` | Path to Caddyfile |
| `BACKUP_DIR` | no | `/backups` | Backup storage directory |
| `BACKUP_KEEP` | no | `50` | Pre-save backups to keep; oldest are pruned after each save (`0` = keep all) |
| `AUDIT_LOG_MAX_BYTES` | no | `5242880` | Rotate the audit log past this size; one rotated file is kept |
| `CADDY_LOG_FILE` | no | `/var/log/caddy/access.log` | Path to Caddy access log (must match Caddyfile) |
| `CADDY_EXPLORE_MAX_EVENTS` | no | `200000` | Events held in memory per range; ~38 B each |
| `GEOIP_DIR` | no | `/data/geoip` | Where the DB-IP Lite databases live |
| `GEOIP_AUTO_UPDATE` | no | `true` | Download a new DB-IP release monthly. `false` for air-gapped hosts |
| `BANS_ENABLED` | no | `true` | IP bans: Security API, background job and view. Sites are unchanged until they import the file |
| `BANS_DIR` | no | `/etc/caddy/console` | Generated Caddy files; inside the Caddyfile directory |
| `BANS_MAX` | no | `10000` | Maximum prefixes rendered into Caddy |
| `BANS_NEVER` | no | empty | Extra protected IPs/CIDRs, comma or space separated; invalid entry stops startup |
| `BANS_SYNC_INTERVAL` | no | `30` | Minimum seconds between CrowdSec-driven reloads (10-3600). |
| `CROWDSEC_URL` | no | empty | LAPI URL; empty disables CrowdSec. The overlay sets `http://crowdsec:8080`. |
| `CROWDSEC_CONSOLE_BOUNCER_KEY` | no | empty | Read-only bouncer key used only by the console. `CROWDSEC_CONSOLE_BOUNCER_KEY_FILE` reads it from a mounted file instead. |
| `CROWDSEC_ORIGINS` | no | `crowdsec,cscli` | LAPI origins synced and shown. |
| `CROWDSEC_POLL_INTERVAL` | no | `10` | Seconds between decision-stream polls (5-300). |
| `GUNICORN_WORKERS` / `GUNICORN_THREADS` | no | `2` / `4` | Server process/thread counts |
| `GUNICORN_PRELOAD` | no | `true` | Load the app once in the master. Set `false` when using `--reload` (the dev stack does) |

## Nginx-to-Caddy cutover

Use the same Compose project/Portainer stack name so the named volumes are reused.
Before Caddy claims host ports 80/443:

1. Verify the production authentication variables and immutable image reference.
2. If you are upgrading from an older internal stack, stop its synthetic-login
   proxy: `docker compose -f docker-compose.internal.yaml stop console-proxy`.
3. Stop Nginx using the host's service manager, freeing 80/443.
4. Start the production definition and remove the internal-only orphan:

   ```bash
   docker compose -f docker-compose.prod.yaml up -d --remove-orphans
   ```

Without `--remove-orphans`, a `console-proxy` left over from an older internal
stack can keep running and injecting `admin@local` after the authenticated stack
starts. Do not add `-v` to
`down` during cutover because that deletes the certificate, backup and log volumes.

## Day-to-day commands

```bash
# Start
docker compose -f docker-compose.prod.yaml up -d

# Logs
docker compose -f docker-compose.prod.yaml logs -f

# Update: set CADDY_CONSOLE_IMAGE to the new immutable sha tag or digest first
docker compose -f docker-compose.prod.yaml pull caddy-console
docker compose -f docker-compose.prod.yaml up -d caddy-console

# Upgrade Caddy: edit its image reference in this Compose file first
docker compose -f docker-compose.prod.yaml pull caddy
docker compose -f docker-compose.prod.yaml up -d caddy

# Restart without changing the image (needed for output-file option changes)
docker compose -f docker-compose.prod.yaml restart caddy
```
