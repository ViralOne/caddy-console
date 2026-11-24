# Security: IP bans

Caddy Console can block clients by IP address or CIDR range on the sites you
choose. This page covers manual file mode, which works with the stock
`caddy:2.11.9-alpine` image and needs no extra service. CrowdSec file sync is
an optional overlay, described in
[CrowdSec file sync (optional)](#crowdsec-file-sync-optional). Cloudflare
client-IP profiles and the country policy are described in
[Cloudflare client IPs and country policy](#cloudflare-client-ips-and-country-policy).

## How it works

The console keeps ban records in `BACKUP_DIR/bans.json` and renders the
effective list into `BANS_DIR/bans-manual.caddy` (default
`/etc/caddy/console/bans-manual.caddy`). A site opts in by importing that file
first:

```caddyfile
example.com {
	import /etc/caddy/console/bans-manual*.caddy

	handle {
		reverse_proxy app:8080
	}
}
```

The import is absolute because Caddy resolves relative imports against its own
working directory when the console reloads it. The `*` lets Caddy start before
the console has written the file. Nothing changes for a site until it imports
the file.

Every change (ban, unban, expiry) is one journaled transaction under the same
lock the editor uses: new files are written beside the old ones, the old ones
are backed up, the running Caddy adapts the unchanged Caddyfile, and only then
does the console POST it to `/load`. A rejected reload restores the previous
files; Caddy keeps its running configuration. If the console cannot tell
whether Caddy applied a change (a timeout after the request was sent), it keeps
the new files, pauses further changes and settles the change from Caddy's
running configuration as soon as it can.

Bans apply to new requests and new connections. Open WebSocket or other
long-lived connections are not cut.

## Which address is banned

A ban matches Caddy's resolved client address (the `client_ip` matcher), the
same address Explore shows. That is the visitor's own address only when Caddy
knows which proxy to trust; without that setup a ban can look right and still
do nothing, or block the wrong people:

- **Behind Cloudflare Tunnel (or another proxy) without `trusted_proxies`**,
  every request comes from the private address of `cloudflared` or the proxy.
  Private ranges are never banned, so no ban ever matches, even though Security
  can still show the site as Protected: the ban check is in place, it just never
  sees a public address.
- **With proxied DNS (the orange cloud) without that setup**, the public
  addresses Explore shows are Cloudflare edge addresses, not visitors. Banning
  one, for example `198.51.100.23`, blocks every visitor Cloudflare happens to
  route through that edge address.

Configure `trusted_proxies` and `client_ip_headers` first, as described in
[Behind a proxy or tunnel: real client IPs](setup.md#behind-a-proxy-or-tunnel-real-client-ips),
then check in Explore that visitors show their own addresses before you ban
any. When the dashboard shows the "Visitors' real IPs are not being logged"
notice, fix that before relying on bans.

## Setup

1. Keep the Caddyfile **directory** mounted: read-write in `caddy-console`,
   read-only in `caddy` (all shipped Compose files already do this).
   `BANS_DIR` must be inside that directory, at the same absolute path in both
   containers, and not behind a symlink.
2. Open **Security**. If it says "Unavailable, not enforced", the message names
   the missing mount or permission. The editor, Dashboard and Explore keep
   working either way.
3. In the editor, put the cursor in a site block and use the snippet
   **Manual bans: protect this site**, or use **Add import in editor** in
   Security. Review the diff, then Save & Reload.

To turn the feature off entirely set `BANS_ENABLED=false`: no checks, no
background job, no Security view.

## Which sites are protected

Security proves enforcement from Caddy's running configuration, per site:

| State | Meaning |
|---|---|
| Protected | The ban check runs before anything that serves the site. |
| Protected, pre-handler present | `redir`, `rewrite`, `basic_auth`, `forward_auth` or `request_header` run first. They never serve the application, but a banned client may get a redirect or a 401 instead of a 403, and an auth service is contacted. |
| Enforcement not verified | Something that can answer the request runs first (`invoke`, a custom global `order`, an unknown handler, or a `handle` placed above the import). Move the import up, or use the strict layout. |
| Not enforced | The site does not import the file. |
| Console site, never banned | The console's own hostname (`SERVER_URL`) or a site block marked `# caddy-console: management`. Never offered the import. |
| Console site imports the ban list: lockout risk | The console's own site imports (or Caddy already enforces) the ban list, for example through a hand-typed import. A ban that matches your address would lock you out of the console. Remove the import line from that site and Save & Reload. |

`handle`, `handle_path` and `route` blocks in the site cannot run before the
ban check, because the generated file uses a matcher-specific `handle`.

**Strict layout.** To reject banned clients before every other directive, wrap
the site's handling in one `route` and import first inside it:

```caddyfile
example.com {
	route {
		import /etc/caddy/console/bans-manual*.caddy
		redir /old /new
		reverse_proxy app:8080
	}
}
```

A site defined in a file the Caddyfile imports is shown with a Copy button
instead of an editor insertion.

## Addresses that are never banned

These are refused when you try to ban them, and excluded again inside the
generated file, so a stale or broad record cannot lock them out: loopback,
RFC 1918 private ranges, link-local (`169.254.0.0/16`, `fe80::/10`), CGNAT
(`100.64.0.0/10`), IPv6 unique local (`fc00::/7`), unspecified, multicast and
reserved addresses, the console container's Docker networks, every entry in
`BANS_NEVER`, and verified console addresses. Ranges wider than `/16` (IPv4)
or `/48` (IPv6) are refused.

The console verifies your address only from the TCP connection. Behind
Cloudflare Tunnel or a front proxy that is a private Docker address, so the
console cannot see your real address: **put your stable WAN address in
`BANS_NEVER`.**

## Durations and expiry

4 hours, 24 hours, 7 days or permanent. A background job checks every 30
seconds and reloads Caddy when an expiry changes the effective list. Several
records can cover one address; it stays banned until all of them are gone.

## Capacity

`BANS_MAX` limits the prefixes rendered into Caddy (overlapping records are
merged for rendering only). A ban that would exceed it is refused; an active
ban is never dropped silently. Measured on an Apple M1 Pro (32 GiB, Docker
29.2.0), stock Caddy 2.11.9, with the budgets adaptation of at most 2 s,
reload of at most 3 s, at most +150 MiB RSS and at most +2 ms p95 over the
0-prefix run. Two runs; the table shows the worse value of each cell, and the
RSS column is the run-1 baseline for the delta (Go does not return memory
between runs, so run 2's 0-prefix row is inflated).

| Prefixes | File | Adapt | Reload | Caddy RSS | p50 | p95 | Within budget |
|---:|---:|---:|---:|---:|---:|---:|:---|
| 0 | 0 KiB | 0.01 s | 0.01 s | 54 MiB | 0.79 ms | 1.35 ms | yes |
| 1,000 | 13 KiB | 0.04 s | 0.07 s | 61 MiB | 0.87 ms | 1.42 ms | yes |
| 10,000 | 132 KiB | 0.39 s | 0.55 s | 92 MiB | 0.85 ms | 1.44 ms | yes |
| 20,000 | 271 KiB | 0.69 s | 1.05 s | 150 MiB | 0.92 ms | 1.33 ms | yes |

All four sizes are within budget; the released default is capped at 10,000,
the size the design targets. Raise `BANS_MAX` (up to 100,000) only after
measuring your own host with `tests/integration/bans_benchmark.py`.

`BANS_MAX` counts the manual and CrowdSec files together. A ban, an expiry or a
CrowdSec sync that would exceed it is refused as a whole; nothing is dropped to
fit.

## States

| State | What it means | What to do |
|---|---|---|
| Enforced | At least one site proves enforcement. | Nothing. |
| Stored but not imported | Records exist, no site imports the file. | Add the import. |
| Policy differs from state | The file was changed outside the console (for example by host recovery). It is not regenerated and its expiry is paused. | Fix the records, then **Re-apply**. |
| Degraded | `bans.json` is unreadable or a transaction cannot be settled. The last generated file stays enforced; changes are paused. | Use the recovery choices in Security: restore a backup, keep the new or the previous files, or reset the list. |
| Reload state unknown | Caddy did not confirm a reload. | Wait for Caddy to answer, or choose in Security. |

An unreadable `bans.json` is never replaced with an empty list; a bounded copy
is kept in `BACKUP_DIR` as `bans.json.quarantine-*`.

<a id="crowdsec-file-sync"></a>

## CrowdSec file sync (optional)

An optional CrowdSec container reads Caddy's access log and decides which
clients to ban. The console polls CrowdSec's Local API (LAPI) as a read-only
bouncer and renders the active decisions into
`BANS_DIR/bans-crowdsec.caddy`, through the same journaled transaction as
manual bans. Sites opt in separately, so one site can use manual bans only,
CrowdSec only, or both.

### Start it

```bash
export CROWDSEC_CONSOLE_BOUNCER_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
docker compose -f docker-compose.prod.yaml -f docker-compose.crowdsec.yaml up -d
```

Keep the key in the same `.env` as the rest of the stack. The same overlay
works with `docker-compose.internal.yaml` and `docker-compose.tunnel.yaml`; the
NAS stack uses `docker-compose.nas.yaml -f docker-compose.crowdsec.nas.yaml`.

#### Keep the key in a file secret instead

The shipped overlay requires `CROWDSEC_CONSOLE_BOUNCER_KEY`: both services read
it with `${CROWDSEC_CONSOLE_BOUNCER_KEY:?...}`, and Compose checks that before
any later `-f` file can override it, so adding a secret on top of the shipped
overlay fails at `docker compose up`. To use a file secret, copy the overlay
(for example to `docker-compose.crowdsec.local.yaml`) and use the copy instead
of the shipped file:

1. Write the key to a file the console user (UID 10001) can read, and keep it
   out of Git:

   ```bash
   mkdir -p secrets
   python -c 'import secrets; print(secrets.token_hex(32))' > secrets/crowdsec_bouncer_key
   chmod 0444 secrets/crowdsec_bouncer_key
   ```

2. In the copy, delete the `BOUNCER_KEY_caddy_console` line from `crowdsec`,
   replace `CROWDSEC_CONSOLE_BOUNCER_KEY` on the console with
   `CROWDSEC_CONSOLE_BOUNCER_KEY_FILE`, and add the secret:

   ```yaml
   services:
     crowdsec:
       # environment: as shipped, without BOUNCER_KEY_caddy_console
       secrets:
         # The official image registers a bouncer for every
         # /run/secrets/bouncer_key_<name>: this one is "caddy_console".
         - source: crowdsec_bouncer_key
           target: bouncer_key_caddy_console

     caddy-console:
       environment:
         CROWDSEC_URL: http://crowdsec:8080
         CROWDSEC_CONSOLE_BOUNCER_KEY_FILE: /run/secrets/crowdsec_bouncer_key
         # CROWDSEC_ORIGINS, CROWDSEC_POLL_INTERVAL, BANS_SYNC_INTERVAL as shipped
       secrets:
         - crowdsec_bouncer_key

   secrets:
     crowdsec_bouncer_key:
       file: ./secrets/crowdsec_bouncer_key
   ```

3. Start it with the copy:

   ```bash
   docker compose -f docker-compose.prod.yaml -f docker-compose.crowdsec.local.yaml up -d
   ```

Do not set both forms. On the CrowdSec side the image registers
`BOUNCER_KEY_caddy_console` from the environment first, so the secret is then
ignored; on the console side the `_FILE` variable wins over the plain key. Two
different values leave CrowdSec refusing the console's key. On the NAS, copy
`docker-compose.crowdsec.nas.yaml` as well: its `crowdsec` service extends the
shipped overlay, so point its `extends.file` at your copy and make the same
console change under `caddy-editor`.
The `crowdsec/` directory of this repository must sit next to the Compose
files: the overlay mounts its acquisition and parser files read-only.

The CrowdSec container publishes no port, mounts the log volume read-only and
shares only the internal `crowdsec-lapi` network with the console (plus an
egress network for Hub downloads). Caddy never joins that network, so CrowdSec
cannot reach the Caddy admin API. Community enrollment is off
(`DISABLE_ONLINE_API=true`).

### Change the bouncer key

CrowdSec registers the bouncer `caddy_console` with your key only on the first
start of its configuration volume (`crowdsec-config`). Changing
`CROWDSEC_CONSOLE_BOUNCER_KEY` later is not enough: CrowdSec keeps accepting the
old key and refuses the new one, and Security shows "CrowdSec refused the
bouncer key". To rotate the key:

1. Put the new key in `.env` (or in the secret file, if you use one).
2. Delete the registered bouncer:

   ```bash
   docker compose -f docker-compose.prod.yaml -f docker-compose.crowdsec.yaml exec crowdsec \
     cscli bouncers delete caddy_console
   ```

3. Recreate both containers so they read the new key; CrowdSec registers it again:

   ```bash
   docker compose -f docker-compose.prod.yaml -f docker-compose.crowdsec.yaml up -d \
     --force-recreate crowdsec caddy-console
   ```

On the NAS stack the files differ and the console service is `caddy-editor`:

```bash
docker compose -f docker-compose.nas.yaml -f docker-compose.crowdsec.nas.yaml exec crowdsec \
  cscli bouncers delete caddy_console
docker compose -f docker-compose.nas.yaml -f docker-compose.crowdsec.nas.yaml up -d \
  --force-recreate crowdsec caddy-editor
```

If you use a copied overlay with a file secret (above), use your copy in these
commands instead.

The console retries a refused key every 60 seconds, so it picks up the new
registration without another restart. The last synced list stays enforced
meanwhile.

### Protect a site

In the editor use **CrowdSec bans: protect this site**, or **Add import in
editor** in Security. It goes directly after the manual import:

```caddyfile
example.com {
	import /etc/caddy/console/bans-manual*.caddy
	import /etc/caddy/console/bans-crowdsec*.caddy

	handle {
		reverse_proxy app:8080
	}
}
```

### Log fields for detection

The console's log filter deletes request and response headers. CrowdSec's Caddy
parser still sees the client address, method, path and status, so path probes
and 404 bursts are detected. For the bad User-Agent and Basic auth brute-force
scenarios, add the **CrowdSec: log fields for detection** snippet to each logged
site, below the ban imports:

```caddyfile
log_append <user_agent {http.request.header.User-Agent}
log_append auth_challenge {http.response.header.Www-Authenticate}
```

These two top-level fields are all the repository's parser
(`crowdsec/parsers/s02-enrich/caddy-console-safe-fields.yaml`) needs. Cookie,
Authorization and API-key headers and bodies are never logged.

### Check that parsing works

```bash
docker compose -f docker-compose.prod.yaml -f docker-compose.crowdsec.yaml exec crowdsec \
  cscli explain --file /var/log/caddy/access.log --type caddy -v
```

Look for `evt.Meta.source_ip`, `http_path`, `http_verb` and `http_status`. The
`source_ip` must be the visitor's address, for example `203.0.113.60`, not a
Docker or Cloudflare address; if it is not, fix `trusted_proxies` first (see
[Which address is banned](#which-address-is-banned)). CrowdSec's parser uses
Caddy's resolved `client_ip`, the same address a ban matches.

### Origins and capacity

`CROWDSEC_ORIGINS` defaults to `crowdsec,cscli`: CrowdSec's own detections and
decisions you add with `cscli`. CAPI and list origins can hold tens of thousands
of decisions; stock Caddy file mode has a finite matcher budget (`BANS_MAX`,
shared with manual bans), so add them only deliberately. If the selected origins
would exceed `BANS_MAX`, the last applied CrowdSec file stays enforced,
automatic apply pauses and Security shows the counts by origin.

### How sync behaves

- One console worker leads the sync (a lock in `BACKUP_DIR`); if it exits,
  another takes over within one poll interval and starts with a full snapshot.
- The first poll, and the first after any error, asks for the full list
  (`startup=true`); later polls fetch changes. Files are rewritten and Caddy is
  reloaded at most once per `BANS_SYNC_INTERVAL` and only when the file changes,
  so a new decision is normally enforced within 60 seconds.
- Each decision is stored separately; deleting one does not unban an address
  another decision still covers. Only `ban` decisions with scope Ip or Range are
  used. Protected addresses (see above) are ignored and shown as such.
- If CrowdSec is unreachable, refuses the key or sends an unusable response, the
  last synced list stays enforced and Security shows the time of the last
  success.

### Removing a decision

CrowdSec decisions are read-only in the console. Security shows a copyable
command for each one; run it inside the CrowdSec container:

```bash
docker compose -f docker-compose.prod.yaml -f docker-compose.crowdsec.yaml exec crowdsec \
  cscli decisions delete --id 42
```

**Reset CrowdSec decisions** in Security only clears the stored copy; decisions
that are still active in CrowdSec return within `BANS_SYNC_INTERVAL`.

## CrowdSec plugin

### What it is

An optional custom Caddy image runs the CrowdSec bouncer inside Caddy, so the
sites you choose enforce CrowdSec decisions without a reload. The plugin polls
CrowdSec's Local API every `ticker_interval` (`10s` in the shipped snippet):
enforcement is near-real-time without reload, not instantaneous. Security shows
the polling interval.

Nothing else changes. Manual bans still render to `bans-manual.caddy`, and
CrowdSec file sync keeps working for every site that imports
`bans-crowdsec*.caddy`. The plugin never writes either file.

### Images

| Image | Contents | Use it when |
|---|---|---|
| `ghcr.io/viralone/caddy-crowdsec` | Stock Caddy 2.11.9 plus the CrowdSec HTTP module. That module also brings the AppSec handler (unused here) and five `github.com/mholt/caddy-l4` modules the bouncer depends on (no layer4 app is configured). | Prod, internal and tunnel stacks. |
| `ghcr.io/viralone/caddy-crowdsec-cloudflare` | The same, plus `caddy-dns/cloudflare` for DNS-01. | The NAS stack, or any stack that issues certificates with DNS-01. Using Cloudflare as a proxy or Tunnel does not need it. |

Tags are `2.11.9-crowdsec-0.15.0` (Caddy and plugin versions) and
`sha-<commit>`. Deploy by digest or by a `sha-*` tag, never by a moving tag.
To read the digest:

```bash
docker buildx imagetools inspect ghcr.io/viralone/caddy-crowdsec:2.11.9-crowdsec-0.15.0
```

Each image records its non-standard modules at
`/usr/share/caddy-console/modules.json`. CI builds both images from committed
`go.mod`/`go.sum` files, checks the module list, publishes an SBOM, scans every
build for vulnerabilities and adapts every shipped plugin snippet with the built
binary. It pushes only from `master`, after every test job has passed.

### Before the first start: bind the admin API

In plugin mode Caddy joins `crowdsec-lapi` so the plugin can poll LAPI. With
the usual `admin 0.0.0.0:2019`, CrowdSec could then reach the unauthenticated
Caddy admin API. The overlay therefore pins Caddy to `172.30.250.2` on
`caddy-admin` (subnet `172.30.250.0/29`), and the Caddyfile must bind the admin
API there and nowhere else:

```caddyfile
{
	admin 172.30.250.2:2019 {
		origins caddy:2019 172.30.250.2:2019
	}
}
```

The image checks this before Caddy listens. With a wildcard, loopback or
missing `admin` line it exits without starting Caddy, for example:

```text
caddy-console preflight: refusing to start Caddy: the admin API listens on a wildcard address (0.0.0.0:2019), which CrowdSec could reach; put this in the global options:
	admin 172.30.250.2:2019 {
		origins caddy:2019 172.30.250.2:2019
	}
```

Later, the console refuses to save a Caddyfile whose admin bind would expose
port 2019 again.

The tunnel stack already gives `caddy-admin` this subnet. The prod, internal and
NAS stacks do not, so take the stack down once (no `-v`, volumes stay) and let
Compose recreate the network with the overlay:

```bash
docker compose -f docker-compose.prod.yaml down
```

### Start it

Order matters: the console renders the protected route definition only once
the running Caddy has the module, and a site import needs that definition.

1. Set the admin bind above in the Caddyfile and start the stack with both
   overlays:

   ```bash
   export CROWDSEC_PLUGIN_BOUNCER_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
   export CADDY_PLUGIN_IMAGE=ghcr.io/viralone/caddy-crowdsec@sha256:<digest>
   docker compose -f docker-compose.prod.yaml -f docker-compose.crowdsec.yaml \
     -f docker-compose.crowdsec-plugin.yaml up -d
   crowdsec/check-plugin-isolation.sh -- -f docker-compose.prod.yaml \
     -f docker-compose.crowdsec.yaml -f docker-compose.crowdsec-plugin.yaml
   ```

   `CROWDSEC_CONSOLE_BOUNCER_KEY` stays as set up for
   [CrowdSec file sync](#crowdsec-file-sync-optional). Keep both keys in `.env`.
2. In the editor insert **CrowdSec plugin: global app** inside the global
   options block and **CrowdSec plugin: load protected route definition** at
   top level, then **Save & Reload**.
3. Wait until Security shows the protected route definition as current.
4. Per site, insert **CrowdSec plugin: protect this site** (or use **Add import
   in editor** in Security), then **Save & Reload**.

The internal and tunnel stacks use the same overlay:

```bash
docker compose -f docker-compose.internal.yaml -f docker-compose.crowdsec.yaml \
  -f docker-compose.crowdsec-plugin.yaml up -d
crowdsec/check-plugin-isolation.sh -- -f docker-compose.internal.yaml \
  -f docker-compose.crowdsec.yaml -f docker-compose.crowdsec-plugin.yaml

docker compose -f docker-compose.tunnel.yaml -f docker-compose.crowdsec.yaml \
  -f docker-compose.crowdsec-plugin.yaml up -d
crowdsec/check-plugin-isolation.sh -- -f docker-compose.tunnel.yaml \
  -f docker-compose.crowdsec.yaml -f docker-compose.crowdsec-plugin.yaml
```

The NAS stack has its own files, its console service is `caddy-editor`, and it
uses the Cloudflare image (`CADDY_PLUGIN_IMAGE=ghcr.io/viralone/caddy-crowdsec-cloudflare@sha256:<digest>`):

```bash
docker compose -f docker-compose.nas.yaml -f docker-compose.crowdsec.nas.yaml \
  -f docker-compose.crowdsec-plugin.nas.yaml up -d
crowdsec/check-plugin-isolation.sh --console caddy-editor -- -f docker-compose.nas.yaml \
  -f docker-compose.crowdsec.nas.yaml -f docker-compose.crowdsec-plugin.nas.yaml
```

### The isolation check

`crowdsec/check-plugin-isolation.sh` runs on the Docker host and needs no
published port: each probe runs in the network namespace of the container it
tests. For every CrowdSec and cloudflared container it proves that:

- the container has no `CAP_NET_RAW` and no `CAP_NET_ADMIN` (see below);
- port 2019 refuses connections at every Caddy address and at `172.30.250.2`;
- Caddy's data-plane port answers on every network the container shares with
  Caddy (`--data-port`, default `80`).

It also checks that the plugin and console bouncer keys differ. Plugin mode is
not started successfully until this check passes: run it after every `up`.
If it fails, stop the stack and fix the reported problem first.

Why capabilities matter: Caddy now has an interface on `crowdsec-lapi`, and
Linux accepts a packet for any of its own addresses on any interface. A
container on a network shared with Caddy that can write raw frames
(`NET_RAW`, which Docker grants by default) or change routes (`NET_ADMIN`)
could address `172.30.250.2:2019` through that shared interface even though it
is not on `caddy-admin`. The plugin overlay runs CrowdSec with
`cap_drop: [ALL]` (it needs no capability), and the shipped stacks already drop
all capabilities from cloudflared. The remaining risk is any container you add
to a network Caddy is on: give it `cap_drop: [ALL]` too. Without
`CAP_DAC_OVERRIDE`, CrowdSec reads only files it owns or that are readable by
everyone, which is why the secret files below are made `0444`.

### Two keys

The plugin is its own bouncer, `caddy_plugin`, with
`CROWDSEC_PLUGIN_BOUNCER_KEY`. The console keeps `caddy_console` with
`CROWDSEC_CONSOLE_BOUNCER_KEY`. The keys must differ: LAPI keeps one stream
cursor per bouncer, so a shared key makes each side miss the changes the other
already fetched. The overlay check and the isolation check both refuse a shared
key. The plugin key goes only to Caddy (and to CrowdSec, which registers it);
the console never receives it.

Rotate it like the console key ([Change the bouncer key](#change-the-bouncer-key)):
put the new key in `.env`, then

```bash
docker compose -f docker-compose.prod.yaml -f docker-compose.crowdsec.yaml \
  -f docker-compose.crowdsec-plugin.yaml exec crowdsec cscli bouncers delete caddy_plugin
docker compose -f docker-compose.prod.yaml -f docker-compose.crowdsec.yaml \
  -f docker-compose.crowdsec-plugin.yaml up -d --force-recreate crowdsec caddy
```

Never write the key into the Caddyfile. Caddy's `/config/` would show it to
anyone who can read the admin API, and the image refuses to start with a
literal key. The Caddyfile carries only `{env.CROWDSEC_PLUGIN_BOUNCER_KEY}` or
`{file.<path>}`, which the plugin resolves when Caddy starts.

#### Keep the plugin key in a file secret instead

As with the console key, the shipped overlay requires the environment key, so
copy `docker-compose.crowdsec-plugin.yaml` (for example to
`docker-compose.crowdsec-plugin.local.yaml`) and use the copy:

1. Write the key to a file that Caddy and CrowdSec can read (both run without
   `CAP_DAC_OVERRIDE`), and keep it out of Git:

   ```bash
   mkdir -p secrets
   python -c 'import secrets; print(secrets.token_hex(32))' > secrets/crowdsec_plugin_bouncer_key
   chmod 0444 secrets/crowdsec_plugin_bouncer_key
   ```

   The trailing newline is fine: Caddy trims it.
2. In the copy, replace Caddy's `CROWDSEC_PLUGIN_BOUNCER_KEY` with the file
   path, give the console the same path (path only, no mount), register the
   secret on CrowdSec and drop `BOUNCER_KEY_caddy_plugin`:

   ```yaml
   services:
     caddy:
       # image, networks and healthcheck as shipped
       environment:
         CADDY_ADMIN_ADDRESS: 172.30.250.2:2019
         CADDY_ADMIN_SUBNET: 172.30.250.0/29
         CROWDSEC_PLUGIN_BOUNCER_KEY_FILE: /run/secrets/crowdsec_plugin_bouncer_key
       secrets:
         - crowdsec_plugin_bouncer_key

     caddy-console:
       environment:
         CADDY_API_URL: http://172.30.250.2:2019
         CADDY_ADMIN_ADDRESS: 172.30.250.2:2019
         CROWDSEC_PLUGIN_BOUNCER_KEY_FILE: /run/secrets/crowdsec_plugin_bouncer_key

     crowdsec:
       cap_drop: [ALL]
       # no BOUNCER_KEY_caddy_plugin
       secrets:
         - source: crowdsec_plugin_bouncer_key
           target: bouncer_key_caddy_plugin

   # networks: as shipped (caddy-admin with its subnet, crowdsec-lapi)
   secrets:
     crowdsec_plugin_bouncer_key:
       file: ./secrets/crowdsec_plugin_bouncer_key
   ```

3. Start the stack with the copy in place of the shipped file, then run the
   isolation check with the same files.

The editor then offers only the `{file./run/secrets/crowdsec_plugin_bouncer_key}`
form of the global app. If the path in `CROWDSEC_PLUGIN_BOUNCER_KEY_FILE`, the
mount and the Caddyfile placeholder differ, the image stops before Caddy
starts and names both paths, never the content. On the NAS, copy
`docker-compose.crowdsec-plugin.nas.yaml` and put the console change under
`caddy-editor`.

### Protected addresses

The plugin reads LAPI directly, so the console cannot filter what it sees.
Instead every plugin site imports a route that never lets a protected address
reach the plugin. The console writes it to `BANS_DIR/crowdsec-plugin-protect.caddy`
(shown with `BANS_NEVER=203.0.113.99`; the real file also lists your Docker
networks and verified console addresses):

```caddyfile
# Managed by Caddy Console. Do not edit; changes are overwritten.
(protect_crowdsec) {
	vars caddy_console_plugin_protect 1
	@caddy_console_crowdsec_candidate {
		not client_ip private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10 203.0.113.99
	}
	crowdsec @caddy_console_crowdsec_candidate
}
```

The matcher holds the same protected set as manual bans (see
[Addresses that are never banned](#addresses-that-are-never-banned)). Every change to them regenerates the file through the same
journaled transaction as the ban files, and `BACKUP_DIR/plugin-policy.json`
records its hash. Security shows that hash with the definition.

Never use the bare `crowdsec` directive in a site: it would run the plugin for
private, Docker and `BANS_NEVER` addresses as well. Security marks such a site
**Plugin runs without the protected ranges**, and the editor warns about it.

As defense in depth, Security offers **CrowdSec plugin: LAPI allowlist**:
copy-only `cscli allowlists ...` commands with the static protected set, run
inside the CrowdSec container. An allowlist stops new decisions for those
addresses but does not remove existing ones, so the protected route stays the
real control.

### Which sites use which path

Each site picks its CrowdSec path by what it imports:

| Site imports | Manual bans | CrowdSec decisions |
|---|---|---|
| `bans-manual*.caddy` and `bans-crowdsec*.caddy` | File | File sync |
| `bans-manual*.caddy` and `import protect_crowdsec` | File | Plugin |
| `bans-manual*.caddy` only | File | None |

Security shows the path on each site. A site that has both CrowdSec imports
shows **file sync and plugin (redundant, both enforce)**: nothing is lost, but
one of them is unnecessary. A site where the global app exists but the site has
no handler is not counted as protected.

### Outages and limits

- If LAPI is unreachable, Caddy keeps enforcing the decisions it already has.
  `enable_hard_fails` stays off, so requests are not refused because of the
  outage.
- If Caddy restarts while LAPI is down, it starts with no CrowdSec decisions
  and enforces them again once LAPI answers. Manual bans are unaffected.
- Plugin mode has no `BANS_MAX` budget: decisions live in Caddy's memory, not in
  Caddyfile matchers. Community (CAPI) and list origins are therefore reasonable
  here. The plugin pulls every origin; `CROWDSEC_ORIGINS` limits only the
  console's file sync and its display.

## Cloudflare client IPs and country policy

Two Security sections, **Client IP** and **Country policy**, decide who a visitor
is and which countries may reach a site. Everything below uses documentation
addresses and `example.com`.

### Client IP profiles

Pick the profile that matches how traffic reaches Caddy. Bans, the country
policy, Explore and logs all use the address it produces.

| Profile | Use when | Trusted for `CF-Connecting-IP` / `CF-IPCountry` |
|---|---|---|
| **Direct** (default) | Visitors connect to Caddy themselves, or an upstream you do not control sits in front. | Nobody. `client_ip` is the TCP peer; every forwarding and Cloudflare header is ignored. |
| **Cloudflare proxied DNS** | Orange cloud, Caddy reachable from the internet. | Only Cloudflare's published edge ranges. |
| **Cloudflare Tunnel** | `cloudflared` runs next to Caddy and no Caddy port is published. | Only the fixed `cloudflared` address you enter (`172.18.0.5`, or a dedicated subnet no wider than /24 for IPv4 or /64 for IPv6). |

The console renders the trusted peers into `cloudflare-trusted-proxies.caddy`.
Import it from the global `servers` block with the snippets **Cloudflare
proxied DNS: real client IP** or **Cloudflare Tunnel: real client IP**:

```caddyfile
{
	servers {
		import /etc/caddy/console/cloudflare-trusted-proxies*.caddy
		client_ip_headers CF-Connecting-IP
	}
}
```

Trusting a header is only as safe as the network path:

- **Proxied DNS needs an origin lock.** A client that connects to the origin
  directly cannot forge its address (its headers are ignored), but it skips
  Cloudflare's WAF and rate limits. Add the **Cloudflare origin guard** snippet or
  a firewall rule that accepts connections only from Cloudflare's ranges and your
  LAN. The guard checks the connecting address, never a header.
- **Tunnel mode needs one fixed peer.** Give `cloudflared` a fixed address on a
  dedicated Docker network and enter it. The console refuses `private_ranges`
  unless you confirm that the listener is reachable only from the tunnel network:
  trusting a broad range lets any container or LAN host forge the client IP.
- Proxied mode adds the edge ranges to the protected set, so a ban or country
  rule can never lock Cloudflare itself out.

**Range auto-update.** In proxied mode the console fetches
`https://www.cloudflare.com/ips-v4` and `/ips-v6` daily
(`CLOUDFLARE_RANGES_AUTO_UPDATE`, **Refresh ranges** does it on demand) and
validates every line: canonical public networks, bounded size, and at least half
of the previous address space kept. A valid change regenerates the trusted
proxies, the protected set and the country file in one journaled transaction and
reloads Caddy once. A failed or implausible fetch keeps the last good list and
Security shows its age. Direct and tunnel mode never contact Cloudflare.

### Country policy

An allowlist: clients outside the selected countries get `403`. Protected
addresses (loopback, private and your LAN, plus the edge ranges in proxied mode)
and the management session are always allowed. Enable it with
`COUNTRY_POLICY_ENABLED=true`, choose countries in Security and import it per
site with **Country policy: protect this site**:

```caddyfile
example.com {
	import /etc/caddy/console/geo*.caddy
	reverse_proxy app:8080
}
```

It has two shapes, chosen by the client-IP profile:

| Shape | Profile | How a client is matched |
|---|---|---|
| **Direct** | Direct | The resolved address is checked against the country's CIDR ranges from the DB-IP Country Lite dataset (CC-BY 4.0, refreshed monthly with the other GeoIP files, `GEOIP_AUTO_UPDATE`). Stock Caddy has no country matcher, so the ranges are written into `geo.caddy`. |
| **Cloudflare** | Proxied or Tunnel | The `CF-IPCountry` header, honored only when the connection comes from a trusted Cloudflare peer. A missing header, or the header from any other peer, is denied for public clients. |

- **Confirm Cloudflare IP Geolocation.** Cloudflare sends `CF-IPCountry` only
  with IP Geolocation on for the zone (Network settings). Security asks you to
  confirm it; without it every public visitor would be denied.
- **XX and T1** are Cloudflare's "unknown" and "Tor" values. They are allowed
  only when you name them in the selection.
- **Switching profiles regenerates the file** for the new shape in the same
  transaction as the profile change.
- **Prefix cap.** A direct policy that needs more than `COUNTRY_MAX_PREFIXES`
  (default and maximum `20000`) prefixes is refused with
  `country_prefix_cap_exceeded` before anything is written: `geo.caddy`,
  `country-policy.json` and the running Caddy stay as they were. Above 10,000
  prefixes Security shows a warning. Large selections scale better as
  **Cloudflare WAF custom rules**.

**Recommendation.** Where Cloudflare fronts the site, enforce country rules in a
Cloudflare WAF custom rule (`ip.src.country in {"CN" "RU"}` with action Block)
so unwanted traffic never reaches your origin or your Caddy reloads. Use the
console's policy as defense in depth, or where there is no Cloudflare.

**Measured cost (direct shape).** Apple M1 Pro, Docker 29.2.0, stock Caddy
2.11.9, 8 sites importing `geo.caddy`, 80 % IPv4 and 20 % IPv6 generated
prefixes, medians of three runs against a clean Caddy, the p95 of the worst allowed
client (last prefix in the file) and of a denied client. Budgets as for bans:
adapt at most 2 s, reload at most 3 s, at most +150 MiB RSS and +2 ms p95.

| Prefixes | File | Adapt | Reload | Caddy RSS | p95 allowed | p95 denied | Within budget |
|---:|---:|---:|---:|---:|---:|---:|:---|
| 0 | 0 KiB | 0.01 s | 0.01 s | 48 MiB | 1.01 ms | 0.89 ms | yes |
| 1,000 | 16 KiB | 0.04 s | 0.06 s | 55 MiB | 0.98 ms | 0.82 ms | yes |
| 10,000 | 163 KiB | 0.32 s | 0.51 s | 82 MiB | 1.13 ms | 0.97 ms | yes |
| 20,000 | 333 KiB | 0.63 s | 0.98 s | 128 MiB | 1.11 ms | 0.99 ms | yes |

All sizes are within budget, so the cap is 20,000, the largest size measured;
the warning starts at 10,000. Reproduce with
`tests/integration/country_benchmark.py`, and check the behavior with
`./dev/country-it.sh`.

## Host recovery

If a ban locks you out of a site, recover from the host without the console.
Stop the console first so it cannot regenerate the file:

```bash
docker compose -f docker-compose.prod.yaml stop caddy-console
sudo sh -c ': > /opt/caddy/console/bans-manual.caddy'
docker compose -f docker-compose.prod.yaml exec caddy sh -c \
  'caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile \
   --address "${CADDY_ADMIN_ADDRESS:-0.0.0.0:2019}"'
docker compose -f docker-compose.prod.yaml start caddy-console
```

With the CrowdSec overlay, add `-f docker-compose.crowdsec.yaml` to every
command and truncate `bans-crowdsec.caddy` instead of (or as well as)
`bans-manual.caddy` when a CrowdSec decision caused the lockout. Stopping
`caddy-console` also stops CrowdSec file regeneration.

With the plugin overlay, add `-f docker-compose.crowdsec.yaml -f docker-compose.crowdsec-plugin.yaml`
(NAS: `-f docker-compose.crowdsec.nas.yaml -f docker-compose.crowdsec-plugin.nas.yaml`)
to every command. The overlay sets `CADDY_ADMIN_ADDRESS=172.30.250.2:2019` in the
Caddy container, so the `--address "${CADDY_ADMIN_ADDRESS:-0.0.0.0:2019}"` above
already uses the fixed admin bind and needs no `-e`:

```bash
docker compose -f docker-compose.prod.yaml -f docker-compose.crowdsec.yaml \
  -f docker-compose.crowdsec-plugin.yaml stop caddy-console
sudo sh -c ': > /opt/caddy/console/bans-manual.caddy'
docker compose -f docker-compose.prod.yaml -f docker-compose.crowdsec.yaml \
  -f docker-compose.crowdsec-plugin.yaml exec caddy sh -c \
  'caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile \
   --address "${CADDY_ADMIN_ADDRESS:-0.0.0.0:2019}"'
docker compose -f docker-compose.prod.yaml -f docker-compose.crowdsec.yaml \
  -f docker-compose.crowdsec-plugin.yaml start caddy-console
```

A CrowdSec decision enforced by the plugin is not in any file: delete it in
CrowdSec (see [Removing a decision](#removing-a-decision)); the plugin drops it
within one polling interval, without a reload.

| Stack | Compose file | Host directory | Admin address for `--address` |
|---|---|---|---|
| Production | `docker-compose.prod.yaml` | `/opt/caddy` | `0.0.0.0:2019` |
| Internal | `docker-compose.internal.yaml` | `/opt/caddy` | `0.0.0.0:2019` |
| Tunnel | `docker-compose.tunnel.yaml` | `/opt/caddy` | `172.30.250.2:2019` (the fixed `admin` bind, listed in its `origins`); add `-e CADDY_ADMIN_ADDRESS=172.30.250.2:2019` to the `exec` |
| NAS | `docker-compose.nas.yaml` | `/volume2/docker/caddy/caddy` | `0.0.0.0:2019` |
| Any stack with the plugin overlay | the base file plus both overlays (above) | as for the base stack | `172.30.250.2:2019`; the overlay sets `CADDY_ADMIN_ADDRESS` in the Caddy container, so `--address "${CADDY_ADMIN_ADDRESS:-0.0.0.0:2019}"` already uses it |

A wildcard `admin 0.0.0.0:2019` only accepts its own listen address as the
CLI's origin, so `localhost:2019` and `127.0.0.1:2019` are rejected with 403.
A fixed bind such as the tunnel stack's needs an `origins` list that includes
that address (`admin 172.30.250.2:2019 { origins caddy:2019 172.30.250.2:2019 }`),
and the command must be given it explicitly. `CADDY_ADMIN_ADDRESS` is not a
Compose setting; it is only read by the `sh -c` above. The wildcard-bound stacks
need no `-e`, because the default is already `0.0.0.0:2019`. For the tunnel stack:

```bash
docker compose -f docker-compose.tunnel.yaml exec -e CADDY_ADMIN_ADDRESS=172.30.250.2:2019 caddy sh -c \
  'caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile \
   --address "${CADDY_ADMIN_ADDRESS:-0.0.0.0:2019}"'
```

When the console starts again, Security shows **Policy differs from state**.
Remove or correct the record that caused the lockout, then use **Re-apply**.
Recovery never needs port 2019 published.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `BANS_ENABLED` | `true` | Security API, background job and view. Sites are unchanged until they import the file. |
| `BANS_DIR` | `/etc/caddy/console` | Directory for generated Caddy files, inside the Caddyfile directory. |
| `BANS_MAX` | `10000` | Maximum prefixes rendered into Caddy (measured above). |
| `BANS_NEVER` | empty | Extra protected IPs/CIDRs, comma or space separated. An invalid entry stops startup. |
| `CLIENT_IP_MODE` | `direct` | Default client-IP profile (`direct`, `cloudflare-proxied`, `cloudflare-tunnel`) until one is saved in Security. |
| `CLOUDFLARE_RANGES_AUTO_UPDATE` | `true` | Daily refresh of Cloudflare's edge ranges in proxied mode. |
| `COUNTRY_POLICY_ENABLED` | `false` | Allows the country policy to be enforced. |
| `COUNTRY_MAX_PREFIXES` | `20000` | Direct country policy prefix cap (1-20000, measured above). |
| `BANS_SYNC_INTERVAL` | `30` | Minimum seconds between CrowdSec-driven reloads (10-3600). |
| `CROWDSEC_URL` | empty | LAPI URL; empty disables CrowdSec. The overlay sets `http://crowdsec:8080`. |
| `CROWDSEC_CONSOLE_BOUNCER_KEY` | empty | Read-only bouncer key used only by the console. `CROWDSEC_CONSOLE_BOUNCER_KEY_FILE` reads it from a mounted file instead. |
| `CROWDSEC_ORIGINS` | `crowdsec,cscli` | LAPI origins synced and shown. |
| `CROWDSEC_POLL_INTERVAL` | `10` | Seconds between decision-stream polls (5-300). |
| `CROWDSEC_PLUGIN_BOUNCER_KEY` | empty | Caddy container only: the plugin's own bouncer key. Never given to the console. |
| `CROWDSEC_PLUGIN_BOUNCER_KEY_FILE` | empty | Absolute path of a mounted secret with the plugin key, used instead of the environment key; the console gets the path only, to offer `{file.<path>}`. |
| `CADDY_ADMIN_ADDRESS` | `0.0.0.0:2019` | Admin address for health checks, recovery and the console's save guard; the plugin overlays set `172.30.250.2:2019`. |
