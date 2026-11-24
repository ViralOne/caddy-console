# Security: IP bans

Caddy Console can block clients by IP address or CIDR range on the sites you
choose. This page covers manual file mode, which works with the stock
`caddy:2.11.9-alpine` image and needs no extra service. CrowdSec file sync is
an optional overlay, described in
[CrowdSec file sync (optional)](#crowdsec-file-sync-optional). Cloudflare trust
profiles and country policy are later additions and are not part of this
release.

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

| Stack | Compose file | Host directory | Admin address for `--address` |
|---|---|---|---|
| Production | `docker-compose.prod.yaml` | `/opt/caddy` | `0.0.0.0:2019` |
| Internal | `docker-compose.internal.yaml` | `/opt/caddy` | `0.0.0.0:2019` |
| Tunnel | `docker-compose.tunnel.yaml` | `/opt/caddy` | `172.30.250.2:2019` (the fixed `admin` bind, listed in its `origins`); add `-e CADDY_ADMIN_ADDRESS=172.30.250.2:2019` to the `exec` |
| NAS | `docker-compose.nas.yaml` | `/volume2/docker/caddy/caddy` | `0.0.0.0:2019` |

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
| `BANS_SYNC_INTERVAL` | `30` | Minimum seconds between CrowdSec-driven reloads (10-3600). |
| `CROWDSEC_URL` | empty | LAPI URL; empty disables CrowdSec. The overlay sets `http://crowdsec:8080`. |
| `CROWDSEC_CONSOLE_BOUNCER_KEY` | empty | Read-only bouncer key used only by the console. `CROWDSEC_CONSOLE_BOUNCER_KEY_FILE` reads it from a mounted file instead. |
| `CROWDSEC_ORIGINS` | `crowdsec,cscli` | LAPI origins synced and shown. |
| `CROWDSEC_POLL_INTERVAL` | `10` | Seconds between decision-stream polls (5-300). |
