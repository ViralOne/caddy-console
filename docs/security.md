# Security: IP bans

Caddy Console can block clients by IP address or CIDR range on the sites you
choose. This page covers manual file mode, which works with the stock
`caddy:2.11.9-alpine` image and needs no extra service. CrowdSec, Cloudflare
trust profiles and country policy are later additions and are not part of
this release.

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
