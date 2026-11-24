# IP bans, optional CrowdSec and Cloudflare trust profiles

Status: revised design · Date: 2026-11-23

## Goal

Let an authenticated Caddy Console operator block unwanted clients manually and,
when explicitly enabled, consume automatic CrowdSec decisions.

The feature is delivered in independent phases:

1. **Manual file mode.** Works with stock `caddy:2.11.9-alpine`. No CrowdSec,
   plugin, Cloudflare or extra service is required.
2. **CrowdSec file-sync add-on.** An optional CrowdSec container detects abusive
   traffic. The console renders active decisions through the same transactional
   file mechanism as manual bans, but into a source-specific file so mixed
   plugin and file-only sites remain correct.
3. **CrowdSec plugin add-on.** An optional custom Caddy image enforces CrowdSec
   decisions without a Caddy reload. Manual bans continue to use file mode.
4. **Cloudflare trust profiles and country policy.** Optional profiles configure
   real client IP handling for Cloudflare proxied DNS or Cloudflare Tunnel.

An operator who does not enable an add-on keeps the stock Caddy image and current
Compose topology. Caddy behavior does not change until a site imports a managed
file or the operator adds the CrowdSec handler to that site.

### Success criteria

- An authenticated operator can manually ban and unban an IP or CIDR.
- Stock Caddy applies a manual change within seconds through a transactional
  config reload.
- Existing `handle`, `handle_path` and `route` site layouts cannot silently run
  before the ban handler.
- Protected addresses remain reachable even if a broad or overlapping ban enters
  the stored state.
- CrowdSec file sync is opt-in and normally applies a decision within 60 seconds.
- Plugin mode is opt-in and applies CrowdSec updates without reloading Caddy. Its
  latency is bounded by the plugin polling interval rather than described as
  instantaneous.
- Direct Caddy, Cloudflare proxied DNS and Cloudflare Tunnel use distinct trusted
  proxy rules. A caller-supplied forwarding or country header is never trusted
  without a trusted transport peer.
- The console management route is not protected by its own ban or country files.
  Host-level recovery remains available.
- `BANS_ENABLED=false` disables the APIs, background jobs and Security view.

## Non-goals

- CrowdSec AppSec/WAF and CAPTCHA remediation.
- A Cloudflare-edge CrowdSec bouncer.
- Automatic CrowdSec community enrollment or blocklist subscription.
- Writing manual console bans back to CrowdSec LAPI. Manual bans remain local in
  this design. Two-way machine credentials can be designed separately after the
  read-only integration is stable.
- Per-site ban storage. A site chooses whether to import the shared effective
  list.
- Terminating existing WebSocket or other long-lived connections. A reload
  applies the new policy to new HTTP requests and new connections.

## Design principles

- **Stock Caddy first.** The complete manual path uses only standard Caddy 2.11.9
  matchers and handlers.
- **Add-ons remain optional.** Baseline Compose files do not require CrowdSec
  secrets, volumes, networks or custom Caddy images.
- **Fail closed for state loss.** A corrupt state file never clears the last
  successfully loaded ban file.
- **Trust peers, not headers.** `CF-Connecting-IP`, `CF-IPCountry` and forwarded
  headers are used only when the immediate peer is trusted by the selected
  profile.
- **Protect at input and enforcement.** Unsafe bans are rejected by the API, and
  protected ranges are also excluded by the generated Caddy matcher.
- **One writer transaction.** State, generated files and Caddy reloads are
  serialized by the existing cross-process Caddyfile lock.
- **No hidden config edits.** UI insertion changes the editor buffer only. The
  operator reviews the diff and uses the existing Check and Save & Reload flow.

# Phase 1: manual file mode

## 1.1 Architecture

The console owns these paths:

```text
BACKUP_DIR/bans.json                      ban records and source policy hashes, mode 0600
BACKUP_DIR/country-policy.json             country state and geo.caddy hash, mode 0600
BACKUP_DIR/cloudflare-ranges.json           edge data and trusted-proxy file hash, mode 0600
BACKUP_DIR/plugin-policy.json              plugin protection policy hash, mode 0600
BANS_DIR/bans-manual.caddy                 manual policy, mode 0644
BANS_DIR/bans-crowdsec.caddy               Phase 2 policy, mode 0644
BANS_DIR/crowdsec-plugin-protect.caddy     Phase 3 reusable protected route, mode 0644
BANS_DIR/geo.caddy                         Phase 4 country policy, mode 0644
BANS_DIR/cloudflare-trusted-proxies.caddy  Phase 4 server option body, mode 0644
BACKUP_DIR/bans-transaction.json           crash-recovery journal, mode 0600
BACKUP_DIR/bans-state-error.json           optional diagnostic metadata, mode 0600
```

`BANS_DIR` defaults to `/etc/caddy/console`. It MUST resolve inside the directory
that contains `CADDYFILE_PATH`, MUST be visible at the same absolute path in both
containers, and MUST NOT traverse a symlink. When `BANS_ENABLED=true`, startup
checks console write access and verifies Caddy visibility by adapting a temporary
managed glob import through the running admin API. Failure does not take the
existing console offline: Security enters **unavailable, not enforced**, mutation
APIs return 503, and the UI shows the missing mount or permission. Baseline editor,
Dashboard and Explore functions continue to work. `BANS_ENABLED=false` skips the
check entirely.

The Caddy container keeps the shared Caddyfile directory mounted read-only. The
console mounts it read-write and performs atomic replacement. The containing
host directory, not an individual file, is mounted so `os.replace()` remains
atomic and visible to Caddy.

## 1.2 Stored record

`bans.json` is versioned and contains independent source records:

```json
{
  "version": 1,
  "records": [
    {
      "id": "console-generated-uuid",
      "source": "manual",
      "source_id": null,
      "scope": "ip",
      "value": "203.0.113.7",
      "reason": "Repeated login attempts",
      "scenario": null,
      "origin": null,
      "actor": "operator@example.com",
      "created_at": "2026-11-23T20:00:00Z",
      "expires_at": "2026-11-24T20:00:00Z"
    }
  ],
  "last_rendered_hashes": {
    "bans-manual.caddy": "sha256:...",
    "bans-crowdsec.caddy": "sha256:..."
  },
  "management_addresses": [
    {
      "value": "198.51.100.20",
      "trust_profile": "direct",
      "last_seen": "2026-11-23T20:00:00Z"
    }
  ]
}
```

Rules:

- IPs and CIDRs are parsed with `ipaddress`, converted to canonical form and
  serialized from the parsed object. Raw request text is never written into a
  Caddyfile.
- IPv4-mapped IPv6 addresses are normalized to IPv4 before comparison.
- `scope` is derived by the server. The client cannot choose an inconsistent
  scope.
- Manual durations are 4 hours, 24 hours, 7 days or permanent.
- `reason` is optional plain text, at most 500 Unicode characters. Control
  characters other than newline and tab are rejected. It is never written into
  the generated Caddyfile.
- Timestamps are UTC RFC 3339 values.
- Multiple records may cover the same address. The effective ban remains until
  every active covering record has expired or been removed.
- Expired records are removed during mutations and by a periodic cleanup job.

## 1.3 Protected addresses

A candidate IP or network is rejected if it overlaps any protected network.
Checking only whether one network contains the start address of another is not
sufficient. Both overlap directions are tested.

The core protected set contains:

- IPv4 and IPv6 loopback;
- RFC 1918 private ranges;
- IPv4 link-local `169.254.0.0/16`;
- IPv6 link-local `fe80::/10`;
- CGNAT `100.64.0.0/10`;
- IPv6 ULA `fc00::/7`;
- unspecified, multicast and reserved addresses;
- Docker network ranges used by the console deployment;
- every valid IP/CIDR in `BANS_NEVER`;
- the verified requesting client IP, when the active trust profile can derive
  it safely.

Cloudflare edge ranges are added by the Cloudflare proxied-DNS profile in Phase 4.
A range wider than `/16` for IPv4 or `/48` for IPv6 is rejected even when it does
not overlap the protected set.

The request-time own-IP rule applies only when the immediate transport peer is
verified. Each successful authenticated console request may update a bounded
`management_addresses` registry in `bans.json`, containing canonical address,
trust profile and `last_seen`. It holds at most 16 addresses, expires entries after
30 days and never accepts a raw forwarding header from an untrusted peer. Manual
mutations protect the current verified address immediately. Background expiry and
CrowdSec sync use the static protected set plus this registry because no operator
request exists in those jobs. Operators with a stable WAN address should still put
it in `BANS_NEVER`.

`BANS_NEVER` is parsed at startup. An invalid token is a configuration error, not
an entry to ignore. Protected values are shown in the UI by category but are not
returned as ban actions.

The generated matcher repeats the exclusion. This protects against stale state,
a previously accepted broad range, and manual file recovery mistakes:

```caddyfile
# Managed by Caddy Console. Do not edit; changes are overwritten.
vars caddy_console_manual_policy 1
@caddy_console_manual_banned {
	client_ip 203.0.113.7 198.51.100.0/24
	not client_ip private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10
}
handle @caddy_console_manual_banned {
	respond 403
}
```

The generated `not client_ip` line also contains canonical `BANS_NEVER`, the
verified current operator address when available, Docker ranges and profile
specific protected ranges.

When no effective manual bans exist, `bans-manual.caddy` contains its managed
comment plus `vars caddy_console_manual_policy 1`. No empty `client_ip` matcher
or `handle` is emitted. The marker is harmless request context and lets live JSON
distinguish an imported empty manual policy from a missing import because Caddyfile
matcher names and comments do not survive adaptation.

## 1.4 Import and handler ordering

A site opts in with an absolute glob import:

```caddyfile
example.com {
	import /etc/caddy/console/bans-manual*.caddy

	handle {
		reverse_proxy app:8080
	}
}
```

Requirements:

- The import is the first direct child of the site block.
- The managed file uses a matcher-specific `handle`, not a top-level `respond`.
  This prevents catch-all `handle`, `handle_path` and `route` application handlers
  from serving a banned request before the ban check.
- Some standard directives, including `redir`, `rewrite`, `basic_auth`,
  `forward_auth`, `request_header` and `invoke`, are ordered before `handle`.
  Most do not expose the protected application, but they may redirect, contact an
  auth service or otherwise perform work before the ban response. The Security
  view reports **application protected, pre-handler present** rather than claiming
  first-handler enforcement.
- A site that requires rejection before every other handler uses strict layout:
  it wraps its HTTP handling in one top-level `route` and places the managed
  import first inside that route. Because `route` preserves literal order, the
  ban check then runs before the following directives.
- The glob allows Caddy to start when the console has not created the managed
  file yet. A missing exact file import would make adaptation fail.
- The console hostname is never offered this import. Production and tunnel
  stacks route the console directly through cloudflared. An internal Caddy site
  serving the console is explicitly marked management-only and excluded.
- A site using `invoke`, an earlier `forward_auth`, a custom global `order`, or an
  unrecognized custom handler is marked **enforcement not fully verified** unless
  live adaptation proves the required ordering.
- Matcher names use the `caddy_console_` prefix. The validator warns about a
  conflicting user-defined matcher or duplicate import.

## 1.5 Apply transaction

The same transaction helper is used by manual bans, CrowdSec file sync, country
policy and Cloudflare trusted-proxy updates. An operation supplies:

- zero or more state files;
- one or more changed managed policy files;
- the current on-disk Caddyfile;
- the source and authenticated actor, or `system` for a background update.

A manual mutation uses this sequence:

1. Authenticate the request with the existing `login_required` mechanism.
2. Require the existing `/api/*` CSRF token for every mutation.
3. Validate and canonicalize the requested value and duration.
4. Acquire `caddyfile_lock()` before reading or changing shared state or policy.
5. Read the current state, remove expired records, normalize and hash current live
   `/config/`, and build all candidate bytes in memory. Before any write, each
   candidate state document already embeds the candidate hash of every policy it
   owns in `last_rendered_hashes`; no separate post-commit hash write exists. For
   a manual operation the changed set is `bans.json` plus
   `bans-manual.caddy`; other phases select their own files.
6. Create and flush one temporary file per target in the target's own directory.
   A temporary managed-policy name MUST be hidden and MUST NOT end in `.caddy`,
   for example `.bans-manual.caddy.<random>.tmp`, so no `*.caddy` import can see
   a partial or abandoned file.
7. Before replacement, copy each previous target into a transaction-specific
   directory under `BACKUP_DIR/.policy-transactions/<transaction-id>/`. Backup
   leaves use a `.bak` suffix, never `.caddy`, and no backup is written under
   `BANS_DIR`. Flush every backup and the backup directory.
8. Persist and flush `bans-transaction.json`. Its bounded `entries` array contains
   `{path, kind, previous_hash, candidate_hash, backup_path}` for every changed
   state or policy file. It also records `replaced_paths`, the previous live JSON
   hash, the adapted candidate JSON hash when available, `reload_required`, actor,
   source and phase `prepared`.
9. Replace each policy file, append its path to `replaced_paths` and flush the
   journal after each step. Replace the already hash-complete state files last,
   appending and flushing each replaced path.
   Each individual replace is atomic on its filesystem; the journal makes the
   whole file set crash-recoverable. Use mode 0644 for Caddy policies and 0600
   for state, journal and backups.
10. Determine reload need from the on-disk import plus the current adapted/live
    source marker for every changed policy. If no changed file is imported, mark
    the journal committed without a Caddy reload and return
    `enforcement: not_enabled` for that source. A policy file that is being
    created also needs a reload whenever the Caddyfile imports any file: an
    import inside an included file is invisible to the console, and the live
    config has no marker while the file did not exist. Re-apply reloads even
    when no file changes.
11. Ask the running Caddy build to adapt the current on-disk Caddyfile while the
    candidates are present. Adaptation checks Caddyfile syntax, imports and module
    names, not runtime provisioning. Store the normalized candidate JSON hash in
    the journal. If adaptation rejects, restore every journal entry and clear the
    journal without calling `/load`.
12. POST the unchanged on-disk Caddyfile text to `/load` with
    `Content-Type: text/caddyfile` while still holding the lock. `/load` is the
    provisioning and transactional runtime validation step.
13. On HTTP success, verify live `/config/` matches the normalized adapted
    candidate, mark the journal committed, verify the already embedded
    `last_rendered_hashes`, invalidate caches, remove backups and audit the change.
    No state file is rewritten after journal commit.
14. On a confirmed non-2xx rejection, restore every previous journal entry. Caddy
    keeps its previous running configuration.
15. On connect timeout before the request or an ambiguous read timeout/reset, do
    not claim rollback. Keep the complete candidate files and journal, report
    `reload_status: failed|unknown`, and stop automatic applies.
16. Release the lock.

At startup, the console acquires `caddyfile_lock()` and resolves an incomplete
journal before accepting mutations:

1. Verify every current, candidate and backup hash named by the journal.
2. Normalize and hash live `/config/` before changing another final path.
3. If a candidate adapted hash was recorded and live equals it, finish every
   candidate replacement, verify the candidate state's embedded policy hashes and
   commit the journal.
4. If live equals the recorded previous live hash, restore every previous file
   and clear the journal. This also handles a crash before candidate adaptation,
   when no candidate adapted hash exists.
5. If live matches neither, the required hash is unavailable, or Caddy cannot be
   queried, enter read-only degraded mode. Do not POST `/load`, restore or guess
   until the operator selects the candidate or previous recovery action.

The expiry cleanup job runs at least once per minute. When it changes any rendered
prefix, it executes this same multi-entry transaction and reload path. An expired
ban therefore does not remain enforced until an unrelated operator action.

No code holds a state lock while making a CrowdSec request. The separate
`bans-sync.lock` introduced in Phase 2 elects a worker but never reverses the lock
order. Every generated-file mutation still enters `caddyfile_lock()`.

## 1.6 Corrupt state and recovery

`bans.json` is a security-control state file and is not treated like disposable
health metadata.

On invalid JSON, invalid schema or an unreadable file:

- do not rewrite it as an empty list;
- do not modify or reload the last successful source-specific policy files;
- copy the bad bytes, subject to a small size limit, to a timestamped quarantine
  file in `BACKUP_DIR`;
- enter read-only degraded mode;
- show the exact recovery choices in the Security view;
- require an explicit operator action to restore a valid backup or reset the
  list.

Host recovery does not depend on the console. The documented procedure first
stops `caddy-console`, which also stops expiry and CrowdSec file regeneration,
then truncates only the policy that caused the lockout:

```bash
docker compose -f docker-compose.prod.yaml stop caddy-console
sudo sh -c ': > /opt/caddy/console/bans-manual.caddy'
sudo sh -c ': > /opt/caddy/console/bans-crowdsec.caddy'
sudo sh -c "printf '%s\n' '(protect_crowdsec) {' '    vars caddy_console_plugin_recovery 1' '}' > /opt/caddy/console/crowdsec-plugin-protect.caddy"
sudo sh -c ': > /opt/caddy/console/geo.caddy'
# Only for a bad Cloudflare trust profile:
sudo sh -c ': > /opt/caddy/console/cloudflare-trusted-proxies.caddy'

docker compose -f docker-compose.prod.yaml exec caddy sh -c \
  'caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile \
   --address "${CADDY_ADMIN_ADDRESS:-0.0.0.0:2019}"'

docker compose -f docker-compose.prod.yaml start caddy-console
```

The operator truncates only the required files, not all of them by default. Every
state document records the last successfully rendered hash for its policy file.
On the next startup, a policy hash that differs from that recorded value and has
no active transaction journal is treated as an out-of-band recovery override:

- the console does not regenerate that file;
- CrowdSec snapshot sync and expiry apply are paused only for the affected file;
- Security shows **policy differs from state**;
- the operator removes or corrects the offending record, then uses the
  authenticated, CSRF-protected `POST /api/security/reapply` action;
- Re-apply creates a normal journaled transaction and clears the recovery hold
  only after confirmed `/load` success.

The plugin overlay documents its fixed `CADDY_ADMIN_ADDRESS`, which must appear in
that bind's `origins` list; the standard wildcard-bound stacks use `0.0.0.0:2019`
inside the Caddy container (a wildcard bind rejects `localhost:2019` as the CLI's origin). Documentation substitutes the
actual Compose file and host path for NAS, internal and tunnel deployments and
verifies the recovery commands in integration tests. Recovery never publishes
port 2019.

## 1.7 API

All routes require `login_required`. Mutations stay under `/api/` so the existing
CSRF middleware applies.

```text
GET    /api/security
GET    /api/security/recovery
POST   /api/security/recovery
POST   /api/security/reapply
POST   /api/security/reset
GET    /api/security/client-ip-profile
PUT    /api/security/client-ip-profile
GET    /api/security/country-policy
PUT    /api/security/country-policy
POST   /api/security/cloudflare-ranges/refresh
GET    /api/bans
POST   /api/bans
DELETE /api/bans/<record-id>
```

`GET /api/security/recovery` returns a server-generated recovery ID, affected
files, safe summary and the actions valid for the current journal or recovery
hold. `POST /api/security/recovery` accepts only that ID and one enumerated action:
`use_candidate`, `use_previous`, or `restore_backup`. Backup choices are opaque
server-generated IDs mapped to journal entries; callers never submit filesystem
paths.

`POST /api/security/reset` requires `{source}` with one of `manual`, `crowdsec`,
`country`, or `cloudflare`, a current state version and an explicit confirmation
flag. It creates a normal journaled transaction, audits the destructive reset and
explains that CrowdSec state returns on the next snapshot unless the upstream
decision is removed.

`PUT /api/security/client-ip-profile` validates the selected mode and all required
peer ranges before generating files. `PUT /api/security/country-policy` validates
the profile and country codes before enabling policy. Cloudflare refresh triggers
the dependency-expanded transaction from Phase 4 and is rate-limited.

`POST /api/bans` accepts `{value, duration, reason}`. The server derives the
actor from the authenticated session and derives the caller IP from the active
trusted transport profile.

`DELETE` addresses a server-generated record ID rather than a caller-supplied IP.
The server verifies that the ID resolves to a manual record before deleting it.
CrowdSec-origin records cannot be deleted through this endpoint.

API responses return structured error codes for invalid IP, invalid range,
protected overlap, range too wide, capacity exceeded, state degraded, adaptation
failure, reload rejection and reload state unknown.

## 1.8 Security view and snippets

The fourth top-level view is **Security** and is present only when
`BANS_ENABLED=true`.

Manual mode shows:

- effective state: enforced, stored but not imported, degraded or reload unknown;
- protected-range summary;
- per-site import status;
- manual ban list with value, GeoIP display data, reason, actor, created time,
  expiry and Unban;
- ignored or expired records;
- a recovery link when enforcement cannot be confirmed.

The first UI snippets are:

1. **Manual bans: protect this site**
   ```caddyfile
   import /etc/caddy/console/bans-manual*.caddy
   ```
2. **Manual bans: host recovery** as copy-only documentation, never inserted.

Snippet metadata includes:

```json
{
  "id": "manual-bans-site",
  "phase": "manual",
  "scope": "site",
  "supported_modes": ["direct", "cloudflare-proxied", "cloudflare-tunnel"],
  "prerequisites": ["BANS_ENABLED"],
  "code": "import /etc/caddy/console/bans-manual*.caddy\n"
}
```

Site insertion is context-aware:

- the cursor must be inside a top-level site block;
- insertion happens immediately after the opening line and before existing
  handlers;
- an equivalent import is not inserted twice;
- a site defined in an external imported file gets Copy only;
- the editor buffer changes, but the UI never saves or reloads automatically;
- all text originating from ban records is rendered with `textContent`, not an
  HTML sink.

# Phase 2: optional CrowdSec file-sync add-on

## 2.1 Activation and topology

CrowdSec file sync is shipped as a Compose overlay, not as a required service in
the baseline files:

```text
docker-compose.crowdsec.yaml
```

Example activation:

```bash
docker compose -f docker-compose.prod.yaml \
  -f docker-compose.crowdsec.yaml up -d
```

The equivalent command is documented for NAS, internal and tunnel stacks.
Running only the baseline Compose file does not create or require CrowdSec.

Topology:

```text
Caddy access log -> read-only caddy-logs volume -> CrowdSec engine/LAPI
                                                   ^
                                                   |
                       caddy-console -> crowdsec-lapi internal network

Caddy enforcement <- bans-crowdsec.caddy <- caddy-console stream synchronizer
```

In file-sync mode, Caddy does not join `crowdsec-lapi`. This preserves the
existing Caddy Admin API isolation.

The CrowdSec service:

- uses a reviewed version tag and immutable image digest;
- publishes no host ports;
- persists `/etc/crowdsec` and `/var/lib/crowdsec/data` in named volumes;
- mounts `caddy-logs` read-only;
- mounts repository-owned acquisition and local parser files read-only;
- joins `crowdsec-lapi`, which is `internal: true`;
- may join a separate ordinary egress network for Hub updates;
- does not join `caddy-admin` or `console-ui`;
- has a health check using `cscli lapi status`;
- is not a required `depends_on` target for baseline services.

Community enrollment is disabled by default with `DISABLE_ONLINE_API=true`.
Operators who deliberately enable CAPI or large blocklists are warned that stock
Caddy file mode has a finite matcher budget and plugin mode is preferred.

## 2.2 CrowdSec collection, parser and acquisition

The Docker environment uses the correct Hub item types:

```yaml
environment:
  COLLECTIONS: crowdsecurity/caddy
  PARSERS: crowdsecurity/whitelists
  DISABLE_ONLINE_API: "true"
```

`crowdsecurity/whitelists` is the legacy package identifier of a parser, not a
collection.

The overlay mounts `/etc/crowdsec/acquis.d/caddy.yaml`:

```yaml
filenames:
  - /var/log/caddy/access.log
labels:
  type: caddy
```

The exact live filename is used so rotated archives are not replayed as new
traffic.

The existing privacy filter removes request and response header maps. The
official Caddy parser can still derive source IP, method, path and status, so
path probes and 404 bursts work. User-Agent and Basic Auth scenarios need
additional safe fields.

The add-on therefore ships a small local parser and a Caddy logging helper that:

- keeps `request>headers` and `resp_headers` deleted from the console log;
- appends only a normalized User-Agent field and an explicit authentication
  failure signal at top level;
- never logs Cookie, Authorization, Proxy-Authorization, API-key headers,
  request bodies or response bodies;
- maps those explicit fields into CrowdSec metadata expected by the selected
  scenarios.

Accepted amendment (Phase 2): the User-Agent is logged as sent through
`log_append <user_agent {http.request.header.User-Agent}`, and the authentication
failure is inferred from the response's `Www-Authenticate` header
(`log_append auth_challenge {http.response.header.Www-Authenticate}`, a `Basic`
challenge on a 401), because a normalized field is not expressible with stock
`log_append`. Cookie, Authorization and bodies are still never logged.

The exact placeholders and parser are validated against the running Caddy 2.11.9
build and CrowdSec image. Setup includes:

```bash
docker compose -f docker-compose.prod.yaml \
  -f docker-compose.crowdsec.yaml exec crowdsec \
  cscli explain --file /var/log/caddy/access.log --type caddy
```

The expected result includes `source_ip`, `http_path`, `http_verb` and
`http_status`. The pinned official Caddy parser maps `source_ip` from Caddy's
`request.client_ip`; the add-on test MUST additionally assert that this value
equals the synthetic visitor IP, not merely that it is populated. Direct mode is
tested in Phase 2. Cloudflare proxied and Tunnel fixtures run with Phase 4. Tests
for the optional fields prove the bad-User-Agent and chosen brute-force scenarios
actually receive their required metadata. If a future parser version no longer
uses `request.client_ip`, the repository-owned local parser restores that mapping
before the image version can be updated.

## 2.3 Read-only LAPI authentication

The console is a read-only CrowdSec bouncer. The CrowdSec container registers a
named key through its supported `BOUNCER_KEY_<name>` mechanism. The secret may
come from an environment variable or Docker secret.

```text
CROWDSEC_CONSOLE_BOUNCER_KEY
```

This key is used only by the console synchronizer. It is never reused by the
Caddy plugin in Phase 3 because LAPI stream cursors are associated with the
bouncer identity.

The key is not returned by the API, logged, placed in audit details or rendered
in the UI.

## 2.4 Stream synchronization

The elected sync worker polls:

```text
GET /v1/decisions/stream?startup=true&scopes=Ip,Range&origins=<configured>
```

After a successful snapshot, normal polls use `startup=false`. The default poll
period is 10 seconds. File reloads are coalesced and occur no more often than
`BANS_SYNC_INTERVAL`, default 30 seconds, and only when rendered policy bytes
change.

A worker MUST perform a new `startup=true` reconciliation when:

- it first acquires `bans-sync.lock`;
- the process restarts;
- authentication is refreshed;
- a previous poll failed or returned a malformed response;
- LAPI was unreachable and becomes healthy again.

Snapshot reconciliation replaces only CrowdSec-source records. Manual records
remain unchanged. Persisting a snapshot or delta uses the Phase 1 journaled
transaction with `bans-crowdsec.caddy` as the policy target; it never rewrites
`bans-manual.caddy`. Expiry cleanup chooses the affected source file and can update
both under one serialized journal when necessary.

Each CrowdSec decision is stored independently with:

```text
source="crowdsec"
source_id=<decision.id>
scope, value, type, origin, scenario
fetched_at
expires_at=fetched_at+parsed_remaining_duration
```

Rules:

- `scope` is compared case-insensitively and only `Ip` and `Range` are accepted.
- Only `type=ban` is enforced. Other remediation types are counted as ignored.
- Go duration strings, including fractional seconds and negative deleted
  durations, are parsed by a bounded parser with unit tests.
- A `deleted` item removes only the matching decision ID. Unknown IDs are no-op.
- Multiple decisions for one IP remain independent. Deleting one does not unban
  the address while another active decision covers it.
- Every new or snapshot decision passes the same canonicalization, overlap and
  width checks as a manual ban.
- Protected CrowdSec decisions are shown as ignored and are never rendered.
- LAPI errors never clear the last successful CrowdSec records or generated file.

The default `CROWDSEC_ORIGINS` is limited to local and explicitly created
operator decisions, for example `crowdsec,cscli`. CAPI/list origins require an
explicit configuration change.

## 2.5 Capacity and rendering

`bans-crowdsec.caddy` uses the Phase 1 handler shape with source-specific names,
so it can be imported beside the manual policy:

```caddyfile
vars caddy_console_crowdsec_policy 1
@caddy_console_crowdsec_banned {
	client_ip <effective CrowdSec prefixes>
	not client_ip <complete protected set>
}
handle @caddy_console_crowdsec_banned {
	respond 403
}
```

An empty CrowdSec set renders the managed comment and
`vars caddy_console_crowdsec_policy 1`, without a matcher or handler.

`BANS_MAX` has a candidate default of 10,000 and limits total effective prefixes
rendered into stock Caddy. That default is not released until the Phase 1
1,000/10,000/20,000-prefix benchmark confirms its adaptation, reload, memory and
request-latency budget. The measured result may lower it. Manual records and local
CrowdSec detections have priority over optional list or CAPI origins.

The console never silently drops a local active ban. If the selected origins
produce more effective prefixes than the cap:

- the last successfully loaded complete policy remains active;
- automatic apply enters degraded state;
- the UI reports counts by origin and the required remediation;
- the operator can restrict `CROWDSEC_ORIGINS`, increase the measured cap or use
  plugin mode.

Overlapping effective networks may be collapsed only for rendering. Stored
records and their independent expiry semantics are preserved.

## 2.6 Failure behavior

- CrowdSec unavailable: keep the last synced list and show the time of the last
  success.
- Bouncer 401/403: stop delta polling, retain enforcement and require a new
  snapshot after credentials are fixed.
- Malformed payload: ignore the complete response, retain enforcement and audit
  a bounded error summary.
- Protected decision: count by reason and keep a bounded sample for diagnosis.
- Caddy adaptation/reload failure: follow the Phase 1 file transaction rules.
- Sync worker exit: another worker attempts leadership within one poll interval
  and starts with `startup=true`.

## 2.7 UI

File-sync mode adds:

- CrowdSec health and last successful snapshot/poll;
- active decisions with scenario and LAPI origin;
- ignored decision counts and reasons;
- capacity use by source;
- a clear label that CrowdSec-origin decisions are read-only;
- a copyable `cscli decisions delete` command for an operator who deliberately
  wants to remove a CrowdSec decision.

File sync adds a site-scoped snippet, inserted after the manual import and before
application handlers:

```caddyfile
import /etc/caddy/console/bans-crowdsec*.caddy
```

A site can import only `bans-manual*.caddy`, only `bans-crowdsec*.caddy`, or both.
The Security view reports each source independently. This source split is what
allows some sites to use the Phase 3 plugin while other sites remain file-only.

The UI does not run copied commands and does not accept machine credentials.

# Phase 3: optional caddy-crowdsec-bouncer plugin

## 3.1 Activation

Plugin mode requires both optional overlays:

```text
docker-compose.crowdsec.yaml
docker-compose.crowdsec-plugin.yaml
```

The plugin overlay:

- replaces only the Caddy image;
- adds Caddy to `crowdsec-lapi`;
- keeps CrowdSec port 8080 unpublished;
- assigns Caddy a fixed address on `caddy-admin`, sets
  `CADDY_ADMIN_ADDRESS=<fixed-caddy-admin-ip>:2019` in the Caddy service
  environment, and uses the same value for health checks and recovery;
- requires the operator to replace `admin 0.0.0.0:2019` before CrowdSec is
  attached, using the address allocated by that Compose variant:

  ```caddyfile
  {
      admin <fixed-caddy-admin-ip>:2019 {
          origins caddy:2019 <fixed-caddy-admin-ip>:2019
      }
  }
  ```

- refuses activation when live `/config/` shows the admin listener on wildcard,
  loopback-only, or any interface shared with CrowdSec;
- updates the health check and console `CADDY_API_URL` to the fixed address;
- never attaches CrowdSec or cloudflared to `caddy-admin`.

A deployment check from the CrowdSec and cloudflared containers MUST confirm that
Caddy port 2019 refuses connections while the intended data-plane port answers.
The plugin overlay is not considered started successfully until this check passes.

## 3.2 Images and dependency pinning

CI builds two optional images:

```text
ghcr.io/viralone/caddy-crowdsec
ghcr.io/viralone/caddy-crowdsec-cloudflare
```

The first contains stock Caddy plus only the CrowdSec HTTP module. The second also
contains `caddy-dns/cloudflare` for operators who need DNS-01. Using Cloudflare as
a reverse proxy or Tunnel does not itself require the DNS plugin.

The build uses the exact module path:

```text
github.com/hslatman/caddy-crowdsec-bouncer/http@<reviewed-version-or-commit>
```

Caddy, xcaddy modules and the final base image are pinned. The reviewed plugin
version MUST use Caddy's native resolved client-IP context, not raw `RemoteAddr`
or an independently parsed `X-Forwarded-For`. CI proves this with direct,
proxied-DNS and Tunnel fixtures before accepting a plugin update. CI also records
`caddy list-modules`, generates an SBOM, runs vulnerability scanning and adapts
every shipped plugin snippet with the built binary.

Tags include both component versions, for example:

```text
2.11.9-crowdsec-<plugin-version>
sha-<commit>
```

Deployments use an immutable digest or `sha-*` tag. Dependabot tracks Docker
`FROM` images. A Go module manifest, Renovate rule or scheduled check tracks
xcaddy module versions because arbitrary `--with` arguments are not assumed to
be managed by Dependabot.

## 3.3 Separate plugin bouncer identity

Plugin mode uses a second key:

```text
CROWDSEC_PLUGIN_BOUNCER_KEY
```

The CrowdSec overlay registers console and plugin keys independently. Sharing one
key between the console UI synchronizer and the plugin is forbidden.

The environment-variable form is:

```caddyfile
{
	crowdsec {
		api_url http://crowdsec:8080
		api_key {env.CROWDSEC_PLUGIN_BOUNCER_KEY}
		ticker_interval 10s
	}
	order crowdsec first
}
```

A deployment using Docker secrets uses the plugin-supported file placeholder
instead of an environment variable:

```caddyfile
api_key {file./run/secrets/crowdsec_plugin_bouncer_key}
```

When `CROWDSEC_PLUGIN_BOUNCER_KEY_FILE` is set, it MUST be a validated absolute
path inside the Caddy container. The recommended Docker-secret path is
`/run/secrets/crowdsec_plugin_bouncer_key`; the variable remains empty by default
and environment-key mode is used instead. The UI derives the `{file.<path>}`
placeholder from the configured path and the overlay mounts that exact source at
that exact container path. A startup check verifies the mount path equals the
placeholder path without reading or logging the secret. Adaptation alone is
not proof that the plugin resolves the placeholder. Integration tests start Caddy,
connect it to the fake LAPI and enforce a local decision in both environment-key
and file-secret modes. If the pinned plugin does not resolve `{file.*}` at
provisioning time, file-secret mode is not shipped until the overlay has a tested
entrypoint that reads the secret into the plugin environment. The UI never inserts
both forms.

The plugin defaults to stream mode. The design does not enable
`disable_streaming`, which would add an LAPI call to the request path. The UI
calls this mode **near-real-time without reload** and shows the configured polling
interval.

The default plugin behavior on a temporary LAPI outage is retained unless a
future explicit setting chooses hard failure. Caddy continues using its last
in-memory decisions when available. Setup tests startup and outage behavior
against the pinned plugin version.

## 3.4 Protected ranges in plugin mode

The plugin consumes LAPI directly, so console-side stream filtering is not a
sufficient safety control.

The console stores the generated reusable definition in
`BANS_DIR/crowdsec-plugin-protect.caddy`; `BACKUP_DIR/plugin-policy.json` stores
its schema version and last rendered hash. Its contents are validated with
`caddy adapt` against the pinned plugin:

```caddyfile
(protect_crowdsec) {
	@caddy_console_crowdsec_candidate {
		not client_ip private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10
	}
	crowdsec @caddy_console_crowdsec_candidate
}
```

The generated matcher also includes canonical `BANS_NEVER`, Docker ranges,
verified management addresses and profile-specific protected ranges. Changes to
any dependency regenerate this managed file through the shared multi-entry
transaction. A CrowdSec LAPI allowlist generated from the same static operator
configuration is defense in depth. Parser allowlists alone are not sufficient
because they do not remove every existing, manual, CAPI or list-origin decision.

The Caddyfile loads the definition once at top level with a tolerant glob:

```caddyfile
import /etc/caddy/console/crowdsec-plugin-protect*.caddy
```

Sites then use `import protect_crowdsec`. The console management site is never
offered either import.

## 3.5 Interaction with file mode

Plugin mode changes source routing per site, not the console's manual-ban UX:

| Site imports/handlers | Manual enforcement | CrowdSec enforcement |
|---|---|---|
| `bans-manual*.caddy` + `bans-crowdsec*.caddy` | File | File sync |
| `bans-manual*.caddy` + `protect_crowdsec` | File | Plugin |
| `bans-manual*.caddy` only | File | None |

Manual records render only to `bans-manual.caddy`. CrowdSec records render only
to `bans-crowdsec.caddy`. The plugin never changes either file. This avoids the
impossible task of removing CrowdSec entries from one shared file for only some
sites.

The console may still poll CrowdSec using its separate read-only key to display
active decisions. A plugin-protected site does not import
`bans-crowdsec*.caddy`; a file-only site may import it. If an operator deliberately
configures both, enforcement is duplicated but not lost, and the UI warns about
the redundant path.

If the plugin app exists globally but a site does not contain the handler, that
site is not labeled protected. Detection recursively walks live
`apps.http.servers.*.routes`, including nested subroutes.

## 3.6 Plugin UI snippets

Plugin mode adds three separate snippets because they belong at different Caddyfile
scopes:

1. **CrowdSec plugin: global app**
   - Scope: inside the existing global options block.
   - Adds `crowdsec { ... }` and `order crowdsec first`.
   - Offers either the environment or file-secret key form.
   - Warns when the running Caddy build lacks the module.
2. **CrowdSec plugin: load protected route definition**
   - Scope: top-level, outside every site and the global options block.
   - Inserts:
     ```caddyfile
     import /etc/caddy/console/crowdsec-plugin-protect*.caddy
     ```
   - Requires a current generated file and shows its protected-range hash.
3. **CrowdSec plugin: protect this site**
   ```caddyfile
   import protect_crowdsec
   ```
   - Scope: site.
   - Inserts before existing handlers only after the definition and global app
     are present.

The UI never tries to insert different scopes at one cursor position. It checks
the running module list, reusable snippet definition and current adapted config
before offering site insertion. CI and JavaScript fixtures adapt the exact code
of every shipped snippet, including both secret variants.

# Phase 4: Cloudflare trust profiles and country policy

This phase has no CrowdSec dependency. It shares the top-level `BANS_ENABLED`
Security feature gate: when that value is false, trust-profile generation, country
policy APIs and the Security view are also disabled. File mode and plugin mode
both consume Caddy's native resolved client IP, so one correct trust profile
benefits manual bans, CrowdSec parsing, plugin enforcement, Explore and GeoIP
display.

## 4.1 Profiles

`CLIENT_IP_MODE` has three values:

```text
direct                  default
cloudflare-proxied
cloudflare-tunnel
```

The value controls validation and UI guidance. Selecting a profile renders
`cloudflare-trusted-proxies.caddy`, but the console does not silently edit the
operator's global options. The operator inserts and saves this global-scope block:

```caddyfile
{
	servers {
		import /etc/caddy/console/cloudflare-trusted-proxies*.caddy
		client_ip_headers CF-Connecting-IP
	}
}
```

For `direct`, the import is not offered and the managed file is comment-only. For
`cloudflare-proxied`, it contains `trusted_proxies static` followed by the current
Cloudflare IPv4 and IPv6 ranges. For `cloudflare-tunnel`, it contains the fixed
cloudflared address or narrow dedicated subnet. The file is a `servers` block
body, not a second global options block.

### Direct

Use when clients connect directly to Caddy or through an unrecognized proxy.

- Do not configure `trusted_proxies` for the listener.
- `client_ip` equals the immediate peer.
- Forwarded and Cloudflare headers are ignored for policy.
- Country policy uses generated country CIDRs.

### Cloudflare proxied DNS

Use when Cloudflare connects to published Caddy ports.

The generated file contains the complete current list. This abbreviated literal is
a documentation and adaptation fixture; production output includes every validated
Cloudflare range:

```caddyfile
trusted_proxies static 173.245.48.0/20 2400:cb00::/32
```

The operator's global block imports it using the common profile snippet above.

Requirements:

- The trusted list contains Cloudflare's published IPv4 and IPv6 ranges only,
  not `private_ranges`.
- The firewall/router should accept public origin traffic only from Cloudflare.
  If direct LAN access is required, exact LAN ranges are handled separately.
- A Caddy origin guard verifies `remote_ip` is Cloudflare or an approved LAN
  before any `CF-IPCountry` policy is trusted.
- Cloudflare edge ranges are added to the generated protected set so a
  misconfigured client-IP chain cannot ban the complete proxy layer.

### Cloudflare Tunnel

Use when cloudflared reaches Caddy over a dedicated Docker network.

- Caddy data-plane ports are not published on the host or forwarded by the
  router.
- The Caddy and cloudflared containers share a dedicated network that contains
  no unrelated service.
- cloudflared receives a fixed address or a narrowly assigned subnet.
- `trusted_proxies` contains that address/subnet, not every private range. For a
  cloudflared container fixed at `172.31.0.2`, the generated file is:

  ```caddyfile
  trusted_proxies static 172.31.0.2/32
  ```

- `client_ip_headers CF-Connecting-IP` selects the visitor address.
- Caddy Admin API remains bound only to the fixed `caddy-admin` interface and is
  unreachable from cloudflared.

A broad `trusted_proxies static private_ranges` is accepted only for a verified
Tunnel-only listener and isolated network. It is rejected by the validator when
the same listener is reachable from arbitrary LAN or published-port peers because
those peers could supply a fake forwarding header.

## 4.2 Cloudflare range updates

Cloudflare ranges are maintained separately from DB-IP updates. Metadata and the
last successfully generated policy hash are stored in
`BACKUP_DIR/cloudflare-ranges.json`; the candidate state embeds the candidate
`cloudflare-trusted-proxies.caddy` hash before the journaled file replacement.

- A bundled last-known-good list ships with the application.
- The updater fetches Cloudflare's documented HTTPS IPv4 and IPv6 endpoints at
  most once per day.
- Every response is size-limited, parsed as canonical networks and rejected if
  empty, malformed or implausibly different from the current list.
- A failed update keeps the last list.
- A validated range change is expanded through a dependency graph before any
  write. The transaction always includes `cloudflare-ranges.json` and
  `cloudflare-trusted-proxies.caddy`. When present or enabled, it also regenerates:
  - `bans.json`, `bans-manual.caddy` and `bans-crowdsec.caddy`, because the
    Cloudflare edge list is part of their protected set;
  - `country-policy.json` and `geo.caddy`, because proxied-DNS country policy
    verifies `remote_ip` against the edge list;
  - `plugin-policy.json` and `crowdsec-plugin-protect.caddy`, because plugin mode
    applies its handler only to non-protected clients.
- Every affected candidate state embeds the candidate hash of the policy it owns.
  The whole expanded set is committed by one Phase 1 multi-entry journal under
  `caddyfile_lock()`; no dependent file is updated in a later transaction.
- If none of the changed managed files is imported, the new list and generated
  policies are stored without reloading Caddy. Otherwise the console performs one
  adaptation and one `/load` for the complete set.
- The Security view shows list age, source, dependency hashes and whether every
  live importer uses the current policy generation.

## 4.3 Country allowlist

Country policy is off by default. State is stored in
`BACKUP_DIR/country-policy.json` with a schema version, selected profile, allowed
ISO country codes, update metadata and the last successfully generated
`geo.caddy` hash. Its candidate state embeds the candidate hash before the shared
journal transaction replaces either file. While country policy is disabled,
`geo.caddy` contains only its managed comment and
`vars caddy_console_country_policy off`; it emits no matcher or handler.

The API accepts only codes from a server-owned ISO list. `XX` and Cloudflare's
special `T1` value are denied unless the operator explicitly includes them.
At least one country is required before enabling the policy.

### Direct country policy

Stock Caddy needs IP ranges because it has no built-in country matcher. The
console downloads DB-IP Country Lite as a dedicated country-range dataset. The
existing City and ASN MMDB readers remain display-only and are not scanned to
reconstruct ranges.

The updater:

- validates compressed and uncompressed size limits;
- validates every start/end address and country code;
- converts ranges to canonical IPv4/IPv6 CIDRs;
- merges only adjacent or overlapping prefixes with the same country;
- keeps the previous dataset on any error;
- regenerates policy only when selected-country output changes.

Generated `geo.caddy` follows the same safe handler shape:

```caddyfile
vars caddy_console_country_policy direct
@caddy_console_country_denied {
	not client_ip <allowed-country-ranges> private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10
}
handle @caddy_console_country_denied {
	respond 403
}
```

`BANS_NEVER` and verified management addresses are included in the allowed side.
The UI shows generated IPv4/IPv6 prefix counts. `COUNTRY_MAX_PREFIXES` is not
assigned a production default until the Phase 4 benchmark measures adaptation,
reload memory and request latency. The benchmark exercises 20,000 prefixes as an
upper test point, not as a pre-approved safe limit. Phase 4 cannot ship until a
measured hard limit and warning threshold are recorded. Larger policies recommend
Cloudflare WAF or a matcher designed for large sets.

### Cloudflare country policy

`CF-IPCountry` is used only after the selected Cloudflare profile has verified the
immediate peer. Public direct origin traffic can never satisfy the Cloudflare
branch by merely adding the header.

For `cloudflare-proxied`, `geo.caddy` contains the current Cloudflare IPv4/IPv6
ranges in the `remote_ip` line below. For `cloudflare-tunnel`, the same position
contains the fixed cloudflared address or dedicated subnet:

```caddyfile
vars caddy_console_country_policy cloudflare
@caddy_console_country_denied {
	not client_ip private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10
	not {
		remote_ip <selected Cloudflare peer ranges>
		header CF-IPCountry RO DE
	}
}
handle @caddy_console_country_denied {
	respond 403
}
```

The first condition exempts LAN and other protected resolved clients. The second
condition denies every remaining request unless both the immediate peer is the
selected Cloudflare peer and the country header has an allowed value. Generated
lines also include `BANS_NEVER` and verified management addresses.

A missing header therefore denies public traffic and increments a specific
diagnostic counter. The UI requires confirmation that Cloudflare IP Geolocation
is enabled before the policy can be marked healthy. `geo.caddy` always contains
exactly one active profile shape, so `import /etc/caddy/console/geo*.caddy` never
combines direct and Cloudflare policies.

Cloudflare WAF country rules remain the recommended option because they reject
traffic before it reaches the origin.

## 4.4 Cloudflare snippets

The existing ambiguous **Cloudflare Only** snippet is replaced. A tunnel sees the
cloudflared private peer, not a public Cloudflare edge address, so one snippet
cannot safely cover both modes.

New snippets:

1. **Cloudflare proxied DNS: real client IP**
   - global `servers` scope;
   - imports `cloudflare-trusted-proxies*.caddy`;
   - adds `CF-Connecting-IP`;
   - requires the generated file to contain current IPv4 and IPv6 edge ranges;
   - shows the origin-lock prerequisite.
2. **Cloudflare Tunnel: real client IP**
   - global `servers` scope;
   - imports the same profile-selected managed file;
   - requires a fixed cloudflared address/subnet and no published Caddy port.
3. **Country policy: protect this site**
   ```caddyfile
   import /etc/caddy/console/geo*.caddy
   ```
4. **Cloudflare origin guard**
   - site scope for proxied-DNS deployments;
   - allows exact LAN ranges separately;
   - verifies `remote_ip`, never a forwarding header.

# Mode detection and health

The Security view reports enforcement per site, not only globally.

Detection uses two inputs:

1. The on-disk Caddyfile and known imports, for editable source location.
2. The adapted/live JSON config, recursively walking servers, routes, subroutes
   and handlers.

Definitions:

| State | Requirement |
|---|---|
| Manual file imported | Live site route contains `vars.caddy_console_manual_policy=1`; an active ban also has a client-IP matcher and 403 handler in effective order |
| CrowdSec file imported | Live site route contains `vars.caddy_console_crowdsec_policy=1`; active decisions also have a client-IP matcher and 403 handler |
| Country policy imported | Live site route contains `vars.caddy_console_country_policy` with the active profile and its denial handler |
| CrowdSec plugin enforced | Live site route contains `http.handlers.crowdsec` in effective order |
| Stored only | Records exist but no verified handler protects the site |
| Degraded | Last good enforcement remains, but state, sync or reload needs attention |
| Unknown | External imports or custom handlers prevent proof of ordering |

A global CrowdSec app without a per-site handler is not enforcement. A raw import
string without a corresponding live marker is not enforcement. Caddyfile matcher
names and comments disappear during adaptation, so source identity comes from the
unique `vars` marker while effective blocking comes from its adjacent matcher and
handler. Empty policies retain the marker. Before deciding that a changed file
needs reload, the console checks both the on-disk import and the current live
marker. Sites in external files get Copy guidance and an Unknown source-edit state
rather than unsafe automatic modification.

# Configuration

| Variable | Default | Phase | Meaning |
|---|---|---|---|
| `BANS_ENABLED` | `true` | 1 | Enables Security APIs, jobs and UI; sites remain unchanged without imports |
| `BANS_DIR` | `/etc/caddy/console` | 1 | Shared directory for generated Caddy files |
| `BANS_MAX` | `10000` candidate | 1 | Maximum total prefixes rendered in file mode; Phase 1 benchmark may lower it |
| `BANS_NEVER` | empty | 1 | Additional protected IPs/CIDRs; invalid input fails startup |
| `BANS_SYNC_INTERVAL` | `30` | 2 | Minimum seconds between automatic CrowdSec-driven reloads |
| `CROWDSEC_URL` | empty | 2 | LAPI URL; empty disables CrowdSec integration |
| `CROWDSEC_CONSOLE_BOUNCER_KEY` | empty | 2 | Read-only key dedicated to the console stream |
| `CROWDSEC_ORIGINS` | `crowdsec,cscli` | 2 | LAPI origins included by file sync and UI |
| `CROWDSEC_POLL_INTERVAL` | `10` | 2 | Seconds between decision-stream polls |
| `CROWDSEC_PLUGIN_BOUNCER_KEY` | empty | 3 | Environment key dedicated to the Caddy plugin |
| `CROWDSEC_PLUGIN_BOUNCER_KEY_FILE` | empty | 3 | Mounted file-secret path used instead of the environment key |
| `CADDY_ADMIN_ADDRESS` | `0.0.0.0:2019` | 3 | Admin address used by health checks/recovery; plugin overlays set the fixed internal address |
| `CLIENT_IP_MODE` | `direct` | 4 | Direct, Cloudflare proxied DNS or Cloudflare Tunnel guidance |
| `CLOUDFLARE_RANGES_AUTO_UPDATE` | `true` | 4 | Refresh the bundled edge list separately from GeoIP |
| `COUNTRY_POLICY_ENABLED` | `false` | 4 | Enables generated country enforcement after configuration |
| `COUNTRY_MAX_PREFIXES` | unset until benchmark | 4 | Hard file-mode country prefix cap selected by the Phase 4 performance gate |

Numeric settings have server-side lower and upper bounds. Secret values support
platform file-secret variants and are never included in diagnostics.

All baseline Compose files pass core variables through without CrowdSec defaults.
The optional overlays introduce CrowdSec-only variables, networks and volumes.

# Audit and observability

Audit events include:

- manual ban created, expired and removed;
- protected or too-wide ban refused;
- CrowdSec snapshot and degraded transition summaries;
- ignored decision counts by reason;
- country policy changed;
- generated policy adapted and loaded;
- confirmed rejection, rollback failure and reload-unknown transition;
- recovery reset.

Audit details are bounded. Secrets and complete LAPI payloads are never logged.
Reasons and actor names remain plain data and are encoded by the UI at output.

Metrics/status include active records by source, rendered prefix count, last
successful Caddy apply, last CrowdSec snapshot/poll, ignored decisions, missing
country headers, Cloudflare range age and current degraded reason.

# Error handling

- Missing managed glob: Caddy continues with no imported content and the UI says
  Not enforced.
- Exact managed file missing after previously being loaded: keep live state,
  recreate only from valid stored state and require adaptation before reload.
- Disk write failure: do not reload; return a structured 500 response.
- Adaptation failure: restore candidate files and do not call `/load`.
- Confirmed `/load` rejection: restore candidate files; running config remains
  unchanged.
- Ambiguous reload result: keep complete candidate disk state, stop automatic
  applies and verify live config before proceeding.
- Corrupt ban state: preserve last generated enforcement and enter read-only
  degraded mode.
- CrowdSec outage: preserve last successful effective list.
- Cloudflare/DB-IP update failure: preserve last known-good data and policy.
- Invalid IP, CIDR, duration, country code or configuration token: return 400 with
  a stable error code and safe message.

# Testing

## Python unit tests

- Manual store schema, migration, atomic write, expiry and independent overlapping
  records.
- Corrupt/unreadable state preserves both source-specific policy files and enters
  degraded mode.
- Crash recovery at every journal phase, including between policy and state
  replacement.
- Hidden `.tmp` files left by a crash never match any managed `*.caddy` glob.
- Transaction backups exist before replacement, remain under
  `BACKUP_DIR/.policy-transactions`, use `.bak`, and never match imports.
- Expiry cleanup regenerates the affected policy and reloads within one minute.
- An out-of-band truncated policy enters recovery hold on restart and is not
  regenerated until authenticated Re-apply.
- Canonical IPv4, IPv6 and IPv4-mapped IPv6 handling.
- Every protected class, both network-overlap directions, own IP and
  `BANS_NEVER`.
- `/16` and `/48` width limits.
- Generated file mode, permissions, empty state and protected exclusions.
- Caddy transaction: adapt rejection, load rejection, connect timeout, ambiguous
  read timeout, rollback failure and lock serialization.
- Authentication and CSRF for every new mutation.
- `BANS_ENABLED=false` skips managed-directory checks, disables Security APIs and
  background jobs, and hides the Security view without affecting existing views.
- `management_addresses` trusts only verified peers, caps at 16, expires after 30
  days and is applied by background expiry and CrowdSec sync.
- Mode detection through nested `handle`, `handle_path`, `route` and subroute.
- Detection and status for `redir`, `rewrite`, `basic_auth`, `forward_auth`,
  `request_header`, `invoke` and custom global `order` before the ban handler.
- Two active CrowdSec decisions for one IP followed by deletion of one ID.
- `startup=true` reconciliation, failover, malformed response, auth failure and
  outage recovery.
- Go duration parsing and expiry.
- Capacity behavior never silently drops a local active record.
- Country dataset validation, IPv4/IPv6 conversion, merging and last-good
  retention.
- Cloudflare range refresh: response size limits, IPv4/IPv6 parsing, empty and
  implausible-diff rejection, last-good retention and daily rate limit.
- Cloudflare dependency expansion updates all affected state and policy files in
  one journal and leaves every dependent hash consistent after recovery.
- Recovery API enumerations, opaque backup IDs, version checks and reset-source
  behavior.

## JavaScript unit tests

- Security route and state formatting.
- Duration and expiry labels.
- Protected IP action suppression.
- Plain-text rendering of reason, scenario, actor and API errors.
- Site-aware snippet insertion, first-child placement and duplicate prevention.
- Global versus site snippet scopes.
- Exact code for every shipped snippet adapts successfully, including manual,
  file-sync, plugin environment/file-secret and Cloudflare profile variants.
- External imported site behavior.
- No native dialogs. Existing dialog components handle confirmations.

## Caddy integration tests

Run against stock `caddy:2.11.9-alpine`:

- manual ban and unban on a simple `reverse_proxy` site;
- enforcement before catch-all `handle`, `handle_path` and `route` application
  handlers;
- partial-state reporting for `redir`, `rewrite`, `basic_auth`, `forward_auth`
  and `invoke`, plus strict first-inside-`route` enforcement;
- expiry-driven regeneration and reload;
- crash recovery between source-policy and state-file replacements;
- private/protected address bypass at runtime;
- exact-file absence versus managed glob absence;
- empty manual, CrowdSec and country files retain distinct `vars` markers after
  adaptation without emitting an IP matcher;
- rejected and accepted reloads;
- host recovery commands against wildcard and fixed Admin API addresses;
- 403 events appear in the access log;
- benchmark 1,000, 10,000 and 20,000 prefixes for adapt time, reload time,
  memory and request latency.

Run the optional CrowdSec overlay:

- `cscli explain` populates required metadata from the real filtered log and
  `source_ip` equals the synthetic resolved visitor IP, not a proxy address;
- 404/path probe, bad User-Agent and selected brute-force scenarios generate
  decisions;
- one decision reaches file enforcement within the 60-second objective;
- LAPI outage preserves the last list;
- no CrowdSec port is published;
- CrowdSec cannot connect to Caddy port 2019.

Run the optional plugin overlay:

- built image reports the expected modules;
- documented global, definition and site snippets adapt successfully in both
  secret modes;
- Caddy starts and enforces a fake-LAPI decision with both environment and
  file-secret keys;
- file-secret startup fails before Caddy launch when the mounted container path
  differs from `CROWDSEC_PLUGIN_BOUNCER_KEY_FILE` or the generated placeholder;
- plugin and console use different bouncer keys;
- the plugin matches Caddy's resolved visitor IP in direct, proxied and Tunnel
  fixtures;
- local decision is enforced without Caddy reload;
- protected decisions do not invoke the plugin;
- manual bans still use `bans-manual.caddy`;
- mixed plugin-protected and file-only sites retain the intended CrowdSec path;
- recovery works with the fixed Admin API address;
- CrowdSec and cloudflared cannot connect to Caddy port 2019.

Run Cloudflare profile fixtures locally with synthetic trusted peers:

- direct mode ignores forged `CF-Connecting-IP` and `CF-IPCountry`;
- every generated `cloudflare-trusted-proxies.caddy` variant imports and adapts;
- proxied mode accepts headers only from configured Cloudflare peers and resolves
  the expected visitor IP;
- tunnel mode accepts headers only from the fixed cloudflared peer and resolves
  the expected visitor IP;
- missing country header fails as documented;
- LAN/protected clients bypass country blocking;
- direct-origin country-header spoofing fails;
- IPv4 and IPv6 Cloudflare ranges are covered;
- direct country policies are benchmarked at 1,000, 10,000 and 20,000 generated
  prefixes, and the test records the measured `COUNTRY_MAX_PREFIXES` and warning
  threshold used by the release gate;
- a policy above `COUNTRY_MAX_PREFIXES` is rejected without changing live or
  last-known-good files.

Existing Python and Node suites remain passing. UI screenshots cover desktop and
mobile, light and dark themes, empty, healthy, degraded and reload-unknown states.

# Delivery gates

## Phase 1 gate

- Stock Caddy integration tests pass.
- `handle`/`route` ordering tests pass.
- Corrupt state, journal crash recovery, expiry reload and ambiguous reload tests
  pass.
- The benchmark establishes the released `BANS_MAX` and records its latency and
  memory budgets.
- The console site remains reachable without the managed import.
- Baseline Compose renders and starts without CrowdSec variables.

## Phase 2 gate

- The optional overlay is the only change required to start CrowdSec.
- Parser and scenario tests prove the documented detections.
- Stream reconciliation and separate source records pass.
- Caddy remains absent from the CrowdSec network.

## Phase 3 gate

- Plugin images are reproducible, pinned and scanned.
- Caddy Admin API is unreachable from every non-console network peer.
- Protected-range plugin tests pass.
- `bans-crowdsec.caddy` is imported only by file-sync sites; plugin sites use the
  protected plugin route, and mixed deployments pass.

## Phase 4 gate

- Each trust profile rejects headers from an untrusted peer.
- Direct mode remains independent of Cloudflare.
- Country data update and last-good behavior pass.
- Benchmarks establish and document `COUNTRY_MAX_PREFIXES` and its warning
  threshold; the phase does not ship with an unmeasured placeholder.
- Recovery tests cover `geo.caddy` and `cloudflare-trusted-proxies.caddy`.
- The old ambiguous Cloudflare snippet is removed.

# Documentation

`docs/security.md` covers:

1. Manual file mode and recovery.
2. CrowdSec file-sync overlay, acquisition, parser verification and origins.
3. Plugin overlay, image selection, separate keys and polling latency.
4. Direct, Cloudflare proxied-DNS and Cloudflare Tunnel trust profiles.
5. Country policy, DB-IP attribution and Cloudflare WAF recommendation.
6. Capacity planning and the difference between stored, enforced, degraded and
   unknown states.

`docs/setup.md` links to the relevant section but keeps its baseline quick start
free of CrowdSec requirements.
