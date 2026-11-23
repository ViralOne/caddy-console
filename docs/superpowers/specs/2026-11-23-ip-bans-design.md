# IP bans, CrowdSec and country allowlist

Status: draft for review · Date: 2026-11-23

## Goal

Let the operator block unwanted clients, by hand and automatically, on **any**
Caddy build, including the stock `caddy:2.11.9-alpine` image with no plugins and
no Cloudflare in front.

Success criteria:
- Manual ban / unban of an IP or CIDR from the console, enforced by stock Caddy
  within seconds, with no extra service.
- Optional CrowdSec: its automatic bans (scanners, 404 bursts, brute force) are
  enforced by the same mechanism, within about 30 s.
- Optional plugin mode (`caddy-crowdsec-bouncer`) for instant enforcement, using
  an image this repo builds; the console works the same in both modes.
- Optional country allowlist that works on stock Caddy and, when the site is
  behind Cloudflare, uses `Cf-IPCountry` instead.
- The operator cannot lock themselves out: LAN, private, loopback and Cloudflare
  ranges and the operator's own IP are never banned or blocked by country.
- Until a site imports the bans file (or uses the plugin), Caddy behaviour is
  unchanged; `BANS_ENABLED=false` hides the feature entirely.

Out of scope: CrowdSec AppSec (WAF), CAPTCHA remediation, Cloudflare-edge
bouncer, community blocklist enrolment (an operator choice, documented only),
per-site ban lists (bans apply to every site that imports the file).

## Decisions already made (user)

- CrowdSec does the automatic detection; the console provides the UI.
- Enforcement in Caddy, not at Cloudflare.
- Must work with plain Caddy, not only the Cloudflare build.
- Country blocking: Cloudflare WAF is recommended in the docs; the console also
  offers a Caddy-side allowlist.

## 1. Enforcement modes

The console detects the mode from the Caddyfile on disk and Caddy's live config
(`/config/`), and shows it in the Security view.

| Mode | Detected when | Enforcement |
|---|---|---|
| **File** (default) | Some site block contains `import /etc/caddy/console/bans.caddy` | Console-managed file + Caddy reload |
| **Plugin** | Live config contains a `crowdsec` handler | `caddy-crowdsec-bouncer` queries CrowdSec per request |
| **Not enforced** | Neither | Security view shows a warning and a **Copy snippet** / **Insert in editor** action |

Both may be present (plugin for CrowdSec bans, file for manual bans); the view
lists what each site uses.

### File mode

- The console owns the directory `/etc/caddy/console/` (inside the Caddyfile
  directory both containers already mount; Caddy's mount stays read-only).
- `bans.caddy` is a snippet body, regenerated from the ban list:
  ```
  # Managed by Caddy Console. Do not edit; changes are overwritten.
  @console_banned client_ip 203.0.113.7 198.51.100.0/24
  respond @console_banned 403
  ```
  With no bans it contains only the comment (an empty matcher would match
  nothing but is rejected by the adapter, so the lines are omitted).
- `client_ip` honours the user's `trusted_proxies` / `client_ip_headers`, so a
  ban hits the real visitor behind Cloudflare or another proxy.
- **The import must use an absolute path.** The console reloads by POSTing the
  Caddyfile text to `/load`, where relative imports resolve against Caddy's
  working directory, not the Caddyfile's.
- Apply = write the file atomically, then POST the on-disk Caddyfile to
  `/load`, holding the existing `caddyfile_lock()` so it never races an editor
  save. If `/load` fails, the previous `bans.caddy` is restored, Caddy keeps its
  running config, and the error is shown and audited.
- Reloads are debounced: a manual ban applies immediately; CrowdSec changes
  are batched and applied at most once every `BANS_SYNC_INTERVAL` (30 s).
- Expired bans are removed by the same sync.

### Plugin mode

- New `caddy/Dockerfile` (xcaddy, Caddy 2.11.9) built in CI into two GHCR
  images: `ghcr.io/viralone/caddy-crowdsec` and
  `ghcr.io/viralone/caddy-crowdsec-cloudflare` (+ `caddy-dns/cloudflare`).
  Tags `2.11.9` and `sha-<commit>`; Dependabot tracks the base image and the
  plugin module versions.
- Caddyfile (documented, and offered as a snippet):
  ```
  {
  	crowdsec {
  		api_url http://crowdsec:8080
  		api_key {env.CROWDSEC_BOUNCER_KEY}
  	}
  	order crowdsec first
  }
  (protect) {
  	crowdsec
  }
  ```

## 2. Ban sources and storage

- **Store:** `BACKUP_DIR/bans.json` — list of
  `{value, scope: "ip"|"range", reason, origin: "manual"|"crowdsec", user,
  created, expires|null}`. Read-modify-write under an flock with atomic
  replace (same pattern as `upstream-health.json`). Corrupt file → treated as
  empty, rewritten, and a warning is logged.
- **Manual bans:** durations 4 h, 24 h, 7 d, permanent; optional reason.
- **CrowdSec (optional)**, enabled by `CROWDSEC_URL`:
  - `CROWDSEC_BOUNCER_KEY` (read-only key): the console acts as a bouncer and
    polls `GET /v1/decisions/stream` (`startup=true` first, then deltas). Only
    `type: ban` decisions with scope `Ip` or `Range` are used; others are
    ignored and counted.
  - `CROWDSEC_MACHINE_USER` / `CROWDSEC_MACHINE_PASSWORD` (optional): with
    these, manual bans and unbans are also written to CrowdSec (machine login →
    `POST /v1/alerts` with a decision, `DELETE /v1/decisions/{id}`), so there
    is one list. Without them, manual bans stay local and CrowdSec bans cannot
    be lifted from the console (the Unban button explains why and shows the
    `cscli decisions delete` command).
  - CrowdSec unreachable → the last synced list stays enforced; the Security
    view shows "CrowdSec unreachable since …". Never clears bans on error.
- **Sync leader:** one worker at a time runs the sync loop, chosen by a
  non-blocking flock on `BACKUP_DIR/bans-sync.lock`; another worker takes over
  within one interval if the holder exits.

## 3. Safety rules (enforced server-side on every ban, from any source)

- Never banned: loopback, RFC 1918 / CGNAT / link-local / ULA ranges, the
  Docker networks of the console, Cloudflare's published ranges (bundled list,
  refreshed with the GeoIP update), the requesting user's own IP, and any entry
  in `BANS_NEVER` (comma-separated IPs/CIDRs).
- A range that *contains* a protected address is refused (e.g. `0.0.0.0/0`).
  Ranges wider than /16 (IPv4) or /48 (IPv6) are refused.
- CrowdSec decisions that violate a rule are skipped and listed as "ignored
  (protected)", not enforced.
- The Caddyfile snippet docs include a matching CrowdSec allowlist
  (`crowdsecurity/whitelists` plus a local parser), so CrowdSec itself does not
  raise those bans.
- Ban list cap: `BANS_MAX` (10 000) entries in the file; beyond that the
  oldest CrowdSec bans are dropped first and a warning is shown.

## 4. Country allowlist (optional)

- Set in the Security view: allowed countries (multi-select, names via
  `Intl.DisplayNames`), off by default. Stored in `BACKUP_DIR/geo.json`.
- Generates `/etc/caddy/console/geo.caddy`, imported like `bans.caddy`:
  - **Behind Cloudflare** (the user chooses "Sites are only reachable through
    Cloudflare"): `@console_foreign not header Cf-IPCountry RO DE …`. The
    option's help text says the header can be forged if the origin is
    reachable directly.
  - **Otherwise:** ranges for the allowed countries taken from the DB-IP
    country database the console already downloads, merged into the fewest
    CIDRs, as `@console_foreign not client_ip <ranges> <private ranges>`.
    Regenerated and reloaded when the database updates. The view shows the
    range count and warns above 20 000.
- Private / LAN ranges and `BANS_NEVER` are always allowed.
- `respond @console_foreign 403`.
- The docs recommend a Cloudflare WAF country rule when Cloudflare is in
  front, because it blocks before traffic reaches the server.

## 5. Console UI

- **Security view** (fourth tab, shown when bans are enabled — always in file
  mode, since manual bans need nothing else):
  - Mode and health line: "Enforced by stock Caddy via bans.caddy on 5 of 7
    sites · CrowdSec synced 12 s ago".
  - Ban list: value, country + network (existing GeoIP), reason / scenario,
    origin, user, created, expires (relative), Unban. Filter and sort.
  - Ignored-decisions count with reasons.
  - Country allowlist section.
  - Sites without the import listed with **Insert in editor** (opens the
    Editor with the import line added to that site block; the user saves as
    usual).
- **IP popover in Explore:** "Banned" badge with reason / expiry; **Ban…**
  (duration select + reason, confirm dialog) or **Unban**. Protected IPs show
  "Protected (LAN)" and no button.
- **Explore:** 403s produced by a ban are visible as normal events; no new
  field.
- **Dashboard:** a tile "Bans · 24h" (new bans, top scenario) when enabled.
- **Snippets panel:** "Protect site (bans)", "Country allowlist", and
  "CrowdSec plugin" templates.
- Every ban, unban, allowlist change and failed apply goes to the audit log.

## 6. Configuration

| Variable | Default | Meaning |
|---|---|---|
| `BANS_ENABLED` | `true` | Turns the feature off entirely when `false` |
| `BANS_DIR` | `/etc/caddy/console` | Where `bans.caddy` / `geo.caddy` are written |
| `BANS_SYNC_INTERVAL` | `30` | Seconds between CrowdSec syncs / batched reloads |
| `BANS_MAX` | `10000` | Max entries written to `bans.caddy` |
| `BANS_NEVER` | empty | Extra IPs/CIDRs that are never banned |
| `CROWDSEC_URL` | empty | e.g. `http://crowdsec:8080`; empty = no CrowdSec |
| `CROWDSEC_BOUNCER_KEY` | empty | Read-only key (`cscli bouncers add caddy-console`) |
| `CROWDSEC_MACHINE_USER` / `_PASSWORD` | empty | Optional, enables two-way manual bans |

Compose files that ship CrowdSec use pass-through variables with no defaults,
like the rest of the stack.

## 7. Compose and docs

- `docker-compose.*.yaml`: optional `crowdsec` service
  (`crowdsecurity/crowdsec` pinned), `COLLECTIONS=crowdsecurity/caddy
  crowdsecurity/whitelists`, acquisition of the Caddy access log via the shared
  `caddy-logs` volume (read-only), LAPI on the internal network only — no
  published ports. Volumes for its config and database.
- `docs/security.md`: file mode setup, CrowdSec setup (bouncer key, machine
  user), plugin images, country allowlist, Cloudflare WAF rule example,
  lock-out recovery (delete `bans.caddy` contents and reload).

## 8. Error handling

- Missing import → "Not enforced" warning; bans are still stored.
- `/load` rejected → previous files restored, error shown, audited.
- Disk write failure → API returns 500 with the message; nothing reloaded.
- CrowdSec auth error / unreachable → status line, last list kept.
- Invalid IP / CIDR input → 400 with a specific message.

## 9. Testing

- Python unit: ban store (add, expire, corrupt file, concurrent writers),
  safety rules (each protected class, wide ranges, own IP, `BANS_NEVER`),
  `bans.caddy` / `geo.caddy` rendering (empty, IPv4/IPv6 mix, cap), CIDR
  merging for countries, mode detection, CrowdSec stream client against a fake
  LAPI (startup, deltas, non-ban types, auth error, outage keeps list), machine
  client (add / delete), rollback on rejected `/load`, sync leader lock.
- JS unit: ban duration / expiry formatting, popover state.
- Dev stack, stock `caddy:2.11.9-alpine`: manual ban → 403 within seconds,
  unban → 200; CrowdSec container with `crowdsecurity/caddy`: burst of
  `/.env`, `/wp-login.php` requests → automatic ban enforced; country
  allowlist on and off; protected IP refused. Plugin image: same burst blocked
  instantly. Screenshots with yab in both themes.
- Existing suites unchanged and passing.
