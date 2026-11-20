# UI redesign: Direction A ("Refined")

Status: draft for review · Date: 2026-11-20

## Goal

Move the whole console to the "A · Refined" design (mockup:
`poc-ui/a-refined/index.html`, audit: `poc-ui/AUDIT.md`) in one redesign, including
every piece of new data the mockup shows. Keep the architecture (Flask + CodeMirror 6
+ Preact views, URL as state), every existing API field, and all current behaviour.

Success criteria:
- Every element in the mockup exists in the app with real data (or is hidden when
  the data is unavailable, never faked).
- All ten problems in the audit are fixed.
- Works at 1440, 1024 and 390 px; no hover-only controls; WCAG AA contrast in both
  themes; status never colour-only; no native `alert()`/`confirm()` left.
- Existing tests pass unchanged; new backend fields have tests; no new runtime
  dependencies.

Out of scope: B's command palette, C's sidebar navigation, real-device touch QA,
new auth features.

## Decisions already made

- One big redesign, not phased (user).
- Everything in the mockup, including new backend data (user).
- Approach 1: port the design into the existing code (user).
- Keep the upstream DNS check, worded as "could not be resolved from the console
  container", warning only (user).

## 1. Design system

- `tokens.css` replaced with A's tokens. Dark: graphite surfaces with a violet tint;
  light: cool paper. Accent `#b2a4ff` (dark) / `#5440d0` (light) only for
  interactive things: links, focus, selected tab, primary buttons. Hosts, users and
  titles use ink colours. Status: good, warn, serious, critical, info, other; 3xx keeps
  blue as a data colour, distinct from the accent.
- Type scale 12/13/14/17/22/30, base 14 px, `font-variant-numeric: tabular-nums` on
  all figures. No uppercase labels. Sections separated by whitespace and hairlines,
  not bordered cards.
- Themes: `data-theme="dark|light"` on `<html>`. Default follows
  `prefers-color-scheme`; the account menu offers System / Dark / Light, stored in
  localStorage (`ui.theme`). A small inline script in `<head>` sets the attribute
  before first paint; the CSP gets a `sha256-` hash for it (no `'unsafe-inline'`).
  CodeMirror theme, histogram and sparklines already read CSS variables.
- Shared components in `style.css`: buttons (primary, secondary, quiet,
  destructive; defines the missing `.btn-save`), status marker (icon shape + word),
  alert block (tinted background + thin border, no side stripe), dialog (native
  `<dialog>`), toast stack, drawer / bottom sheet.
- Breakpoints: ≤1024 px — Explore facets become a drawer behind "Filters (n)", side
  panels overlay the editor; ≤720 px — tabs become a bottom bar, Sites table and
  event stream become stacked rows, IP popover / Backups / Snippets / account menu
  become bottom sheets, find bar wraps.
- New JS modules under `src/static/js/app/ui/`: `dialog.js` (`confirmDialog`,
  `alertDialog`, returning promises), `toast.js` (`toast(msg, {kind, action})`),
  `theme.js`; and `format.js` (relative time with absolute time in `title`, country
  name via `Intl.DisplayNames` with the code as fallback, HTTP status text table).

## 2. Backend additions (backward compatible)

| Endpoint | New field / behaviour | Implementation |
|---|---|---|
| `/api/sites` | `previous_total`: request count in the equal-length window before the range; `null` if the index does not cover it | Count via bisect on `ts` in the same lock; no extra file reads beyond what the cache already holds |
| `/api/upstreams` | `unhealthy_since` (epoch or `null`) per upstream | Transitions persisted to `BACKUP_DIR/upstream-health.json` (atomic replace); first observer of a change records it; shared by all workers, survives restarts |
| `/api/upstreams` | `configured_sites`: number of distinct site hosts in Caddy's live config | From the config already fetched for the upstream map |
| `/api/status` | `last_change: {action, user, ts}` or `null` | Newest save/restore entry in the audit log |
| `/api/validate` | warning "Line N: not formatted — Check will fix whitespace on K lines" | Line diff of content vs `caddy fmt` output (already cached) |
| `/api/validate` | warning "Line N: upstream `host:port` could not be resolved from the console container" | `socket.getaddrinfo` per non-IP dial host, 1 s timeout, results cached 60 s, skips placeholders (`{…}`), never blocks save |
| `welcome.html` | "Manage the Caddy server at `<host>`" and allowed-list hint | Host from `SERVER_URL`, else request host |

## 3. Views

**Header:** brand mark + "Caddy Console"; tabs Dashboard / Explore / Editor; editor
tools [Find | Snippets | Backups], Check, Save & Reload (disabled "No changes" when
clean); account menu with avatar, session line, Theme picker, Editor keys picker
(Standard / Vim), shortcuts, log out, version.

**Dashboard:**
- Verdict block at the top, derived from existing data: critical upstream ("photos.example.com
  is down", "health check to 127.0.0.1:2283 has failed since 14:31", other sites'
  state, worst 5xx site) with "Investigate in Explore" and "Open <site> block"
  (switches to Editor and puts the cursor on that site's block). When nothing is
  wrong: a calm "All 7 sites are serving" line instead.
- Config card: syntax + modules, Caddy version, "Changed 3h ago by ops@…", file path.
- KPI row without boxes: requests (+n% vs previous window when available), 5xx rate
  ("28 errors, mostly torrent"), sites with traffic "7 of 7 configured", bandwidth
  out ("nas.example.com is 33%"). Every figure links to Explore.
- "Real IPs not logged" notice in the new alert style (How to fix, Dismiss + undo
  toast).
- Sites table: health marker + word, `high` / `slow` tags (5xx ≥ 10 %, p95 ≥ 2 s),
  sparkline; unhealthy row tinted.
- Recent changes: verb ("Saved", "Signed in", "Restored"), user, detail, relative
  time.

**Explore:** facets with "N values" and visible exclude buttons, excluded state =
strike + "excluded" tag + pressed button; Country facet shows names; query bar with
range chip, range select, Live; histogram with axis labels inside the plot, "now"
at the right edge, readout under the axis also driven by arrow keys; stats line;
stream rows; expanded row with status text ("504 Gateway timeout"), a duration
note "upstream timeout" when the status is 504, country name, "Cloudflare ray" with copy, raw JSON collapsed behind "Show
original log line"; IP popover restyled (bottom sheet on mobile).

**Editor:** validation warnings strip with line links; find/replace bar; Vim bar;
status bar shown only in the Editor; Backups and Snippets panels restyled; save-diff
modal and rollback / delete use `dialog.js`; results as toasts.

**Login:** on-system page, brand mark, server host line, Google button or Cloudflare
Access message, allowed-list hint.

## 4. Error handling

- New fields missing or `null` → the matching UI line is hidden, never shown as 0.
- `upstream-health.json` unreadable or corrupt → treated as empty and rewritten;
  `unhealthy_since` becomes "since this console noticed".
- DNS check timeouts → no warning (absence of evidence is not a failure).
- Theme storage blocked → follows the OS for that page.

## 5. Testing

- Python unit tests: `previous_total` (covered / not covered), `unhealthy_since`
  transitions across two simulated workers and restart, corrupt state file,
  `configured_sites`, `last_change`, fmt-diff warning line numbers, resolve warning
  (resolvable, unresolvable, IP literal, placeholder, timeout).
- JS unit tests: `format.js` (relative times, country names, status text),
  `theme.js` preference handling.
- Existing suites unchanged and passing.
- Manual in the dev stack: every view at 1440 / 1024 / 390 px, both themes, all
  dialogs, keyboard-only pass, impeccable detector clean on the built pages.
- Screenshots in `docs/screenshots/` regenerated.
