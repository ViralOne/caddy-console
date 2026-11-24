# IP Bans Phase 2 (CrowdSec File Sync) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An operator who adds the optional `docker-compose.crowdsec.yaml` overlay gets CrowdSec detections from Caddy's filtered access log turned into 403s on the sites that import `bans-crowdsec*.caddy`, normally within 60 seconds, through the same journaled file transaction as manual bans, while every baseline stack stays exactly as it is.

**Architecture:** A CrowdSec container reads the shared `caddy-logs` volume read-only and serves LAPI on an `internal: true` network that only the console joins. In the console, one gunicorn worker wins a non-blocking `flock` on `BACKUP_DIR/bans-sync.lock` and polls `GET /v1/decisions/stream` as a read-only bouncer (`startup=true` first, then deltas) with no lock held. It keeps the accepted decisions in memory and, at most once per `BANS_SYNC_INTERVAL`, reconciles them into `crowdsec` records in `bans.json` and renders `BANS_DIR/bans-crowdsec.caddy` with the Phase 1 `txn.apply_locked()` under `caddyfile_lock()`. Health is shared with the other workers through `BACKUP_DIR/bans-crowdsec-sync.json`. The Security view shows each source per site, the CrowdSec health, read-only decisions, ignored counts and capacity.

**Tech Stack:** Python 3 / Flask / gunicorn, stdlib `fcntl`/`decimal`/`json`, `requests` (already a dependency), `unittest`; Preact + htm (committed `explore-vendor.js`), plain ES modules, node `assert` scripts; stock `caddy:2.11.9-alpine`; `crowdsecurity/crowdsec:v1.8.2` pinned by digest in the optional overlay and the integration script.

**Spec:** `docs/superpowers/specs/2026-11-23-ip-bans-design.md` (binding). This plan covers "Phase 2: optional CrowdSec file-sync add-on" (2.1-2.7), the Phase 2 rows and parts of "Mode detection and health", "Configuration", "Audit and observability", "Error handling", "Testing" (Phase 2 unit tests and "Run the optional CrowdSec overlay"), the "Phase 2 gate", and the CrowdSec section of `docs/security.md`. Task 0 fixes three Phase 1 UI defects found during Phase 1 verification. The Phase 1 plan (`docs/superpowers/plans/2026-11-24-ip-bans-phase1.md`) describes the code this plan extends. Phases 3-4 are out of scope; their extension points are named under "Extension points" below.

## Global Constraints

- English everywhere (UI copy, comments, docs, commit messages).
- No new runtime dependencies: `pyproject.toml` `dependencies` and `package.json` stay unchanged. `npm run build` must leave `git diff -- src/static/js/` empty.
- No native `alert()`/`confirm()`/`prompt()` (`tests/no-native-dialogs.test.mjs`); confirmations use `src/static/js/app/ui/dialog.js`.
- Text from records, LAPI or API responses (value, scenario, origin, reason, actor, messages) is rendered only as text nodes (Preact text children or `textContent`). No `innerHTML`, `outerHTML`, `insertAdjacentHTML` or `dangerouslySetInnerHTML` in new or touched files.
- Commits use the already configured git identity. Never run `git config`. One commit per task with the message given in the task.
- Documentation and tests use `example.com` hostnames and documentation addresses only (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`). Nothing personal.
- Baseline Compose files (`docker-compose.{prod,internal,tunnel,nas,dev}.yaml`) are not changed in behaviour. CrowdSec lives only in `docker-compose.crowdsec.yaml` (and the NAS companion `docker-compose.crowdsec.nas.yaml`, see Task 9). `dev/check-compose.sh` keeps failing if a baseline file mentions CrowdSec.
- The CrowdSec image is `crowdsecurity/crowdsec:v1.8.2@sha256:65b74942f7e7ed5c60fde4ac15fc4ba715904c398c8b16dd451f4907d90347d4` (multi-arch index digest of tag `v1.8.2`, read with `docker buildx imagetools inspect crowdsecurity/crowdsec:v1.8.2`). It publishes no host ports, joins `crowdsec-lapi` (`internal: true`) and `crowdsec-egress` only, never `caddy-admin` or `console-ui`. Caddy never joins `crowdsec-lapi`.
- CrowdSec environment is exactly `COLLECTIONS: crowdsecurity/caddy`, `PARSERS: crowdsecurity/whitelists`, `DISABLE_ONLINE_API: "true"`, plus `BOUNCER_KEY_caddy_console` (the official image registers a bouncer named `caddy_console` with that key; changing a key later needs `cscli bouncers delete caddy_console` first).
- The bouncer key (`CROWDSEC_CONSOLE_BOUNCER_KEY`, or the file named by `CROWDSEC_CONSOLE_BOUNCER_KEY_FILE`) is sent only in the `X-Api-Key` header. It never appears in an exception message, log line, audit entry, status file, API response or the UI. Tests assert this.
- Lock order: `bans-sync.lock` (held by the leader for its lifetime) may be held while taking `caddyfile_lock()`; never the reverse. No LAPI HTTP request is made while `caddyfile_lock()` is held. `caddyfile_lock()` is not re-entrant: never call `service.availability()` (which takes it for its probe) while holding it.
- Background jobs start only from gunicorn's `post_worker_init` (or `app.py` in single-process dev), never in the master (see `src/bans/jobs.py`).
- LAPI stream: `GET {CROWDSEC_URL}/v1/decisions/stream?startup=true|false&scopes=Ip,Range&origins=<CROWDSEC_ORIGINS>` with `X-Api-Key`. Response `{"new": [...]|null, "deleted": [...]|null}`; each decision has `id` (integer), `origin`, `scenario`, `scope` (case varies: `Ip`, `ip`, `Range`), `type`, `value` (an IP may carry `/32`), `duration` (Go duration string, negative for deleted ones). `null` lists are empty lists.
- Configuration (spec table, Phase 2 rows): `BANS_SYNC_INTERVAL` default `30` (bounds 10-3600); `CROWDSEC_URL` default empty (empty disables CrowdSec); `CROWDSEC_CONSOLE_BOUNCER_KEY` default empty (plus `CROWDSEC_CONSOLE_BOUNCER_KEY_FILE`); `CROWDSEC_ORIGINS` default `crowdsec,cscli`; `CROWDSEC_POLL_INTERVAL` default `10` (bounds 5-300). An invalid `CROWDSEC_URL` or `CROWDSEC_ORIGINS` refuses startup like an invalid `BANS_NEVER`; a missing key is a health state, not a startup failure.
- `BANS_ENABLED=false` disables CrowdSec too: no sync thread, no CrowdSec snippets, no CrowdSec status.
- Generated CrowdSec policy shape is spec 2.5 verbatim: header comment, `vars caddy_console_crowdsec_policy 1`, then (only when decisions exist) `@caddy_console_crowdsec_banned { client_ip ...; not client_ip ... }` and `handle @caddy_console_crowdsec_banned { respond 403 }`.
- Any Caddyfile loaded into the dev `caddy-target` during integration MUST keep `admin 0.0.0.0:2019`.
- Test commands (CI uses `unittest`, not pytest): `uv run --frozen python -m unittest discover -s tests -t .` and `for t in tests/*.test.mjs; do node "$t" || exit 1; done`. One module: `uv run --frozen python -m unittest tests.test_crowdsec_lapi -v`.

## Review Focus

1. **A quiet LAPI answers `{"new": null, "deleted": null}`.** That is a successful empty poll, not a malformed response; nothing degrades and no snapshot is forced. Pinned by `test_null_lists_are_empty` (Task 2) and the FakeLapi, which sends `null` for every empty list in every Task 5 test.
2. **A decision arrives as `{"scope": "ip", "value": "91.241.19.122/32"}` (lowercase scope, host prefix) or as an IPv4-mapped IPv6 address.** It is one canonical IP (`91.241.19.122`), stored and rendered like a manual ban, and the Unban lookup finds it. Pinned by `test_ip_scope_accepts_host_prefix_case_and_mapped_ipv6` (Task 2).
3. **The same decisions come back on every snapshot (leader change, LAPI restart).** `bans.json` and the policy keep their bytes and Caddy is not reloaded; only a real change (new, removed, or extended by more than two minutes) writes. Pinned by `test_repeated_snapshot_is_idempotent` and `test_extended_decision_is_refreshed_without_a_reload` (Task 4).
4. **The operator removes `CROWDSEC_URL` after decisions were synced.** The stored CrowdSec records keep rendering until they expire or are reset; an install that never used CrowdSec never gets a `bans-crowdsec.caddy` and never reloads for it. Pinned by `test_unconfigured_install_never_creates_the_crowdsec_file` and `test_crowdsec_turned_off_keeps_expiring_and_resettable` (Task 3).
5. **CrowdSec bans the operator's own verified console address** (in the `management_addresses` registry, not in `BANS_NEVER`). The decision is ignored as `protected:operator`, never rendered, and shown in the protected sample. Pinned by `test_decision_for_a_verified_console_address_is_ignored` (Task 4).

---

## File Structure

**Backend (new, `src/bans/`):**
- `lapi.py`: CrowdSec settings (`url()`, `origins()`, `enabled()`, `read_key()`), Go duration parser, decision-stream client and decision classification. Pure apart from one `requests.get`.
- `sync.py`: `Leadership` (the `bans-sync.lock` flock) and `Synchronizer` (poll, merge, coalesced apply, health, transition audit).
- `syncstate.py`: read/write `BACKUP_DIR/bans-crowdsec-sync.json`, the health document every worker reads.

**Backend (modified):** `src/config.py` (Phase 2 rows), `src/bans/store.py` (CrowdSec record rules and constructor), `src/bans/render.py` (register `crowdsec`, `active_sources()`, total capacity), `src/bans/service.py` (active sources everywhere, `apply_crowdsec()`, per-source status and site rows, Task 0 unreachable status), `src/bans/scan.py` (`after=` for import position, per-source warnings), `src/bans/detect.py` (other sources' ban routes are not pre-handlers), `src/bans/jobs.py` (sync thread), `src/routes/editor.py` (CrowdSec warnings and snippet filter), `src/snippets.json` (two CrowdSec snippets).

**Frontend (new):** `src/static/js/app/security-crowdsec.js` (CrowdSec section of the Security view).

**Frontend (modified):** `security-model.js`, `security.js`, `ip-info.js`, `explore.js`, `snippet-insert.js`, `panels.js`, `main.js`.

**CrowdSec files (new, repository-owned, mounted read-only):** `crowdsec/acquis.d/caddy.yaml`, `crowdsec/parsers/s02-enrich/caddy-console-safe-fields.yaml`.

**Compose (new):** `docker-compose.crowdsec.yaml`, `docker-compose.crowdsec.nas.yaml`.

**Tests (new):** `tests/_crowdsec.py` (FakeLapi and helpers; not discovered), `tests/test_crowdsec_config.py`, `tests/test_crowdsec_lapi.py`, `tests/test_crowdsec_sources.py`, `tests/test_crowdsec_apply.py`, `tests/test_crowdsec_sync.py`, `tests/test_crowdsec_leader.py`, `tests/test_crowdsec_status.py`; integration `tests/integration/crowdsec_it.py` (not `test_*`, never discovered).

**Tests (modified):** `tests/test_bans_service.py`, `tests/test_bans_detect.py`, `tests/test_bans_api.py`, `tests/security-model.test.mjs`, `tests/ip-info.test.mjs`, `tests/snippet-insert.test.mjs`, `tests/integration/make_detect_fixtures.py`, `tests/fixtures/bans/adapted-layouts.json` (regenerated).

**Ops/docs:** `dev/check-compose.sh`, `dev/crowdsec-it.sh` (new), `dev/run.sh` (`down --remove-orphans`), `.github/workflows/docker-publish.yml`, `docs/security.md`, `docs/setup.md`, `docs/development.md`.

**Extension points kept for Phases 3-4:**
- `render.SOURCES` stays keyed by source; Phase 3's plugin route is a separate managed file with its own state, so it adds a `PolicySource`-like entry without touching `crowdsec`.
- `lapi.fetch_stream()` takes the key as an argument, so a Phase 3 display-only poll can reuse it with the console key while the plugin uses `CROWDSEC_PLUGIN_BOUNCER_KEY`.
- `service.protected_for()` stays the single protected-set builder; Phase 4 adds Cloudflare ranges through `protected.build(profile=...)` and the sync picks them up unchanged.
- Site rows carry `policies[<source>]`, so Phase 3 adds `"plugin"` and Phase 4 `"country"` without changing the row shape.
- `apply_crowdsec()` returns a `SyncApply`; Phase 4's dependency expansion can add `bans-crowdsec.caddy` to its one journal through `_candidates()`.

---

### Task 0: Phase 1 UI polish

Three fixes found during Phase 1 verification: (a) the Security ban list's Created column shows a raw absolute timestamp; (b) with Caddy unreachable every site says "Not loaded yet — Save & Reload to load this site into Caddy"; (c) the Explore IP popover closes when the Ban/Unban dialog is used, so the new badge only shows after reopening it.

Root causes: (a) `security.js` renders `absoluteTime(r.created_at)`; the dashboard uses `relativeTime` with the absolute time in `title` (`dashboard-model.js` returns `{rel, abs}`). (b) `service._site_rows()` gets no live rows when `live is None`, so every on-disk block falls into the `not_loaded` branch. (c) `ui/dialog.js` appends the `<dialog>` to `<body>`, outside `.ip-pop`; `explore.js`'s document-level `click`/`keydown`/`scroll` handlers treat a click, Esc or scroll inside the dialog as "outside the popover" and close it. `BanSection` already refetches after the dialog (`refresh(body)` bumps `tick`), so keeping the popover mounted is the whole fix.

**Files:**
- Modify: `src/static/js/app/security-model.js` (import from `format.js`; `createdCell`; `SITE.caddy_unreachable`)
- Modify: `src/static/js/app/security.js` (`BanList` Created cell)
- Modify: `src/bans/service.py` (`_site_rows`, `_management_status`)
- Modify: `src/static/js/app/ip-info.js` (append `keepsIpPopover`, `inDialog`)
- Modify: `src/static/js/app/explore.js:112-127` (popover close handlers)
- Test: `tests/security-model.test.mjs`, `tests/ip-info.test.mjs`, `tests/test_bans_service.py`

**Interfaces:**
- Produces: `createdCell(value, now = Date.now()) -> {text, title}` in `security-model.js`; site status value `"caddy_unreachable"` from `service.status()` rows (Task 6 keeps it per source); `keepsIpPopover(target) -> boolean` and `inDialog(target) -> boolean` in `ip-info.js`.

- [ ] **Step 1: Write the failing JS tests**

Append to `tests/security-model.test.mjs` before its final `console.log` line:

```js
console.log('\n--- Phase 1 polish ---');
const F = await import(path.join(APP, 'format.js'));
check('Created is relative, with the absolute time as its title', () => {
  const c = M.createdCell('2026-11-23T19:00:00Z', NOW);
  assert.equal(c.text, '1h ago');
  assert.equal(c.title, F.absoluteTime('2026-11-23T19:00:00Z'));
  assert.deepEqual(M.createdCell('garbage', NOW), { text: '', title: '' });
});
check('a site is unknown, not "not loaded", while Caddy is unreachable', () => {
  const s = M.siteStatus({ status: 'caddy_unreachable' });
  assert.equal(s.label, 'Unknown while Caddy is unreachable');
  assert.equal(s.tone, 'warn');
  assert.doesNotMatch(s.detail, /Save & Reload/);
  assert.match(s.detail, /admin API/);
  assert.deepEqual(M.siteActions({ status: 'caddy_unreachable', source: 'main', import: { present: true } }), []);
  assert.deepEqual(M.siteActions({ status: 'caddy_unreachable', source: 'main', import: { present: false } }), ['insert', 'copy']);
});
```

Append to `tests/ip-info.test.mjs` before its final `console.log` line (the file already imports `ip-info.js`; add `keepsIpPopover, inDialog` to that import's destructuring, or read them from the module object it already holds):

```js
// A fake event target: closest(selector) finds an ancestor matching any listed selector.
const at = (...ancestors) => ({ closest: (sel) => (sel.split(',').map(s => s.trim()).some(s => ancestors.includes(s)) ? {} : null) });
check('clicks inside the popover, its trigger or a modal dialog keep the IP popover open', () => {
  assert.equal(keepsIpPopover(at('.ip-pop')), true);
  assert.equal(keepsIpPopover(at('.field-value-click')), true);
  assert.equal(keepsIpPopover(at('dialog')), true);        // Ban/Unban dialogs live under <body>
  assert.equal(keepsIpPopover(at('.stream')), false);
  assert.equal(keepsIpPopover(null), false);
  assert.equal(keepsIpPopover({}), false);                 // document or window: no closest()
});
check('Esc and scroll inside a dialog belong to the dialog', () => {
  assert.equal(inDialog(at('dialog')), true);
  assert.equal(inDialog(at('.ip-pop')), false);
  assert.equal(inDialog(undefined), false);
});
```

(If `tests/ip-info.test.mjs` uses a different helper name than `check`, use its helper; keep the assertions.)

- [ ] **Step 2: Write the failing Python test**

Append to class `JournalRecoveryTest` in `tests/test_bans_service.py` (it holds the other site-row tests):

```python
    def test_sites_are_unknown_while_caddy_is_unreachable(self):
        _bans.write_caddyfile(f"a.example.com {{\n\timport {env.BANS_DIR}/bans-manual*.caddy\n\trespond 200\n}}\n"
                              "b.example.com {\n\trespond 200\n}\n"
                              "c.example.com { # caddy-console: management\n\trespond 200\n}\n")
        self.caddy.down = True
        sites = {s["label"]: s for s in service.status(None)["sites"]}
        self.assertEqual(sites["a.example.com"]["status"], "caddy_unreachable")
        self.assertTrue(sites["a.example.com"]["import"]["present"])
        self.assertEqual(sites["b.example.com"]["status"], "caddy_unreachable")
        self.assertIn("unreachable", sites["b.example.com"]["detail"])
        self.assertNotIn("Save & Reload", sites["b.example.com"]["detail"])
        self.assertEqual(sites["c.example.com"]["status"], "management")
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `node tests/security-model.test.mjs; node tests/ip-info.test.mjs; uv run --frozen python -m unittest tests.test_bans_service.JournalRecoveryTest.test_sites_are_unknown_while_caddy_is_unreachable -v`
Expected: FAIL (`M.createdCell is not a function`, `keepsIpPopover is not defined`, `'not_loaded' != 'caddy_unreachable'`).

- [ ] **Step 4: Implement (a) and the model half of (b)**

At the top of `src/static/js/app/security-model.js`, after the header comment:

```js
import { absoluteTime, relativeTime } from './format.js';
```

Below `durationLabel`:

```js
/** A table time cell: relative text, absolute time for the title tooltip (as the dashboard does). */
export function createdCell(value, now = Date.now()) {
  return { text: relativeTime(value, now), title: absoluteTime(value) };
}
```

In `SITE` add, after `not_loaded`:

```js
  caddy_unreachable: ['Unknown while Caddy is unreachable', 'warn'],
```

In `siteStatus`'s detail map add, after `not_loaded`:

```js
    caddy_unreachable: 'The Caddy admin API did not answer, so whether this site enforces the ban list cannot be checked. The import line on disk is shown as it is.',
```

`siteActions` needs no change: `caddy_unreachable` is not in its "nothing to offer" list, and `import.present` still suppresses the actions.

In `src/static/js/app/security.js`, add `createdCell` to the `./security-model.js` import, and replace the Created cell in `BanList`:

```js
          <td title=${createdCell(r.created_at).title}>${createdCell(r.created_at).text}</td>
```

- [ ] **Step 5: Implement the backend half of (b)**

In `src/bans/service.py`, in `_site_rows`, replace the fallback loop over unseen blocks with:

```python
    unreachable = live is None
    fallback = "caddy_unreachable" if unreachable else "not_loaded"
    fallback_detail = ("The Caddy admin API is unreachable, so whether this site enforces the ban list "
                       "cannot be checked." if unreachable
                       else "This site block is not in Caddy's running configuration.")
    for b in blocks:
        if b.start not in seen:
            imp = scan.block_import_state(text, b, src.path)
            rows.append({"label": b.hosts[0] if b.hosts else b.addresses[0], "hosts": b.hosts,
                         "status": _management_status(fallback, imp) if set(b.hosts) & management else fallback,
                         "pre_handlers": [], "detail": fallback_detail,
                         "source": "main", "line": b.start, "import": imp})
```

In `_management_status`, accept the new status as "not enforcing live":

```python
    if live_status in ("not_imported", "not_loaded", "caddy_unreachable") and not (imp and imp.get("present")):
```

- [ ] **Step 6: Implement (c)**

Append to `src/static/js/app/ip-info.js`:

```js
/** Whether a document-level click should leave the IP popover open: it landed
 * inside the popover, on its trigger, or inside one of the app's modal dialogs
 * (Ban/Unban), which ui/dialog.js appends to <body>, outside the popover. */
export function keepsIpPopover(target) {
  return !!(target && typeof target.closest === 'function' && target.closest('.ip-pop, .field-value-click, dialog'));
}

/** Whether a key or scroll event came from inside a modal dialog. */
export function inDialog(target) {
  return !!(target && typeof target.closest === 'function' && target.closest('dialog'));
}
```

In `src/static/js/app/explore.js`, add `import { inDialog, keepsIpPopover } from './ip-info.js';` with the other imports, and replace the three handlers in the IP-popover effect:

```js
  // The IP popover closes the same way, but clicks inside it must not. The
  // Ban/Unban dialogs are outside it (appended to <body>): a click, Esc or
  // scroll there belongs to the dialog, and the popover must survive it so its
  // ban state refreshes in place when the dialog completes.
  useEffect(() => {
    if (!ipPop) return;
    const close = (ev) => { if (!keepsIpPopover(ev.target)) setIpPop(null); };
    const esc = (ev) => { if (ev.key === 'Escape' && !inDialog(ev.target)) setIpPop(null); };
    // Fixed-position, so it would float away from its row on scroll.
    const scroll = (ev) => { if (!ev.target.closest?.('.ip-pop') && !inDialog(ev.target)) setIpPop(null); };
```

(The rest of the effect, the listener registration and cleanup, is unchanged.) After the dialog resolves, `BanSection`'s existing `refresh(body)` increments `tick`, which refetches `/api/bans?covering=` and shows or hides the Banned badge in place. Focus returns to the Ban/Unban button because `ui/dialog.js` restores the opener, which is still connected.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `node tests/security-model.test.mjs && node tests/ip-info.test.mjs && uv run --frozen python -m unittest tests.test_bans_service -v`
Expected: PASS.

- [ ] **Step 8: Check in the browser**

Run: `./dev/run.sh up`. In Security, the Created column shows "just now" with the absolute time on hover. Stop Caddy (`docker compose -f docker-compose.dev.yaml stop caddy-target`), refresh Security: site rows read "Unknown while Caddy is unreachable"; start it again. In Explore, open an event, click a public client IP, Ban…, confirm: the popover stays open and shows "Banned"; Unban: the badge disappears without reopening.

- [ ] **Step 9: Run the full suites and commit**

Run: `uv run --frozen python -m unittest discover -s tests -t . && for t in tests/*.test.mjs; do node "$t" || exit 1; done`

```bash
git add src/static/js/app/security-model.js src/static/js/app/security.js src/static/js/app/ip-info.js \
  src/static/js/app/explore.js src/bans/service.py tests/security-model.test.mjs tests/ip-info.test.mjs tests/test_bans_service.py
git commit -m "fix(security): relative Created time, Caddy-unreachable site status, IP popover survives Ban/Unban"
```

---

### Task 1: CrowdSec settings and the Go duration parser

**Files:**
- Modify: `src/config.py` (append after `BANS_NEVER`)
- Create: `src/bans/lapi.py` (settings and durations; Task 2 adds the client)
- Modify: `src/bans/service.py` (`init_config`)
- Test: `tests/test_crowdsec_config.py`

**Interfaces:**
- Produces: `config.BANS_SYNC_INTERVAL: int`, `config.CROWDSEC_URL: str`, `config.CROWDSEC_CONSOLE_BOUNCER_KEY: str`, `config.CROWDSEC_CONSOLE_BOUNCER_KEY_FILE: str`, `config.CROWDSEC_ORIGINS: str`, `config.CROWDSEC_POLL_INTERVAL: int`. In `lapi`: `ConfigError(ValueError)`, `parse_url(raw) -> str` (`""` when unset), `parse_origins(raw) -> tuple[str, ...]` (lowercased, unique, ordered), `url() -> str`, `origins() -> tuple`, `enabled() -> bool`, `read_key() -> (key | None, problem | None)`, `LIST_ORIGINS = ("capi", "lists")`, `parse_go_duration(text) -> float` (seconds; raises `ValueError`).
- Read settings as `config.X` at call time so tests can patch them.

- [ ] **Step 1: Write the failing test**

`tests/test_crowdsec_config.py`:

```python
"""CrowdSec settings, key handling and Go durations (spec 2.3, 2.4, Configuration).

Run with:  uv run --frozen python -m unittest tests.test_crowdsec_config -v
"""
import os
import tempfile
import unittest
from unittest import mock

import tests._env  # noqa: F401

from src import config
from src.bans import lapi, service


class SettingsTest(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual((config.BANS_SYNC_INTERVAL, config.CROWDSEC_POLL_INTERVAL), (30, 10))
        self.assertEqual(config.CROWDSEC_ORIGINS, "crowdsec,cscli")
        self.assertEqual(config.CROWDSEC_URL, "")          # tests/_env.py sets none: CrowdSec off
        self.assertFalse(lapi.enabled())

    def test_numeric_bounds(self):
        for name, low, high in (("BANS_SYNC_INTERVAL", 10, 3600), ("CROWDSEC_POLL_INTERVAL", 5, 300)):
            for bad in (str(low - 1), str(high + 1), "ten"):
                with self.subTest(name=name, bad=bad), mock.patch.dict(os.environ, {name: bad}):
                    with self.assertRaises(RuntimeError):
                        config.bounded_int(name, 1, low, high)

    def test_url(self):
        self.assertEqual(lapi.parse_url(""), "")
        self.assertEqual(lapi.parse_url(" http://crowdsec:8080/ "), "http://crowdsec:8080")
        self.assertEqual(lapi.parse_url("https://lapi.example.com"), "https://lapi.example.com")
        for bad in ("crowdsec:8080", "ftp://crowdsec", "http://user:pw@crowdsec:8080", "http://crowdsec:8080/v1",
                    "http://crowdsec:8080?x=1", "http://crowdsec:99999", "http://"):
            with self.subTest(bad=bad), self.assertRaises(lapi.ConfigError):
                lapi.parse_url(bad)

    def test_origins(self):
        self.assertEqual(lapi.parse_origins("crowdsec,cscli"), ("crowdsec", "cscli"))
        self.assertEqual(lapi.parse_origins(" CAPI, lists ,capi"), ("capi", "lists"))
        for bad in ("", " , ", "crowd sec", "a;b", "x" * 33):
            with self.subTest(bad=bad), self.assertRaises(lapi.ConfigError):
                lapi.parse_origins(bad)

    def test_enabled_needs_bans_and_a_url(self):
        with mock.patch.object(config, "CROWDSEC_URL", "http://crowdsec:8080"):
            self.assertTrue(lapi.enabled())
            with mock.patch.object(config, "BANS_ENABLED", False):
                self.assertFalse(lapi.enabled())

    def test_invalid_url_or_origins_refuse_startup(self):
        for name, value in (("CROWDSEC_URL", "crowdsec:8080"), ("CROWDSEC_ORIGINS", "a b")):
            with self.subTest(name=name), mock.patch.object(config, name, value):
                service.reset_caches()
                with self.assertRaises(RuntimeError) as cm:
                    service.init_config()
                self.assertIn(name, str(cm.exception))
        service.reset_caches()


class KeyTest(unittest.TestCase):
    def test_env_key(self):
        with mock.patch.multiple(config, CROWDSEC_CONSOLE_BOUNCER_KEY=" k3y-0123 ", CROWDSEC_CONSOLE_BOUNCER_KEY_FILE=""):
            self.assertEqual(lapi.read_key(), ("k3y-0123", None))

    def test_file_key_wins_and_problems_never_echo_the_key(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("file-key-456\n")
        self.addCleanup(os.remove, f.name)
        with mock.patch.multiple(config, CROWDSEC_CONSOLE_BOUNCER_KEY="env-key", CROWDSEC_CONSOLE_BOUNCER_KEY_FILE=f.name):
            self.assertEqual(lapi.read_key(), ("file-key-456", None))
        with mock.patch.multiple(config, CROWDSEC_CONSOLE_BOUNCER_KEY="", CROWDSEC_CONSOLE_BOUNCER_KEY_FILE=f.name + ".missing"):
            key, problem = lapi.read_key()
            self.assertIsNone(key)
            self.assertIn("CROWDSEC_CONSOLE_BOUNCER_KEY_FILE", problem)
        for bad in ("", "has space", "x" * 257, "café"):
            with self.subTest(bad=bad), mock.patch.multiple(config, CROWDSEC_CONSOLE_BOUNCER_KEY=bad,
                                                            CROWDSEC_CONSOLE_BOUNCER_KEY_FILE=""):
                key, problem = lapi.read_key()
                self.assertIsNone(key)
                if bad.strip():
                    self.assertNotIn(bad, problem)


class GoDurationTest(unittest.TestCase):
    def test_valid(self):
        cases = {"4h": 14400, "1.5h": 5400, "22h20m11.909761348s": 80411.909761348, "300ms": 0.3,
                 ".5s": 0.5, "1µs": 1e-6, "1μs": 1e-6, "1us": 1e-6, "2ns": 2e-9, "0": 0, "+3m": 180,
                 "-18897h25m52.809576151s": -(18897 * 3600 + 25 * 60 + 52.809576151), "167h59m20.890999684s": 604760.890999684}
        for text, seconds in cases.items():
            with self.subTest(text=text):
                self.assertAlmostEqual(lapi.parse_go_duration(text), seconds, places=9)

    def test_invalid(self):
        for bad in ("", "h", "4", "4d", "4h ", " 4h", "--1s", "1e3s", "1h" * 33, "999999999h", "1.2.3s", None, 5):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                lapi.parse_go_duration(bad)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run --frozen python -m unittest tests.test_crowdsec_config -v`
Expected: FAIL with `ImportError: cannot import name 'lapi'`.

- [ ] **Step 3: Add the settings**

Append to `src/config.py`:

```python
# CrowdSec file sync (docs/security.md#crowdsec-file-sync). Only the optional
# docker-compose.crowdsec.yaml sets CROWDSEC_URL; empty means no CrowdSec at all.
# src/bans/lapi.py validates the URL and origins; service.init_config() refuses
# startup on an invalid value. The key is read at poll time, never logged.
BANS_SYNC_INTERVAL = bounded_int("BANS_SYNC_INTERVAL", 30, 10, 3600)
CROWDSEC_URL = os.environ.get("CROWDSEC_URL", "")
CROWDSEC_CONSOLE_BOUNCER_KEY = os.environ.get("CROWDSEC_CONSOLE_BOUNCER_KEY", "")
CROWDSEC_CONSOLE_BOUNCER_KEY_FILE = os.environ.get("CROWDSEC_CONSOLE_BOUNCER_KEY_FILE", "").strip()
CROWDSEC_ORIGINS = os.environ.get("CROWDSEC_ORIGINS", "crowdsec,cscli")
CROWDSEC_POLL_INTERVAL = bounded_int("CROWDSEC_POLL_INTERVAL", 10, 5, 300)
```

- [ ] **Step 4: Create `src/bans/lapi.py` with settings and durations**

```python
"""CrowdSec Local API from the read-only bouncer side (spec 2.3, 2.4).

Settings, Go durations and the decision stream. The bouncer key is only ever
placed in the X-Api-Key header: it never appears in an exception message, a
log line, the status file, an audit entry or an API response.
"""
import re
from decimal import Decimal, InvalidOperation
from urllib.parse import urlsplit

from .. import config

KEY_MAX = 256
LIST_ORIGINS = ("capi", "lists")
_KEY = re.compile(r"^[\x21-\x7e]{1,256}$")
_ORIGIN = re.compile(r"^[a-z0-9_-]{1,32}$")


class ConfigError(ValueError):
    pass


def parse_url(raw) -> str:
    text = (raw or "").strip().rstrip("/")
    if not text:
        return ""
    parts = urlsplit(text)
    try:
        port_ok = parts.port is None or 0 < parts.port < 65536
    except ValueError:
        port_ok = False
    if (parts.scheme not in ("http", "https") or not parts.hostname or parts.username is not None
            or parts.password is not None or parts.path or parts.query or parts.fragment or not port_ok):
        raise ConfigError(f"CROWDSEC_URL must be http(s)://host[:port] and nothing else, got {text!r}")
    return text


def parse_origins(raw) -> tuple:
    out = []
    for item in (raw or "").split(","):
        item = item.strip().lower()
        if not item:
            continue
        if not _ORIGIN.match(item):
            raise ConfigError(f"CROWDSEC_ORIGINS has an invalid origin {item!r}")
        if item not in out:
            out.append(item)
    if not out:
        raise ConfigError("CROWDSEC_ORIGINS must list at least one origin, for example crowdsec,cscli")
    return tuple(out)


def url() -> str:
    return parse_url(config.CROWDSEC_URL)


def origins() -> tuple:
    return parse_origins(config.CROWDSEC_ORIGINS)


def enabled() -> bool:
    return bool(config.BANS_ENABLED and url())


def read_key():
    """(key, None) or (None, problem). The _FILE variant wins when set and is
    re-read on every poll, so a rotated secret is picked up (and forces a new
    startup snapshot, see sync.Synchronizer). Problems never contain the key."""
    path = config.CROWDSEC_CONSOLE_BOUNCER_KEY_FILE
    if path:
        try:
            with open(path, "rb") as f:
                text = f.read(KEY_MAX + 2).decode("utf-8", "replace").strip()
        except OSError as e:
            return None, f"Cannot read CROWDSEC_CONSOLE_BOUNCER_KEY_FILE ({e.strerror or type(e).__name__})."
    else:
        text = (config.CROWDSEC_CONSOLE_BOUNCER_KEY or "").strip()
    if not text:
        return None, "No bouncer key: set CROWDSEC_CONSOLE_BOUNCER_KEY or CROWDSEC_CONSOLE_BOUNCER_KEY_FILE."
    if not _KEY.match(text):
        return None, "The bouncer key must be 1-256 printable ASCII characters without spaces."
    return text, None


# --- Go durations (time.ParseDuration) ----------------------------------------------

_UNITS = {"ns": Decimal("1e-9"), "us": Decimal("1e-6"), "µs": Decimal("1e-6"), "μs": Decimal("1e-6"),
          "ms": Decimal("1e-3"), "s": Decimal(1), "m": Decimal(60), "h": Decimal(3600)}
_PART = re.compile(r"(\d+(?:\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h)")
DURATION_MAX_TEXT = 64
DURATION_MAX_SECONDS = Decimal(100 * 366 * 86400)


def parse_go_duration(text) -> float:
    """Seconds as a float, negative for LAPI's deleted decisions. Bounded: at
    most 64 characters and 100 years, so a hostile payload cannot cost much."""
    if not isinstance(text, str) or not 0 < len(text) <= DURATION_MAX_TEXT:
        raise ValueError("duration must be a short string")
    sign, body = 1, text
    if body[0] in "+-":
        sign, body = (-1 if body[0] == "-" else 1), body[1:]
    if body == "0":
        return 0.0
    if not body:
        raise ValueError(f"invalid duration {text!r}")
    total, pos = Decimal(0), 0
    while pos < len(body):
        m = _PART.match(body, pos)
        if not m:
            raise ValueError(f"invalid duration {text!r}")
        try:
            total += Decimal(m.group(1)) * _UNITS[m.group(2)]
        except InvalidOperation:
            raise ValueError(f"invalid duration {text!r}") from None
        if total > DURATION_MAX_SECONDS:
            raise ValueError(f"duration {text!r} is out of range")
        pos = m.end()
    return float(sign * total)
```

- [ ] **Step 5: Validate at startup**

In `src/bans/service.py`, add `lapi` to the `from . import ...` line and extend `init_config`:

```python
def init_config() -> None:
    """create_app() calls this: an invalid BANS_NEVER, CROWDSEC_URL or
    CROWDSEC_ORIGINS refuses startup."""
    try:
        never_networks()
    except protected.ConfigError as e:
        raise RuntimeError(f"BANS_NEVER has an {e}") from e
    try:
        lapi.parse_url(config.CROWDSEC_URL)
        lapi.parse_origins(config.CROWDSEC_ORIGINS)
    except lapi.ConfigError as e:
        raise RuntimeError(str(e)) from e
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `uv run --frozen python -m unittest tests.test_crowdsec_config -v && uv run --frozen python -m unittest discover -s tests -t .`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/config.py src/bans/lapi.py src/bans/service.py tests/test_crowdsec_config.py
git commit -m "feat(crowdsec): settings, bouncer key handling and a bounded Go duration parser"
```

---

### Task 2: LAPI decision-stream client and decision classification

**Files:**
- Modify: `src/bans/lapi.py` (append the client)
- Create: `tests/_crowdsec.py` (FakeLapi and helpers; not a test module)
- Test: `tests/test_crowdsec_lapi.py`

**Interfaces:**
- Consumes: `lapi.parse_go_duration`, `addr.canonical`, `addr.check_width`, `addr.scope_of`.
- Produces in `lapi`: `STREAM_PATH = "/v1/decisions/stream"`, `MAX_BYTES = 32 MiB`, `MAX_DECISIONS = 200000`; exceptions `LapiUnavailable`, `LapiAuthError`, `LapiMalformed` (messages are safe, never the key); `Decision(id: str, scope: str, value: str, type: str, origin: str, scenario: str, remaining: float)`; `Stream(new: tuple[Decision], deleted: tuple[str])`; `Accepted(decision_id: str, net, origin: str, scenario: str, fetched_at: datetime, expires_at: datetime)`; `fetch_stream(base_url, key, *, startup: bool, origins: tuple) -> Stream`; `parse_stream(body: bytes) -> Stream`; `classify(d: Decision, origins: tuple, fetched_at) -> (Accepted | None, reason | None)` with reasons `not_ban`, `scope`, `origin`, `expired`, `invalid_value`, `too_wide` (`IGNORE_REASONS`).
- Produces in `tests/_crowdsec.py`: `URL`, `KEY`, `enable(test, **extra)`, `accepted(value, decision_id="1", origin="crowdsec", scenario=..., hours=4, now=None)`, `FakeLapi` with `add(...) -> str`, `delete(id)`, `mode` (`ok|down|status|raw`), `status`, `raw`, `calls`, `install(test)`. Install FakeLapi after `_bans.FakeCaddy`; it delegates every non-LAPI GET to the previously installed `requests.get`.

- [ ] **Step 1: Write the FakeLapi**

`tests/_crowdsec.py`:

```python
"""Shared fixtures for the CrowdSec tests (not a test module: never discovered).

FakeLapi stands in for CrowdSec's Local API by patching requests.get. Install it
after _bans.FakeCaddy: GETs that are not for URL go to the previous requests.get,
so both fakes work in one test. Empty lists are sent as null, as LAPI does.
"""
import json
from datetime import timedelta
from unittest import mock

import requests

from src import config

URL = "http://crowdsec.invalid:8080"
KEY = "console-test-key-6f1d0c2a9b"


def enable(test, **extra):
    values = {"CROWDSEC_URL": URL, "CROWDSEC_CONSOLE_BOUNCER_KEY": KEY, "CROWDSEC_CONSOLE_BOUNCER_KEY_FILE": "",
              "CROWDSEC_ORIGINS": "crowdsec,cscli", **extra}
    for name, value in values.items():
        p = mock.patch.object(config, name, value)
        p.start()
        test.addCleanup(p.stop)


def accepted(value, decision_id="1", origin="crowdsec", scenario="crowdsecurity/http-probing", hours=4, now=None):
    from src.bans import addr, lapi, store
    now = now or store.utc_now()
    return lapi.Accepted(str(decision_id), addr.canonical(value), origin, scenario, now, now + timedelta(hours=hours))


class FakeStreamResponse:
    def __init__(self, status_code=200, body=b""):
        self.status_code, self.body, self.closed = status_code, body, False
        self.headers = {"Content-Type": "application/json"}

    def iter_content(self, chunk_size=1):
        for i in range(0, len(self.body), chunk_size):
            yield self.body[i:i + chunk_size]

    def close(self):
        self.closed = True


class FakeLapi:
    def __init__(self):
        self.current = {}                    # id -> decision dict, the active set
        self.new_since, self.deleted_since = [], []
        self.mode = "ok"                     # ok | down | status | raw
        self.status = 200
        self.raw = b""
        self.calls = []
        self._seq = 100

    def add(self, value, *, scope="Ip", type="ban", origin="crowdsec", scenario="crowdsecurity/http-probing",
            duration="3h59m58.5s", id=None):
        if id is None:
            self._seq += 1
            id = self._seq
        d = {"id": int(id), "scope": scope, "value": value, "type": type, "origin": origin,
             "scenario": scenario, "duration": duration}
        self.current[str(id)] = d
        self.new_since.append(d)
        return str(id)

    def delete(self, id):
        d = self.current.pop(str(id), None) or {"id": int(id), "scope": "Ip", "value": "192.0.2.250", "type": "ban",
                                                "origin": "crowdsec", "scenario": "x"}
        self.deleted_since.append({**d, "duration": "-1m5.5s"})

    def _body(self, startup):
        if startup:
            new, deleted = list(self.current.values()), []
        else:
            new, deleted = self.new_since, self.deleted_since
        self.new_since, self.deleted_since = [], []
        return json.dumps({"new": new or None, "deleted": deleted or None}).encode()

    def _get(self, url, params=None, headers=None, timeout=None, **kw):
        if not url.startswith(URL):
            return self._prev(url, params=params, headers=headers, timeout=timeout, **kw)
        self.calls.append({"path": url[len(URL):], "params": dict(params or {}),
                           "key": (headers or {}).get("X-Api-Key"), "stream": kw.get("stream"),
                           "allow_redirects": kw.get("allow_redirects"), "timeout": timeout})
        if self.mode == "down":
            raise requests.ConnectionError("fake lapi is down")
        if self.mode == "status":
            return FakeStreamResponse(self.status, b'{"message":"access forbidden"}')
        if self.mode == "raw":
            return FakeStreamResponse(200, self.raw)
        return FakeStreamResponse(200, self._body((params or {}).get("startup") == "true"))

    def install(self, test):
        self._prev = requests.get
        p = mock.patch.object(requests, "get", self._get)
        p.start()
        test.addCleanup(p.stop)
        return self
```

- [ ] **Step 2: Write the failing test**

`tests/test_crowdsec_lapi.py`:

```python
"""Decision stream client and classification (spec 2.4).

Run with:  uv run --frozen python -m unittest tests.test_crowdsec_lapi -v
"""
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import tests._env  # noqa: F401
from tests import _bans, _crowdsec

from src.bans import addr, lapi

NOW = datetime(2026, 11, 24, 12, 0, 0, tzinfo=timezone.utc)
ORIGINS = ("crowdsec", "cscli")


def d(**kw):
    base = {"id": "7", "scope": "Ip", "value": "203.0.113.7", "type": "ban", "origin": "crowdsec",
            "scenario": "crowdsecurity/http-probing", "remaining": 3600.0}
    base.update(kw)
    return lapi.Decision(**base)


class FetchTest(unittest.TestCase):
    def setUp(self):
        _bans.FakeCaddy().install(self)
        self.lapi = _crowdsec.FakeLapi().install(self)

    def test_request_shape(self):
        self.lapi.add("203.0.113.7")
        stream = lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=ORIGINS)
        call = self.lapi.calls[0]
        self.assertEqual(call["path"], "/v1/decisions/stream")
        self.assertEqual(call["params"], {"startup": "true", "scopes": "Ip,Range", "origins": "crowdsec,cscli"})
        self.assertEqual((call["key"], call["stream"], call["allow_redirects"]), (_crowdsec.KEY, True, False))
        self.assertEqual([x.value for x in stream.new], ["203.0.113.7"])
        lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=False, origins=ORIGINS)
        self.assertEqual(self.lapi.calls[1]["params"]["startup"], "false")

    def test_null_lists_are_empty(self):
        stream = lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=False, origins=ORIGINS)
        self.assertEqual((stream.new, stream.deleted), ((), ()))

    def test_errors_are_typed_and_never_carry_the_key(self):
        self.lapi.mode = "down"
        with self.assertRaises(lapi.LapiUnavailable) as cm:
            lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=ORIGINS)
        self.assertNotIn(_crowdsec.KEY, str(cm.exception))
        self.lapi.mode = "status"
        for status, exc in ((401, lapi.LapiAuthError), (403, lapi.LapiAuthError), (500, lapi.LapiUnavailable)):
            self.lapi.status = status
            with self.subTest(status=status), self.assertRaises(exc) as cm:
                lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=ORIGINS)
            self.assertNotIn(_crowdsec.KEY, str(cm.exception))

    def test_oversized_response_is_malformed(self):
        self.lapi.mode, self.lapi.raw = "raw", b" " * 64
        with mock.patch.object(lapi, "MAX_BYTES", 32), self.assertRaises(lapi.LapiMalformed):
            lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=ORIGINS)


class ParseTest(unittest.TestCase):
    def body(self, new=None, deleted=None):
        return json.dumps({"new": new, "deleted": deleted}).encode()

    def item(self, **kw):
        base = {"id": 2266, "origin": "CAPI", "scenario": "crowdsecurity/http-sensitive-files", "scope": "ip",
                "type": "ban", "value": "91.241.19.122/32", "duration": "22h20m11.909761348s"}
        base.update(kw)
        return base

    def test_documented_example(self):
        stream = lapi.parse_stream(self.body([self.item()], [self.item(id=1, duration="-18897h25m52.809576151s")]))
        self.assertEqual(stream.new[0].id, "2266")
        self.assertAlmostEqual(stream.new[0].remaining, 80411.909761348)
        self.assertEqual(stream.deleted, ("1",))

    def test_any_bad_item_rejects_the_whole_response(self):
        bad_items = [{"id": "x"}, self.item(id=True), self.item(id=0), self.item(duration="4d"),
                     self.item(value=7), self.item(value="x" * 65), self.item(scope=None), "nope"]
        for item in bad_items:
            with self.subTest(item=item), self.assertRaises(lapi.LapiMalformed):
                lapi.parse_stream(self.body([self.item(), item]))
        for raw in (b"", b"[]", b"{", b'{"new": {}}', "ÿ".encode("latin-1"), b'{"new": []}'):
            with self.subTest(raw=raw), self.assertRaises(lapi.LapiMalformed):
                lapi.parse_stream(raw)

    def test_too_many_decisions(self):
        with mock.patch.object(lapi, "MAX_DECISIONS", 1), self.assertRaises(lapi.LapiMalformed):
            lapi.parse_stream(self.body([self.item(), self.item(id=2)]))

    def test_missing_scenario_is_empty(self):
        item = self.item()
        del item["scenario"]
        self.assertEqual(lapi.parse_stream(self.body([item])).new[0].scenario, "")


class ClassifyTest(unittest.TestCase):
    def test_ban_ip_and_range(self):
        a, reason = lapi.classify(d(), ORIGINS, NOW)
        self.assertIsNone(reason)
        self.assertEqual((a.decision_id, addr.token(a.net), a.expires_at), ("7", "203.0.113.7", NOW + timedelta(hours=1)))
        a, _ = lapi.classify(d(scope="Range", value="198.51.100.0/24"), ORIGINS, NOW)
        self.assertEqual(addr.token(a.net), "198.51.100.0/24")

    def test_ip_scope_accepts_host_prefix_case_and_mapped_ipv6(self):
        for scope, value in (("ip", "91.241.19.122/32"), ("IP", "91.241.19.122"), ("Ip", "::ffff:91.241.19.122")):
            with self.subTest(value=value):
                a, reason = lapi.classify(d(scope=scope, value=value), ORIGINS, NOW)
                self.assertEqual((reason, addr.token(a.net)), (None, "91.241.19.122"))

    def test_ignored_reasons(self):
        cases = (
            (d(type="captcha"), "not_ban"),
            (d(scope="Country", value="RO"), "scope"),
            (d(origin="CAPI"), "origin"),
            (d(remaining=0.9), "expired"),
            (d(remaining=-5), "expired"),
            (d(value="not-an-ip"), "invalid_value"),
            (d(scope="Ip", value="198.51.100.0/24"), "invalid_value"),
            (d(scope="Range", value="198.0.0.0/8"), "too_wide"),
            (d(scope="Range", value="2001:db8::/32"), "too_wide"),
        )
        for decision, reason in cases:
            with self.subTest(reason=reason, value=decision.value):
                self.assertEqual(lapi.classify(decision, ORIGINS, NOW), (None, reason))

    def test_origin_compare_is_case_insensitive(self):
        a, reason = lapi.classify(d(origin="CAPI"), ("capi",), NOW)
        self.assertIsNone(reason)
        self.assertEqual(a.origin, "CAPI")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run --frozen python -m unittest tests.test_crowdsec_lapi -v`
Expected: FAIL with `AttributeError: module 'src.bans.lapi' has no attribute 'fetch_stream'`.

- [ ] **Step 4: Implement the client**

Add to the imports of `src/bans/lapi.py`:

```python
import json
from dataclasses import dataclass
from datetime import timedelta

import requests as http_client

from . import addr
```

Append:

```python
# --- decision stream (spec 2.4) --------------------------------------------------------

STREAM_PATH = "/v1/decisions/stream"
SCOPES = "Ip,Range"
TIMEOUT = (3.05, 15)
MAX_BYTES = 32 * 1024 * 1024
MAX_DECISIONS = 200000
IGNORE_REASONS = ("not_ban", "scope", "origin", "expired", "invalid_value", "too_wide")


class LapiUnavailable(Exception):
    pass


class LapiAuthError(Exception):
    pass


class LapiMalformed(Exception):
    pass


@dataclass(frozen=True)
class Decision:
    id: str
    scope: str
    value: str
    type: str
    origin: str
    scenario: str
    remaining: float


@dataclass(frozen=True)
class Stream:
    new: tuple
    deleted: tuple


@dataclass(frozen=True)
class Accepted:
    decision_id: str
    net: object
    origin: str
    scenario: str
    fetched_at: object
    expires_at: object


def _read_bounded(resp) -> bytes:
    chunks, size = [], 0
    try:
        for chunk in resp.iter_content(65536):
            size += len(chunk)
            if size > MAX_BYTES:
                raise LapiMalformed("the response is larger than 32 MiB")
            chunks.append(chunk)
    except http_client.RequestException as e:
        raise LapiUnavailable(f"reading the response failed ({type(e).__name__})") from None
    return b"".join(chunks)


def fetch_stream(base_url, key, *, startup: bool, origins) -> Stream:
    """One poll. Raises LapiUnavailable, LapiAuthError or LapiMalformed; the
    messages name only exception types and status codes, never the key."""
    params = {"startup": "true" if startup else "false", "scopes": SCOPES, "origins": ",".join(origins)}
    headers = {"X-Api-Key": key, "Accept": "application/json", "User-Agent": "caddy-console"}
    try:
        resp = http_client.get(base_url + STREAM_PATH, params=params, headers=headers, timeout=TIMEOUT,
                               stream=True, allow_redirects=False)
    except http_client.RequestException as e:
        raise LapiUnavailable(type(e).__name__) from None
    try:
        if resp.status_code in (401, 403):
            raise LapiAuthError(f"HTTP {resp.status_code}")
        if resp.status_code != 200:
            raise LapiUnavailable(f"HTTP {resp.status_code}")
        body = _read_bounded(resp)
    finally:
        resp.close()
    return parse_stream(body)


def _text(item, name, limit, required=True) -> str:
    value = item.get(name)
    if value is None and not required:
        return ""
    if not isinstance(value, str) or len(value) > limit:
        raise LapiMalformed(f"decision field {name!r} is missing or invalid")
    return value


def _decision(item) -> Decision:
    if not isinstance(item, dict):
        raise LapiMalformed("a decision is not an object")
    did = item.get("id")
    if isinstance(did, bool) or not isinstance(did, int) or not 0 < did < 10 ** 20:
        raise LapiMalformed("decision field 'id' is missing or invalid")
    try:
        remaining = parse_go_duration(item.get("duration"))
    except ValueError:
        raise LapiMalformed("decision field 'duration' is missing or invalid") from None
    return Decision(str(did), _text(item, "scope", 16), _text(item, "value", 64), _text(item, "type", 32),
                    _text(item, "origin", 64), _text(item, "scenario", 256, required=False), remaining)


def parse_stream(body: bytes) -> Stream:
    """The whole response or nothing: one bad item rejects all of it (spec 2.6)."""
    try:
        doc = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise LapiMalformed("the response is not JSON") from None
    if not isinstance(doc, dict) or "new" not in doc or "deleted" not in doc:
        raise LapiMalformed("the response has no new/deleted lists")
    lists = []
    for name in ("new", "deleted"):
        items = doc[name]
        if items is None:
            items = []
        if not isinstance(items, list):
            raise LapiMalformed(f"{name!r} is not a list")
        lists.append(items)
    if len(lists[0]) + len(lists[1]) > MAX_DECISIONS:
        raise LapiMalformed(f"more than {MAX_DECISIONS} decisions in one response")
    return Stream(tuple(_decision(i) for i in lists[0]), tuple(_decision(i).id for i in lists[1]))


def classify(d: Decision, origins, fetched_at):
    """(Accepted, None) or (None, reason). The protected-set check needs the
    stored management registry, so service.apply_crowdsec() does it later."""
    if d.type.lower() != "ban":
        return None, "not_ban"
    scope = d.scope.lower()
    if scope not in ("ip", "range"):
        return None, "scope"
    if d.origin.lower() not in origins:
        return None, "origin"
    seconds = int(d.remaining)              # floor: never ban longer than CrowdSec says
    if seconds <= 0:
        return None, "expired"
    try:
        net = addr.canonical(d.value)
    except addr.AddressError:
        return None, "invalid_value"
    if scope == "ip" and addr.scope_of(net) != "ip":
        return None, "invalid_value"
    try:
        addr.check_width(net)
    except addr.AddressError:
        return None, "too_wide"
    return Accepted(d.id, net, d.origin, d.scenario, fetched_at, fetched_at + timedelta(seconds=seconds)), None
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run --frozen python -m unittest tests.test_crowdsec_lapi tests.test_crowdsec_config -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/bans/lapi.py tests/_crowdsec.py tests/test_crowdsec_lapi.py
git commit -m "feat(crowdsec): read-only LAPI decision-stream client with bounded parsing"
```

---

### Task 3: CrowdSec records, the `crowdsec` policy source and total capacity

**Files:**
- Modify: `src/bans/store.py` (`_check_record`, `new_crowdsec_record`)
- Modify: `src/bans/render.py` (register `crowdsec`, `active_sources`, `check_capacity`, `CapacityError.by_source`)
- Modify: `src/bans/service.py` (`_holds`, `_candidates`, `_transact`, `expire_tick`, `reapply`, `reset`, `list_bans`, `_public`)
- Test: `tests/test_crowdsec_sources.py`; existing `tests/test_bans_store.py`, `tests/test_bans_render.py`, `tests/test_bans_service.py` stay green.

**Interfaces:**
- Consumes: `lapi.Accepted` (Task 2) only through `new_crowdsec_record` arguments.
- Produces: `store.new_crowdsec_record(decision_id: str, net, origin: str, scenario: str, fetched_at, expires_at) -> Record` (id `crowdsec-<decision id>`, actor `system`, reason `""`, `created_at` = fetch time); `render.SOURCES["crowdsec"]`; `render.active_sources(state=None) -> dict[name, PolicySource]`; `render.check_capacity(by_source: dict[str, int], limit: int)` raising `CapacityError(count, limit, by_source)`; `service._candidates(state, prot, holds, now)` now renders every active source and checks the total; `service._transact(..., affects=("manual",))`; `list_bans()` adds `rendered_by_source`; `_public()` adds `source_id`.
- Schema decision (see "Spec decisions"): `bans.json` stays at schema version 1. A CrowdSec record keeps `fetched_at` in `created_at`; only `type=ban` decisions are stored, so `type` is implicit.

- [ ] **Step 1: Write the failing test**

`tests/test_crowdsec_sources.py`:

```python
"""The crowdsec source beside manual: records, rendering, capacity, expiry,
holds, Re-apply and Reset (spec 2.4, 2.5, 1.6).

Run with:  uv run --frozen python -m unittest tests.test_crowdsec_sources -v
"""
import os
import unittest
from datetime import timedelta
from unittest import mock

import tests._env as env
from tests import _bans, _crowdsec

from src import audit, config
from src.bans import addr, fsio, protected, render, service, store

CS = render.SOURCES["crowdsec"]
MANUAL = render.SOURCES["manual"]
BOTH = ("example.com {{\n\timport {d}/bans-manual*.caddy\n\timport {d}/bans-crowdsec*.caddy\n"
        "\trespond 200\n}}\n").format(d=env.BANS_DIR)


def cs_record(value, decision_id, hours=4, now=None):
    now = now or store.utc_now()
    return store.new_crowdsec_record(str(decision_id), addr.canonical(value), "crowdsec",
                                     "crowdsecurity/http-probing", now, now + timedelta(hours=hours))


def put_records(*records):
    state = store.load()
    state.records.extend(records)
    fsio.atomic_write(store.STATE_PATH, store.dumps(state), 0o600)


class SourcesCase(unittest.TestCase):
    def setUp(self):
        _bans.reset(BOTH)
        _bans.fresh_audit(self)
        service.reset_caches()
        docker = mock.patch.object(protected, "read_docker_networks", lambda: [])
        docker.start()
        self.addCleanup(docker.stop)
        self.caddy = _bans.FakeCaddy().install(self)

    def tearDown(self):
        service.reset_caches()

    def ban(self, value="203.0.113.7"):
        return service.add_ban({"value": value, "duration": "24h", "reason": ""}, "admin@example.com", None)


class RecordTest(SourcesCase):
    def test_crowdsec_record_round_trip_and_rules(self):
        r = cs_record("203.0.113.9", 42)
        self.assertEqual((r.id, r.source, r.source_id, r.actor, r.reason, r.origin), (
            "crowdsec-42", "crowdsec", "42", "system", "", "crowdsec"))
        state = store.State(records=[r])
        self.assertEqual(store.parse(store.dumps(state)).records[0], r)
        for field, bad in (("source_id", None), ("source_id", "4x"), ("source_id", "1" * 21),
                           ("origin", None), ("origin", ""), ("reason", "manual note")):
            broken = store.Record(**{**r.__dict__, field: bad})
            with self.subTest(field=field, bad=bad), self.assertRaises(store.StateCorrupt):
                store.parse(store.dumps(store.State(records=[broken])))


class RenderTest(SourcesCase):
    def test_crowdsec_policy_shape(self):
        data = render.render_policy(CS, [addr.canonical("203.0.113.9")], ["private_ranges"], 10)
        self.assertEqual(data.decode(), render.HEADER + "vars caddy_console_crowdsec_policy 1\n"
                         "@caddy_console_crowdsec_banned {\n\tclient_ip 203.0.113.9\n\tnot client_ip private_ranges\n}\n"
                         "handle @caddy_console_crowdsec_banned {\n\trespond 403\n}\n")
        self.assertEqual(render.render_policy(CS, [], ["private_ranges"], 10).decode(),
                         render.HEADER + "vars caddy_console_crowdsec_policy 1\n")
        self.assertEqual((CS.glob, CS.import_line), ("bans-crowdsec*.caddy", f"import {env.BANS_DIR}/bans-crowdsec*.caddy"))

    def test_active_sources(self):
        self.assertEqual(list(render.active_sources(store.State())), ["manual"])
        self.assertEqual(list(render.active_sources(None)), ["manual"])
        self.assertIn("crowdsec", render.active_sources(store.State(records=[cs_record("203.0.113.9", 1)])))
        self.assertIn("crowdsec", render.active_sources(store.State(last_rendered_hashes={CS.filename: "sha256:" + "0" * 64})))
        with mock.patch.object(config, "CROWDSEC_URL", _crowdsec.URL):
            self.assertEqual(list(render.active_sources(store.State())), ["manual", "crowdsec"])

    def test_check_capacity_counts_the_total(self):
        render.check_capacity({"manual": 2, "crowdsec": 1}, 3)
        with self.assertRaises(render.CapacityError) as cm:
            render.check_capacity({"manual": 2, "crowdsec": 2}, 3)
        self.assertEqual((cm.exception.count, cm.exception.limit, cm.exception.by_source),
                         (4, 3, {"manual": 2, "crowdsec": 2}))


class ServiceSourcesTest(SourcesCase):
    def test_unconfigured_install_never_creates_the_crowdsec_file(self):
        self.assertEqual(self.ban()[1], 201)
        self.assertFalse(os.path.exists(CS.path))
        self.assertNotIn(CS.filename, store.load().last_rendered_hashes)

    def test_configured_crowdsec_renders_an_empty_policy_beside_manual(self):
        _crowdsec.enable(self)
        self.assertEqual(self.ban()[1], 201)
        state = store.load()
        self.assertEqual(fsio.read_bytes(CS.path), render.HEADER.encode() + b"vars caddy_console_crowdsec_policy 1\n")
        self.assertEqual(state.last_rendered_hashes[CS.filename], fsio.sha256_tag(fsio.read_bytes(CS.path)))
        self.assertIn(b"203.0.113.7", fsio.read_bytes(MANUAL.path))

    def test_capacity_counts_both_sources(self):
        _crowdsec.enable(self)
        put_records(cs_record("198.51.100.9", 1))
        with mock.patch.object(config, "BANS_MAX", 2):
            self.assertEqual(self.ban("203.0.113.7")[1], 201)
            body, status = self.ban("203.0.113.8")
        self.assertEqual((status, body["code"]), (409, "capacity_exceeded"))
        self.assertEqual([r.value for r in store.load().records if r.source == "manual"], ["203.0.113.7"])

    def test_crowdsec_records_expire_through_the_tick(self):
        _crowdsec.enable(self)
        now = store.utc_now()
        put_records(cs_record("198.51.100.9", 1, hours=1, now=now))
        self.assertEqual(service.reapply({"source": "crowdsec"}, "op", None)[1], 200)   # render it once
        self.assertIn(b"198.51.100.9", fsio.read_bytes(CS.path))
        self.assertEqual(service.expire_tick(now + timedelta(hours=2)), "applied")
        self.assertNotIn(b"198.51.100.9", fsio.read_bytes(CS.path))
        self.assertIn("ban_expired", [e["action"] for e in audit.iter_entries()])

    def test_crowdsec_turned_off_keeps_expiring_and_resettable(self):
        _crowdsec.enable(self)
        now = store.utc_now()
        put_records(cs_record("198.51.100.9", 1, hours=1, now=now))
        self.assertEqual(service.reapply({"source": "crowdsec"}, "op", None)[1], 200)
        with mock.patch.object(config, "CROWDSEC_URL", ""):
            self.assertIn("crowdsec", render.active_sources(store.load()))
            version = store.load().version
            body, status = service.reset({"source": "crowdsec", "version": version, "confirm": True}, "op", None)
            self.assertEqual(status, 200, body)
            self.assertNotIn(b"198.51.100.9", fsio.read_bytes(CS.path))
            self.assertIn("unless", body["message"])

    def test_reset_crowdsec_is_not_enabled_without_crowdsec_state(self):
        version = store.load().version
        body, _ = service.reset({"source": "crowdsec", "version": version, "confirm": True}, "op", None)
        self.assertEqual(body["code"], "source_not_enabled")

    def test_held_crowdsec_file_does_not_mark_a_manual_ban_held(self):
        _crowdsec.enable(self)
        self.ban("203.0.113.7")
        fsio.atomic_write(CS.path, b"", 0o644)            # host recovery truncated it
        body, status = self.ban("203.0.113.8")
        self.assertEqual(status, 201)
        self.assertEqual(body["enforcement"], "enforced")
        self.assertEqual(fsio.read_bytes(CS.path), b"")    # held: not regenerated
        body, status = service.reapply({"source": "crowdsec"}, "op", None)
        self.assertEqual(status, 200, body)
        self.assertIn(b"vars caddy_console_crowdsec_policy 1", fsio.read_bytes(CS.path))

    def test_crowdsec_records_cannot_be_removed_and_list_reports_both_sources(self):
        _crowdsec.enable(self)
        self.ban()
        put_records(cs_record("198.51.100.9", 1))
        body, status = service.list_bans()
        self.assertEqual(body["rendered_by_source"], {"manual": 1, "crowdsec": 1})
        cs = next(r for r in body["records"] if r["source"] == "crowdsec")
        self.assertEqual(cs["source_id"], "1")
        self.assertEqual(service.remove_ban(cs["id"], "op", None)[1], 403)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run --frozen python -m unittest tests.test_crowdsec_sources -v`
Expected: FAIL with `KeyError: 'crowdsec'` at import.

- [ ] **Step 3: Store rules and constructor**

In `src/bans/store.py`, add `_DECISION_ID = re.compile(r"^[0-9]{1,20}$")` beside `_HASH_RE`, and in `_check_record` after the manual-record rule:

```python
    if r.source == "crowdsec":
        if not isinstance(r.source_id, str) or not _DECISION_ID.match(r.source_id):
            raise ValueError("crowdsec records carry their LAPI decision id")
        if not r.origin:
            raise ValueError("crowdsec records carry their LAPI origin")
        if r.reason:
            raise ValueError("crowdsec records carry no reason")
```

Below `new_manual_record`:

```python
def new_crowdsec_record(decision_id, net, origin, scenario, fetched_at, expires_at) -> Record:
    """One LAPI decision. The id is derived from the decision id, so the same
    decision always maps to the same record; created_at is when it was fetched."""
    return Record(id=f"crowdsec-{decision_id}", source="crowdsec", source_id=str(decision_id),
                  scope=addr.scope_of(net), value=addr.token(net), reason="", scenario=scenario or None,
                  origin=origin, actor="system", created_at=iso(fetched_at), expires_at=iso(expires_at))
```

- [ ] **Step 4: Render registry, active sources and total capacity**

In `src/bans/render.py`, replace the `SOURCES` comment entry with the real one and change `CapacityError`:

```python
SOURCES = {
    "manual": PolicySource("manual", "bans-manual.caddy",
                           "caddy_console_manual_policy", "caddy_console_manual_banned"),
    "crowdsec": PolicySource("crowdsec", "bans-crowdsec.caddy",
                             "caddy_console_crowdsec_policy", "caddy_console_crowdsec_banned"),
}


def active_sources(state=None) -> dict:
    """The sources the console renders. Manual always. CrowdSec once it is
    configured, or once it left something behind (records or a recorded policy
    hash), so turning CrowdSec off still lets expiry and Reset clear what it
    rendered. An install that never used CrowdSec never gets bans-crowdsec.caddy."""
    out = {"manual": SOURCES["manual"]}
    cs = SOURCES["crowdsec"]
    if config.CROWDSEC_URL or (state is not None and (
            any(r.source == "crowdsec" for r in state.records) or cs.filename in state.last_rendered_hashes)):
        out["crowdsec"] = cs
    return out


class CapacityError(Exception):
    def __init__(self, count: int, limit: int, by_source=None):
        super().__init__(f"{count} prefixes exceed the limit of {limit}")
        self.count, self.limit, self.by_source = count, limit, dict(by_source or {})


def check_capacity(by_source: dict, limit: int) -> None:
    """BANS_MAX is a total over every source rendered into stock Caddy (spec 2.5)."""
    total = sum(by_source.values())
    if total > limit:
        raise CapacityError(total, limit, by_source)
```

- [ ] **Step 5: Service uses active sources everywhere**

In `src/bans/service.py`:

`_holds`:

```python
def _holds(state) -> dict:
    """Sources whose file differs from the hash recorded at their last render:
    an out-of-band recovery override (spec 1.6). Not regenerated until Re-apply."""
    out = {}
    for name, src in render.active_sources(state).items():
        recorded = state.last_rendered_hashes.get(src.filename)
        actual = fsio.sha256_tag(fsio.read_bytes(src.path))
        if recorded != actual:
            out[name] = "missing" if actual is None else "differs"
    return out
```

`_candidates`:

```python
def _candidates(state, prot, holds, now) -> list:
    """Every active source's candidate policy (held ones excepted) plus the
    state that embeds their hashes. Held sources still count toward BANS_MAX:
    their file stays loaded in Caddy."""
    sources = render.active_sources(state)
    prefixes = {name: render.effective_prefixes(state.records, now, name) for name in sources}
    render.check_capacity({name: len(p) for name, p in prefixes.items()}, config.BANS_MAX)
    changes, owns = [], []
    for name, src in sources.items():
        if name in holds:
            continue
        data = render.render_policy(src, prefixes[name], prot.exclusion_tokens(), config.BANS_MAX)
        state.last_rendered_hashes[src.filename] = fsio.sha256_tag(data)
        changes.append(txn.Change(src.path, "policy", data, marker=src.marker))
        owns.append(src.filename)
    changes.append(txn.Change(store.STATE_PATH, "state", store.dumps(state), owns=tuple(owns)))
    return changes
```

`_transact`: add keyword `affects=("manual",)`; change the prune line to

```python
        expired = store.prune_expired(state, now, sources=[n for n in render.active_sources(state) if n not in holds])
```

change the capacity message to name the sources:

```python
        except render.CapacityError as e:
            parts = ", ".join(f"{n} {c}" for n, c in e.by_source.items())
            return _error("capacity_exceeded", f"This would render {e.count} prefixes ({parts}); the limit "
                          f"(BANS_MAX) is {e.limit}. Remove or merge bans first.", 409, count=e.count,
                          limit=e.limit, by_source=e.by_source)
```

and make the held notice apply only to the sources the mutation touches:

```python
    if outcome.ok and set(holds) & set(affects):
```

`expire_tick`: change its prune line the same way as `_transact`'s.

`reapply`: accept any registered source and check it is active inside the mutation:

```python
def reapply(payload, actor, remote_addr):
    source = payload.get("source", "manual") if isinstance(payload, dict) else None
    if source not in render.SOURCES:
        return _error("invalid_source", "Unknown policy source.", 400)

    def mutate(state, now, version):
        if source not in render.active_sources(state):
            raise BanError("source_not_enabled", f"The {source} source is not in use.", 400)
        return Mutation({"source": source}, 200, [("bans_reapply", source)])
    # Re-apply also reloads unchanged files: Caddy may never have loaded the
    # policy (an import in an included file, added before the file existed).
    return _transact(actor, _verified_client(remote_addr), mutate, force=(source,), source="reapply",
                     force_reload=True, affects=(source,))
```

`reset`: replace the `render.SOURCES` check and the confirmation message, and check activity in the mutation:

```python
    if source not in render.SOURCES:
        return _error("source_not_enabled", f"The {source} source is not part of this version.", 400)
    what = "manual ban" if source == "manual" else "stored CrowdSec decision"
    if payload.get("confirm") is not True:
        return _error("confirmation_required", f"Resetting deletes every {what}; send confirm: true.", 400)
    expected = payload.get("version")

    def mutate(state, now, version):
        if source not in render.active_sources(state):
            raise BanError("source_not_enabled", f"The {source} source is not in use.", 400)
        if expected != version:
            raise BanError("version_conflict", "The ban list changed since you loaded it; reload the Security view.", 409)
        removed = [r for r in state.records if r.source == source]
        state.records = [r for r in state.records if r.source != source]
        body = {"removed": len(removed)}
        if source == "crowdsec":
            body["message"] = (f"Removed {len(removed)} stored CrowdSec decisions. They return within "
                               f"{config.BANS_SYNC_INTERVAL} seconds unless they are removed in CrowdSec "
                               "(cscli decisions delete).")
        return Mutation(body, 200, [("bans_reset", f"{source}: removed {len(removed)} records")])
    return _transact(actor, _verified_client(remote_addr), mutate, force=(source,), allow_corrupt=True,
                     source="reset", affects=(source,))
```

The Mutation `message` key overrides the outcome's message because `_transact` builds `{**_outcome_body(outcome), **result.body}`.

`_public`: add `"source_id"` to the copied key tuple.

`list_bans` (the full-list return): replace `rendered_prefixes` computation with

```python
    by_source = {n: len(render.effective_prefixes(state.records, now, n)) for n in render.active_sources(state)}
    return {"records": [_public(r, now, prot) for r in records], "state_version": state.version,
            "rendered_prefixes": by_source["manual"], "rendered_by_source": by_source,
            "max_prefixes": config.BANS_MAX}, 200
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `uv run --frozen python -m unittest tests.test_crowdsec_sources -v && uv run --frozen python -m unittest discover -s tests -t .`
Expected: PASS. (`test_reset_contract` still gets `source_not_enabled` for crowdsec: its state has no CrowdSec records and `CROWDSEC_URL` is empty.)

- [ ] **Step 7: Commit**

```bash
git add src/bans/store.py src/bans/render.py src/bans/service.py tests/test_crowdsec_sources.py
git commit -m "feat(crowdsec): crowdsec records and policy source beside manual, with a total BANS_MAX"
```

---
### Task 4: The CrowdSec apply transaction

**Files:**
- Modify: `src/bans/service.py` (new section "CrowdSec file sync": `SyncApply`, `_reconcile_crowdsec`, `apply_crowdsec`)
- Test: `tests/test_crowdsec_apply.py`

**Interfaces:**
- Consumes: `lapi.Accepted` (Task 2); `store.new_crowdsec_record`, `render.active_sources`, `_candidates` (Task 3); Phase 1 `availability(background=True)`, `txn.resolve_pending`, `txn.apply_locked`, `protected_for`, `_holds`, `_expired_events`, `_after_commit`.
- Produces: `service.SyncApply` dataclass (`code: str`, `message: str`, `added: int`, `removed: int`, `active: int`, `protected: dict[category, int]`, `protected_sample: list[{value, category, scenario, origin}]`, `by_origin: dict`, `capacity: dict | None`, property `ok`). Codes: `applied` (Caddy reloaded), `stored` (state changed, policy bytes did not, no reload), `unchanged`, `held`, `capacity_exceeded`, `corrupt`, `degraded` (pending journal), `unavailable` (managed directory), or a txn failure code (`adaptation_failed`, `reload_rejected`, `reload_unknown`, ...). `service.apply_crowdsec(desired: iterable[lapi.Accepted], *, snapshot: bool = False, ignored: dict | None = None, now=None) -> SyncApply`. Audit actions `crowdsec_snapshot` and `crowdsec_sync` travel in the txn journal, so they are written only when the change commits.

- [ ] **Step 1: Write the failing test**

`tests/test_crowdsec_apply.py`:

```python
"""service.apply_crowdsec(): reconcile the leader's decisions into crowdsec
records and bans-crowdsec.caddy through the Phase 1 transaction (spec 2.4-2.6).

Run with:  uv run --frozen python -m unittest tests.test_crowdsec_apply -v
"""
import os
import unittest
from datetime import timedelta
from unittest import mock

import tests._env as env
from tests import _bans, _crowdsec

from src import audit, config
from src.bans import fsio, protected, render, service, store, txn

CS, MANUAL = render.SOURCES["crowdsec"], render.SOURCES["manual"]
BOTH = ("example.com {{\n\timport {d}/bans-manual*.caddy\n\timport {d}/bans-crowdsec*.caddy\n"
        "\trespond 200\n}}\n").format(d=env.BANS_DIR)
A = _crowdsec.accepted


def client_ip_line(path):
    lines = [l for l in (fsio.read_bytes(path) or b"").decode().splitlines() if l.startswith("\tclient_ip ")]
    return lines[0].split()[1:] if lines else []


class ApplyCase(unittest.TestCase):
    def setUp(self):
        _bans.reset(BOTH)
        _bans.fresh_audit(self)
        service.reset_caches()
        docker = mock.patch.object(protected, "read_docker_networks", lambda: [])
        docker.start()
        self.addCleanup(docker.stop)
        self.caddy = _bans.FakeCaddy().install(self)
        _crowdsec.enable(self)

    def tearDown(self):
        service.reset_caches()

    def loads(self):
        return sum(1 for kind, _ in self.caddy.calls if kind == "load")

    def crowdsec_records(self):
        return [r for r in store.load().records if r.source == "crowdsec"]


class ApplyTest(ApplyCase):
    def test_snapshot_replaces_only_crowdsec_records(self):
        service.add_ban({"value": "203.0.113.7", "duration": "24h", "reason": "x"}, "admin@example.com", None)
        manual_bytes = fsio.read_bytes(MANUAL.path)
        r = service.apply_crowdsec([A("203.0.113.9", 1), A("198.51.100.0/24", 2)], snapshot=True,
                                   ignored={"not_ban": 2})
        self.assertEqual((r.code, r.added, r.removed, r.active, r.by_origin), ("applied", 2, 0, 2, {"crowdsec": 2}))
        self.assertEqual([x.id for x in self.crowdsec_records()], ["crowdsec-1", "crowdsec-2"])
        self.assertEqual([x.value for x in store.load().records if x.source == "manual"], ["203.0.113.7"])
        self.assertEqual(fsio.read_bytes(MANUAL.path), manual_bytes)
        self.assertEqual(client_ip_line(CS.path), ["198.51.100.0/24", "203.0.113.9"])
        r = service.apply_crowdsec([A("203.0.113.9", 1)], snapshot=True)
        self.assertEqual((r.code, r.removed), ("applied", 1))
        self.assertEqual(client_ip_line(CS.path), ["203.0.113.9"])
        snap = [e for e in audit.iter_entries() if e["action"] == "crowdsec_snapshot"]
        self.assertIn("ignored: not_ban 2", snap[0]["detail"])
        self.assertEqual(snap[0]["user"], "system")

    def test_repeated_snapshot_is_idempotent(self):
        decisions = [A("203.0.113.9", 1)]
        self.assertEqual(service.apply_crowdsec(decisions, snapshot=True).code, "applied")
        state_bytes, loads = fsio.read_bytes(store.STATE_PATH), self.loads()
        again = [A("203.0.113.9", 1, now=store.utc_now() + timedelta(seconds=30))]
        self.assertEqual(service.apply_crowdsec(again, snapshot=True).code, "unchanged")
        self.assertEqual((fsio.read_bytes(store.STATE_PATH), self.loads()), (state_bytes, loads))

    def test_extended_decision_is_refreshed_without_a_reload(self):
        service.apply_crowdsec([A("203.0.113.9", 1, hours=4)])
        loads = self.loads()
        r = service.apply_crowdsec([A("203.0.113.9", 1, hours=7)])
        self.assertEqual(r.code, "stored")
        self.assertEqual(self.loads(), loads)
        expires = store.parse_iso(self.crowdsec_records()[0].expires_at)
        self.assertGreater(expires, store.utc_now() + timedelta(hours=6))

    def test_decision_for_a_verified_console_address_is_ignored(self):
        # The operator used the console from 198.51.100.20: it is in the registry, not BANS_NEVER.
        service.add_ban({"value": "203.0.113.7", "duration": "24h", "reason": ""}, "admin@example.com", "198.51.100.20")
        r = service.apply_crowdsec([A("198.51.100.20", 1), A("10.1.2.3", 2), A("203.0.113.9", 3)])
        self.assertEqual(r.protected, {"operator": 1, "private": 1})
        self.assertEqual(sorted(s["value"] for s in r.protected_sample), ["10.1.2.3", "198.51.100.20"])
        self.assertEqual(client_ip_line(CS.path), ["203.0.113.9"])
        self.assertEqual([x.source_id for x in self.crowdsec_records()], ["3"])

    def test_expired_decisions_are_dropped(self):
        past = store.utc_now() - timedelta(hours=5)
        r = service.apply_crowdsec([A("203.0.113.9", 1, hours=1, now=past)])
        self.assertEqual((r.ok, r.active), (True, 0))
        self.assertEqual(self.crowdsec_records(), [])

    def test_capacity_refuses_the_whole_snapshot_and_keeps_the_last_policy(self):
        service.add_ban({"value": "203.0.113.7", "duration": "24h", "reason": ""}, "admin@example.com", None)
        with mock.patch.object(config, "BANS_MAX", 3):
            self.assertEqual(service.apply_crowdsec([A("192.0.2.1", 1), A("192.0.2.2", 2)]).code, "applied")
            before = (fsio.read_bytes(CS.path), fsio.read_bytes(store.STATE_PATH))
            r = service.apply_crowdsec([A("192.0.2.1", 1), A("192.0.2.2", 2), A("192.0.2.3", 3, origin="cscli")])
        self.assertEqual(r.code, "capacity_exceeded")
        self.assertEqual(r.capacity, {"count": 4, "limit": 3, "by_source": {"manual": 1, "crowdsec": 3}})
        self.assertEqual(r.by_origin, {"crowdsec": 2, "cscli": 1})
        self.assertIn("CROWDSEC_ORIGINS", r.message)
        self.assertEqual((fsio.read_bytes(CS.path), fsio.read_bytes(store.STATE_PATH)), before)

    def test_held_crowdsec_file_pauses_sync_only(self):
        service.apply_crowdsec([A("203.0.113.9", 1)])
        fsio.atomic_write(CS.path, b"", 0o644)
        r = service.apply_crowdsec([A("203.0.113.9", 1), A("203.0.113.10", 2)])
        self.assertEqual(r.code, "held")
        self.assertEqual(fsio.read_bytes(CS.path), b"")
        body, status = service.add_ban({"value": "198.51.100.7", "duration": "4h", "reason": ""}, "op", None)
        self.assertEqual((status, body["enforcement"]), (201, "enforced"))

    def test_corrupt_state_is_left_alone(self):
        service.apply_crowdsec([A("203.0.113.9", 1)])
        policy = fsio.read_bytes(CS.path)
        fsio.atomic_write(store.STATE_PATH, b"{not json", 0o600)
        self.assertEqual(service.apply_crowdsec([A("203.0.113.10", 2)]).code, "corrupt")
        self.assertEqual((fsio.read_bytes(store.STATE_PATH), fsio.read_bytes(CS.path)), (b"{not json", policy))

    def test_pending_journal_pauses_sync(self):
        fsio.atomic_write(txn.JOURNAL_PATH, b"garbage", 0o600)
        self.assertEqual(service.apply_crowdsec([A("203.0.113.9", 1)]).code, "degraded")
        self.assertFalse(os.path.exists(CS.path))

    def test_adaptation_failure_rolls_back_and_reports(self):
        service.apply_crowdsec([A("203.0.113.9", 1)])
        policy = fsio.read_bytes(CS.path)
        synced = [e["action"] for e in audit.iter_entries()].count("crowdsec_sync")
        self.caddy.adapt_status = 400
        r = service.apply_crowdsec([A("203.0.113.10", 2)])
        self.assertEqual((r.ok, r.code), (False, "adaptation_failed"))
        self.assertEqual(fsio.read_bytes(CS.path), policy)
        actions = [e["action"] for e in audit.iter_entries()]
        self.assertEqual(actions.count("crowdsec_sync"), synced)      # a rolled-back change is never audited
        self.assertIn("bans_adapt_rejected", actions)

    def test_audit_never_contains_the_key(self):
        service.apply_crowdsec([A("203.0.113.9", 1)], snapshot=True, ignored={"origin": 1})
        with open(env.AUDIT_LOG, encoding="utf-8") as f:
            self.assertNotIn(_crowdsec.KEY, f.read())


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run --frozen python -m unittest tests.test_crowdsec_apply -v`
Expected: FAIL with `AttributeError: module 'src.bans.service' has no attribute 'apply_crowdsec'`.

- [ ] **Step 3: Implement**

In `src/bans/service.py` add `import collections` and `from datetime import timedelta` to the imports, then add before the "reads" section:

```python
# --- CrowdSec file sync (spec 2.4-2.6) ---------------------------------------------------

REFRESH_TOLERANCE = timedelta(minutes=2)
PROTECTED_SAMPLE_MAX = 10
_SYNC_OK = ("applied", "stored", "unchanged")


@dataclass
class SyncApply:
    code: str
    message: str = ""
    added: int = 0
    removed: int = 0
    active: int = 0
    protected: dict = field(default_factory=dict)
    protected_sample: list = field(default_factory=list)
    by_origin: dict = field(default_factory=dict)
    capacity: object = None

    @property
    def ok(self) -> bool:
        return self.code in _SYNC_OK


def _counts_text(counts) -> str:
    return ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "none"


def _reconcile_crowdsec(state, wanted) -> tuple:
    """Replace the crowdsec records with `wanted` (decision id -> Accepted).
    A record whose decision, value and expiry (within REFRESH_TOLERANCE) are
    unchanged is kept as it is, so a repeated snapshot changes no byte."""
    old = {r.source_id: r for r in state.records if r.source == "crowdsec"}
    keep, added = [], 0
    for did, a in wanted.items():
        r = old.get(did)
        if (r is not None and r.value == addr.token(a.net) and r.expires_at
                and abs(store.parse_iso(r.expires_at) - a.expires_at) <= REFRESH_TOLERANCE):
            keep.append(r)
            continue
        added += r is None
        keep.append(store.new_crowdsec_record(did, a.net, a.origin, a.scenario, a.fetched_at, a.expires_at))
    removed = sum(1 for did in old if did not in wanted)
    keep.sort(key=lambda r: int(r.source_id))
    state.records = [r for r in state.records if r.source != "crowdsec"] + keep
    return keep, added, removed


def apply_crowdsec(desired, *, snapshot=False, ignored=None, now=None) -> SyncApply:
    """Make the stored crowdsec records equal the sync leader's accepted
    decisions and render bans-crowdsec.caddy through the Phase 1 transaction.
    Manual records are never touched. Called only by sync.Synchronizer, never
    while caddyfile_lock() is held and never with an LAPI request in flight.

    Every failure keeps the last loaded policy (spec 2.6): a corrupt state, a
    pending journal, a held file or a capacity overflow returns before any write."""
    avail = availability(background=True)
    if not avail.ok:
        return SyncApply("unavailable", avail.message)
    with caddyfile_lock():
        pending = txn.resolve_pending()
        if pending is not None:
            return SyncApply("degraded", pending.message)
        try:
            state = store.load()
        except store.StateCorrupt as e:
            store.quarantine(e.raw, str(e))
            return SyncApply("corrupt", f"{e}. CrowdSec sync is paused until the ban state is recovered in Security.")
        now = now or store.utc_now()
        holds = _holds(state)
        if "crowdsec" in holds:
            return SyncApply("held", "bans-crowdsec.caddy differs from the stored state (for example after host "
                             "recovery). CrowdSec sync is paused for that file until you Re-apply it in Security.")
        expired = store.prune_expired(state, now, sources=[n for n in render.active_sources(state) if n not in holds])
        store.prune_management(state, now)
        prot = protected_for(state)
        wanted, prot_counts, sample = {}, collections.Counter(), []
        for a in desired:
            if a.expires_at <= now:
                continue
            category = prot.overlap(a.net)
            if category:
                prot_counts[category] += 1
                if len(sample) < PROTECTED_SAMPLE_MAX:
                    sample.append({"value": addr.token(a.net), "category": category,
                                   "scenario": a.scenario, "origin": a.origin})
                continue
            wanted[a.decision_id] = a
        keep, added, removed = _reconcile_crowdsec(state, wanted)
        result = SyncApply("unchanged", added=added, removed=removed, active=len(keep),
                           protected=dict(prot_counts), protected_sample=sample,
                           by_origin=dict(collections.Counter(r.origin for r in keep)))
        try:
            changes = _candidates(state, prot, holds, now)
        except render.CapacityError as e:
            parts = ", ".join(f"{n} {c}" for n, c in e.by_source.items())
            result.code = "capacity_exceeded"
            result.capacity = {"count": e.count, "limit": e.limit, "by_source": e.by_source}
            result.message = (f"CrowdSec decisions would render {e.count} prefixes in total ({parts}); the limit "
                              f"(BANS_MAX) is {e.limit}. The last applied CrowdSec policy stays enforced and "
                              "automatic apply is paused. Restrict CROWDSEC_ORIGINS, raise BANS_MAX after "
                              "measuring (docs/security.md#capacity), or use plugin mode once it is available.")
            return result
        events = _expired_events(expired)
        all_ignored = {**(ignored or {}), **{f"protected:{k}": v for k, v in prot_counts.items()}}
        if snapshot:
            events.append(("crowdsec_snapshot", f"{len(keep)} active, {added} added, {removed} removed; "
                           f"ignored: {_counts_text(all_ignored)}"))
        elif added or removed:
            events.append(("crowdsec_sync", f"{len(keep)} active, {added} added, {removed} removed"))
        outcome = txn.apply_locked(changes, actor="system", source="crowdsec", audit_events=events)
        if outcome.ok:
            _after_commit(None)
    if not outcome.ok:
        result.code = outcome.code or "apply_failed"
    elif outcome.reload_status == "applied":
        result.code = "applied"
    elif outcome.enforcement != "unchanged":
        result.code = "stored"
    result.message = outcome.message
    return result
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run --frozen python -m unittest tests.test_crowdsec_apply tests.test_crowdsec_sources -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/bans/service.py tests/test_crowdsec_apply.py
git commit -m "feat(crowdsec): reconcile synced decisions into bans-crowdsec.caddy through the ban transaction"
```

---

### Task 5: Stream synchronizer, sync leader and the shared health file

**Files:**
- Create: `src/bans/syncstate.py`
- Create: `src/bans/sync.py`
- Modify: `src/bans/jobs.py` (sync thread)
- Test: `tests/test_crowdsec_sync.py`, `tests/test_crowdsec_leader.py`

**Interfaces:**
- Consumes: `lapi.read_key/url/origins/fetch_stream/classify` and the exceptions (Tasks 1-2); `service.apply_crowdsec` and `SyncApply` (Task 4).
- Produces: `syncstate.PATH` (`BACKUP_DIR/bans-crowdsec-sync.json`, 0600), `syncstate.VERSION = 1`, `syncstate.FIELDS`, `syncstate.write(doc)`, `syncstate.read() -> dict | None`. `sync.LOCK_PATH` (`BACKUP_DIR/bans-sync.lock`), `sync.AUTH_RETRY_SECONDS = 60`, `sync.Leadership(path=None)` with `try_acquire() -> bool` and `release()`, `sync.Synchronizer(*, monotonic=time.monotonic, wall=store.utc_now)` with `step() -> str` (the LAPI state). LAPI states: `starting`, `ok`, `unreachable`, `auth_failed`, `malformed`, `missing_key`. Apply states: `pending`, `ok`, `capacity_exceeded`, `held`, `degraded`, `failed`. Audit actions `crowdsec_degraded` and `crowdsec_recovered` on state transitions (actor `system`). `jobs.start_background()` also starts a `bans-sync` thread per worker when `lapi.enabled()`.
- Status document keys (Task 6 and the Security view read them): `version, leader_pid, updated_at, lapi_state, lapi_message, apply_state, apply_message, last_poll_at, last_success_at, last_snapshot_at, last_apply_at, decisions, by_origin, ignored, protected_sample, capacity, origins, poll_interval, sync_interval`.

- [ ] **Step 1: Write the failing sync test**

`tests/test_crowdsec_sync.py`:

```python
"""The stream synchronizer against the fake LAPI and the fake admin API
(spec 2.4, 2.6, Testing: startup reconciliation, failover, malformed response,
auth failure, outage recovery, independent decisions).

Run with:  uv run --frozen python -m unittest tests.test_crowdsec_sync -v
"""
import fcntl
import logging
import os
import unittest
from datetime import timedelta
from unittest import mock

import tests._env as env
from tests import _bans, _crowdsec

from src import audit, config
from src.bans import fsio, lapi, protected, render, service, store, sync, syncstate
from src.routes import editor

CS, MANUAL = render.SOURCES["crowdsec"], render.SOURCES["manual"]
BOTH = ("example.com {{\n\timport {d}/bans-manual*.caddy\n\timport {d}/bans-crowdsec*.caddy\n"
        "\trespond 200\n}}\n").format(d=env.BANS_DIR)


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class SyncCase(unittest.TestCase):
    def setUp(self):
        _bans.reset(BOTH)
        _bans.fresh_audit(self)
        service.reset_caches()
        docker = mock.patch.object(protected, "read_docker_networks", lambda: [])
        docker.start()
        self.addCleanup(docker.stop)
        self.caddy = _bans.FakeCaddy().install(self)
        self.lapi = _crowdsec.FakeLapi().install(self)
        _crowdsec.enable(self)
        self.clock = Clock()
        self.sync = sync.Synchronizer(monotonic=self.clock)

    def tearDown(self):
        service.reset_caches()

    def step(self, advance=0):
        self.clock.t += advance
        return self.sync.step()

    def startups(self):
        return [c["params"]["startup"] for c in self.lapi.calls]

    def policy_ips(self):
        lines = [l for l in (fsio.read_bytes(CS.path) or b"").decode().splitlines() if l.startswith("\tclient_ip ")]
        return lines[0].split()[1:] if lines else []

    def loads(self):
        return sum(1 for kind, _ in self.caddy.calls if kind == "load")

    def actions(self):
        return [e["action"] for e in audit.iter_entries()]


class StreamTest(SyncCase):
    def test_first_poll_is_a_snapshot_then_deltas(self):
        self.lapi.add("203.0.113.7")
        self.assertEqual(self.step(), "ok")
        self.assertEqual(self.policy_ips(), ["203.0.113.7"])
        self.step(10)
        self.assertEqual(self.startups(), ["true", "false"])
        doc = syncstate.read()
        self.assertEqual((doc["lapi_state"], doc["apply_state"], doc["decisions"], doc["leader_pid"]),
                         ("ok", "ok", 1, os.getpid()))
        self.assertTrue(doc["last_snapshot_at"] and doc["last_success_at"] and doc["last_apply_at"])
        self.assertEqual(os.stat(syncstate.PATH).st_mode & 0o777, 0o600)
        self.assertIn("crowdsec_snapshot", self.actions())

    def test_snapshot_never_rewrites_manual_records_or_policy(self):
        service.add_ban({"value": "198.51.100.7", "duration": "24h", "reason": ""}, "admin@example.com", None)
        manual = fsio.read_bytes(MANUAL.path)
        self.lapi.add("203.0.113.7")
        self.step()
        self.assertEqual(fsio.read_bytes(MANUAL.path), manual)
        self.assertEqual([r.value for r in store.load().records if r.source == "manual"], ["198.51.100.7"])

    def test_two_decisions_for_one_ip_stay_independent(self):
        self.lapi.add("203.0.113.7", id=1)
        self.lapi.add("203.0.113.7", id=2, scenario="crowdsecurity/http-bad-user-agent")
        self.step()
        self.assertEqual(sorted(r.source_id for r in store.load().records), ["1", "2"])
        self.lapi.delete(1)
        self.step(30)
        self.assertEqual(self.policy_ips(), ["203.0.113.7"])
        self.lapi.delete(2)
        self.step(30)
        self.assertEqual(self.policy_ips(), [])

    def test_unknown_deleted_id_is_a_noop(self):
        self.lapi.add("203.0.113.7", id=1)
        self.step()
        self.lapi.delete(999)
        self.assertEqual(self.step(30), "ok")
        self.assertEqual(self.policy_ips(), ["203.0.113.7"])

    def test_ignored_decisions_are_counted_by_reason(self):
        self.lapi.add("203.0.113.7", type="captcha")
        self.lapi.add("RO", scope="Country")
        self.lapi.add("203.0.113.8", origin="CAPI")
        self.lapi.add("10.0.0.5")
        self.step()
        self.assertEqual(syncstate.read()["ignored"], {"not_ban": 1, "scope": 1, "origin": 1, "protected:private": 1})
        self.assertEqual([r for r in store.load().records if r.source == "crowdsec"], [])

    def test_reloads_are_coalesced_to_the_sync_interval(self):
        self.lapi.add("203.0.113.7")
        self.step()
        self.assertEqual(self.loads(), 1)
        self.lapi.add("203.0.113.8")
        self.step(10)
        self.step(10)
        self.assertEqual((self.loads(), self.policy_ips()), (1, ["203.0.113.7"]))
        self.step(10)                                    # 30 s after the last apply
        self.assertEqual((self.loads(), self.policy_ips()), (2, ["203.0.113.7", "203.0.113.8"]))

    def test_already_expired_decisions_are_not_stored(self):
        self.sync = sync.Synchronizer(monotonic=self.clock, wall=lambda: store.utc_now() - timedelta(hours=2))
        self.lapi.add("203.0.113.7", duration="1h")
        self.step()
        self.assertEqual(self.policy_ips(), [])

    def test_a_new_leader_starts_with_a_snapshot(self):
        self.lapi.add("203.0.113.7")
        self.step()
        self.step(10)
        successor = sync.Synchronizer(monotonic=self.clock)
        successor.step()
        self.assertEqual(self.startups(), ["true", "false", "true"])


class FailureTest(SyncCase):
    def setUp(self):
        super().setUp()
        self.lapi.add("203.0.113.7")
        self.step()
        self.records = [r.id for r in store.load().records]
        self.policy = fsio.read_bytes(CS.path)

    def assert_enforcement_kept(self):
        self.assertEqual([r.id for r in store.load().records], self.records)
        self.assertEqual(fsio.read_bytes(CS.path), self.policy)

    def test_malformed_response_keeps_enforcement_and_resnapshots(self):
        self.lapi.mode, self.lapi.raw = "raw", b'{"new": [{"id": "x"}], "deleted": null}'
        self.assertEqual(self.step(30), "malformed")
        self.assert_enforcement_kept()
        self.assertIn("crowdsec_degraded", self.actions())
        self.lapi.mode = "ok"
        self.assertEqual(self.step(10), "ok")
        self.assertEqual(self.startups()[-1], "true")
        self.assertIn("crowdsec_recovered", self.actions())

    def test_auth_failure_stops_delta_polling_until_a_snapshot_succeeds(self):
        self.lapi.mode, self.lapi.status = "status", 403
        self.assertEqual(self.step(10), "auth_failed")
        calls = len(self.lapi.calls)
        self.step(10)
        self.assertEqual(len(self.lapi.calls), calls)            # no polling inside AUTH_RETRY_SECONDS
        self.step(sync.AUTH_RETRY_SECONDS)
        self.assertEqual((len(self.lapi.calls), self.startups()[-1]), (calls + 1, "true"))
        self.assert_enforcement_kept()
        self.lapi.mode = "ok"
        self.assertEqual(self.step(sync.AUTH_RETRY_SECONDS), "ok")
        self.assertEqual(self.startups()[-1], "true")

    def test_outage_keeps_the_last_list_and_resnapshots_on_recovery(self):
        self.lapi.mode = "down"
        self.assertEqual(self.step(30), "unreachable")
        self.assertEqual(self.step(30), "unreachable")
        self.assert_enforcement_kept()
        self.assertEqual(syncstate.read()["lapi_state"], "unreachable")
        self.lapi.mode = "ok"
        self.assertEqual(self.step(10), "ok")
        self.assertEqual(self.startups()[-1], "true")

    def test_rotated_key_forces_a_snapshot(self):
        self.step(10)
        with mock.patch.object(config, "CROWDSEC_CONSOLE_BOUNCER_KEY", "rotated-key-2"):
            self.step(10)
        self.assertEqual((self.startups()[-1], self.lapi.calls[-1]["key"]), ("true", "rotated-key-2"))

    def test_missing_key_is_a_health_state(self):
        calls = len(self.lapi.calls)
        with mock.patch.object(config, "CROWDSEC_CONSOLE_BOUNCER_KEY", ""):
            self.assertEqual(self.step(10), "missing_key")
        self.assertEqual(len(self.lapi.calls), calls)
        self.assert_enforcement_kept()

    def test_capacity_pauses_apply_and_reports_counts_by_origin(self):
        self.lapi.add("203.0.113.8", origin="cscli")
        with mock.patch.object(config, "BANS_MAX", 1):
            self.step(30)
        doc = syncstate.read()
        self.assertEqual((doc["lapi_state"], doc["apply_state"]), ("ok", "capacity_exceeded"))
        self.assertEqual(doc["by_origin"], {"crowdsec": 1, "cscli": 1})
        self.assertEqual(doc["capacity"]["count"], 2)
        self.assert_enforcement_kept()

    def test_the_key_never_leaves_the_header(self):
        with self.assertLogs("src", level="DEBUG") as logs:
            logging.getLogger("src.test").info("capture start")
            for mode, status in (("status", 401), ("raw", 200), ("down", 200), ("ok", 200)):
                self.lapi.mode, self.lapi.status, self.lapi.raw = mode, status, b"[]"
                self.step(sync.AUTH_RETRY_SECONDS)
        with open(syncstate.PATH, encoding="utf-8") as f:
            status_text = f.read()
        with open(env.AUDIT_LOG, encoding="utf-8") as f:
            audit_text = f.read()
        for text in (status_text, audit_text, "\n".join(logs.output)):
            self.assertNotIn(_crowdsec.KEY, text)
        self.assertTrue(all(c["key"] == _crowdsec.KEY for c in self.lapi.calls))

    def test_no_lapi_request_while_caddyfile_lock_is_held(self):
        real = lapi.fetch_stream

        def checked(*args, **kwargs):
            fd = os.open(editor._LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)   # BlockingIOError if anyone holds it
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
            return real(*args, **kwargs)
        with mock.patch.object(lapi, "fetch_stream", checked):
            self.lapi.add("203.0.113.8")
            for _ in range(3):
                self.assertEqual(self.step(30), "ok")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Write the failing leader test**

`tests/test_crowdsec_leader.py`:

```python
"""Sync leadership across processes and the per-worker sync thread (spec 1.5
'bans-sync.lock', 2.6 'Sync worker exit').

Run with:  uv run --frozen python -m unittest tests.test_crowdsec_leader -v
"""
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

import tests._env  # noqa: F401
from tests import _crowdsec

from src import config
from src.bans import jobs, sync

HOLDER = ("import fcntl, os, sys\n"
          "fd = os.open(sys.argv[1], os.O_CREAT | os.O_RDWR, 0o600)\n"
          "fcntl.flock(fd, fcntl.LOCK_EX)\n"
          "print('locked', flush=True)\n"
          "sys.stdin.read()\n")


class LeadershipTest(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "bans-sync.lock")

    def test_one_leader_per_lock_file(self):
        a, b = sync.Leadership(self.path), sync.Leadership(self.path)
        self.assertTrue(a.try_acquire())
        self.assertTrue(a.try_acquire())                      # idempotent while held
        self.assertFalse(b.try_acquire())
        a.release()
        self.assertTrue(b.try_acquire())
        b.release()

    def test_a_lock_held_by_another_process_blocks_until_it_exits(self):
        holder = subprocess.Popen([sys.executable, "-c", HOLDER, self.path],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.addCleanup(holder.kill)
        self.assertEqual(holder.stdout.readline().strip(), "locked")
        leader = sync.Leadership(self.path)
        self.assertFalse(leader.try_acquire())
        holder.stdin.close()                                 # the "worker" exits
        holder.wait(10)
        self.assertTrue(leader.try_acquire())
        leader.release()


class SyncThreadTest(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(jobs, "_started", False)
        p.start()
        self.addCleanup(p.stop)

    def started_names(self):
        names = []

        class FakeThread:
            def __init__(self, target=None, args=(), name=None, daemon=None):
                names.append(name)

            def start(self):
                pass
        with mock.patch.object(jobs.threading, "Thread", FakeThread):
            jobs.start_background()
        return names

    def test_sync_thread_only_when_crowdsec_is_configured(self):
        self.assertEqual(self.started_names(), ["bans-expiry"])
        jobs._started = False
        _crowdsec.enable(self)
        self.assertEqual(self.started_names(), ["bans-expiry", "bans-sync"])

    def run_loop(self, leads, steps_before_stop=2, crash=False):
        stop, steps = threading.Event(), []

        def step(_self):
            steps.append(1)
            if crash and len(steps) == 1:
                raise RuntimeError("boom")
            if len(steps) >= steps_before_stop:
                stop.set()
            return "ok"
        if not leads:
            threading.Timer(0.2, stop.set).start()
        with mock.patch.object(sync.Leadership, "try_acquire", lambda self: leads), \
                mock.patch.object(sync.Leadership, "release", lambda self: None), \
                mock.patch.object(sync.Synchronizer, "step", step), \
                mock.patch.object(config, "CROWDSEC_POLL_INTERVAL", 0.01):
            jobs._sync_loop(stop)
        return steps

    def test_loop_steps_only_while_leading(self):
        self.assertEqual(len(self.run_loop(leads=True)), 2)
        self.assertEqual(self.run_loop(leads=False), [])

    def test_loop_survives_a_crashing_step(self):
        with self.assertLogs(jobs.log, "ERROR"):
            self.assertEqual(len(self.run_loop(leads=True, crash=True)), 2)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `uv run --frozen python -m unittest tests.test_crowdsec_sync tests.test_crowdsec_leader -v`
Expected: FAIL with `ImportError: cannot import name 'sync'`.

- [ ] **Step 4: Create `src/bans/syncstate.py`**

```python
"""BACKUP_DIR/bans-crowdsec-sync.json: the CrowdSec health the sync leader
reports so every worker's Security view can show it.

Disposable diagnostics, not security-control state: an unreadable file means
"no report", never degraded bans. Only the listed fields are written or read,
and none of them is the bouncer key.
"""
import json
import os

from ..config import BACKUP_DIR
from . import fsio

PATH = os.path.join(BACKUP_DIR, "bans-crowdsec-sync.json")
MAX_BYTES = 256 * 1024
VERSION = 1
FIELDS = ("version", "leader_pid", "updated_at", "lapi_state", "lapi_message", "apply_state", "apply_message",
          "last_poll_at", "last_success_at", "last_snapshot_at", "last_apply_at", "decisions", "by_origin",
          "ignored", "protected_sample", "capacity", "origins", "poll_interval", "sync_interval")


def write(doc) -> None:
    data = json.dumps({k: doc.get(k) for k in FIELDS}, sort_keys=True, ensure_ascii=False).encode("utf-8")
    fsio.atomic_write(PATH, data, 0o600)


def read():
    try:
        with open(PATH, "rb") as f:
            raw = f.read(MAX_BYTES + 1)
    except OSError:
        return None
    if len(raw) > MAX_BYTES:
        return None
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        return None
    if not isinstance(doc, dict) or doc.get("version") != VERSION:
        return None
    return {k: doc.get(k) for k in FIELDS}
```

- [ ] **Step 5: Create `src/bans/sync.py`**

```python
"""CrowdSec decision-stream synchronizer and its leader lock (spec 2.4, 2.6).

Exactly one process leads: it holds a non-blocking flock on
BACKUP_DIR/bans-sync.lock for as long as it lives, polls LAPI and applies the
result through service.apply_crowdsec(). Every gunicorn worker runs a sync
thread that retries the lock once per poll interval, so a dead leader is
replaced within one interval, and a new leader always starts with
startup=true. flock locks belong to an open file description, so two workers
(or two Leadership objects in one process) never both hold it, and the kernel
releases it when the leader exits.

Lock order: bans-sync.lock, then caddyfile_lock() inside apply_crowdsec().
Nothing takes bans-sync.lock while holding caddyfile_lock(), and fetch_stream()
runs before apply_crowdsec(), never inside it.
"""
import collections
import fcntl
import logging
import os
import time

from .. import audit, config
from ..config import BACKUP_DIR
from . import lapi, store, syncstate

LOCK_PATH = os.path.join(BACKUP_DIR, "bans-sync.lock")
AUTH_RETRY_SECONDS = 60
log = logging.getLogger(__name__)
_APPLY_STATES = {"capacity_exceeded": "capacity_exceeded", "held": "held",
                 "corrupt": "degraded", "degraded": "degraded", "unavailable": "degraded"}


class Leadership:
    def __init__(self, path=None):
        self.path, self.fd = path or LOCK_PATH, None

    def try_acquire(self) -> bool:
        if self.fd is not None:
            return True
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return False
        except OSError:
            os.close(fd)
            raise
        self.fd = fd
        return True

    def release(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def _audit(action, detail) -> None:
    try:
        audit.log_action(action, "system", detail)
    except OSError as e:
        log.warning("IP bans: could not write audit event %s: %s", action, e)


class Synchronizer:
    def __init__(self, *, monotonic=time.monotonic, wall=store.utc_now):
        self._mono, self._wall = monotonic, wall
        self.desired = {}                         # decision id -> lapi.Accepted
        self.ignored = collections.Counter()
        self.need_snapshot = True                 # first poll of every leader is startup=true
        self.snapshot_audit = False
        self.key = None
        self.lapi_state, self.lapi_message = "starting", ""
        self.apply_state, self.apply_message = "pending", ""
        self.last_attempt = None                  # monotonic seconds
        self.last_apply = None
        self.last_result = None
        self.times = dict.fromkeys(("last_poll_at", "last_success_at", "last_snapshot_at", "last_apply_at"))

    def _set(self, kind, state, message="") -> None:
        before = getattr(self, kind + "_state")
        setattr(self, kind + "_state", state)
        setattr(self, kind + "_message", message)
        if state == before:
            return
        if state == "ok":
            if before not in ("starting", "pending"):
                _audit("crowdsec_recovered", f"{kind}: ok")
        else:
            _audit("crowdsec_degraded", f"{kind} {state}: {message}")

    def step(self) -> str:
        """One poll, and at most one apply per BANS_SYNC_INTERVAL. Never raises
        for LAPI problems: they become the LAPI state, and enforcement stays."""
        now_m = self._mono()
        key, problem = lapi.read_key()
        if key is None:
            self.need_snapshot = True
            self._set("lapi", "missing_key", problem)
            self._write()
            return self.lapi_state
        if key != self.key:
            self.key, self.need_snapshot = key, True        # first key, or a rotated one
        if (self.lapi_state == "auth_failed" and self.last_attempt is not None
                and now_m - self.last_attempt < AUTH_RETRY_SECONDS):
            self._write()                                   # spec 2.6: no delta polling while refused
            return self.lapi_state
        startup = self.need_snapshot
        self.last_attempt = now_m
        fetched_at = self._wall()
        self.times["last_poll_at"] = store.iso(fetched_at)
        try:
            stream = lapi.fetch_stream(lapi.url(), key, startup=startup, origins=lapi.origins())
        except lapi.LapiAuthError as e:
            self.need_snapshot = True
            self._set("lapi", "auth_failed", f"LAPI refused the console's bouncer key ({e}). Enforcement is "
                      f"unchanged; a full snapshot follows once the key works (retried every {AUTH_RETRY_SECONDS} s).")
        except lapi.LapiMalformed as e:
            self.need_snapshot = True
            self._set("lapi", "malformed", f"LAPI sent an unusable response ({e}); it was ignored and "
                      "enforcement is unchanged.")
        except lapi.LapiUnavailable as e:
            self.need_snapshot = True
            self._set("lapi", "unreachable", f"LAPI is unreachable ({e}). The last synced list stays enforced.")
        else:
            self._merge(stream, startup, fetched_at)
            self.need_snapshot = False
            self.times["last_success_at"] = store.iso(fetched_at)
            if startup:
                self.times["last_snapshot_at"] = store.iso(fetched_at)
                self.snapshot_audit = True
            self._set("lapi", "ok")
            self._maybe_apply(now_m)
        self._write()
        return self.lapi_state

    def _merge(self, stream, startup, fetched_at) -> None:
        if startup:                                   # reconciliation: the snapshot is the whole truth
            self.desired, self.ignored = {}, collections.Counter()
        for did in stream.deleted:
            self.desired.pop(did, None)               # an unknown id is a no-op
        origins = lapi.origins()
        for d in stream.new:
            accepted, reason = lapi.classify(d, origins, fetched_at)
            if accepted is None:
                self.ignored[reason] += 1
                self.desired.pop(d.id, None)
            else:
                self.desired[d.id] = accepted

    def _maybe_apply(self, now_m) -> None:
        """Every BANS_SYNC_INTERVAL, whether or not a delta arrived: a full
        reconcile is cheap when nothing changed (no write, no reload), and it
        restores records an operator Reset until CrowdSec itself drops them."""
        if self.last_apply is not None and now_m - self.last_apply < config.BANS_SYNC_INTERVAL:
            return
        from . import service                        # service imports the editor routes; keep this lazy
        result = service.apply_crowdsec(list(self.desired.values()), snapshot=self.snapshot_audit,
                                        ignored=dict(self.ignored))
        self.last_apply, self.last_result = now_m, result
        self.times["last_apply_at"] = store.iso(self._wall())
        if result.ok:
            self.snapshot_audit = False
            self._set("apply", "ok")
        else:
            self._set("apply", _APPLY_STATES.get(result.code, "failed"), result.message)

    def _write(self) -> None:
        result = self.last_result
        ignored = dict(self.ignored)
        if result is not None:
            ignored.update({f"protected:{k}": v for k, v in result.protected.items()})
        doc = {"version": syncstate.VERSION, "leader_pid": os.getpid(), "updated_at": store.iso(self._wall()),
               "lapi_state": self.lapi_state, "lapi_message": self.lapi_message,
               "apply_state": self.apply_state, "apply_message": self.apply_message, **self.times,
               "decisions": len(self.desired),
               "by_origin": dict(collections.Counter(a.origin for a in self.desired.values())),
               "ignored": ignored, "protected_sample": result.protected_sample if result else [],
               "capacity": result.capacity if result else None, "origins": list(lapi.origins()),
               "poll_interval": config.CROWDSEC_POLL_INTERVAL, "sync_interval": config.BANS_SYNC_INTERVAL}
        try:
            syncstate.write(doc)
        except OSError as e:
            log.warning("IP bans: could not write the CrowdSec status file: %s", e)
```

- [ ] **Step 6: Start the sync thread per worker**

In `src/bans/jobs.py`, extend the module docstring with one paragraph:

```text
When CrowdSec is configured, every worker also runs a "bans-sync" thread. Only
the worker holding BACKUP_DIR/bans-sync.lock polls LAPI (src/bans/sync.py);
the others retry the lock each poll interval and take over when it exits.
```

Add `import os` and `from . import lapi` to the imports, then add `_sync_loop` and update `start_background`:

```python
def _sync_loop(stop) -> None:
    from . import sync
    leader, synchronizer = sync.Leadership(), None
    while True:
        try:
            if leader.try_acquire():
                if synchronizer is None:
                    synchronizer = sync.Synchronizer()
                    log.info("IP bans: worker %d leads CrowdSec sync", os.getpid())
                synchronizer.step()
        except Exception:  # noqa: BLE001 - the thread must survive anything
            log.exception("IP bans: CrowdSec sync step crashed")
        if stop.wait(config.CROWDSEC_POLL_INTERVAL):
            leader.release()
            return


def start_background():
    global _started
    if _started or not config.BANS_ENABLED:
        return None
    _started = True
    stop = threading.Event()
    threading.Thread(target=_loop, args=(stop,), name="bans-expiry", daemon=True).start()
    if lapi.enabled():
        threading.Thread(target=_sync_loop, args=(stop,), name="bans-sync", daemon=True).start()
    return stop
```

`gunicorn.conf.py` and `app.py` need no change: both already call `start_background()` per worker (or in the single dev process), never in the master.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `uv run --frozen python -m unittest tests.test_crowdsec_sync tests.test_crowdsec_leader tests.test_bans_jobs -v`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/bans/syncstate.py src/bans/sync.py src/bans/jobs.py tests/test_crowdsec_sync.py tests/test_crowdsec_leader.py
git commit -m "feat(crowdsec): elected per-worker stream sync with coalesced applies and shared health"
```

---

### Task 6: Per-source status, site detection and the Security API

**Files:**
- Modify: `src/bans/detect.py` (`_events`, `_status`: other sources' ban routes are not pre-handlers)
- Modify: `src/bans/scan.py` (`block_import_state(..., after=())`)
- Modify: `src/bans/service.py` (`_site_rows`, `status`, `_recovery_info_locked`, `_crowdsec_status`)
- Modify: `tests/integration/make_detect_fixtures.py`; regenerate `tests/fixtures/bans/adapted-layouts.json`
- Test: `tests/test_crowdsec_status.py`; existing `tests/test_bans_detect.py`, `tests/test_bans_service.py`, `tests/test_bans_api.py` stay green.

**Interfaces:**
- Consumes: `syncstate.read()` (Task 5), `render.active_sources` (Task 3), `lapi.enabled/origins/LIST_ORIGINS` (Task 1).
- Produces: `scan.block_import_state(text, block, path, after=())`: `first_child` is also true when only other managed imports named by `after` precede this one. `GET /api/security` adds `sources.crowdsec` = `{file, import_line, hold, hold_reason, rendered_prefixes, active_records, enabled, origins, list_origins, sync (syncstate doc or null), stale}` when the source is active; `limits = {max_prefixes, used, by_source}`; every site row keeps the Phase 1 top-level keys (manual's `status`, `pre_handlers`, `detail`, `import`) and adds `policies: {<source>: {status, pre_handlers, detail, import}}` for every active source. `recovery` gains `held_sources: [names]`. `STALE_POLLS = 3`.

- [ ] **Step 1: Add the real-Caddy fixtures**

In `tests/integration/make_detect_fixtures.py`, add after `EMPTY`:

```python
CS_ACTIVE = (
    "# Managed by Caddy Console. Do not edit; changes are overwritten.\n"
    "vars caddy_console_crowdsec_policy 1\n"
    "@caddy_console_crowdsec_banned {\n"
    "\tclient_ip 192.0.2.0/24 203.0.113.9\n"
    "\tnot client_ip private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10\n"
    "}\n"
    "handle @caddy_console_crowdsec_banned {\n"
    "\trespond 403\n"
    "}\n"
)
IMP_CS = f"import {DIR}/active/bans-crowdsec*.caddy"
```

add two layouts to `LAYOUTS`:

```python
    "manual_and_crowdsec": site("\t{imp}\n\t" + IMP_CS + "\n\treverse_proxy 127.0.0.1:9\n"),
    "crowdsec_only": site("\t" + IMP_CS + "\n\treverse_proxy 127.0.0.1:9\n"),
```

and in `main()` write the CrowdSec file beside the manual one:

```python
    with open(f"{DIR}/active/bans-crowdsec.caddy", "w", encoding="utf-8") as f:
        f.write(CS_ACTIVE)
```

Regenerate with the dev stack:

```bash
./dev/run.sh up
docker compose -f docker-compose.dev.yaml exec -T caddy-console \
  /app/.venv/bin/python - < tests/integration/make_detect_fixtures.py > tests/fixtures/bans/adapted-layouts.json
git diff --stat tests/fixtures/bans/adapted-layouts.json
```

Expected: only the two new keys are added; the existing layouts are byte-identical (if Caddy renamed anything, stop and investigate before continuing).

- [ ] **Step 2: Write the failing test**

`tests/test_crowdsec_status.py`:

```python
"""Per-source site detection and the CrowdSec part of GET /api/security
(spec "Mode detection and health", 2.7).

Run with:  uv run --frozen python -m unittest tests.test_crowdsec_status -v
"""
import json
import os
import unittest
from datetime import timedelta
from unittest import mock

import tests._env as env
from tests import _bans, _crowdsec

from src import config
from src.bans import addr, detect, fsio, protected, render, scan, service, store, syncstate

CS, MANUAL = render.SOURCES["crowdsec"], render.SOURCES["manual"]
with open(os.path.join(os.path.dirname(__file__), "fixtures", "bans", "adapted-layouts.json"), encoding="utf-8") as f:
    FIXTURES = json.load(f)
D = env.BANS_DIR


def write_state(manual=(), crowdsec=()):
    now = store.utc_now()
    state = store.State()
    for v in manual:
        state.records.append(store.new_manual_record(addr.canonical(v), "24h", "", "a@example.com", now))
    for i, v in enumerate(crowdsec, 1):
        state.records.append(store.new_crowdsec_record(str(i), addr.canonical(v), "crowdsec", "s", now,
                                                       now + timedelta(hours=4)))
    fsio.atomic_write(store.STATE_PATH, store.dumps(state), 0o600)


class DetectTest(unittest.TestCase):
    def test_a_manual_ban_route_before_the_crowdsec_one_is_not_a_pre_handler(self):
        live = FIXTURES["manual_and_crowdsec"]
        m = detect.site_statuses(live, MANUAL, True, expected_ranges=["198.51.100.0/24", "203.0.113.7"])[0]
        c = detect.site_statuses(live, CS, True, expected_ranges=["192.0.2.0/24", "203.0.113.9"])[0]
        self.assertEqual((m.status, c.status, c.pre_handlers), ("enforced", "enforced", []))
        only = detect.site_statuses(FIXTURES["crowdsec_only"], CS, True)[0]
        self.assertEqual(only.status, "enforced")
        self.assertEqual(detect.site_statuses(FIXTURES["crowdsec_only"], MANUAL, False)[0].status, "not_imported")

    def test_import_position_after_the_manual_import(self):
        text = (f"a.example.com {{\n\timport {D}/bans-manual*.caddy\n\timport {D}/bans-crowdsec*.caddy\n\trespond 200\n}}\n"
                f"b.example.com {{\n\trespond 200\n\timport {D}/bans-crowdsec*.caddy\n}}\n"
                f"c.example.com {{\n\troute {{\n\t\timport {D}/bans-manual*.caddy\n\t\timport {D}/bans-crowdsec*.caddy\n"
                "\t\trespond 200\n\t}\n}\n")
        a, b, c = scan.site_blocks(text)
        after = (MANUAL.path,)
        self.assertTrue(scan.block_import_state(text, a, CS.path, after=after)["first_child"])
        self.assertFalse(scan.block_import_state(text, a, CS.path)["first_child"])     # Phase 1 rule unchanged
        self.assertFalse(scan.block_import_state(text, b, CS.path, after=after)["first_child"])
        self.assertEqual(scan.block_import_state(text, c, CS.path, after=after)["layout"], "strict")


class StatusCase(unittest.TestCase):
    def setUp(self):
        _bans.reset(f"a.example.com {{\n\timport {D}/bans-manual*.caddy\n\timport {D}/bans-crowdsec*.caddy\n"
                    "\treverse_proxy 127.0.0.1:9\n}\n")
        _bans.fresh_audit(self)
        service.reset_caches()
        docker = mock.patch.object(protected, "read_docker_networks", lambda: [])
        docker.start()
        self.addCleanup(docker.stop)
        self.caddy = _bans.FakeCaddy().install(self)

    def tearDown(self):
        service.reset_caches()


class StatusTest(StatusCase):
    def test_crowdsec_source_appears_only_when_active(self):
        self.assertEqual(list(service.status(None)["sources"]), ["manual"])
        _crowdsec.enable(self)
        status = service.status(None)
        self.assertEqual(list(status["sources"]), ["manual", "crowdsec"])
        cs = status["sources"]["crowdsec"]
        self.assertEqual((cs["enabled"], cs["origins"], cs["list_origins"], cs["sync"], cs["stale"]),
                         (True, ["crowdsec", "cscli"], [], None, True))
        self.assertEqual(cs["import_line"], f"import {D}/bans-crowdsec*.caddy")

    def test_sync_report_and_staleness(self):
        _crowdsec.enable(self, CROWDSEC_ORIGINS="crowdsec,capi")
        doc = {"version": syncstate.VERSION, "updated_at": store.iso(store.utc_now()), "lapi_state": "ok",
               "apply_state": "ok", "decisions": 3}
        syncstate.write(doc)
        cs = service.status(None)["sources"]["crowdsec"]
        self.assertEqual((cs["sync"]["decisions"], cs["stale"], cs["list_origins"]), (3, False, ["capi"]))
        syncstate.write({**doc, "updated_at": store.iso(store.utc_now() - timedelta(minutes=5))})
        self.assertTrue(service.status(None)["sources"]["crowdsec"]["stale"])

    def test_sites_report_each_source(self):
        _crowdsec.enable(self)
        write_state(manual=("198.51.100.0/24", "203.0.113.7"), crowdsec=("192.0.2.0/24", "203.0.113.9"))
        self.caddy.live = FIXTURES["manual_and_crowdsec"]
        status = service.status(None)
        row = status["sites"][0]
        self.assertEqual((row["status"], row["policies"]["manual"]["status"], row["policies"]["crowdsec"]["status"]),
                         ("enforced", "enforced", "enforced"))
        self.assertTrue(row["policies"]["crowdsec"]["import"]["first_child"])
        self.assertEqual(status["limits"], {"max_prefixes": config.BANS_MAX, "used": 4,
                                            "by_source": {"manual": 2, "crowdsec": 2}})

    def test_console_site_importing_crowdsec_is_a_lockout_risk(self):
        _crowdsec.enable(self)
        _bans.write_caddyfile(f"a.example.com {{ # caddy-console: management\n\timport {D}/bans-crowdsec*.caddy\n"
                              "\treverse_proxy 127.0.0.1:9\n}\n")
        row = service.status(None)["sites"][0]
        self.assertEqual((row["status"], row["policies"]["crowdsec"]["status"]), ("management", "management_imported"))

    def test_unreachable_caddy_marks_every_policy_unknown(self):
        _crowdsec.enable(self)
        self.caddy.down = True
        row = service.status(None)["sites"][0]
        self.assertEqual({p["status"] for p in row["policies"].values()}, {"caddy_unreachable"})

    def test_held_sources_are_listed_for_recovery(self):
        _crowdsec.enable(self)
        service.add_ban({"value": "203.0.113.7", "duration": "24h", "reason": ""}, "op", None)
        fsio.atomic_write(CS.path, b"", 0o644)
        info = service.recovery_info()
        self.assertEqual((info["kind"], info["held_sources"], info["files"]), ("policy_hold", ["crowdsec"],
                                                                              ["bans-crowdsec.caddy"]))
        self.assertTrue(service.status(None)["sources"]["crowdsec"]["hold"])

    def test_status_never_contains_the_key(self):
        _crowdsec.enable(self)
        syncstate.write({"version": syncstate.VERSION, "updated_at": store.iso(store.utc_now())})
        self.assertNotIn(_crowdsec.KEY, json.dumps(service.status(None)))


class ApiTest(_bans.ApiCase):
    def test_security_api_reports_crowdsec_and_bans_lists_it_read_only(self):
        _crowdsec.enable(self)
        write_state(crowdsec=("203.0.113.9",))
        body = self.get("/api/security").get_json()
        self.assertIn("crowdsec", body["sources"])
        rec = next(r for r in self.get("/api/bans").get_json()["records"] if r["source"] == "crowdsec")
        self.assertEqual(self.delete(f"/api/bans/{rec['id']}").status_code, 403)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run --frozen python -m unittest tests.test_crowdsec_status -v`
Expected: FAIL (`'unknown' != 'enforced'` for CrowdSec after manual, `unexpected keyword argument 'after'`, `KeyError: 'policies'`).

- [ ] **Step 4: Detection skips other managed ban routes**

In `src/bans/detect.py`, give every event a fourth element, `shielded`: true for a route that is itself a managed ban route and for everything inside it. Such a route only answers 403 to clients it bans, so it is never a pre-handler for another source.

```python
def _events(route, out, scope, shielded=False) -> None:
    """Routes and handlers in execution order, descending into subroutes.
    `scope` identifies the route list a route belongs to; `shielded` marks a
    managed ban route (any source) and everything inside it."""
    shielded = shielded or _is_ban_route(route)
    out.append(("route", route, scope, shielded))
    for h in route.get("handle") or []:
        if not isinstance(h, dict):
            continue
        if h.get("handler") == "subroute":
            inner = id(h)
            for r in h.get("routes") or []:
                if isinstance(r, dict):
                    _events(r, out, inner, shielded)
        else:
            out.append(("handler", h, scope, shielded))
```

In `_status`, update the three places that unpack events:

```python
    marker_at = next((i for i, (k, v, _, _) in enumerate(events) if k == "handler" and _is_marker(v, source.marker)), None)
    ...
    ban_at = next((i for i, (k, v, sc, _) in enumerate(events)
                   if i > marker_at and k == "route" and sc == scope and _is_ban_route(v, expected)), None)
    ...
    for kind, h, _, shielded in events[:ban_at]:
        if kind != "handler" or shielded or _is_marker(h, source.marker):
            continue
```

`_is_ban_route(route)` without `expected` matches any managed shape, which is what "another source's ban route" needs. The manual source's own result is unchanged: its ban route is `events[ban_at]`, outside the slice.

- [ ] **Step 5: Import position after other managed imports**

In `src/bans/scan.py`, replace the `first` / `strict` part of `block_import_state`:

```python
def block_import_state(text, block, path, after=()) -> dict:
    """`after`: other managed policy paths that may come before this import
    (the CrowdSec import goes directly after the manual one)."""
    lines = str(text).split("\n")
    children, depth = [], 1
    for n in range(block.start, block.end - 1):        # interior lines; n + 1 is the line number
        line = _strip(lines[n])
        if not line:
            continue
        children.append((n + 1, line, depth))
        bare = _PLACEHOLDER.sub("", line)
        depth += bare.count("{") - bare.count("}")
    matches = [ln for ln, line, _ in children if _is_policy_import(line, path)]
    state = {"present": bool(matches), "count": len(matches),
             "line": matches[0] if matches else None, "first_child": False, "layout": None}

    def leads(seq) -> bool:
        for _, line in seq:
            if _is_policy_import(line, path):
                return True
            if not any(_is_policy_import(line, p) for p in after):
                return False
        return False
    top = [(ln, line) for ln, line, d in children if d == 1]
    if leads(top):
        state.update(first_child=True, layout="site")
    elif top and _ROUTE.match(top[0][1]):
        route_ln = top[0][0]
        inner = [(ln, line) for ln, line, d in children if d == 2 and ln > route_ln]
        if leads(inner):
            state.update(first_child=True, layout="strict")
    return state
```

- [ ] **Step 6: Per-source status and site rows**

In `src/bans/service.py`, add `syncstate` to the `from . import ...` line, add `STALE_POLLS = 3` beside the other constants, and replace `_site_rows` and `status` (the Task 0 fallback stays):

```python
def _site_rows(live, text, state, now, holds) -> list:
    """One row per site: the manual policy's result at the top level (the Phase 1
    shape) plus `policies` for every active source. `state` None means the
    stored records are unknown (corrupt), so any managed ban route counts."""
    sources = render.active_sources(state)
    after = {"crowdsec": (render.SOURCES["manual"].path,)}
    blocks = scan.site_blocks(text)
    management = scan.management_hosts(text, scan.console_host())
    detected = {}
    if live is not None:
        for name, src in sources.items():
            prefixes = None if state is None else render.effective_prefixes(state.records, now, name)
            expected = None if name in holds or prefixes is None else [addr.token(p) for p in prefixes]
            detected[name] = detect.site_statuses(live, src, bool(prefixes), expected_ranges=expected)

    def policy(name, status, block, mgmt, found=None):
        imp = scan.block_import_state(text, block, sources[name].path, after=after.get(name, ())) if block else None
        return {"status": _management_status(status, imp) if mgmt else status,
                "pre_handlers": found.pre_handlers if found else [], "detail": found.detail if found else "",
                "import": imp}

    rows, seen = [], set()
    for i, s in enumerate(detected.get("manual", [])):
        block = next((b for b in blocks if set(b.hosts) & set(s.hosts)), None) if s.hosts \
            else next((b for b in blocks if s.label in b.addresses), None)
        if block is not None:
            seen.add(block.start)
        mgmt = bool(set(s.hosts) & management)
        policies = {name: policy(name, found[i].status, block, mgmt, found[i]) for name, found in detected.items()}
        rows.append({"label": s.label, "hosts": s.hosts, "source": "main" if block else "external",
                     "line": block.start if block else None, **policies["manual"], "policies": policies})
    unreachable = live is None
    fallback = "caddy_unreachable" if unreachable else "not_loaded"
    fallback_detail = ("The Caddy admin API is unreachable, so whether this site enforces the ban list "
                       "cannot be checked." if unreachable
                       else "This site block is not in Caddy's running configuration.")
    for b in blocks:
        if b.start in seen:
            continue
        mgmt = bool(set(b.hosts) & management)
        policies = {name: {**policy(name, fallback, b, mgmt), "detail": fallback_detail} for name in sources}
        rows.append({"label": b.hosts[0] if b.hosts else b.addresses[0], "hosts": b.hosts, "source": "main",
                     "line": b.start, **policies["manual"], "policies": policies})
    return rows


def _crowdsec_status(now) -> dict:
    enabled = lapi.enabled()
    origins = list(lapi.origins()) if enabled else []
    doc = syncstate.read() if enabled else None
    stale = enabled
    if doc and doc.get("updated_at"):
        try:
            age = (now - store.parse_iso(doc["updated_at"])).total_seconds()
            stale = age > STALE_POLLS * config.CROWDSEC_POLL_INTERVAL + config.BANS_SYNC_INTERVAL
        except ValueError:
            stale = True
    return {"enabled": enabled, "origins": origins,
            "list_origins": [o for o in origins if o in lapi.LIST_ORIGINS], "sync": doc, "stale": stale}


def status(remote_addr) -> dict:
    avail = availability()
    info = recovery_info()
    try:
        state = store.load()
    except store.StateCorrupt:
        state = None
    now = store.utc_now()
    holds = _holds(state) if state else {}
    sources = {}
    for name, src in render.active_sources(state).items():
        rendered = len(render.effective_prefixes(state.records, now, name)) if state else 0
        sources[name] = {
            "file": src.path, "import_line": src.import_line, "hold": name in holds,
            "hold_reason": holds.get(name), "rendered_prefixes": rendered,
            "active_records": sum(1 for r in (state.records if state else [])
                                  if r.source == name and not r.expired(now)),
        }
    if "crowdsec" in sources:
        sources["crowdsec"].update(_crowdsec_status(now))
    try:
        live, caddy = caddy_admin.live_config(), {"reachable": True, "message": None}
    except caddy_admin.CaddyUnavailable as e:
        live, caddy = None, {"reachable": False, "message": f"The Caddy admin API is unreachable ({e})."}
    degraded = None
    if info["required"] and info["kind"] in ("journal", "state_corrupt"):
        degraded = {"kind": info["kind"], "reason": info["reason"], "phase": info["phase"], "message": info["summary"]}
    by_source = {name: s["rendered_prefixes"] for name, s in sources.items()}
    return {
        "enabled": True, "available": avail.ok,
        "unavailable": None if avail.ok else {"code": avail.code, "message": avail.message},
        "state_version": info["state_version"], "degraded": degraded, "recovery": info,
        "sources": sources,
        "protected": protected_for(state or store.State(), _verified_client(remote_addr)).summary(),
        "sites": _site_rows(live, _read_caddyfile(), state, now, holds),
        "caddy": caddy,
        "limits": {"max_prefixes": config.BANS_MAX, "used": sum(by_source.values()), "by_source": by_source},
        "last_apply": _last_apply(),
    }
```

`_management_status` is unchanged from Task 0.

In `_recovery_info_locked`, add `"held_sources": []` to `base`, and in the `policy_hold` branch add `"held_sources": sorted(holds)` and use the active sources' filenames (`render.SOURCES[n].filename for n in sorted(holds)` already works because `holds` comes from `_holds`). Change its summary to "A managed ban file differs from the stored state, for example after host recovery. It is not regenerated, and its expiry and CrowdSec sync are paused, until you fix the records and Re-apply."

- [ ] **Step 7: Run the tests to verify they pass**

Run: `uv run --frozen python -m unittest tests.test_crowdsec_status tests.test_bans_detect tests.test_bans_service tests.test_bans_api -v`
Expected: PASS. (Phase 1 site-row tests read the unchanged top-level keys.)

- [ ] **Step 8: Commit**

```bash
git add src/bans/detect.py src/bans/scan.py src/bans/service.py tests/integration/make_detect_fixtures.py \
  tests/fixtures/bans/adapted-layouts.json tests/test_crowdsec_status.py
git commit -m "feat(crowdsec): per-source site enforcement and CrowdSec health in the Security API"
```

---
### Task 7: CrowdSec snippets, validator warnings and editor insertion

**Files:**
- Modify: `src/snippets.json` (two entries after `manual-bans-recovery`)
- Modify: `src/routes/editor.py` (`get_snippets` filter and context; validate warnings)
- Modify: `src/bans/scan.py` (`bans_warnings` keywords)
- Modify: `src/static/js/app/snippet-insert.js` (`after` option)
- Modify: `src/static/js/app/panels.js` (`insertSiteFirst` targets, `insertBanImportAtLine(line, source)`, refusal copy)
- Modify: `src/static/js/app/main.js` (`app:insert-ban-import` passes `source`)
- Test: `tests/snippet-insert.test.mjs`, `tests/test_bans_api.py`, `tests/test_bans_detect.py`

**Interfaces:**
- Consumes: `scan.block_import_state(..., after=)` (Task 6).
- Produces: snippet ids `crowdsec-bans-site` (site, `site-first`, after the manual import) and `crowdsec-log-fields` (site, `copy-only`), both with prerequisites `["BANS_ENABLED", "CROWDSEC_URL"]`; `/api/snippets` context adds `crowdsec: bool`; `scan.bans_warnings(text, path, management=frozenset(), *, label="manual ban list", short="the ban list", after=(), reserved=True)`; `planSiteInsertion(text, cursorLine, code, { target, managementHosts, after = [] })`; `insertBanImportAtLine(siteLine, source = 'manual')`; the `app:insert-ban-import` event detail is `{ line, source }` (Task 8 sends it).

- [ ] **Step 1: Write the failing tests**

Append to `tests/snippet-insert.test.mjs` before its final `console.log`, and change the existing "scopes" check as shown:

```js
const CS_T = '/etc/caddy/console/bans-crowdsec.caddy';
const CS_CODE = 'import /etc/caddy/console/bans-crowdsec*.caddy\n';
const CS_OPTS = { target: CS_T, managementHosts: ['console.example.com'], after: [T] };
const WITH_MANUAL = ['a.example.com {', '\timport /etc/caddy/console/bans-manual*.caddy', '\treverse_proxy 127.0.0.1:9', '}', ''].join('\n');
check('the CrowdSec import goes directly after the manual import', () => {
  const p = planSiteInsertion(WITH_MANUAL, 1, CS_CODE, CS_OPTS);
  assert.deepEqual([p.ok, p.line, p.text], [true, 3, '\timport /etc/caddy/console/bans-crowdsec*.caddy\n']);
});
check('without a manual import the CrowdSec import goes first', () => {
  const p = planSiteInsertion(CF, 13, CS_CODE, CS_OPTS);
  assert.deepEqual([p.ok, p.line], [true, 14]);
});
check('the CrowdSec import is not inserted twice, nor into the console site', () => {
  const twice = applyPlan(WITH_MANUAL, planSiteInsertion(WITH_MANUAL, 1, CS_CODE, CS_OPTS));
  assert.equal(planSiteInsertion(twice, 1, CS_CODE, CS_OPTS).reason, 'duplicate');
  assert.equal(planSiteInsertion(CF, 29, CS_CODE, CS_OPTS).reason, 'management-site');
});
check('the CrowdSec snippets carry their metadata', () => {
  const s = snippets.find(x => x.id === 'crowdsec-bans-site');
  assert.deepEqual([s.phase, s.scope, s.insert, s.prerequisites, s.code],
    ['crowdsec', 'site', 'site-first', ['BANS_ENABLED', 'CROWDSEC_URL'], CS_CODE]);
  const f = snippets.find(x => x.id === 'crowdsec-log-fields');
  assert.deepEqual([f.scope, f.insert, f.prerequisites], ['site', 'copy-only', ['BANS_ENABLED', 'CROWDSEC_URL']]);
  assert.match(f.code, /^log_append <user_agent \{http\.request\.header\.User-Agent\}$/m);
  assert.match(f.code, /^log_append auth_challenge \{http\.response\.header\.Www-Authenticate\}$/m);
  assert.doesNotMatch(f.code, /Authorization|Cookie/i);
});
```

Replace the existing "scopes" check with:

```js
check('scopes: ban imports insert first in a site, everything else is copy only', () => {
  for (const s of snippets.filter(x => x.scope)) {
    const importsBans = s.scope === 'site' && /^import \S*bans-\w+\*\.caddy\n$/.test(s.code);
    assert.equal(s.insert, importsBans ? 'site-first' : 'copy-only', s.id);
  }
  assert.doesNotMatch(snippets.find(x => x.id === 'manual-bans-recovery').code, /^import /m);
});
```

Append to class `SecurityApiTest` in `tests/test_bans_api.py` (add `from tests import _crowdsec` to the imports):

```python
    def test_crowdsec_snippets_only_when_configured(self):
        ids = [s["id"] for s in self.get("/api/snippets").get_json()["snippets"]]
        self.assertNotIn("crowdsec-bans-site", ids)
        self.assertNotIn("crowdsec-log-fields", ids)
        _crowdsec.enable(self)
        body = self.get("/api/snippets").get_json()
        by_id = {s["id"]: s for s in body["snippets"]}
        self.assertEqual(by_id["crowdsec-bans-site"]["code"], f"import {env.BANS_DIR}/bans-crowdsec*.caddy\n")
        self.assertIn("crowdsec-log-fields", by_id)
        self.assertTrue(body["context"]["crowdsec"])

    def test_validate_reports_crowdsec_import_problems(self):
        text = f"a.example.com {{\n\trespond 200\n\timport {env.BANS_DIR}/bans-crowdsec*.caddy\n}}\n"
        self.assertFalse(any("CrowdSec" in w for w in self.post("/api/validate", {"content": text}).get_json()["warnings"]))
        _crowdsec.enable(self)
        warnings = self.post("/api/validate", {"content": text}).get_json()["warnings"]
        self.assertTrue(any("put the CrowdSec import first" in w for w in warnings), warnings)
        ok = (f"a.example.com {{\n\timport {env.BANS_DIR}/bans-manual*.caddy\n"
              f"\timport {env.BANS_DIR}/bans-crowdsec*.caddy\n\trespond 200\n}}\n")
        self.assertEqual([w for w in self.post("/api/validate", {"content": ok}).get_json()["warnings"]
                          if "import" in w], [])
```

Append to the warnings test class in `tests/test_bans_detect.py` (the one holding `test_validator_warnings`):

```python
    def test_crowdsec_warnings(self):
        cs = "/etc/caddy/console/bans-crowdsec.caddy"
        text = ("a.example.com {\n\timport /etc/caddy/console/bans-crowdsec*.caddy\n"
                "\timport /etc/caddy/console/bans-crowdsec*.caddy\n}\n"
                "console.example.com {\n\timport /etc/caddy/console/bans-crowdsec*.caddy\n}\n"
                "x.example.com {\n\t@caddy_console_mine path /a\n\trespond @caddy_console_mine 404\n}\n")
        warnings = scan.bans_warnings(text, cs, {"console.example.com"}, label="CrowdSec ban list",
                                      short="the CrowdSec ban list", after=(P,), reserved=False)
        self.assertEqual(warnings, [
            "Line 2: this site imports the CrowdSec ban list 2 times; keep one import.",
            "Line 6: this is the console's own site; importing the CrowdSec ban list here could lock you out of the console.",
        ])
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node tests/snippet-insert.test.mjs; uv run --frozen python -m unittest tests.test_bans_api tests.test_bans_detect -v`
Expected: FAIL (`Cannot read properties of undefined (reading 'phase')`, `unexpected keyword argument 'label'`, missing snippet ids).

- [ ] **Step 3: Snippets**

Add to `src/snippets.json` after `manual-bans-recovery`:

```json
  {
    "id": "crowdsec-bans-site",
    "name": "CrowdSec bans: protect this site",
    "description": "Answer 403 to addresses CrowdSec decided to ban. Goes first in a site block, or directly after the manual ban import.",
    "phase": "crowdsec",
    "scope": "site",
    "insert": "site-first",
    "supported_modes": ["direct", "cloudflare-proxied", "cloudflare-tunnel"],
    "prerequisites": ["BANS_ENABLED", "CROWDSEC_URL"],
    "code": "import /etc/caddy/console/bans-crowdsec*.caddy\n"
  },
  {
    "id": "crowdsec-log-fields",
    "name": "CrowdSec: log fields for detection",
    "description": "Logs the User-Agent and a Basic auth challenge as two top-level access-log fields, so CrowdSec's bad User-Agent and brute-force scenarios work while request and response headers stay out of the log. Put it in each logged site, below the ban imports. Copy only.",
    "phase": "crowdsec",
    "scope": "site",
    "insert": "copy-only",
    "supported_modes": ["direct", "cloudflare-proxied", "cloudflare-tunnel"],
    "prerequisites": ["BANS_ENABLED", "CROWDSEC_URL"],
    "code": "log_append <user_agent {http.request.header.User-Agent}\nlog_append auth_challenge {http.response.header.Www-Authenticate}\n"
  }
```

(Keep the file's existing indentation style; the snippet array stays valid JSON.)

- [ ] **Step 4: Snippet filter, context and validate warnings**

In `src/routes/editor.py` `get_snippets`, after the `BANS_ENABLED` early return:

```python
    crowdsec = bool(config.CROWDSEC_URL)
    snippets = [s for s in snippets if crowdsec or "CROWDSEC_URL" not in s.get("prerequisites", [])]
```

and add `"crowdsec": crowdsec,` to the returned `context`. In the validate handler, replace the `if config.BANS_ENABLED:` block:

```python
    if config.BANS_ENABLED:
        mgmt = bans_scan.management_hosts(content, bans_scan.console_host())
        manual_path = bans_render.SOURCES["manual"].path
        warnings += bans_scan.bans_warnings(content, manual_path, mgmt)
        if config.CROWDSEC_URL:
            warnings += bans_scan.bans_warnings(content, bans_render.SOURCES["crowdsec"].path, mgmt,
                                                label="CrowdSec ban list", short="the CrowdSec ban list",
                                                after=(manual_path,), reserved=False)
```

In `src/bans/scan.py`, add beside `FIRST_MSG`:

```python
AFTER_MSG = ("put the CrowdSec import first in the site block, or directly after the manual ban import, "
             "so nothing runs before the ban check.")
```

and give `bans_warnings` the keywords (manual output stays byte-identical):

```python
def bans_warnings(text, path, management=frozenset(), *, label="manual ban list", short="the ban list",
                  after=(), reserved=True) -> list:
    out = []
    if reserved:
        for i, raw in enumerate(str(text).split("\n"), 1):
            if _USER_MATCHER.match(_strip(raw)):
                out.append(f"Line {i}: matcher names starting with @caddy_console_ are reserved for "
                           "Caddy Console's generated policy; rename this matcher.")
    for block in site_blocks(text):
        st = block_import_state(text, block, path, after=after)
        if not st["present"]:
            continue
        if set(block.hosts) & set(management):
            out.append(f"Line {st['line']}: this is the console's own site; importing {short} "
                       "here could lock you out of the console.")
        if st["count"] > 1:
            out.append(f"Line {st['line']}: this site imports the {label} {st['count']} times; keep one import.")
        if not st["first_child"]:
            out.append(f"Line {st['line']}: {AFTER_MSG if after else FIRST_MSG}")
    return out
```

(In the test text above the duplicated imports are the first two children, so `first_child` holds and no position warning appears; the console site's import is its first child too.)

- [ ] **Step 5: Insertion after the manual import**

In `src/static/js/app/snippet-insert.js`, change the signature and add the `after` branch just before the existing `firstChild` computation:

```js
export function planSiteInsertion(text, cursorLine, code, { target, managementHosts = [], after = [] } = {}) {
```

```js
  // `after`: managed imports that may lead the block (the CrowdSec import goes
  // directly after the manual one). Skip a leading run of them, if any.
  const kids = [];
  for (let n = block.start + 1; n <= block.end - 1; n++) if (stripComment(lines[n - 1])) kids.push(n);
  const leadsAfter = (n) => {
    const m = stripComment(lines[n - 1]).match(/^import\s+(\S+)/);
    return !!m && after.some(t => importMatches(m[1], t));
  };
  let lead = 0;
  while (lead < kids.length && leadsAfter(kids[lead])) lead++;
  if (lead > 0) {
    const prev = kids[lead - 1];
    const indent = lines[prev - 1].match(/^\s*/)[0];
    return { ok: true, block, line: prev + 1, text: indent + String(code).trim() + '\n' };
  }
```

In `src/static/js/app/panels.js`, derive the target per snippet and pass `after`:

```js
const SNIPPET_FILES = { 'manual-bans-site': 'bans-manual.caddy', 'crowdsec-bans-site': 'bans-crowdsec.caddy' };
const SOURCE_SNIPPETS = { manual: 'manual-bans-site', crowdsec: 'crowdsec-bans-site' };
```

In `insertSiteFirst`, replace the `planSiteInsertion` call:

```js
  const dir = ctx.bans_dir || '/etc/caddy/console';
  const plan = planSiteInsertion(editorView.state.doc.toString(), cursorLine, s.code, {
    target: `${dir}/${SNIPPET_FILES[s.id] || 'bans-manual.caddy'}`,
    managementHosts: ctx.management_hosts || [],
    after: s.id === 'crowdsec-bans-site' ? [`${dir}/bans-manual.caddy`] : [],
  });
```

Change `REFUSED.duplicate` to `'This site already imports this ban list.'`, and `insertBanImportAtLine`:

```js
/** Security view entry: a site with no known line (external import) gets Copy only. */
export async function insertBanImportAtLine(siteLine, source = 'manual') {
  let data;
  try { data = await loadSnippetData(); }
  catch (e) { toast(`Could not load snippets: ${e.message}`, { kind: 'error' }); return false; }
  const s = data.snippets.find(x => x.id === SOURCE_SNIPPETS[source]);
  if (!s) { toast('This ban list is not available: CrowdSec is not configured.', { kind: 'warn' }); return false; }
  if (!Number.isInteger(siteLine)) {
    toast('This site is not defined in the editor buffer (for example an imported file), so the import cannot be inserted here.',
      { kind: 'warn', action: { label: 'Copy', run: () => copySnippet(s) } });
    return false;
  }
  return insertSiteFirst(s, siteLine);
}
```

In `src/static/js/app/main.js`:

```js
  if (!(await insertBanImportAtLine(e.detail.line, e.detail.source || 'manual'))) revealLine(e.detail.line);
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `for t in tests/*.test.mjs; do node "$t" || exit 1; done && uv run --frozen python -m unittest tests.test_bans_api tests.test_bans_detect -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/snippets.json src/routes/editor.py src/bans/scan.py src/static/js/app/snippet-insert.js \
  src/static/js/app/panels.js src/static/js/app/main.js tests/snippet-insert.test.mjs tests/test_bans_api.py tests/test_bans_detect.py
git commit -m "feat(crowdsec): site snippet after the manual import, log-field helper and validator warnings"
```

---

### Task 8: Security view: CrowdSec health, decisions and per-source sites

**Files:**
- Create: `src/static/js/app/security-crowdsec.js`
- Modify: `src/static/js/app/security-model.js`
- Modify: `src/static/js/app/security.js` (`App`, `Sites`, `Recovery`, manual list filter)
- Modify: `src/static/css/style.css` (two small rules)
- Test: `tests/security-model.test.mjs`

**Interfaces:**
- Consumes: `GET /api/security` (`sources.crowdsec`, `limits`, `sites[].policies`, `recovery.held_sources`) from Task 6; `GET /api/bans` records with `source`, `source_id`, `scenario`, `origin`; the `app:insert-ban-import` detail `{line, source}` from Task 7.
- Produces in `security-model.js`: `SOURCE_LABELS`, `crowdsecState(src, now) -> {tone, title, detail}`, `syncTimes(sync, now) -> [{label, text, title}]`, `ignoredRows(ignored) -> [{reason, label, count}]`, `cscliDeleteCommand(record) -> string`, `capacityText(limits) -> string`, `LIST_ORIGIN_WARNING`; `overallState` now considers every source's hold, every policy's status and CrowdSec health. `security-crowdsec.js` exports `CrowdSecSection({ src, records })`.

- [ ] **Step 1: Write the failing model tests**

Append to `tests/security-model.test.mjs` before the "no HTML sinks" block, and add `'security-crowdsec.js'` to that block's file list:

```js
console.log('\n--- CrowdSec ---');
const CS_OK = { enabled: true, stale: false, origins: ['crowdsec', 'cscli'], list_origins: [],
  sync: { lapi_state: 'ok', apply_state: 'ok', decisions: 3, updated_at: '2026-11-23T19:59:50Z',
          last_success_at: '2026-11-23T19:59:50Z', last_snapshot_at: '2026-11-23T19:00:00Z', last_apply_at: null } };
check('CrowdSec health wording and tone', () => {
  assert.deepEqual([M.crowdsecState(CS_OK, NOW).tone, M.crowdsecState(CS_OK, NOW).title], ['ok', '3 active decisions synced']);
  const down = { ...CS_OK, sync: { ...CS_OK.sync, lapi_state: 'unreachable', lapi_message: 'LAPI is unreachable (ConnectionError).' } };
  const s = M.crowdsecState(down, NOW);
  assert.deepEqual([s.tone, s.title], ['warn', 'CrowdSec unreachable, last synced list kept']);
  assert.match(s.detail, /ConnectionError.*Last successful poll just now/);
  const key = M.crowdsecState({ ...CS_OK, sync: { ...CS_OK.sync, lapi_state: 'auth_failed' } }, NOW);
  assert.equal(key.tone, 'crit');
  const cap = M.crowdsecState({ ...CS_OK, sync: { ...CS_OK.sync, apply_state: 'capacity_exceeded', apply_message: 'too many' } }, NOW);
  assert.deepEqual([cap.tone, cap.title], ['crit', 'Over capacity: automatic apply paused']);
  assert.equal(M.crowdsecState({ ...CS_OK, stale: true }, NOW).title, 'CrowdSec sync report is out of date');
  assert.equal(M.crowdsecState({ ...CS_OK, sync: null }, NOW).title, 'No CrowdSec sync report yet');
  assert.equal(M.crowdsecState({ enabled: false }, NOW).title, 'CrowdSec is not configured');
});
check('sync times are relative with an absolute title', () => {
  const t = M.syncTimes(CS_OK.sync, NOW);
  assert.deepEqual(t.map(x => [x.label, x.text]), [['Last snapshot', '1h ago'], ['Last successful poll', 'just now'], ['Last apply', 'Never']]);
  assert.equal(t[0].title, F.absoluteTime('2026-11-23T19:00:00Z'));
});
check('ignored counts are labelled and sorted', () => {
  assert.deepEqual(M.ignoredRows({ origin: 1, 'protected:private': 4, not_ban: 0, odd: 2 }).map(r => [r.label, r.count]), [
    ['Protected (private network)', 4], ['odd', 2], ['Origin not in CROWDSEC_ORIGINS', 1]]);
  assert.deepEqual(M.ignoredRows(undefined), []);
});
check('the cscli command only ever carries a numeric decision id', () => {
  assert.equal(M.cscliDeleteCommand({ source_id: '42' }), 'cscli decisions delete --id 42');
  for (const bad of ['42; rm -rf /', '', null, '4 2', 'x']) assert.equal(M.cscliDeleteCommand({ source_id: bad }), '');
});
check('capacity by source', () => {
  assert.equal(M.capacityText({ max_prefixes: 10000, used: 5, by_source: { manual: 3, crowdsec: 2 } }),
    '5 of 10000 prefixes rendered (manual 3, CrowdSec 2).');
  assert.equal(M.capacityText({ max_prefixes: 10000, used: 3, by_source: { manual: 3 } }), '3 of 10000 prefixes rendered.');
});
check('overall state counts any enforcing source and any held file', () => {
  const base = { available: true, caddy: { reachable: true }, sources: { manual: { hold: false }, crowdsec: { ...CS_OK, hold: false } } };
  const sites = [{ status: 'not_imported', policies: { manual: { status: 'not_imported' }, crowdsec: { status: 'enforced' } } }];
  assert.equal(M.overallState({ ...base, sites }, 0).title, 'Enforced on 1 site');
  const held = { ...base, sites, sources: { ...base.sources, crowdsec: { ...base.sources.crowdsec, hold: true } } };
  assert.equal(M.overallState(held, 0).title, 'Policy differs from state');
  const risk = [{ status: 'management', policies: { manual: { status: 'management' }, crowdsec: { status: 'management_imported' } } }];
  assert.equal(M.overallState({ ...base, sites: risk }, 0).tone, 'crit');
  const capped = { ...base, sites, sources: { ...base.sources, crowdsec: { ...CS_OK, hold: false, sync: { ...CS_OK.sync, apply_state: 'capacity_exceeded' } } } };
  assert.deepEqual([M.overallState(capped, 0).tone, M.overallState(capped, 0).title], ['warn', 'CrowdSec sync needs attention']);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node tests/security-model.test.mjs`
Expected: FAIL with `M.crowdsecState is not a function`.

- [ ] **Step 3: Implement the model**

Append to `src/static/js/app/security-model.js`:

```js
export const SOURCE_LABELS = { manual: 'Manual', crowdsec: 'CrowdSec' };
export const LIST_ORIGIN_WARNING = 'CAPI and list origins can hold tens of thousands of decisions. Stock Caddy file mode has a finite matcher budget (BANS_MAX); prefer plugin mode for them once it is available.';

const TONE_RANK = { none: 0, ok: 1, warn: 2, crit: 3 };
const LAPI_STATES = {
  ok: ['Connected to CrowdSec', 'ok'],
  starting: ['Starting', 'none'],
  unreachable: ['CrowdSec unreachable, last synced list kept', 'warn'],
  auth_failed: ['CrowdSec refused the bouncer key', 'crit'],
  malformed: ['CrowdSec sent an unusable response', 'warn'],
  missing_key: ['No bouncer key configured', 'crit'],
};
const APPLY_STATES = {
  ok: ['', 'ok'],
  pending: ['Waiting for the first sync', 'none'],
  capacity_exceeded: ['Over capacity: automatic apply paused', 'crit'],
  held: ['CrowdSec file differs from state: sync paused', 'warn'],
  degraded: ['Ban state needs attention: sync paused', 'crit'],
  failed: ['Applying CrowdSec decisions failed', 'crit'],
};

export function crowdsecState(src, now = Date.now()) {
  if (!src?.enabled) {
    return { tone: 'none', title: 'CrowdSec is not configured', detail: 'Stored CrowdSec decisions stay enforced until they expire or are reset. Start the docker-compose.crowdsec.yaml overlay to sync again.' };
  }
  const s = src.sync;
  if (!s) return { tone: 'warn', title: 'No CrowdSec sync report yet', detail: 'No console worker has polled CrowdSec yet. If this lasts, check the console logs.' };
  if (src.stale) {
    return { tone: 'warn', title: 'CrowdSec sync report is out of date', detail: `Last report ${relativeTime(s.updated_at, now) || 'unknown'}; no worker is polling CrowdSec right now.` };
  }
  const [lapiTitle, lapiTone] = LAPI_STATES[s.lapi_state] || ['Unknown CrowdSec state', 'warn'];
  const [applyTitle, applyTone] = APPLY_STATES[s.apply_state] || APPLY_STATES.failed;
  const tone = TONE_RANK[applyTone] > TONE_RANK[lapiTone] ? applyTone : lapiTone;
  const n = Number(s.decisions) || 0;
  const title = s.lapi_state !== 'ok' ? lapiTitle : (applyTitle || `${n} active ${n === 1 ? 'decision' : 'decisions'} synced`);
  const last = s.last_success_at ? `Last successful poll ${relativeTime(s.last_success_at, now)}.` : '';
  const detail = [s.lapi_state !== 'ok' ? s.lapi_message : '', s.apply_state !== 'ok' ? s.apply_message : '', last]
    .filter(Boolean).join(' ');
  return { tone, title, detail };
}

export function syncTimes(sync, now = Date.now()) {
  return [['Last snapshot', sync?.last_snapshot_at], ['Last successful poll', sync?.last_success_at], ['Last apply', sync?.last_apply_at]]
    .map(([label, at]) => ({ label, text: at ? relativeTime(at, now) : 'Never', title: at ? absoluteTime(at) : '' }));
}

const IGNORED = {
  not_ban: 'Not a ban (captcha or another remediation)', scope: 'Scope other than Ip or Range',
  origin: 'Origin not in CROWDSEC_ORIGINS', expired: 'Already expired', invalid_value: 'Invalid address',
  too_wide: 'Range wider than /16 (IPv4) or /48 (IPv6)',
};

export function ignoredRows(ignored) {
  return Object.entries(ignored || {}).filter(([, n]) => Number(n) > 0)
    .map(([reason, count]) => ({
      reason, count: Number(count),
      label: reason.startsWith('protected:') ? `Protected (${protectedLabel(reason.slice('protected:'.length))})` : (IGNORED[reason] || reason),
    }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
}

/** Copy-only text; the id is checked so nothing else can ride along. */
export function cscliDeleteCommand(record) {
  const id = String(record?.source_id ?? '');
  return /^[0-9]{1,20}$/.test(id) ? `cscli decisions delete --id ${id}` : '';
}

export function capacityText(limits) {
  const by = Object.entries(limits?.by_source || {});
  const name = (n) => (n === 'manual' ? 'manual' : SOURCE_LABELS[n] || n);   // mid-sentence: "manual 3, CrowdSec 2"
  const parts = by.length > 1 ? ` (${by.map(([n, c]) => `${name(n)} ${c}`).join(', ')})` : '';
  return `${limits?.used ?? 0} of ${limits?.max_prefixes ?? 0} prefixes rendered${parts}.`;
}
```

Then update `baseState` in the same file: add `const policiesOf = (site) => Object.values(site.policies || { manual: site });` above it, and replace the hold, lockout and enforced-count lines:

```js
  const held = Object.entries(status.sources || {}).filter(([, s]) => s?.hold).map(([n]) => SOURCE_LABELS[n] || n);
  if (held.length) {
    return { tone: 'warn', title: 'Policy differs from state', body: `The ${held.join(' and ')} ban file was changed outside the console. Fix the records, then Re-apply.` };
  }
  if ((status.sites || []).some(s => policiesOf(s).some(p => p.status === 'management_imported'))) {
    return { tone: 'crit', title: 'Console site imports the ban list: lockout risk', body: 'Remove the import line from the console site in the editor, then Save & Reload.' };
  }
  const cs = status.sources?.crowdsec;
  if (cs?.enabled && crowdsecState(cs).tone === 'crit') {
    return { tone: 'warn', title: 'CrowdSec sync needs attention', body: crowdsecState(cs).title };
  }
  const ENFORCING = ['enforced', 'enforced_pre_handler', 'imported_empty'];
  const n = (status.sites || []).filter(s => policiesOf(s).some(p => ENFORCING.includes(p.status))).length;
```

- [ ] **Step 4: The CrowdSec section**

`src/static/js/app/security-crowdsec.js`:

```js
// CrowdSec part of the Security view (spec 2.7): sync health and times,
// read-only decisions with scenario and origin, ignored counts, protected
// samples and a copyable cscli command. Wording lives in security-model.js;
// every string from LAPI or the API is a text child (a text node).
import { h, htm } from '../explore-vendor.js';
import { Icon } from './icons.js';
import { toast } from './ui/toast.js';
import {
  LIST_ORIGIN_WARNING, createdCell, crowdsecState, cscliDeleteCommand, expiryLabel, ignoredRows, protectedLabel, syncTimes,
} from './security-model.js';

const html = htm.bind(h);
const SEV = { crit: 'critical', warn: 'warn', ok: 'ok', none: 'ok' };

function copy(text, what) {
  navigator.clipboard.writeText(text).then(
    () => toast(`${what} copied`, { kind: 'ok' }),
    () => toast('Could not copy to the clipboard', { kind: 'error' }));
}

function Decisions({ records }) {
  if (!records.length) return html`<p class="metrics-hint">No active CrowdSec decisions.</p>`;
  return html`
    <table class="sec-table">
      <thead><tr><th>Address</th><th>Scenario</th><th>Origin</th><th>Fetched</th><th>Expiry</th><th><span class="sr">Actions</span></th></tr></thead>
      <tbody>${records.map(r => {
        const fetched = createdCell(r.created_at);
        const cmd = cscliDeleteCommand(r);
        return html`
          <tr key=${r.id} class=${r.expired ? 'expired' : ''}>
            <td class="mono">${r.value}${r.protected && html` <span class="sec-tag" title=${'Protected: ' + protectedLabel(r.protected)}>ignored, protected</span>`}</td>
            <td>${r.scenario || ''}</td>
            <td>${r.origin || ''}</td>
            <td title=${fetched.title}>${fetched.text}</td>
            <td>${expiryLabel(r.expires_at)}</td>
            <td>${cmd && html`<button class="btn sm btn-quiet" type="button" title=${cmd} onClick=${() => copy(cmd, 'cscli command')}><${Icon} name="copy" size=${14} />Copy cscli command</button>`}</td>
          </tr>`;
      })}</tbody>
    </table>`;
}

export function CrowdSecSection({ src, records }) {
  const st = crowdsecState(src);
  const sync = src.sync || {};
  const ignored = ignoredRows(sync.ignored);
  const sample = sync.protected_sample || [];
  return html`
    <section aria-labelledby="sec-cs-h">
      <div class="h-sec"><h2 id="sec-cs-h">CrowdSec decisions</h2>
        <p>Read-only, synced from CrowdSec's Local API. To remove one, delete it in CrowdSec (run the copied command inside the crowdsec container).</p></div>
      <p class=${'sec-cs-state sev-' + SEV[st.tone]} role=${st.tone === 'crit' ? 'alert' : 'status'}>
        <strong>${st.title}</strong>${st.detail && html` <span class="muted small">${st.detail}</span>`}</p>
      <dl class="sec-protected">
        ${syncTimes(sync).map(t => html`<div key=${t.label}><dt>${t.label}</dt><dd title=${t.title}>${t.text}</dd></div>`)}
        <div><dt>Origins</dt><dd class="mono">${(src.origins || []).join(', ')}</dd></div>
      </dl>
      ${(src.list_origins || []).length > 0 && html`<p class="metrics-hint">${LIST_ORIGIN_WARNING}</p>`}
      ${ignored.length > 0 && html`
        <div class="sec-ignored"><span class="k">Ignored decisions</span>
          <ul>${ignored.map(r => html`<li key=${r.reason}>${r.label}: ${r.count}</li>`)}</ul></div>`}
      ${sample.length > 0 && html`<p class="muted small">Protected, never rendered: ${sample.map(p => `${p.value} (${protectedLabel(p.category)})`).join(', ')}</p>`}
      <${Decisions} records=${records} />
    </section>`;
}
```

- [ ] **Step 5: Wire it into the view**

In `src/static/js/app/security.js`:
- import `CrowdSecSection` from `./security-crowdsec.js`, and `SOURCE_LABELS, capacityText` from `./security-model.js`;
- in `App`, split the records and render the section:

```js
  const records = bans?.records || [];
  const manualRecords = records.filter(r => r.source === 'manual');
  const crowdsecRecords = records.filter(r => r.source === 'crowdsec');
  const manual = status.sources.manual;
  const cs = status.sources.crowdsec;
```

  pass `records=${manualRecords}` to `BanList` and `records=${manualRecords.length}` to `Verdict`; replace the manual header paragraph with `<p>${manual.active_records} active. ${capacityText(status.limits)}</p>`; after the manual-bans section add `${cs && html`<${CrowdSecSection} src=${cs} records=${crowdsecRecords} />`}`; pass `sources=${status.sources}` to `Sites` and `Recovery`; and show one import line per source in the Sites header (`Object.entries(status.sources).map(([n, s]) => html`<p class="sec-import" key=${n}>${SOURCE_LABELS[n]} import line: <code>${s.import_line}</code></p>`)`).
- replace `Sites` so each site lists every active source:

```js
function Sites({ sites, sources }) {
  if (!sites.length) return html`<p class="metrics-hint">No sites in the running configuration.</p>`;
  const names = Object.keys(sources);
  return html`
    <ul class="sec-sites">${sites.map(s => html`
      <li key=${s.label + ':' + (s.line || '')}>
        <span class="mono">${s.label}</span>
        ${names.map(name => {
          const p = s.policies?.[name] || s;
          const st = siteStatus(p);
          const acts = siteActions({ ...p, source: s.source });
          return html`
            <div class=${'sec-policy tone-' + st.tone} key=${name}>
              ${names.length > 1 && html`<span class="sec-src">${SOURCE_LABELS[name]}</span>`}
              <span class="sec-state">${st.label}</span>
              ${st.detail && html`<span class="muted small">${st.detail}</span>`}
              <span class="acts">
                ${acts.includes('insert') && html`<button class="btn sm" type="button"
                    onClick=${() => document.dispatchEvent(new CustomEvent('app:insert-ban-import', { detail: { line: s.line, source: name } }))}>Add import in editor</button>`}
                ${acts.includes('copy') && html`<button class="btn sm btn-quiet" type="button" onClick=${() => copy(sources[name].import_line, 'Import line')}><${Icon} name="copy" size=${14} />Copy import</button>`}
              </span>
            </div>`;
        })}
      </li>`)}</ul>`;
}
```

- in `Recovery({ info, onDone, sources })`, Re-apply per held source and a CrowdSec reset:

```js
  const reapply = async (source) => finish(await call('/api/security/reapply', 'POST', { source }), 'Re-applied; Caddy reloaded.');
  const resetCrowdsec = async () => {
    const ok = await confirmDialog({ title: 'Delete every stored CrowdSec decision?', body: 'Caddy reloads without them. CrowdSec decisions that are still active return within the sync interval unless you also delete them in CrowdSec.', confirmLabel: 'Reset CrowdSec decisions', danger: true });
    if (ok) finish(await call('/api/security/reset', 'POST', { source: 'crowdsec', version: info.state_version, confirm: true }), 'CrowdSec decisions reset.');
  };
  const held = info.held_sources?.length ? info.held_sources : ['manual'];
```

  and in the actions row replace the Re-apply button with `${info.reapply && held.map(n => html`<button class="btn btn-primary" type="button" key=${'re-' + n} onClick=${() => reapply(n)}>${n === 'manual' && held.length === 1 ? 'Re-apply' : `Re-apply ${SOURCE_LABELS[n]}`}</button>`)}` and add `${info.reset && sources?.crowdsec && html`<button class="btn btn-danger" type="button" onClick=${resetCrowdsec}>Reset CrowdSec decisions</button>`}` after the manual reset button.

Append to `src/static/css/style.css` (next to the other `.sec-` rules):

```css
.sec-sites .sec-policy { display: flex; flex-wrap: wrap; gap: .25rem .75rem; align-items: baseline; }
.sec-src { font-size: .75rem; text-transform: uppercase; letter-spacing: .04em; color: var(--muted, inherit); min-width: 5.5rem; }
```

(If `style.css` names its muted colour variable differently, use that variable; do not add a new colour.)

- [ ] **Step 6: Run the tests and check in the browser**

Run: `for t in tests/*.test.mjs; do node "$t" || exit 1; done && npm run build && git diff --exit-code -- src/static/js/`
Expected: PASS and no bundle diff.

With the dev stack and the overlay running (Task 9 adds the overlay; until then, set `CROWDSEC_URL=http://crowdsec.invalid:8080` and a key on the dev console to see the unreachable state), check Security in light and dark themes on desktop and a 390 px wide window: the CrowdSec section shows its state, times, origins and the empty table; site rows list Manual and CrowdSec separately; with Caddy stopped every policy reads "Unknown while Caddy is unreachable".

- [ ] **Step 7: Commit**

```bash
git add src/static/js/app/security-crowdsec.js src/static/js/app/security-model.js src/static/js/app/security.js \
  src/static/css/style.css tests/security-model.test.mjs
git commit -m "feat(security): CrowdSec health, read-only decisions and per-source site status"
```

---

### Task 9: The optional CrowdSec Compose overlay and its CrowdSec files

**Files:**
- Create: `docker-compose.crowdsec.yaml`, `docker-compose.crowdsec.nas.yaml`
- Create: `crowdsec/acquis.d/caddy.yaml`, `crowdsec/parsers/s02-enrich/caddy-console-safe-fields.yaml`
- Create: `dev/check-crowdsec-overlay.py`
- Modify: `dev/check-compose.sh`, `dev/run.sh` (`down -v --remove-orphans`)

**Interfaces:**
- Consumes: the console settings from Task 1 (`CROWDSEC_URL`, key, origins, intervals).
- Produces: services `crowdsec` (image pinned by digest, no ports, networks `crowdsec-lapi` + `crowdsec-egress`, named volumes `crowdsec-config:/etc/crowdsec` and `crowdsec-data:/var/lib/crowdsec/data`, `caddy-logs` read-only) and the console attachment (`CROWDSEC_URL=http://crowdsec:8080`, network `crowdsec-lapi`). The NAS stack's console service is `caddy-editor`, so it uses `docker-compose.crowdsec.nas.yaml`, which `extends` the same `crowdsec` service. The parser maps two top-level log fields, `user_agent` and `auth_challenge`, which the Task 7 `crowdsec-log-fields` snippet writes.

- [ ] **Step 1: Write the failing check**

`dev/check-crowdsec-overlay.py`:

```python
"""Check the CrowdSec overlay's isolation rules on `docker compose config --format json` (stdin).

  docker compose -f BASE -f OVERLAY config --format json | python3 dev/check-crowdsec-overlay.py CADDY CONSOLE
"""
import json
import re
import sys

IMAGE = re.compile(r"^crowdsecurity/crowdsec:v\d+\.\d+\.\d+@sha256:[0-9a-f]{64}$")
ENV = {"COLLECTIONS": "crowdsecurity/caddy", "PARSERS": "crowdsecurity/whitelists", "DISABLE_ONLINE_API": "true"}
MOUNTS = ("/etc/crowdsec/acquis.d/caddy.yaml", "/etc/crowdsec/parsers/s02-enrich/caddy-console-safe-fields.yaml",
          "/var/log/caddy")


def nets(service):
    return set(service.get("networks") or {})


def main(caddy, console):
    cfg = json.load(sys.stdin)
    services, problems = cfg["services"], []
    cs = services.get("crowdsec")
    if cs is None:
        sys.exit("no crowdsec service")
    if not IMAGE.match(cs.get("image", "")):
        problems.append(f"crowdsec image is not pinned by version and digest: {cs.get('image')}")
    if cs.get("ports"):
        problems.append("crowdsec publishes ports")
    if nets(cs) != {"crowdsec-lapi", "crowdsec-egress"}:
        problems.append(f"crowdsec networks are {sorted(nets(cs))}")
    if not (cfg.get("networks", {}).get("crowdsec-lapi") or {}).get("internal"):
        problems.append("crowdsec-lapi is not internal")
    for name, svc in services.items():
        if name not in ("crowdsec", console) and "crowdsec-lapi" in nets(svc):
            problems.append(f"{name} joins crowdsec-lapi")
    if "crowdsec-lapi" in nets(services[caddy]):
        problems.append("Caddy joins crowdsec-lapi")
    if "crowdsec-lapi" not in nets(services[console]):
        problems.append("the console does not join crowdsec-lapi")
    env = cs.get("environment") or {}
    problems += [f"crowdsec {k} must be {v!r}" for k, v in ENV.items() if env.get(k) != v]
    cenv = services[console].get("environment") or {}
    if cenv.get("CROWDSEC_URL") != "http://crowdsec:8080":
        problems.append("the console has no CROWDSEC_URL=http://crowdsec:8080")
    if not env.get("BOUNCER_KEY_caddy_console") or env.get("BOUNCER_KEY_caddy_console") != cenv.get("CROWDSEC_CONSOLE_BOUNCER_KEY"):
        problems.append("BOUNCER_KEY_caddy_console and the console's CROWDSEC_CONSOLE_BOUNCER_KEY differ or are empty")
    mounts = {v.get("target"): v for v in cs.get("volumes") or []}
    problems += [f"{t} is not mounted read-only" for t in MOUNTS if not (mounts.get(t) or {}).get("read_only")]
    if problems:
        sys.exit("\n".join(problems))


main(*sys.argv[1:3])
```

Append to `dev/check-compose.sh`:

```bash
# Phase 2 gate: the optional overlay is the only change needed to start CrowdSec,
# and it keeps Caddy off the CrowdSec network. NAS uses its companion file
# because its console service is named caddy-editor.
export CROWDSEC_CONSOLE_BOUNCER_KEY=dummy-check-key
for combo in "docker-compose.prod.yaml docker-compose.crowdsec.yaml caddy caddy-console" \
             "docker-compose.internal.yaml docker-compose.crowdsec.yaml caddy caddy-console" \
             "docker-compose.tunnel.yaml docker-compose.crowdsec.yaml caddy caddy-console" \
             "docker-compose.dev.yaml docker-compose.crowdsec.yaml caddy-target caddy-console" \
             "docker-compose.nas.yaml docker-compose.crowdsec.nas.yaml caddy caddy-editor"; do
  read -r base overlay caddy console <<<"$combo"
  docker compose -f "$base" -f "$overlay" config --format json | python3 dev/check-crowdsec-overlay.py "$caddy" "$console" \
    || { echo "$base + $overlay: CrowdSec overlay check failed" >&2; exit 1; }
  echo "$base + $overlay: ok"
done
```

The existing baseline loop above it stays first and unchanged, so a baseline file that mentions CrowdSec still fails.

- [ ] **Step 2: Run it to verify it fails**

Run: `./dev/check-compose.sh`
Expected: the five baseline lines print `ok`, then FAIL with `open docker-compose.crowdsec.yaml: no such file or directory`.

- [ ] **Step 3: CrowdSec acquisition and the local parser**

`crowdsec/acquis.d/caddy.yaml`:

```yaml
# Caddy Console's CrowdSec acquisition (docs/security.md#crowdsec-file-sync).
# Only the live file: rotated archives (access-*.log) are never replayed.
filenames:
  - /var/log/caddy/access.log
labels:
  type: caddy
```

`crowdsec/parsers/s02-enrich/caddy-console-safe-fields.yaml`:

```yaml
# Caddy Console deletes request>headers and resp_headers from the access log
# (they carry cookies and tokens), so crowdsecurity/caddy-logs finds no
# User-Agent and no Www-Authenticate header. The console's "CrowdSec: log
# fields for detection" snippet appends two safe top-level fields instead:
#   user_agent      the request's User-Agent
#   auth_challenge  the response's Www-Authenticate (set by basic_auth on a 401)
# This enricher maps them to what the shipped scenarios read:
#   crowdsecurity/http-bad-user-agent  evt.Parsed.http_user_agent
#   crowdsecurity/http-generic-bf      evt.Meta.sub_type == 'auth_fail'
# (the same rule caddy-logs applies to the unfiltered Www-Authenticate header).
# It never sees Cookie, Authorization or a body: those are not in the log.
name: caddy-console/caddy-safe-fields
description: "Safe User-Agent and Basic auth failure fields from Caddy Console's filtered access log"
filter: "evt.Meta.log_type == 'http_access-log' && evt.Unmarshaled.caddy != nil && evt.Unmarshaled.caddy.request != nil"
statics:
  - parsed: http_user_agent
    expression: "evt.Parsed.http_user_agent not in ['', nil] ? evt.Parsed.http_user_agent : get(evt.Unmarshaled.caddy, 'user_agent')"
  - meta: http_user_agent
    expression: evt.Parsed.http_user_agent
  - meta: sub_type
    expression: "evt.Meta.sub_type not in ['', nil] ? evt.Meta.sub_type : (evt.Meta.http_status == '401' && get(evt.Unmarshaled.caddy, 'auth_challenge') != nil && evt.Unmarshaled.caddy.auth_challenge startsWith 'Basic' ? 'auth_fail' : nil)"
```

(No `onsuccess`: an s02 enricher must not stop the other enrichers in its stage, such as `dateparse-enrich`.)

- [ ] **Step 4: The overlays**

`docker-compose.crowdsec.yaml`:

```yaml
# Optional CrowdSec file-sync add-on (docs/security.md#crowdsec-file-sync).
#
#   docker compose -f docker-compose.prod.yaml -f docker-compose.crowdsec.yaml up -d
#
# Works with the prod, internal, tunnel and dev stacks; the NAS stack uses
# docker-compose.crowdsec.nas.yaml. Running only a baseline file never starts
# CrowdSec. CrowdSec reads Caddy's access log read-only and answers only the
# console on the internal crowdsec-lapi network; Caddy never joins it, so the
# Caddy admin API stays unreachable from CrowdSec. No port is published.
services:
  crowdsec:
    # Reviewed tag plus its immutable multi-arch index digest:
    #   docker buildx imagetools inspect crowdsecurity/crowdsec:v1.8.2
    image: crowdsecurity/crowdsec:v1.8.2@sha256:65b74942f7e7ed5c60fde4ac15fc4ba715904c398c8b16dd451f4907d90347d4
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    pids_limit: 256
    environment:
      COLLECTIONS: crowdsecurity/caddy
      PARSERS: crowdsecurity/whitelists
      # No community enrollment or blocklists by default (spec 2.1).
      DISABLE_ONLINE_API: "true"
      # Registers the read-only bouncer "caddy_console" at first start. To change
      # the key later: cscli bouncers delete caddy_console, then restart.
      BOUNCER_KEY_caddy_console: ${CROWDSEC_CONSOLE_BOUNCER_KEY:?Set CROWDSEC_CONSOLE_BOUNCER_KEY (python -c "import secrets; print(secrets.token_hex(32))")}
    volumes:
      - crowdsec-config:/etc/crowdsec
      - crowdsec-data:/var/lib/crowdsec/data
      - caddy-logs:/var/log/caddy:ro
      - ./crowdsec/acquis.d/caddy.yaml:/etc/crowdsec/acquis.d/caddy.yaml:ro
      - ./crowdsec/parsers/s02-enrich/caddy-console-safe-fields.yaml:/etc/crowdsec/parsers/s02-enrich/caddy-console-safe-fields.yaml:ro
    networks:
      - crowdsec-lapi
      # Hub downloads at start (COLLECTIONS, PARSERS, scenario data files).
      - crowdsec-egress
    healthcheck:
      test: ["CMD", "cscli", "lapi", "status"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 90s

  caddy-console:
    environment:
      CROWDSEC_URL: http://crowdsec:8080
      CROWDSEC_CONSOLE_BOUNCER_KEY: ${CROWDSEC_CONSOLE_BOUNCER_KEY:?Set CROWDSEC_CONSOLE_BOUNCER_KEY}
      CROWDSEC_ORIGINS: ${CROWDSEC_ORIGINS:-crowdsec,cscli}
      CROWDSEC_POLL_INTERVAL: ${CROWDSEC_POLL_INTERVAL:-10}
      BANS_SYNC_INTERVAL: ${BANS_SYNC_INTERVAL:-30}
    networks:
      - crowdsec-lapi

networks:
  # CrowdSec <-> console only. No other service may join it.
  crowdsec-lapi:
    internal: true
  crowdsec-egress:

volumes:
  crowdsec-config:
  crowdsec-data:
  caddy-logs:
```

`docker-compose.crowdsec.nas.yaml`:

```yaml
# The CrowdSec add-on for docker-compose.nas.yaml, whose console service is
# named caddy-editor (docs/security.md#crowdsec-file-sync):
#
#   docker compose -f docker-compose.nas.yaml -f docker-compose.crowdsec.nas.yaml up -d
services:
  crowdsec:
    extends:
      file: docker-compose.crowdsec.yaml
      service: crowdsec

  caddy-editor:
    environment:
      CROWDSEC_URL: http://crowdsec:8080
      CROWDSEC_CONSOLE_BOUNCER_KEY: ${CROWDSEC_CONSOLE_BOUNCER_KEY:?Set CROWDSEC_CONSOLE_BOUNCER_KEY}
      CROWDSEC_ORIGINS: ${CROWDSEC_ORIGINS:-crowdsec,cscli}
      CROWDSEC_POLL_INTERVAL: ${CROWDSEC_POLL_INTERVAL:-10}
      BANS_SYNC_INTERVAL: ${BANS_SYNC_INTERVAL:-30}
    networks:
      - crowdsec-lapi

networks:
  crowdsec-lapi:
    internal: true
  crowdsec-egress:

volumes:
  crowdsec-config:
  crowdsec-data:
  caddy-logs:
```

In `dev/run.sh`, change the `down` branch to `"${COMPOSE[@]}" down -v --remove-orphans`, so a CrowdSec container left by an interrupted integration run does not keep the dev networks busy.

- [ ] **Step 5: Run the check to verify it passes**

Run: `./dev/check-compose.sh`
Expected: five baseline `ok` lines, then five overlay `ok` lines.

- [ ] **Step 6: Smoke-test the image and the parser**

```bash
export CROWDSEC_CONSOLE_BOUNCER_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"
./dev/run.sh up
docker compose -f docker-compose.dev.yaml -f docker-compose.crowdsec.yaml up -d --wait --wait-timeout 300 crowdsec caddy-console
C=(docker compose -f docker-compose.dev.yaml -f docker-compose.crowdsec.yaml exec -T crowdsec)
"${C[@]}" cscli lapi status
"${C[@]}" cscli bouncers list -o json | grep -q '"caddy_console"'
"${C[@]}" cscli explain -v --type caddy --log '{"level":"info","ts":1764000000.5,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"172.18.0.1","remote_port":"5555","client_ip":"203.0.113.60","proto":"HTTP/1.1","method":"GET","host":"explain.example.com","uri":"/private/x"},"status":401,"user_agent":"caddy-console-it/1.0","auth_challenge":"Basic realm=\"restricted\""}' \
  | grep -E 'evt\.Meta\.source_ip : 203\.0\.113\.60|http_user_agent : .*caddy-console-it/1\.0|evt\.Meta\.sub_type : .*auth_fail'
```

Expected: `lapi status` reports the API as reachable, the bouncer exists, and the `grep` prints three matching lines (`source_ip`, `http_user_agent`, `sub_type`). If `cscli explain` reports an expression error in `caddy-console/caddy-safe-fields`, fix only the expression syntax; these three lines are the contract (Task 10 asserts them against real Caddy output). Then hand the stack back:

```bash
docker compose -f docker-compose.dev.yaml -f docker-compose.crowdsec.yaml rm -sf crowdsec
docker compose -f docker-compose.dev.yaml up -d caddy-console
```

- [ ] **Step 7: Commit**

```bash
git add docker-compose.crowdsec.yaml docker-compose.crowdsec.nas.yaml crowdsec/ dev/check-crowdsec-overlay.py \
  dev/check-compose.sh dev/run.sh
git commit -m "feat(crowdsec): optional pinned CrowdSec overlay with read-only log acquisition and safe-field parser"
```

---

### Task 10: CrowdSec overlay integration, CI and `docs/security.md`

**Files:**
- Create: `tests/integration/crowdsec_it.py`, `dev/crowdsec-it.sh`
- Modify: `.github/workflows/docker-publish.yml` (one step in `test-integration`)
- Modify: `docs/security.md`, `docs/setup.md`, `docs/development.md`

**Interfaces:**
- Consumes: everything above, running for real: the dev stack plus `docker-compose.crowdsec.yaml`, with gunicorn's two workers electing the sync leader.
- Produces: `./dev/crowdsec-it.sh` (needs Docker and network access to the CrowdSec Hub; no secrets: it generates a throwaway bouncer key) and `tests/integration/crowdsec_it.py` subcommands `prepare`, `restore`, `explain-traffic`, `check-explain IP`, `scenario-traffic`, `wait-decisions`, `wait-enforced IP T0 SECONDS STATUS`, `check-records IP ORIGIN`, `outage-start IP`, `outage-check IP`, `outage-recovered`, `failover`.

- [ ] **Step 1: Write the integration driver**

`tests/integration/crowdsec_it.py`:

```python
"""CrowdSec file sync end to end (spec "Run the optional CrowdSec overlay").

Runs inside caddy-console of the dev stack started with docker-compose.crowdsec.yaml,
one step per call; dev/crowdsec-it.sh drives the steps that need the host or the
crowdsec container. It talks to the real console only through its files and
Caddy's data plane, so it proves what the gunicorn workers actually do.

  python -m tests.integration.crowdsec_it <command> [args]
"""
import json
import os
import re
import signal
import sys
import time

import requests

CADDYFILE = os.environ.get("CADDYFILE_PATH", "/etc/caddy/Caddyfile")
SAVED = os.path.join(os.path.dirname(CADDYFILE), ".crowdsec-it.Caddyfile.orig")
API = os.environ.get("CADDY_API_URL", "http://caddy-target:2019")
DATA = os.environ.get("CADDY_DATA_URL", "http://caddy-target:80")
LAPI = os.environ.get("CROWDSEC_URL", "http://crowdsec:8080")
BANS_DIR = os.environ.get("BANS_DIR", "/etc/caddy/console")
BACKUP_DIR = os.environ.get("BACKUP_DIR", "/backups")
STATUS = os.path.join(BACKUP_DIR, "bans-crowdsec-sync.json")
STATE = os.path.join(BACKUP_DIR, "bans.json")
POLICY = os.path.join(BANS_DIR, "bans-crowdsec.caddy")
MARK = "/tmp/crowdsec-it.json"
EXPLAIN_LOG = "/var/log/caddy/explain-it.log"
HASH = "$2a$14$Zkx19XLiW6VYouLHR5NmfOFU0z2GTNmpkT/5qqR7hx4IjWJPDhjvG"
UA = "caddy-console-it/1.0"
BAD_UA = "sqlmap/1.8.2#stable (https://sqlmap.org)"
CS, AUTH, EXPLAIN = "cs.it.example.com", "auth.cs.it.example.com", "explain.cs.it.example.com"
EXPECT = {"203.0.113.61": "crowdsecurity/http-probing",
          "203.0.113.62": "crowdsecurity/http-bad-user-agent",
          "203.0.113.63": "crowdsecurity/http-generic-bf"}

FIELDS = ("\tlog_append <user_agent {http.request.header.User-Agent}\n"
          "\tlog_append auth_challenge {http.response.header.Www-Authenticate}\n")
IMPORTS = f"\timport {BANS_DIR}/bans-manual*.caddy\n\timport {BANS_DIR}/bans-crowdsec*.caddy\n"


def log_block(path):
    return ("\tlog {\n\t\toutput file " + path + " {\n\t\t\tmode 0644\n\t\t}\n"
            "\t\tformat filter {\n\t\t\twrap json\n\t\t\trequest>headers delete\n\t\t\tresp_headers delete\n\t\t}\n\t}\n")


TEXT = ("{\n\tadmin 0.0.0.0:2019\n\tservers {\n\t\ttrusted_proxies static private_ranges\n"
        "\t\tclient_ip_headers X-Forwarded-For\n\t}\n}\n\n"
        f"http://{CS} {{\n" + IMPORTS + FIELDS + log_block("/var/log/caddy/access.log")
        + "\trespond /ok \"ok\" 200\n\trespond 404\n}\n\n"
        f"http://{AUTH} {{\n" + IMPORTS + FIELDS + log_block("/var/log/caddy/access.log")
        + "\tbasic_auth {\n\t\tit " + HASH + "\n\t}\n\trespond \"secret\" 200\n}\n\n"
        f"http://{EXPLAIN} {{\n" + FIELDS + log_block(EXPLAIN_LOG)
        + "\tbasic_auth /private/* {\n\t\tit " + HASH + "\n\t}\n\trespond /ok \"ok\" 200\n\trespond 404\n}\n")


def fail(message):
    sys.exit(f"crowdsec_it: {message}")


def wait(pred, seconds, what):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            if pred():
                return
        except (requests.RequestException, OSError, ValueError, KeyError, TypeError):
            pass
        time.sleep(1)
    fail(f"timed out after {seconds}s waiting for {what}")


def load(text):
    r = requests.post(f"{API}/load", data=text.encode("utf-8"), headers={"Content-Type": "text/caddyfile"}, timeout=20)
    if r.status_code != 200:
        fail(f"/load answered {r.status_code}: {r.text[:500]}")


def get(host, path="/ok", ip="203.0.113.60", ua=UA, auth=None):
    return requests.get(DATA + path, headers={"Host": host, "X-Forwarded-For": ip, "User-Agent": ua},
                        auth=auth, timeout=5, allow_redirects=False)


def status():
    with open(STATUS, encoding="utf-8") as f:
        return json.load(f)


def policy_bytes():
    with open(POLICY, "rb") as f:
        return f.read()


def decisions(ip):
    key = os.environ["CROWDSEC_CONSOLE_BOUNCER_KEY"]
    r = requests.get(f"{LAPI}/v1/decisions", params={"ip": ip}, headers={"X-Api-Key": key}, timeout=5)
    r.raise_for_status()
    return r.json() or []


def utc_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def cmd_prepare():
    # The Caddyfile must use the shipped snippet lines verbatim, so a successful
    # /load below is also the "every shipped snippet adapts" check (spec Testing).
    with open("/app/src/snippets.json", encoding="utf-8") as f:
        shipped = {s["id"]: s["code"] for s in json.load(f) if "id" in s}
    for sid in ("crowdsec-bans-site", "crowdsec-log-fields"):
        for line in shipped[sid].replace("/etc/caddy/console/", BANS_DIR + "/").splitlines():
            if "\t" + line + "\n" not in TEXT:
                fail(f"the integration Caddyfile does not use the shipped {sid} line {line!r}")
    if not os.path.exists(SAVED):
        with open(CADDYFILE, "rb") as f, open(SAVED, "wb") as out:
            out.write(f.read())
    with open(CADDYFILE, "w", encoding="utf-8") as f:
        f.write(TEXT)
    load(TEXT)
    wait(lambda: get(CS).status_code == 200, 30, "the integration site")


def cmd_restore():
    if os.path.exists(SAVED):
        with open(SAVED, "rb") as f:
            data = f.read()
        with open(CADDYFILE, "wb") as f:
            f.write(data)
        os.remove(SAVED)
        load(data.decode("utf-8"))


def cmd_explain_traffic():
    codes = [get(EXPLAIN, "/ok").status_code, get(EXPLAIN, "/missing").status_code,
             get(EXPLAIN, "/private/x", auth=("it", "wrong-password")).status_code]
    if codes != [200, 404, 401]:
        fail(f"explain site answered {codes}")

    def logged():
        with open(EXPLAIN_LOG, encoding="utf-8") as f:
            return f.read().count("\n") >= 3
    wait(logged, 20, "three lines in the explain log")
    with open(EXPLAIN_LOG, encoding="utf-8") as f:
        text = f.read()
    for leak in ('"headers"', '"resp_headers"', "Authorization", "wrong-password"):
        if leak in text:
            fail(f"the filtered log contains {leak}")
    if '"user_agent"' not in text or '"auth_challenge":"Basic' not in text:
        fail("the log lacks the user_agent or auth_challenge field (is log_append ordered before basic_auth?)")


def cmd_check_explain(ip):
    out = sys.stdin.read()
    value = r"(?:.* -> )?"
    need = [rf"evt\.Meta\.source_ip : {value}{re.escape(ip)}\s*$", rf"evt\.Meta\.http_path : {value}/missing\s*$",
            rf"evt\.Meta\.http_verb : {value}GET\s*$", rf"evt\.Meta\.http_status : {value}404\s*$",
            rf"evt\.Parsed\.http_user_agent : {value}{re.escape(UA)}\s*$", rf"evt\.Meta\.sub_type : {value}auth_fail\s*$"]
    missing = [p for p in need if not re.search(p, out, re.M)]
    seen = set(re.findall(rf"evt\.Meta\.source_ip : {value}(\S+)\s*$", out, re.M))
    if missing or seen != {ip}:
        fail(f"cscli explain: missing {missing}; source_ip values {sorted(seen)} (expected only {ip})\n{out[-3000:]}")
    print(f"cscli explain: source_ip is the visitor {ip}; path, verb, status, User-Agent and auth_fail present")


def cmd_scenario_traffic():
    for i in range(20):
        get(CS, f"/probe-{i}/admin.php", ip="203.0.113.61")
    for _ in range(3):
        get(CS, "/ok", ip="203.0.113.62", ua=BAD_UA)
    for _ in range(8):
        get(AUTH, "/", ip="203.0.113.63", auth=("it", "wrong-password"))


def cmd_wait_decisions():
    for ip, scenario in EXPECT.items():
        wait(lambda: scenario in {d.get("scenario") for d in decisions(ip)}, 180, f"{scenario} for {ip}")
        print(f"{ip}: {scenario}")
    for ip in EXPECT:
        wait(lambda: get(CS, ip=ip).status_code == 403, 90, f"file enforcement for {ip}")


def cmd_wait_enforced(ip, t0, seconds, expect):
    wait(lambda: get(CS, ip=ip).status_code == int(expect), int(seconds) + 10, f"HTTP {expect} for {ip}")
    elapsed = time.time() - float(t0)
    if elapsed > float(seconds):
        fail(f"{ip} reached HTTP {expect} after {elapsed:.0f}s; the objective is {seconds}s")
    print(f"{ip}: HTTP {expect} after {elapsed:.0f}s")


def cmd_check_records(ip, origin):
    with open(STATE, encoding="utf-8") as f:
        records = json.load(f)["records"]
    hits = [r for r in records if r["source"] == "crowdsec" and r["value"] == ip]
    if not hits or any(r["origin"] != origin or r["actor"] != "system" or not r["source_id"].isdigit() for r in hits):
        fail(f"unexpected crowdsec records for {ip}: {hits}")


def cmd_outage_start(ip):
    if get(CS, ip=ip).status_code != 403:
        fail(f"{ip} is not enforced before the outage")
    with open(MARK, "w", encoding="utf-8") as f:
        json.dump({"policy": policy_bytes().decode(), "snapshot": status()["last_snapshot_at"], "ip": ip}, f)


def cmd_outage_check(ip):
    with open(MARK, encoding="utf-8") as f:
        mark = json.load(f)
    wait(lambda: status()["lapi_state"] == "unreachable", 3 * status()["poll_interval"] + 20, "lapi_state unreachable")
    time.sleep(status()["sync_interval"])
    if policy_bytes().decode() != mark["policy"] or get(CS, ip=ip).status_code != 403:
        fail("the outage changed the CrowdSec policy or dropped enforcement")


def cmd_outage_recovered():
    with open(MARK, encoding="utf-8") as f:
        mark = json.load(f)
    wait(lambda: status()["lapi_state"] == "ok" and status()["last_snapshot_at"] > mark["snapshot"], 90,
         "a startup=true snapshot after LAPI recovered")


def sync_workers():
    out = []
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                if b"gunicorn" not in f.read():
                    continue
            names = []
            for tid in os.listdir(f"/proc/{pid}/task"):
                with open(f"/proc/{pid}/task/{tid}/comm", encoding="utf-8") as f:
                    names.append(f.read().strip())
        except OSError:
            continue
        if "bans-sync" in names:
            out.append(int(pid))
    return out


def cmd_failover():
    workers = sync_workers()
    if len(workers) < 2:
        fail(f"expected a bans-sync thread in every worker, found {workers}")
    doc = status()
    old = doc["leader_pid"]
    if old not in workers:
        fail(f"leader {old} is not one of the workers {workers}")
    t0 = utc_iso()
    os.kill(old, signal.SIGTERM)
    wait(lambda: status()["leader_pid"] not in (None, old) and status()["last_snapshot_at"] >= t0,
         3 * doc["poll_interval"] + 30, "a new leader that starts with a snapshot")
    print(f"sync leader {old} -> {status()['leader_pid']}, snapshot {status()['last_snapshot_at']}")


COMMANDS = {name[4:].replace("_", "-"): fn for name, fn in list(globals().items()) if name.startswith("cmd_")}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        fail(f"usage: python -m tests.integration.crowdsec_it {{{','.join(COMMANDS)}}} [args]")
    COMMANDS[sys.argv[1]](*sys.argv[2:])
```

- [ ] **Step 2: Write the runner**

`dev/crowdsec-it.sh` (make it executable: `chmod +x dev/crowdsec-it.sh`):

```bash
#!/usr/bin/env bash
# CrowdSec file-sync overlay, end to end (spec "Run the optional CrowdSec
# overlay", Phase 2 gate). Needs Docker and network access to the CrowdSec Hub.
# Uses a throwaway bouncer key, so CI needs no secret. Hands the dev stack back
# without CrowdSec and with its own Caddyfile.
set -euo pipefail
cd "$(dirname "$0")/.."
export CADDY_CONSOLE_UID="$(id -u)" CADDY_CONSOLE_GID="$(id -g)" BUILDX_BUILDER="${BUILDX_BUILDER:-default}"
export CROWDSEC_CONSOLE_BOUNCER_KEY="${CROWDSEC_CONSOLE_BOUNCER_KEY:-$(python3 -c 'import secrets; print(secrets.token_hex(24))')}"
BASE=(docker compose -f docker-compose.dev.yaml)
COMPOSE=(docker compose -f docker-compose.dev.yaml -f docker-compose.crowdsec.yaml)
IPS="203.0.113.60 203.0.113.61 203.0.113.62 203.0.113.63 203.0.113.70 203.0.113.71"
it() { "${COMPOSE[@]}" exec -T caddy-console /app/.venv/bin/python -m tests.integration.crowdsec_it "$@"; }
cscli() { "${COMPOSE[@]}" exec -T crowdsec cscli "$@"; }
forget() { for ip in $IPS; do cscli decisions delete --ip "$ip" >/dev/null 2>&1 || true; done; }

restore() {
  status=$?
  if [ "$status" -ne 0 ]; then "${COMPOSE[@]}" logs --tail 200 crowdsec caddy-console >&2 || true; fi
  "${COMPOSE[@]}" up -d crowdsec >/dev/null 2>&1 || true
  forget
  it restore >/dev/null 2>&1 || true
  "${COMPOSE[@]}" rm -sf crowdsec >/dev/null 2>&1 || true
  "${BASE[@]}" up -d caddy-console >/dev/null 2>&1 || true    # back to the baseline environment
  if [ "$status" -ne 0 ]; then echo "crowdsec integration: FAILED (exit $status)" >&2; fi
  exit "$status"
}
trap restore EXIT

./dev/run.sh up
"${COMPOSE[@]}" up -d --wait --wait-timeout 300 crowdsec caddy-console
cscli bouncers list -o json | grep -q '"caddy_console"'
forget
it prepare

# Isolation: no published CrowdSec port, Caddy off crowdsec-lapi, no route from CrowdSec to 2019.
CS_ID="$("${COMPOSE[@]}" ps -q crowdsec)"
docker inspect "$CS_ID" | python3 -c 'import json,sys; p=json.load(sys.stdin)[0]["NetworkSettings"]["Ports"] or {}; sys.exit(1 if any(p.values()) else 0)'
CADDY_NETS="$(docker inspect -f '{{json .NetworkSettings.Networks}}' "$("${COMPOSE[@]}" ps -q caddy-target)")"
if grep -q crowdsec-lapi <<<"$CADDY_NETS"; then echo "Caddy joined crowdsec-lapi" >&2; exit 1; fi
"${COMPOSE[@]}" exec -T crowdsec sh -c 'command -v wget' >/dev/null
ADMIN_IP="$("${COMPOSE[@]}" exec -T caddy-console getent hosts caddy-target | awk 'NR == 1 {print $1}')"
test -n "$ADMIN_IP"
for target in caddy-target "$ADMIN_IP"; do
  if "${COMPOSE[@]}" exec -T crowdsec wget -q -T 3 -O /dev/null "http://$target:2019/config/"; then
    echo "CrowdSec reached the Caddy admin API at $target:2019" >&2; exit 1
  fi
done
echo "isolation: ok"

# Parsing of the real filtered log: source_ip must be the synthetic visitor, not the proxy peer.
it explain-traffic
cscli explain --file /var/log/caddy/explain-it.log --type caddy -v | it check-explain 203.0.113.60

# Scenarios: 404 path probe, bad User-Agent, Basic auth brute force, each enforced by the file.
it scenario-traffic
it wait-decisions

# One local decision reaches file enforcement within 60 s, and its deletion too.
t0=$(date +%s); cscli decisions add --ip 203.0.113.70 --duration 1h --reason caddy-console-it >/dev/null
it wait-enforced 203.0.113.70 "$t0" 60 403
it check-records 203.0.113.70 cscli
t0=$(date +%s); cscli decisions delete --ip 203.0.113.70 >/dev/null
it wait-enforced 203.0.113.70 "$t0" 60 200

# LAPI outage keeps the last list; recovery starts with startup=true.
cscli decisions add --ip 203.0.113.71 --duration 1h --reason caddy-console-it >/dev/null
it wait-enforced 203.0.113.71 "$(date +%s)" 60 403
it outage-start 203.0.113.71
"${COMPOSE[@]}" stop crowdsec
it outage-check 203.0.113.71
"${COMPOSE[@]}" up -d --wait --wait-timeout 300 crowdsec
it outage-recovered

# Leader failover across gunicorn workers.
it failover

echo "crowdsec integration: all passed"
```

- [ ] **Step 3: Run it**

Run: `./dev/crowdsec-it.sh`
Expected: `isolation: ok`, the `cscli explain` line, the three scenario lines, `203.0.113.70: HTTP 403 after <=60s`, `HTTP 200 after <=60s`, the leader change line, then `crowdsec integration: all passed`. Then `./dev/bans-it.sh` still passes (the Phase 1 suite is unaffected).

If `explain-traffic` fails with "lacks the user_agent or auth_challenge field", Caddy 2.11.9 runs `basic_auth` before `log_append`: stop and raise it with the spec owner instead of adding a global `order` to operators' Caddyfiles. If a scenario name differs because the pinned hub renamed it, update `EXPECT` only after reading `cscli scenarios list` in the container.

- [ ] **Step 4: CI**

In `.github/workflows/docker-publish.yml`, job `test-integration`, add after "Stock Caddy integration (IP bans)":

```yaml
      - name: CrowdSec overlay integration (file sync)
        run: ./dev/crowdsec-it.sh
```

No secret is needed: the script generates its bouncer key, and the "Stop the dev stack" step's `./dev/run.sh down` now removes orphans.

- [ ] **Step 5: Documentation**

In `docs/security.md`:
- Replace the last two sentences of the intro paragraph with: "CrowdSec file sync is an optional overlay, described in [CrowdSec file sync (optional)](#crowdsec-file-sync-optional). Cloudflare trust profiles and country policy are later additions and are not part of this release."
- In "Host recovery", add after the first code block: "With the CrowdSec overlay, add `-f docker-compose.crowdsec.yaml` to every command and truncate `bans-crowdsec.caddy` instead of (or as well as) `bans-manual.caddy` when a CrowdSec decision caused the lockout. Stopping `caddy-console` also stops CrowdSec file regeneration."
- In "Capacity", add: "`BANS_MAX` counts the manual and CrowdSec files together. A ban, an expiry or a CrowdSec sync that would exceed it is refused as a whole; nothing is dropped to fit."
- Add to the Configuration table:

```markdown
| `BANS_SYNC_INTERVAL` | `30` | Minimum seconds between CrowdSec-driven reloads (10-3600). |
| `CROWDSEC_URL` | empty | LAPI URL; empty disables CrowdSec. The overlay sets `http://crowdsec:8080`. |
| `CROWDSEC_CONSOLE_BOUNCER_KEY` | empty | Read-only bouncer key used only by the console. `CROWDSEC_CONSOLE_BOUNCER_KEY_FILE` reads it from a mounted file instead. |
| `CROWDSEC_ORIGINS` | `crowdsec,cscli` | LAPI origins synced and shown. |
| `CROWDSEC_POLL_INTERVAL` | `10` | Seconds between decision-stream polls (5-300). |
```

- Add this section before "Host recovery":

````markdown
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

Keep the key in the same `.env` as the rest of the stack. On a platform with
file secrets, give the console `CROWDSEC_CONSOLE_BOUNCER_KEY_FILE` instead, and
CrowdSec a Docker secret named `bouncer_key_caddy_console` with the same value
(the official image registers a bouncer from either form). The same overlay
works with `docker-compose.internal.yaml` and `docker-compose.tunnel.yaml`; the
NAS stack uses `docker-compose.nas.yaml -f docker-compose.crowdsec.nas.yaml`.
The `crowdsec/` directory of this repository must sit next to the Compose
files: the overlay mounts its acquisition and parser files read-only.

The CrowdSec container publishes no port, mounts the log volume read-only and
shares only the internal `crowdsec-lapi` network with the console (plus an
egress network for Hub downloads). Caddy never joins that network, so CrowdSec
cannot reach the Caddy admin API. Community enrollment is off
(`DISABLE_ONLINE_API=true`). CrowdSec registers the bouncer `caddy_console` with
your key on first start; to change the key later run
`cscli bouncers delete caddy_console` in the container, then restart it.

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
````

In `docs/setup.md`, extend the "IP bans (optional)" paragraph with: "For automatic bans from CrowdSec, add the optional overlay described in [CrowdSec file sync](security.md#crowdsec-file-sync-optional); the quick start above needs nothing from it." and add the five CrowdSec rows to its environment table (same text as above, with `no` in the Required column).

In `docs/development.md`, below the `./dev/bans-it.sh` line, add:

```bash
./dev/crowdsec-it.sh   # dev stack + docker-compose.crowdsec.yaml, runs tests/integration/crowdsec_it.py
```

with one sentence: "It needs network access to the CrowdSec Hub and generates its own bouncer key."

- [ ] **Step 6: Phase 2 gate**

Run and confirm each item:
- `./dev/check-compose.sh`: baseline files render without CrowdSec; every overlay combination passes (the overlay is the only change required to start CrowdSec; Caddy is absent from `crowdsec-lapi`).
- `./dev/crowdsec-it.sh`: parser and scenario detections, 60-second enforcement, outage, isolation and failover pass.
- `./dev/bans-it.sh`: Phase 1 stays green.
- `uv run --frozen python -m unittest discover -s tests -t .` and `for t in tests/*.test.mjs; do node "$t" || exit 1; done`: stream reconciliation and separate source records pass.
- `npm run build && git diff --exit-code -- src/static/js/`: no bundle drift.
- `grep -rn "CROWDSEC" docker-compose.prod.yaml docker-compose.internal.yaml docker-compose.tunnel.yaml docker-compose.nas.yaml docker-compose.dev.yaml` prints nothing.

- [ ] **Step 7: Commit**

```bash
git add tests/integration/crowdsec_it.py dev/crowdsec-it.sh .github/workflows/docker-publish.yml \
  docs/security.md docs/setup.md docs/development.md
git commit -m "test(crowdsec): overlay integration in CI and CrowdSec file-sync documentation"
```

---

## Spec decisions this plan makes

1. **Record schema.** `bans.json` stays at schema version 1. A CrowdSec record carries its fetch time in `created_at` and only `type=ban` decisions are stored, so the spec's `type` and `fetched_at` fields need no new keys or migration. Record id `crowdsec-<decision id>`, actor `system`, empty reason.
2. **When `bans-crowdsec.caddy` exists.** It is rendered only once `CROWDSEC_URL` is set or CrowdSec state exists (records or a recorded hash). Phase 1 installs never get the file or a reload for it. After CrowdSec is turned off, stored records keep rendering until they expire or are reset.
3. **Capacity.** `BANS_MAX` is a total over both files. A sync that would exceed it is refused as a whole (last policy kept, apply degraded, counts by origin). No partial render by origin priority; manual and local origins are protected because nothing is ever dropped to fit.
4. **Coalescing.** The leader polls every `CROWDSEC_POLL_INTERVAL` and reconciles at most once per `BANS_SYNC_INTERVAL`, every interval, whether or not a delta arrived. A no-op reconcile writes nothing. As a result a Reset of CrowdSec records is undone within the interval, not only at the next snapshot.
5. **Auth failure.** After a 401/403 the leader stops delta polling and retries a `startup=true` poll every 60 s, so a fixed key is picked up without a restart. A changed key (env or `_FILE`) counts as "authentication refreshed".
6. **Shared health.** The leader writes `BACKUP_DIR/bans-crowdsec-sync.json` (0600) after every poll; any worker serves it. It counts as stale after 3 polls plus one sync interval.
7. **NAS.** Its console service is `caddy-editor`, so `docker-compose.crowdsec.nas.yaml` `extends` the overlay's `crowdsec` service. Baseline files are untouched.
8. **Log fields.** The "explicit authentication failure signal" is the late `log_append auth_challenge {http.response.header.Www-Authenticate}`. The parser marks `sub_type=auth_fail` on a 401 with a `Basic` challenge, the rule `crowdsecurity/caddy-logs` applies to the header the filter deletes. The User-Agent is logged as sent; the helper is copy-only so it never displaces the first-child ban import.
9. **Image.** `crowdsecurity/crowdsec:v1.8.2` pinned by its multi-arch index digest.
10. **Configuration errors.** An invalid `CROWDSEC_URL` or `CROWDSEC_ORIGINS` (empty included) refuses startup; a missing or unreadable key is a health state. The query uses the spec's `scopes=Ip,Range`.
11. **Removing a decision.** The UI copies `cscli decisions delete --id <id>` without a Compose prefix (the console cannot know the operator's Compose files); `docs/security.md` shows the full `docker compose ... exec crowdsec` form.
