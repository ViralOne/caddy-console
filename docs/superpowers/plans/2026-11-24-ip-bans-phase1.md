# IP Bans Phase 1 (Manual File Mode) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An authenticated operator can ban and unban an IP or CIDR from the console, and stock `caddy:2.11.9-alpine` enforces it within seconds through a journaled, crash-recoverable file transaction and a transactional `/load`.

**Architecture:** A new backend package `src/bans/` keeps state (`BACKUP_DIR/bans.json`), renders one source-specific Caddy policy (`BANS_DIR/bans-manual.caddy`) and commits both through a multi-entry journal under the existing `caddyfile_lock()`, then adapts and POSTs the unchanged on-disk Caddyfile to `/load`. Enforcement per site is proven from the live `/config/` JSON (the `vars caddy_console_manual_policy 1` marker plus the adjacent `client_ip` matcher and 403 handler), combined with an on-disk scan for editable source location. The frontend adds a fourth Preact view (Security), Ban/Unban in the Explore IP popover and a context-aware snippet that only edits the editor buffer.

**Tech Stack:** Python 3 / Flask / gunicorn, stdlib `ipaddress`/`json`/`fcntl`, `requests` (already a dependency), `unittest`; Preact + htm (committed `explore-vendor.js`), plain ES modules, node `assert` test scripts; stock Caddy 2.11.9 in the existing dev Compose stack for integration and benchmark.

**Spec:** `docs/superpowers/specs/2026-11-23-ip-bans-design.md` (binding). This plan covers "Phase 1: manual file mode" (1.1-1.8) and the Phase 1 parts of "Mode detection and health", "Configuration", "Audit and observability", "Error handling", "Testing", "Phase 1 gate" and the manual-mode section of `docs/security.md`. CrowdSec, plugin, Cloudflare profiles and country policy are out of scope; their extension points are named in each task's **Interfaces** block.

## Global Constraints

- Stock Caddy only: `caddy:2.11.9-alpine`, standard `vars`, `client_ip`, `not`, `handle`, `respond`. No plugin, no image change.
- No new runtime dependencies: `pyproject.toml` `dependencies` and `package.json` stay unchanged. `npm run build` must leave `git diff -- src/static/js/` empty.
- English everywhere (UI copy, comments, docs, commit messages).
- No native `alert()`/`confirm()`/`prompt()` (enforced by `tests/no-native-dialogs.test.mjs`); confirmations use `src/static/js/app/ui/dialog.js`.
- Text from ban records or API responses (value, reason, actor, messages) is rendered only as text nodes (`textContent` or Preact text children). No `innerHTML`, `outerHTML`, `insertAdjacentHTML` or `dangerouslySetInnerHTML` in new or touched files.
- Commits use the already configured git identity. Never run `git config`. One commit per task with the message given in the task.
- Paths and modes (spec 1.1, Phase 1 subset): `BACKUP_DIR/bans.json` 0600; `BANS_DIR/bans-manual.caddy` 0644; `BACKUP_DIR/bans-transaction.json` 0600; `BACKUP_DIR/bans-state-error.json` 0600; backups under `BACKUP_DIR/.policy-transactions/<transaction-id>/` with a `.bak` suffix, never under `BANS_DIR`.
- A temporary managed-policy name MUST be hidden and MUST NOT end in `.caddy` (`.bans-manual.caddy.<random>.tmp`).
- Every generated-file mutation runs inside `caddyfile_lock()` (`src/routes/editor.py`). The lock is a per-call `flock` on a new fd, so it is NOT re-entrant: never call a function that takes it while already holding it.
- Sites opt in with the absolute glob import `import /etc/caddy/console/bans-manual*.caddy` (with `BANS_DIR` substituted when it differs). Relative imports resolve against Caddy's cwd under `/load`, so only absolute paths are offered.
- Generated file shape is spec 1.3 verbatim: header comment, `vars caddy_console_manual_policy 1`, then (only when bans exist) `@caddy_console_manual_banned { client_ip ...; not client_ip ... }` and `handle @caddy_console_manual_banned { respond 403 }`. Matcher names use the `caddy_console_` prefix.
- Manual durations are exactly `4h`, `24h`, `7d`, `permanent`. `reason` is optional, at most 500 Unicode characters, control characters other than newline and tab rejected, never written into a Caddyfile.
- A range wider than `/16` (IPv4) or `/48` (IPv6) is rejected. Overlap with the protected set is tested in both directions.
- Never use `ipaddress`'s `is_private`/`is_global` for protection: Python counts the TEST-NET documentation ranges as private. Use the explicit lists in `src/bans/protected.py`. Tests use `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and `2001:db8::/32` as bannable public addresses.
- Timestamps are UTC RFC 3339 with `Z` (`2026-11-23T20:00:00Z`).
- Configuration (spec table, Phase 1 rows): `BANS_ENABLED` default `true`; `BANS_DIR` default `/etc/caddy/console`; `BANS_MAX` candidate `10000` until Task 16 measures it; `BANS_NEVER` default empty, invalid input fails startup.
- `BANS_ENABLED=false`: no directory check, no probe, no jobs, `/security` and every `/api/security*` and `/api/bans*` route returns 404, the Security tab and ban snippets are absent, existing views are unchanged.
- Any Caddyfile loaded into the dev `caddy-target` during spikes, integration or benchmark MUST keep `admin 0.0.0.0:2019`, or the console loses the admin API until `./dev/run.sh reset`.
- Test commands (CI uses `unittest`, not pytest): `uv run --frozen python -m unittest discover -s tests -t .` and `for t in tests/*.test.mjs; do node "$t" || exit 1; done`. One module: `uv run --frozen python -m unittest tests.test_bans_addr -v`.

## Review Focus

1. **A site with a path-specific `handle /api/* {}` beside a catch-all `handle {}`.** Caddy sub-sorts `handle` routes by path length; a banned client requesting `/api/x` must still get 403 because the managed `handle` (matcher, no path) keeps its first position. Pinned by `test_path_specific_handle_does_not_bypass` (Task 15) and the `handle_path_specific` / `handle_before_import` detection fixtures (Task 5).
2. **The operator uses Save & Reload in the editor while a ban transaction is left `reload_unknown`.** The editor's `/load` loads the candidate policy that is already on disk, so the journal should resolve to committed instead of leaving Security degraded forever. Pinned by `test_editor_reload_commits_pending_candidate` (Task 8).
3. **`BANS_NEVER` gains an address after a ban that covers it already exists.** No crash; the record is flagged as protected in the list and the address appears in the generated `not client_ip` line. Pinned by `test_record_overlapping_new_never_is_flagged_and_excluded` (Task 9).
4. **Unban from the IP popover when a broader range also covers the IP.** The popover should say "Banned by 198.51.100.0/24" rather than claim the address is free. Pinned by `security-model.test.mjs` "banState after removing the exact record still reports the covering range" (Task 13).
5. **IPv4-mapped IPv6 input and host bits in a CIDR** (`::ffff:203.0.113.7`, `203.0.113.7/24`). Stored and looked up canonically (`203.0.113.7`, `203.0.113.0/24`), so the covering lookup and Unban find the record. Pinned by `test_covering_lookup_accepts_mapped_ipv6` (Task 9) and `CanonicalTest` (Task 2).

---

## File Structure

**Backend (new, `src/bans/`):** one responsibility per file.
- `__init__.py`: package docstring only.
- `addr.py`: parse and canonicalize IPs/CIDRs, IPv4-mapped normalization, scope, render token, width limit, verified client address.
- `protected.py`: protected set builder (core classes, `BANS_NEVER`, Docker networks, verified console addresses, a `profile` slot for Phase 4), overlap check, rendered `not client_ip` tokens, UI summary.
- `fsio.py`: hidden temp write, atomic replace, directory fsync, `sha256:` tags.
- `store.py`: `bans.json` schema, parse/serialize, record creation, expiry, management-address registry, quarantine, state snapshots.
- `render.py`: `PolicySource` registry keyed by source (Phase 2 adds `crowdsec`), effective prefixes, policy bytes, capacity check.
- `scan.py`: on-disk Caddyfile site blocks, import glob matching, per-block import state, console (management) site, validator warnings.
- `detect.py`: live JSON walk: marker present, per-site enforcement status and pre-handler classification.
- `caddy.py`: admin API client for `/config/`, `/adapt`, `/load` with explicit outcomes and normalized config hash.
- `txn.py`: the multi-entry journaled transaction, startup/lazy journal recovery, operator recovery actions, editor-reload reconciliation.
- `service.py`: availability check, mutations, holds, status, recovery API logic, expiry tick.
- `jobs.py`: per-worker expiry thread.

**Backend (new):** `src/routes/security.py` (blueprint, registered only when enabled).

**Backend (modified):** `src/config.py`, `src/__init__.py`, `src/validator.py` (`adapt_caddyfile`, `admin_error`), `src/routes/editor.py` (template flag, snippets filter/context, validate warnings, reconcile hook), `src/snippets.json`, `gunicorn.conf.py`, `app.py`.

**Frontend (new, `src/static/js/app/`):** `security-model.js` (pure wording/state), `security.js` (Preact view), `ban-dialog.js` (ban/unban flows), `snippet-insert.js` (pure insertion planning).

**Frontend (modified):** `router.js`, `caddyfile.js`, `main.js`, `panels.js`, `ip-popover.js`, `caddyfile-sites.js` (`&(name)` named routes are not sites), `ui/dialog.js` (`formDialog`), `src/templates/index.html`, `src/static/css/style.css`.

**Tests (new):** `tests/_bans.py` (reset helper, `FakeCaddy`, `ApiCase`; not discovered), `tests/test_bans_config.py`, `tests/test_bans_addr.py`, `tests/test_bans_store.py`, `tests/test_bans_render.py`, `tests/test_bans_detect.py`, `tests/test_bans_caddy.py`, `tests/test_bans_txn.py`, `tests/test_bans_recovery.py`, `tests/test_bans_service.py`, `tests/test_bans_api.py`, `tests/test_bans_jobs.py`, `tests/fixtures/bans/adapted-layouts.json` (generated by real Caddy), `tests/security-model.test.mjs`, `tests/snippet-insert.test.mjs`; integration: `tests/integration/__init__.py`, `tests/integration/_env.py`, `tests/integration/make_detect_fixtures.py`, `tests/integration/spike_load_roundtrip.py`, `tests/integration/bans_caddy_it.py`, `tests/integration/bans_recovery_prep.py`, `tests/integration/bans_benchmark.py`. Integration files are not named `test_*.py`, so `unittest discover` never imports them (they need their own environment).

**Tests (modified):** `tests/_env.py` (BANS_* values), `tests/shell.test.mjs` (fourth tab), `tests/router.test.mjs` and `tests/caddyfile-sites.test.mjs` (appended checks only).

**Ops/docs:** `docker-compose.dev.yaml` (mount `./tests`, BANS env), the four baseline Compose files (BANS_* passthrough), `dev/bans-it.sh`, `dev/check-compose.sh`, `.github/workflows/docker-publish.yml` (integration job), `docs/security.md` (new), `docs/setup.md`, `docs/development.md`.

**Extension points for Phases 2-4 (no rework needed):**
- `render.SOURCES`: Phase 2 registers `PolicySource("crowdsec", "bans-crowdsec.caddy", "caddy_console_crowdsec_policy", "caddy_console_crowdsec_banned")`; `service._candidates()` already loops over every source and `detect.site_statuses()` takes a source.
- `txn.Change(owns=...)`: every state file lists the policies it owns; `apply_locked()` takes any number of state and policy entries (Phase 4 dependency expansion passes `country-policy.json`, `geo.caddy`, `cloudflare-ranges.json`, ... in one call).
- `protected.build(profile=...)`: Phase 4 passes Cloudflare edge ranges; `service._verified_client()` is the single place a trust profile will derive the client IP.
- `store.SOURCES` already accepts `crowdsec` records; `POST /api/security/reset` validates all four spec sources and answers `source_not_enabled` for the three later ones.

---

### Task 1: Configuration, test environment and the Caddy behaviour spike

**Files:**
- Modify: `src/config.py` (append after the GeoIP settings)
- Modify: `tests/_env.py`
- Modify: `docker-compose.dev.yaml` (console `environment` and `volumes`)
- Create: `src/bans/__init__.py`
- Create: `tests/test_bans_config.py`
- Create: `tests/integration/__init__.py`, `tests/integration/make_detect_fixtures.py`, `tests/integration/spike_load_roundtrip.py`
- Create (generated): `tests/fixtures/bans/adapted-layouts.json`

**Interfaces:**
- Produces: `config.BANS_ENABLED: bool`, `config.BANS_DIR: str`, `config.BANS_MAX: int`, `config.BANS_NEVER: str`, `config.bounded_int(name, default, low, high) -> int`. `tests/_env.BANS_DIR`. A JSON fixture mapping layout name to the `result` of a real `POST /adapt`, consumed by Task 5.
- Read these settings as `config.BANS_ENABLED` etc. at call time (`from .. import config`), not with `from ..config import BANS_ENABLED`, so tests can patch them.

- [ ] **Step 1: Write the failing test**

`tests/test_bans_config.py`:

```python
"""BANS_* settings: defaults, bounds and the test environment they run in.

Run with:  uv run --frozen python -m unittest tests.test_bans_config -v
"""
import os
import unittest
from unittest import mock

import tests._env as env  # noqa: F401  (sets env before src is imported)

from src import config


class BansConfigTest(unittest.TestCase):
    def test_test_environment_keeps_bans_dir_inside_the_caddyfile_dir(self):
        self.assertTrue(config.BANS_ENABLED)
        self.assertEqual(config.BANS_DIR, env.BANS_DIR)
        self.assertEqual(os.path.dirname(config.BANS_DIR), os.path.dirname(config.CADDYFILE))
        self.assertEqual(config.BANS_NEVER, "")

    def test_bans_max_has_a_bounded_default(self):
        self.assertTrue(1 <= config.BANS_MAX <= 100000)

    def test_bounded_int_rejects_out_of_range_and_garbage(self):
        with mock.patch.dict(os.environ, {"X_TEST": "0"}):
            with self.assertRaises(RuntimeError):
                config.bounded_int("X_TEST", 5, 1, 10)
        with mock.patch.dict(os.environ, {"X_TEST": "ten"}):
            with self.assertRaises(RuntimeError):
                config.bounded_int("X_TEST", 5, 1, 10)
        with mock.patch.dict(os.environ, {"X_TEST": " 7 "}):
            self.assertEqual(config.bounded_int("X_TEST", 5, 1, 10), 7)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("X_TEST", None)
            self.assertEqual(config.bounded_int("X_TEST", 5, 1, 10), 5)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --frozen python -m unittest tests.test_bans_config -v`
Expected: FAIL with `AttributeError: module 'tests._env' has no attribute 'BANS_DIR'`.

- [ ] **Step 3: Implement config and test env**

Append to `src/config.py`:

```python
def bounded_int(name: str, default: int, low: int, high: int) -> int:
    """An integer setting with server-side bounds; anything else stops startup."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise RuntimeError(f"{name} must be an integer between {low} and {high}, got {raw!r}") from None
    if not low <= value <= high:
        raise RuntimeError(f"{name} must be between {low} and {high}, got {value}")
    return value


# IP bans (docs/security.md). Sites are unchanged until one imports the managed
# file, so this defaults on. BANS_DIR must be inside the Caddyfile directory and
# visible at the same absolute path in the Caddy container.
BANS_ENABLED = os.environ.get("BANS_ENABLED", "true").lower() not in ("0", "false", "no")
BANS_DIR = os.environ.get("BANS_DIR", "/etc/caddy/console").rstrip("/") or "/etc/caddy/console"
# Total prefixes rendered into stock Caddy. Task 16's benchmark sets the default.
BANS_MAX = bounded_int("BANS_MAX", 10000, 1, 100000)
# Extra protected IPs/CIDRs, comma or space separated. Parsed by src/bans/protected.py
# at app start; one invalid token refuses startup.
BANS_NEVER = os.environ.get("BANS_NEVER", "")
```

In `tests/_env.py`, add `BANS_DIR = os.path.join(ROOT, "console")` beside the other paths and these keys to the `os.environ.update({...})` call:

```python
    "BANS_ENABLED": "true",
    "BANS_DIR": BANS_DIR,
    "BANS_NEVER": "",
```

Create `src/bans/__init__.py`:

```python
"""IP bans: manual file mode (docs/security.md, spec Phase 1).

State lives in BACKUP_DIR/bans.json; the generated Caddy policy lives in
BANS_DIR/bans-manual.caddy; both change only through txn.apply_locked().
"""
```

Create empty `tests/integration/__init__.py` (a docstring line: `"""Stock-Caddy integration helpers; run inside the dev console container."""`).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run --frozen python -m unittest tests.test_bans_config -v`
Expected: 3 tests PASS. Then the full suite: `uv run --frozen python -m unittest discover -s tests -t .` stays green.

- [ ] **Step 5: Mount tests into the dev console and pass BANS env**

In `docker-compose.dev.yaml`, `caddy-console` service: add to `environment:`

```yaml
      BANS_ENABLED: "true"
      BANS_DIR: /etc/caddy/console
```

and to `volumes:` (after `./src:/app/src:ro`):

```yaml
      # Integration suites under tests/integration run inside this container,
      # the only place that shares /etc/caddy with caddy-target and reaches 2019.
      - ./tests:/app/tests:ro
```

- [ ] **Step 6: Write the two spike scripts**

`tests/integration/make_detect_fixtures.py` (stdin-runnable, stdlib plus `requests` only, never calls `/load`):

```python
"""Adapt representative site layouts with the running Caddy and print the JSON.

  docker compose -f docker-compose.dev.yaml exec -T caddy-console \
    /app/.venv/bin/python - < tests/integration/make_detect_fixtures.py \
    > tests/fixtures/bans/adapted-layouts.json

Only POST /adapt is used, so the running dev configuration never changes.
"""
import json
import os
import sys

import requests

API = os.environ.get("CADDY_API_URL", "http://caddy-target:2019")
DIR = "/etc/caddy/console-fixtures"
ACTIVE = (
    "# Managed by Caddy Console. Do not edit; changes are overwritten.\n"
    "vars caddy_console_manual_policy 1\n"
    "@caddy_console_manual_banned {\n"
    "\tclient_ip 198.51.100.0/24 203.0.113.7\n"
    "\tnot client_ip private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10\n"
    "}\n"
    "handle @caddy_console_manual_banned {\n"
    "\trespond 403\n"
    "}\n"
)
EMPTY = ("# Managed by Caddy Console. Do not edit; changes are overwritten.\n"
         "vars caddy_console_manual_policy 1\n")
IMP = f"import {DIR}/active/bans-manual*.caddy"
IMP_EMPTY = f"import {DIR}/empty/bans-manual*.caddy"
G = "{\n\tadmin 0.0.0.0:2019\n}\n"
HASH = "$2a$14$Zkx19XLiW6VYouLHR5NmfOFU0z2GTNmpkT/5qqR7hx4IjWJPDhjvG"


def site(body, imp=IMP, global_block=G, before=""):
    return f"{global_block}{before}a.example.com {{\n{body.format(imp=imp)}}}\n"


LAYOUTS = {
    "simple_proxy": site("\t{imp}\n\treverse_proxy 127.0.0.1:9\n"),
    "handle_catchall": site("\t{imp}\n\thandle {{\n\t\treverse_proxy 127.0.0.1:9\n\t}}\n"),
    "handle_path_specific": site("\t{imp}\n\thandle /api/* {{\n\t\trespond \"api\"\n\t}}\n\thandle {{\n\t\trespond \"app\"\n\t}}\n"),
    "handle_before_import": site("\thandle /x/* {{\n\t\trespond \"x\"\n\t}}\n\t{imp}\n\thandle {{\n\t\trespond \"app\"\n\t}}\n"),
    "handle_path": site("\t{imp}\n\thandle_path /static/* {{\n\t\trespond \"static\"\n\t}}\n\thandle {{\n\t\trespond \"app\"\n\t}}\n"),
    "route_strict": site("\troute {{\n\t\t{imp}\n\t\tredir /old /new\n\t\treverse_proxy 127.0.0.1:9\n\t}}\n"),
    "redir_before": site("\t{imp}\n\tredir /old /new\n\treverse_proxy 127.0.0.1:9\n"),
    "rewrite_before": site("\t{imp}\n\trewrite /old /new\n\treverse_proxy 127.0.0.1:9\n"),
    "basic_auth_before": site("\t{imp}\n\tbasic_auth {{\n\t\tbob " + HASH.replace("{", "{{").replace("}", "}}") + "\n\t}}\n\treverse_proxy 127.0.0.1:9\n"),
    "forward_auth_before": site("\t{imp}\n\tforward_auth 127.0.0.1:9 {{\n\t\turi /verify\n\t}}\n\treverse_proxy 127.0.0.1:9\n"),
    "request_header_before": site("\t{imp}\n\trequest_header X-Test 1\n\treverse_proxy 127.0.0.1:9\n"),
    "invoke_before": site("\t{imp}\n\tinvoke app\n", before="&(app) {\n\trespond \"named\" 200\n}\n"),
    "custom_order_first": site("\t{imp}\n\trespond \"hi\" 200\n", global_block="{\n\tadmin 0.0.0.0:2019\n\torder respond first\n}\n"),
    "empty_policy": site("\t{imp}\n\treverse_proxy 127.0.0.1:9\n", imp=IMP_EMPTY),
    "not_imported": site("\treverse_proxy 127.0.0.1:9\n"),
}


def main():
    for sub, body in (("active", ACTIVE), ("empty", EMPTY)):
        os.makedirs(f"{DIR}/{sub}", exist_ok=True)
        with open(f"{DIR}/{sub}/bans-manual.caddy", "w", encoding="utf-8") as f:
            f.write(body)
    out = {}
    for name, text in LAYOUTS.items():
        resp = requests.post(f"{API}/adapt", data=text.encode(), timeout=20,
                             headers={"Content-Type": "text/caddyfile"})
        if resp.status_code != 200:
            sys.exit(f"{name}: adapt failed: {resp.text}")
        out[name] = resp.json()["result"]
    json.dump(out, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")


main()
```

`tests/integration/spike_load_roundtrip.py` (proves the assumptions Task 6 and Task 7 rely on, then restores the dev config):

```python
"""Does GET /config/ after POST /load equal the POST /adapt result, byte for byte
after key sorting? Also prints the adapted marker and matcher shapes.

  docker compose -f docker-compose.dev.yaml exec -T caddy-console \
    /app/.venv/bin/python - < tests/integration/spike_load_roundtrip.py
"""
import hashlib
import json
import os

import requests

API = os.environ.get("CADDY_API_URL", "http://caddy-target:2019")
H = {"Content-Type": "text/caddyfile"}
DIR = "/etc/caddy/console-fixtures/active"
norm = lambda c: hashlib.sha256(json.dumps(c, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

original = open("/etc/caddy/Caddyfile", encoding="utf-8").read()
text = original + f"\nhttp://spike.example.com {{\n\timport {DIR}/bans-manual*.caddy\n\trespond \"ok\" 200\n}}\n"
adapted = requests.post(f"{API}/adapt", data=text.encode(), headers=H, timeout=20).json()["result"]
try:
    load = requests.post(f"{API}/load", data=text.encode(), headers=H, timeout=20)
    live = requests.get(f"{API}/config/", timeout=5).json()
    print("load-status:", load.status_code)
    print("roundtrip-equal:", norm(adapted) == norm(live))

    def find(node, pred, out):
        if isinstance(node, dict):
            if pred(node):
                out.append(node)
            for v in node.values():
                find(v, pred, out)
        elif isinstance(node, list):
            for v in node:
                find(v, pred, out)
        return out

    print("marker:", find(live, lambda d: "caddy_console_manual_policy" in d, [])[:1])
    print("matcher:", json.dumps(find(live, lambda d: "client_ip" in d and "not" in d, [])[:1]))
finally:
    requests.post(f"{API}/load", data=original.encode(), headers=H, timeout=20)
```

- [ ] **Step 7: Run the spike against the dev stack**

Run:
```bash
./dev/run.sh up
docker compose -f docker-compose.dev.yaml exec -T caddy-console \
  /app/.venv/bin/python - < tests/integration/make_detect_fixtures.py \
  > tests/fixtures/bans/adapted-layouts.json
docker compose -f docker-compose.dev.yaml exec -T caddy-console \
  /app/.venv/bin/python - < tests/integration/spike_load_roundtrip.py
```
(Create `tests/fixtures/bans/` first with `mkdir -p tests/fixtures/bans`.)
Expected: the fixture file holds 15 top-level keys; the spike prints `load-status: 200`, `roundtrip-equal: True`, a marker whose `caddy_console_manual_policy` value is `"1"` or `1`, and a matcher with `client_ip.ranges` and `not[0].client_ip.ranges` where `private_ranges` is expanded to CIDRs.

**STOP and report to the user if `roundtrip-equal` is `False`:** the transaction's "live equals adapted" verification (Task 7) and journal recovery (Task 8) depend on it. Do not weaken the comparison; the normalization in `src/bans/caddy.py` would first need a reviewed list of volatile keys.

- [ ] **Step 8: Commit**

```bash
git add src/config.py src/bans/__init__.py tests/_env.py tests/test_bans_config.py \
  tests/integration/__init__.py tests/integration/make_detect_fixtures.py \
  tests/integration/spike_load_roundtrip.py tests/fixtures/bans/adapted-layouts.json \
  docker-compose.dev.yaml
git commit -m "feat(bans): config, test environment and real Caddy adaptation fixtures"
```

---

### Task 2: Address canonicalization and the protected set

**Files:**
- Create: `src/bans/addr.py`, `src/bans/protected.py`
- Test: `tests/test_bans_addr.py`

**Interfaces:**
- Produces (`addr`): `AddressError(code, message)` with `.code` in `invalid_ip | invalid_range | range_too_wide`; `canonical(value) -> IPv4Network | IPv6Network`; `unmap(net)`; `scope_of(net) -> "ip" | "range"`; `token(net) -> str` (bare address for /32 and /128); `check_width(net)`; `client_address(raw) -> IPv4Address | IPv6Address | None`.
- Produces (`protected`): `ConfigError`; `LABELS: dict[str, str]`; `overlaps(a, b) -> bool`; `parse_never(raw) -> tuple[Network, ...]`; `docker_networks(route_text) -> list[Network]`; `read_docker_networks() -> list[Network]`; `build(*, never=(), management=(), docker=(), profile=()) -> Protected` with `.overlap(net) -> str | None` (category), `.exclusion_tokens() -> list[str]`, `.summary() -> list[dict]`. Phase 4 passes Cloudflare edge ranges as `profile=`.

- [ ] **Step 1: Write the failing tests**

`tests/test_bans_addr.py`:

```python
"""Ban targets: canonical form, scope, width and the protected set.

Run with:  uv run --frozen python -m unittest tests.test_bans_addr -v
"""
import ipaddress
import unittest

import tests._env  # noqa: F401

from src.bans import addr, protected

net = ipaddress.ip_network


class CanonicalTest(unittest.TestCase):
    def test_ipv4_and_ipv6_are_canonical(self):
        self.assertEqual(addr.token(addr.canonical(" 203.0.113.7 ")), "203.0.113.7")
        self.assertEqual(addr.token(addr.canonical("2001:DB8:0:0::1")), "2001:db8::1")
        self.assertEqual(addr.token(addr.canonical("203.0.113.7/24")), "203.0.113.0/24")
        self.assertEqual(addr.token(addr.canonical("203.0.113.7/32")), "203.0.113.7")
        self.assertEqual(addr.token(addr.canonical("2001:db8::/48")), "2001:db8::/48")

    def test_ipv4_mapped_ipv6_becomes_ipv4(self):
        self.assertEqual(addr.token(addr.canonical("::ffff:203.0.113.7")), "203.0.113.7")
        self.assertEqual(addr.token(addr.canonical("::ffff:198.51.100.0/120")), "198.51.100.0/24")

    def test_scope_is_derived_from_the_parsed_value(self):
        self.assertEqual(addr.scope_of(addr.canonical("203.0.113.7")), "ip")
        self.assertEqual(addr.scope_of(addr.canonical("203.0.113.0/24")), "range")
        self.assertEqual(addr.scope_of(addr.canonical("2001:db8::1/128")), "ip")

    def test_invalid_input_gets_stable_codes(self):
        for raw in ("", "abc", "1.2.3", "203.0.113.7 198.51.100.1", "fe80::1%eth0", None, 7, "1" * 100, "010.1.1.1"):
            with self.subTest(raw=raw), self.assertRaises(addr.AddressError) as cm:
                addr.canonical(raw)
            self.assertEqual(cm.exception.code, "invalid_ip")
        for raw in ("203.0.113.0/33", "x/24", "2001:db8::/129", "203.0.113.0/"):
            with self.subTest(raw=raw), self.assertRaises(addr.AddressError) as cm:
                addr.canonical(raw)
            self.assertEqual(cm.exception.code, "invalid_range")

    def test_width_limits(self):
        addr.check_width(addr.canonical("203.0.0.0/16"))
        addr.check_width(addr.canonical("2001:db8::/48"))
        for raw in ("203.0.0.0/15", "2001:db8::/47"):
            with self.subTest(raw=raw), self.assertRaises(addr.AddressError) as cm:
                addr.check_width(addr.canonical(raw))
            self.assertEqual(cm.exception.code, "range_too_wide")

    def test_client_address(self):
        self.assertEqual(str(addr.client_address("203.0.113.7")), "203.0.113.7")
        self.assertEqual(str(addr.client_address("::ffff:203.0.113.7")), "203.0.113.7")
        for raw in (None, "", "junk", "203.0.113.0/24"):
            self.assertIsNone(addr.client_address(raw))


class ProtectedTest(unittest.TestCase):
    def setUp(self):
        self.p = protected.build(never=protected.parse_never("198.51.100.9, 2001:db8:1::/64"))

    def test_every_core_class_is_protected(self):
        cases = {
            "127.0.0.1": "loopback", "::1": "loopback",
            "10.1.2.3": "private", "172.16.5.5": "private", "192.168.1.1": "private",
            "169.254.1.1": "link_local", "fe80::1": "link_local",
            "100.64.1.1": "cgnat", "fd12::1": "ula",
            "0.0.0.0": "special", "224.0.0.1": "special", "240.0.0.1": "special",
            "ff02::1": "special", "::": "special",
        }
        for raw, category in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(self.p.overlap(addr.canonical(raw)), category)

    def test_documentation_ranges_are_bannable(self):
        for raw in ("203.0.113.7", "192.0.2.1", "2001:db8::1", "198.18.0.1"):
            with self.subTest(raw=raw):
                self.assertIsNone(self.p.overlap(addr.canonical(raw)))

    def test_overlap_is_checked_in_both_directions(self):
        self.assertEqual(self.p.overlap(addr.canonical("198.51.100.9")), "never")      # inside
        self.assertEqual(self.p.overlap(addr.canonical("198.51.100.0/24")), "never")   # contains
        self.assertEqual(self.p.overlap(addr.canonical("2001:db8:1::/48")), "never")
        self.assertEqual(self.p.overlap(addr.canonical("2001:db8:1::5")), "never")
        self.assertIsNone(self.p.overlap(addr.canonical("198.51.101.0/24")))
        self.assertTrue(protected.overlaps(net("10.0.0.0/8"), net("10.1.0.0/16")))
        self.assertTrue(protected.overlaps(net("10.1.0.0/16"), net("10.0.0.0/8")))

    def test_families_never_overlap(self):
        # ::a00:1 has the same integer value as 10.0.0.1; it must not read as private.
        self.assertIsNone(self.p.overlap(addr.canonical("::a00:1")))

    def test_verified_console_addresses(self):
        p = protected.build(management=[net("198.51.100.20/32")])
        self.assertEqual(p.overlap(addr.canonical("198.51.100.0/24")), "operator")

    def test_parse_never_rejects_invalid_tokens(self):
        self.assertEqual(protected.parse_never(""), ())
        self.assertEqual(protected.parse_never(" 203.0.113.7,198.51.100.0/24  2001:db8::1 "),
                         (net("203.0.113.7/32"), net("198.51.100.0/24"), net("2001:db8::1/128")))
        with self.assertRaises(protected.ConfigError):
            protected.parse_never("203.0.113.7, nope")

    def test_exclusion_tokens_add_only_uncovered_extras(self):
        p = protected.build(never=protected.parse_never("198.51.100.9 10.1.1.1"),
                            management=[net("198.51.100.20/32")],
                            docker=[net("172.18.0.0/16")])
        tokens = p.exclusion_tokens()
        self.assertEqual(tokens[:5], ["private_ranges", "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10"])
        self.assertEqual(tokens[5:], ["198.51.100.9", "198.51.100.20"])

    def test_docker_networks_from_proc_route(self):
        text = ("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
                "eth0\t00000000\t010012AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
                "eth0\t000012AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n")
        self.assertEqual(protected.docker_networks(text), [net("172.18.0.0/16")])
        self.assertEqual(protected.docker_networks("garbage"), [])

    def test_summary_groups_by_category_with_labels(self):
        summary = {s["category"]: s for s in self.p.summary()}
        self.assertEqual(summary["never"]["values"], ["198.51.100.9", "2001:db8:1::/64"])
        self.assertEqual(summary["loopback"]["label"], "Loopback")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --frozen python -m unittest tests.test_bans_addr -v`
Expected: FAIL with `ImportError: cannot import name 'addr' from 'src.bans'`.

- [ ] **Step 3: Implement `src/bans/addr.py`**

```python
"""Parse ban targets into canonical networks. Raw request text never reaches a
Caddyfile: everything written out is serialized from the parsed object."""
import ipaddress

IPV4_MIN_PREFIX = 16
IPV6_MIN_PREFIX = 48
_MAPPED = ipaddress.ip_network("::ffff:0:0/96")


class AddressError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def unmap(net):
    """::ffff:a.b.c.d/(96+n) -> a.b.c.d/n, so IPv4 clients compare as IPv4."""
    if net.version == 6 and net.prefixlen >= 96 and net.subnet_of(_MAPPED):
        return ipaddress.ip_network(f"{net.network_address.ipv4_mapped}/{net.prefixlen - 96}")
    return net


def canonical(value):
    text = value.strip() if isinstance(value, str) else ""
    code = "invalid_range" if "/" in text else "invalid_ip"
    kind = "CIDR range" if code == "invalid_range" else "IP address"
    if not text or len(text) > 64 or "%" in text or any(c.isspace() for c in text):
        raise AddressError(code, f"Enter a single {kind}.")
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise AddressError(code, f"{text} is not a valid {kind}.") from None
    return unmap(net)


def scope_of(net) -> str:
    return "ip" if net.prefixlen == net.max_prefixlen else "range"


def token(net) -> str:
    return str(net.network_address) if scope_of(net) == "ip" else str(net)


def check_width(net) -> None:
    limit = IPV4_MIN_PREFIX if net.version == 4 else IPV6_MIN_PREFIX
    if net.prefixlen < limit:
        raise AddressError("range_too_wide", f"Ranges wider than /{limit} cannot be banned for IPv{net.version}.")


def client_address(raw):
    """The canonical address of a transport peer string, or None."""
    if not isinstance(raw, str) or "/" in raw:
        return None
    try:
        ip = ipaddress.ip_address(raw.strip())
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip
```

- [ ] **Step 4: Implement `src/bans/protected.py`**

```python
"""Addresses that can never be banned, checked at input and repeated in the
generated `not client_ip` line (spec 1.3)."""
import ipaddress
import re
import socket
import struct
from dataclasses import dataclass

from . import addr

_n = ipaddress.ip_network
CORE = (
    ("loopback", ("127.0.0.0/8", "::1/128")),
    ("private", ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")),
    ("link_local", ("169.254.0.0/16", "fe80::/10")),
    ("cgnat", ("100.64.0.0/10",)),
    ("ula", ("fc00::/7",)),
    ("special", ("0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4", "::/128", "ff00::/8")),
)
LABELS = {
    "loopback": "Loopback", "private": "Private (RFC 1918)", "link_local": "Link-local",
    "cgnat": "Carrier-grade NAT", "ula": "IPv6 unique local",
    "special": "Unspecified, multicast and reserved", "docker": "Docker networks",
    "never": "BANS_NEVER", "operator": "Verified console addresses", "profile": "Client-IP profile",
}
# What the rendered exclusion always starts with. Caddy's private_ranges is
# 127/8, 10/8, 172.16/12, 192.168/16, fd00::/8 and ::1/128.
RENDER_BASE = ("private_ranges", "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10")
_RENDER_BASE_NETS = tuple(_n(x) for x in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8", "::1/128",
    "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10"))
DYNAMIC = ("docker", "never", "operator", "profile")


class ConfigError(ValueError):
    pass


def overlaps(a, b) -> bool:
    """Interval intersection, so containment in either direction counts."""
    return (a.version == b.version
            and a.network_address <= b.broadcast_address
            and b.network_address <= a.broadcast_address)


def parse_never(raw: str) -> tuple:
    out = []
    for item in re.split(r"[\s,]+", raw or ""):
        if not item:
            continue
        try:
            out.append(addr.canonical(item))
        except addr.AddressError as e:
            raise ConfigError(f"invalid entry {item!r}: {e}") from None
    return tuple(out)


def docker_networks(route_text: str) -> list:
    """IPv4 networks this container is attached to, from /proc/net/route."""
    nets = []
    for line in (route_text or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 8:
            continue
        try:
            dest = socket.inet_ntoa(struct.pack("<I", int(parts[1], 16)))
            mask = socket.inet_ntoa(struct.pack("<I", int(parts[7], 16)))
            candidate = ipaddress.ip_network(f"{dest}/{mask}")
        except (ValueError, struct.error, OSError):
            continue
        if candidate.prefixlen > 0 and candidate not in nets:
            nets.append(candidate)
    return nets


def read_docker_networks() -> list:
    try:
        with open("/proc/net/route", encoding="ascii") as f:
            return docker_networks(f.read())
    except OSError:
        return []


@dataclass(frozen=True)
class Protected:
    entries: tuple   # ((category, network), ...)

    def overlap(self, candidate):
        for category, protected_net in self.entries:
            if overlaps(candidate, protected_net):
                return category
        return None

    def exclusion_tokens(self) -> list:
        extras = [n for cat, n in self.entries if cat in DYNAMIC]
        out = list(RENDER_BASE)
        for family in (4, 6):
            for n in ipaddress.collapse_addresses([e for e in extras if e.version == family]):
                if not any(n.version == b.version and n.subnet_of(b) for b in _RENDER_BASE_NETS):
                    out.append(addr.token(n))
        return out

    def summary(self) -> list:
        groups = {}
        for category, n in self.entries:
            groups.setdefault(category, []).append(addr.token(n))
        return [{"category": c, "label": LABELS[c], "values": v} for c, v in groups.items()]


def build(*, never=(), management=(), docker=(), profile=()) -> Protected:
    entries = [(cat, _n(v)) for cat, values in CORE for v in values]
    for category, nets in (("never", never), ("operator", management), ("docker", docker), ("profile", profile)):
        entries.extend((category, addr.unmap(_n(x) if isinstance(x, str) else ipaddress.ip_network(x))) for x in nets)
    return Protected(tuple(entries))
```

Note: `build(..., docker=...)` entries are checked after `never`/`operator`, so a docker range inside RFC 1918 still reports `private` first, which is the useful label.

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run --frozen python -m unittest tests.test_bans_addr -v`
Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/bans/addr.py src/bans/protected.py tests/test_bans_addr.py
git commit -m "feat(bans): canonical ban targets and the protected address set"
```

---

### Task 3: File I/O helpers and the `bans.json` store

**Files:**
- Create: `src/bans/fsio.py`, `src/bans/store.py`
- Test: `tests/test_bans_store.py`

**Interfaces:**
- Consumes: `addr.canonical`, `addr.token`, `addr.scope_of`.
- Produces (`fsio`): `sha256_tag(data: bytes | None) -> str | None` (`"sha256:<hex>"`), `read_bytes(path) -> bytes | None`, `fsync_dir(path)`, `write_temp(directory, basename, data, mode) -> str`, `atomic_write(path, data, mode)`.
- Produces (`store`): `STATE_PATH`, `ERROR_PATH`, `SNAPSHOT_DIR`, `SOURCES = ("manual", "crowdsec")`, `DURATIONS`, `REASON_MAX = 500`, `MANAGEMENT_MAX = 16`, `MANAGEMENT_TTL`; `StateCorrupt(message, raw)`; `InputError(code, message)`; `Record` (fields exactly the spec 1.2 keys, `.network`, `.expired(now)`); `State` (`records`, `last_rendered_hashes`, `management_addresses`, `raw`, `raw_hash`, `.version`); `utc_now()`, `iso(dt)`, `parse_iso(text)`; `parse(raw) -> State`; `load(path=None) -> State`; `dumps(state) -> bytes`; `validate_reason`, `validate_duration`; `new_manual_record(net, duration, reason, actor, now)`; `prune_expired(state, now, sources=None) -> list[Record]`; `prune_management(state, now) -> bool`; `touch_management(state, ip, profile, now) -> bool`; `management_networks(state) -> list`; `quarantine(raw, error) -> str | None`; `read_error()`, `clear_error()`; `save_snapshot(raw)`, `list_snapshots() -> list[dict]`, `snapshot_bytes(snapshot_id) -> bytes | None`.

- [ ] **Step 1: Write the failing tests**

`tests/test_bans_store.py`:

```python
"""bans.json: schema, round trip, expiry, registry, quarantine and snapshots.

Run with:  uv run --frozen python -m unittest tests.test_bans_store -v
"""
import json
import os
import stat
import unittest
from datetime import timedelta

import tests._env as env  # noqa: F401
from tests import _bans

from src.bans import addr, fsio, store

NOW = store.parse_iso("2026-11-23T20:00:00Z")


def rec(value="203.0.113.7", duration="24h", reason="", now=NOW):
    return store.new_manual_record(addr.canonical(value), duration, reason, "admin@example.com", now)


class StoreRoundTripTest(unittest.TestCase):
    def setUp(self):
        _bans.reset()

    def test_missing_file_is_an_empty_state(self):
        state = store.load()
        self.assertEqual((state.records, state.raw_hash, state.version), ([], None, "empty"))

    def test_round_trip_is_deterministic_and_private(self):
        state = store.State(records=[rec(), rec("198.51.100.0/24", "permanent", "line 1\n\tline 2")],
                            last_rendered_hashes={"bans-manual.caddy": fsio.sha256_tag(b"x")})
        data = store.dumps(state)
        self.assertEqual(data, store.dumps(store.parse(data)))
        fsio.atomic_write(store.STATE_PATH, data, 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(store.STATE_PATH).st_mode), 0o600)
        loaded = store.load()
        self.assertEqual([r.value for r in loaded.records], ["203.0.113.7", "198.51.100.0/24"])
        self.assertEqual(loaded.records[1].expires_at, None)
        self.assertEqual(loaded.version, fsio.sha256_tag(data)[7:23])
        doc = json.loads(data)
        self.assertEqual(doc["version"], 1)
        self.assertEqual(set(doc["records"][0]), {"id", "source", "source_id", "scope", "value", "reason",
                                                  "scenario", "origin", "actor", "created_at", "expires_at"})

    def test_invalid_documents_are_corrupt_not_empty(self):
        good = json.loads(store.dumps(store.State(records=[rec()])))
        bad_docs = {
            "not json": b"{nope",
            "array": b"[]",
            "future version": {**good, "version": 2},
            "unknown key": {**good, "extra": 1},
            "non-canonical value": {**good, "records": [{**good["records"][0], "value": "203.0.113.7/32"}]},
            "scope mismatch": {**good, "records": [{**good["records"][0], "scope": "range"}]},
            "control char": {**good, "records": [{**good["records"][0], "reason": "a\x07b"}]},
            "offset timestamp": {**good, "records": [{**good["records"][0], "created_at": "2026-11-23T20:00:00+00:00"}]},
            "duplicate id": {**good, "records": [good["records"][0], good["records"][0]]},
            "bad hash": {**good, "last_rendered_hashes": {"bans-manual.caddy": "md5:abc"}},
            "bad source": {**good, "records": [{**good["records"][0], "source": "other"}]},
        }
        for name, doc in bad_docs.items():
            with self.subTest(name=name):
                raw = doc if isinstance(doc, bytes) else json.dumps(doc).encode()
                with self.assertRaises(store.StateCorrupt) as cm:
                    store.parse(raw)
                self.assertEqual(cm.exception.raw, raw)

    def test_unreadable_file_is_corrupt(self):
        if os.geteuid() == 0:
            self.skipTest("root can read a 0000 file")
        fsio.atomic_write(store.STATE_PATH, store.dumps(store.State()), 0o000)
        with self.assertRaises(store.StateCorrupt):
            store.load()


class InputValidationTest(unittest.TestCase):
    def test_reason_limits(self):
        self.assertEqual(store.validate_reason(None), "")
        self.assertEqual(store.validate_reason("é" * 500), "é" * 500)
        self.assertEqual(store.validate_reason("a\nb\tc"), "a\nb\tc")
        for bad in ("é" * 501, "a\rb", "a\x85b", 5):
            with self.subTest(bad=bad), self.assertRaises(store.InputError) as cm:
                store.validate_reason(bad)
            self.assertEqual(cm.exception.code, "invalid_reason")

    def test_durations(self):
        for d in ("4h", "24h", "7d", "permanent"):
            self.assertEqual(store.validate_duration(d), d)
        for bad in ("1h", "", None, "PERMANENT"):
            with self.subTest(bad=bad), self.assertRaises(store.InputError) as cm:
                store.validate_duration(bad)
            self.assertEqual(cm.exception.code, "invalid_duration")
        r = rec(duration="4h")
        self.assertEqual(r.expires_at, "2026-11-24T00:00:00Z")
        self.assertEqual(r.created_at, "2026-11-23T20:00:00Z")


class ExpiryAndRegistryTest(unittest.TestCase):
    def test_expired_records_go_and_overlapping_records_stay_independent(self):
        short, long_, forever = rec(duration="4h"), rec(duration="7d"), rec("198.51.100.0/24", "permanent")
        state = store.State(records=[short, long_, forever])
        removed = store.prune_expired(state, NOW + timedelta(hours=5))
        self.assertEqual([r.id for r in removed], [short.id])
        self.assertEqual([r.id for r in state.records], [long_.id, forever.id])

    def test_prune_can_be_limited_to_sources(self):
        state = store.State(records=[rec(duration="4h")])
        self.assertEqual(store.prune_expired(state, NOW + timedelta(hours=5), sources=["crowdsec"]), [])
        self.assertEqual(len(state.records), 1)

    def test_registry_caps_at_16_and_expires_after_30_days(self):
        state = store.State()
        for i in range(20):
            store.touch_management(state, addr.client_address(f"203.0.113.{i}"), "direct", NOW + timedelta(minutes=i))
        self.assertEqual(len(state.management_addresses), 16)
        self.assertNotIn("203.0.113.0", [m["value"] for m in state.management_addresses])
        self.assertTrue(store.touch_management(state, addr.client_address("203.0.113.19"), "direct", NOW + timedelta(days=1)))
        self.assertEqual(len(state.management_addresses), 16)
        self.assertTrue(store.prune_management(state, NOW + timedelta(days=30, minutes=30)))
        self.assertEqual([m["value"] for m in state.management_addresses], ["203.0.113.19"])
        self.assertEqual([str(n) for n in store.management_networks(state)], ["203.0.113.19/32"])
        self.assertFalse(store.touch_management(state, None, "direct", NOW))


class QuarantineAndSnapshotTest(unittest.TestCase):
    def setUp(self):
        _bans.reset()

    def test_quarantine_is_bounded_private_and_written_once(self):
        raw = b"x" * (2 * 1024 * 1024)
        name = store.quarantine(raw, "bans.json is not valid JSON")
        path = os.path.join(env.BACKUP_DIR, name)
        self.assertEqual(os.path.getsize(path), 1024 * 1024)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(store.quarantine(raw, "again"), name)
        self.assertEqual(len([n for n in os.listdir(env.BACKUP_DIR) if n.startswith("bans.json.quarantine-")]), 1)
        self.assertEqual(store.read_error()["quarantine"], name)
        store.clear_error()
        self.assertIsNone(store.read_error())

    def test_snapshots_keep_five_with_opaque_ids(self):
        for i in range(7):
            store.save_snapshot(store.dumps(store.State(records=[rec(f"203.0.113.{i}")])))
        snaps = store.list_snapshots()
        self.assertEqual(len(snaps), 5)
        for s in snaps:
            self.assertRegex(s["id"], r"^[0-9a-f]{16}$")
            self.assertEqual(s["records"], 1)
            self.assertIsNotNone(store.snapshot_bytes(s["id"]))
        self.assertIsNone(store.snapshot_bytes("../../etc/passwd"))


if __name__ == "__main__":
    unittest.main()
```

This test imports `tests/_bans.py`. Create it now with only `reset()`; Task 6 extends it.

```python
"""Shared fixtures for the IP-ban tests (not a test module: never discovered).

reset() returns every ban-related file to a clean slate; FakeCaddy (Task 6)
stands in for the admin API.
"""
import os
import shutil

import tests._env as env

MANUAL_SITE = "example.com {{\n\timport {bans_dir}/bans-manual*.caddy\n\trespond 200\n}}\n"


def write_caddyfile(text):
    with open(env.CADDYFILE, "w", encoding="utf-8") as f:
        f.write(text)


def reset(caddyfile=None):
    for name in os.listdir(env.BACKUP_DIR):
        if name.startswith("bans") or name.startswith(".bans"):
            path = os.path.join(env.BACKUP_DIR, name)
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            else:
                os.remove(path)
    shutil.rmtree(os.path.join(env.BACKUP_DIR, ".policy-transactions"), ignore_errors=True)
    shutil.rmtree(env.BANS_DIR, ignore_errors=True)
    os.makedirs(env.BANS_DIR)
    write_caddyfile(caddyfile if caddyfile is not None else MANUAL_SITE.format(bans_dir=env.BANS_DIR))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --frozen python -m unittest tests.test_bans_store -v`
Expected: FAIL with `ImportError: cannot import name 'fsio' from 'src.bans'`.

- [ ] **Step 3: Implement `src/bans/fsio.py`**

```python
"""Small, fully flushed file operations shared by the ban store and transaction."""
import hashlib
import os
import tempfile


def sha256_tag(data):
    return None if data is None else "sha256:" + hashlib.sha256(data).hexdigest()


def read_bytes(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        return None


def fsync_dir(directory: str) -> None:
    """Best effort, like the editor's save path: a filesystem that refuses a
    directory fsync must not turn a completed replace into a failure."""
    try:
        fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def write_temp(directory: str, basename: str, data: bytes, mode: int) -> str:
    """A flushed, hidden temp file beside its target: ".<basename>.<random>.tmp".

    The leading dot and the .tmp suffix mean no `*.caddy` import glob can ever
    match a partial or abandoned file.
    """
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=f".{basename}.", suffix=".tmp")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            fd = -1
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        if fd >= 0:
            os.close(fd)
        try:
            os.remove(tmp)
        except FileNotFoundError:
            pass
        raise
    return tmp


def atomic_write(path: str, data: bytes, mode: int) -> None:
    directory = os.path.dirname(path) or "."
    tmp = write_temp(directory, os.path.basename(path), data, mode)
    try:
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except FileNotFoundError:
            pass
        raise
    fsync_dir(directory)
```

- [ ] **Step 4: Implement `src/bans/store.py`**

```python
"""bans.json: versioned ban records, rendered-policy hashes and the verified
console-address registry (spec 1.2). A security-control file: anything that is
not exactly this schema is quarantined and reported, never rewritten as empty
(spec 1.6). Writes happen only through txn.apply_locked()."""
import hashlib
import json
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from ..config import BACKUP_DIR
from . import addr, fsio

STATE_PATH = os.path.join(BACKUP_DIR, "bans.json")
ERROR_PATH = os.path.join(BACKUP_DIR, "bans-state-error.json")
SNAPSHOT_DIR = os.path.join(BACKUP_DIR, ".bans-snapshots")
SNAPSHOT_KEEP = 5
STATE_MAX_BYTES = 32 * 1024 * 1024
QUARANTINE_MAX_BYTES = 1024 * 1024
SCHEMA_VERSION = 1
SOURCES = ("manual", "crowdsec")          # crowdsec records arrive in Phase 2
TRUST_PROFILES = ("direct", "cloudflare-proxied", "cloudflare-tunnel")
DURATIONS = {"4h": timedelta(hours=4), "24h": timedelta(hours=24),
             "7d": timedelta(days=7), "permanent": None}
REASON_MAX = 500
MANAGEMENT_MAX = 16
MANAGEMENT_TTL = timedelta(days=30)
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_KEYS = {"version", "records", "last_rendered_hashes", "management_addresses"}
_RECORD_KEYS = {"id", "source", "source_id", "scope", "value", "reason", "scenario",
                "origin", "actor", "created_at", "expires_at"}


class StateCorrupt(Exception):
    def __init__(self, message, raw=None):
        super().__init__(message)
        self.raw = raw


class InputError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(text):
    if not isinstance(text, str) or not text.endswith("Z"):
        raise ValueError(f"not a UTC RFC 3339 timestamp: {text!r}")
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


@dataclass
class Record:
    id: str
    source: str
    source_id: object
    scope: str
    value: str
    reason: str
    scenario: object
    origin: object
    actor: str
    created_at: str
    expires_at: object

    @property
    def network(self):
        return addr.canonical(self.value)

    def expired(self, now) -> bool:
        return self.expires_at is not None and parse_iso(self.expires_at) <= now


@dataclass
class State:
    records: list = field(default_factory=list)
    last_rendered_hashes: dict = field(default_factory=dict)
    management_addresses: list = field(default_factory=list)
    raw: object = None          # bytes as read; None when the file did not exist
    raw_hash: object = None

    @property
    def version(self) -> str:
        return self.raw_hash[7:23] if self.raw_hash else "empty"


def validate_reason(value) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise InputError("invalid_reason", "Reason must be text.")
    if len(value) > REASON_MAX:
        raise InputError("invalid_reason", f"Reason must be at most {REASON_MAX} characters.")
    if _CONTROL.search(value):
        raise InputError("invalid_reason", "Reason may not contain control characters other than newline and tab.")
    return value


def validate_duration(value) -> str:
    if value not in DURATIONS:
        raise InputError("invalid_duration", "Duration must be 4h, 24h, 7d or permanent.")
    return value


def _opt_str(value, limit=200):
    if value is not None and (not isinstance(value, str) or len(value) > limit):
        raise ValueError("optional field must be a short string or null")


def _check_record(r: Record) -> None:
    if not isinstance(r.id, str) or not 0 < len(r.id) <= 64:
        raise ValueError("record id")
    if r.source not in SOURCES:
        raise ValueError(f"unknown source {r.source!r}")
    if not isinstance(r.actor, str) or len(r.actor) > 320:
        raise ValueError("actor")
    for v in (r.source_id, r.scenario, r.origin):
        _opt_str(v)
    if r.source == "manual" and (r.source_id, r.scenario, r.origin) != (None, None, None):
        raise ValueError("manual records carry no source_id, scenario or origin")
    validate_reason(r.reason)
    parse_iso(r.created_at)
    if r.expires_at is not None:
        parse_iso(r.expires_at)
    if not isinstance(r.value, str):
        raise ValueError("value")
    net = addr.canonical(r.value)
    if addr.token(net) != r.value:
        raise ValueError(f"value {r.value!r} is not canonical")
    if addr.scope_of(net) != r.scope:
        raise ValueError(f"scope of {r.value!r} must be {addr.scope_of(net)}")


def migrate(doc):
    """Bring an older document to SCHEMA_VERSION. A newer one is never downgraded."""
    if not isinstance(doc, dict):
        raise TypeError("top level must be an object")
    if doc.get("version") == SCHEMA_VERSION:
        return doc
    raise ValueError(f"unsupported schema version {doc.get('version')!r}")


def _from_doc(doc) -> State:
    unknown = set(doc) - _KEYS
    if unknown:
        raise ValueError(f"unknown keys {sorted(unknown)}")
    records, ids = [], set()
    for item in doc["records"]:
        if not isinstance(item, dict) or set(item) != _RECORD_KEYS:
            raise ValueError("record keys do not match the schema")
        r = Record(**item)
        _check_record(r)
        if r.id in ids:
            raise ValueError(f"duplicate record id {r.id}")
        ids.add(r.id)
        records.append(r)
    hashes = doc["last_rendered_hashes"]
    if not isinstance(hashes, dict) or not all(
            isinstance(k, str) and k.endswith(".caddy") and "/" not in k
            and isinstance(v, str) and _HASH_RE.match(v) for k, v in hashes.items()):
        raise ValueError("last_rendered_hashes")
    mgmt = doc["management_addresses"]
    if not isinstance(mgmt, list) or len(mgmt) > MANAGEMENT_MAX:
        raise ValueError("management_addresses")
    for m in mgmt:
        if not isinstance(m, dict) or set(m) != {"value", "trust_profile", "last_seen"}:
            raise ValueError("management address keys")
        ip = addr.client_address(m["value"])
        if ip is None or str(ip) != m["value"] or m["trust_profile"] not in TRUST_PROFILES:
            raise ValueError("management address")
        parse_iso(m["last_seen"])
    return State(records, dict(hashes), [dict(m) for m in mgmt])


def parse(raw: bytes) -> State:
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise StateCorrupt(f"bans.json is not valid JSON ({e})", raw) from None
    try:
        state = _from_doc(migrate(doc))
    except (KeyError, TypeError, ValueError) as e:
        raise StateCorrupt(f"bans.json has an invalid schema ({e})", raw) from None
    state.raw, state.raw_hash = raw, fsio.sha256_tag(raw)
    return state


def load(path=None) -> State:
    path = path or STATE_PATH
    try:
        with open(path, "rb") as f:
            raw = f.read(STATE_MAX_BYTES + 1)
    except FileNotFoundError:
        return State()
    except OSError as e:
        raise StateCorrupt(f"Cannot read bans.json ({e.strerror or e})", None) from None
    if len(raw) > STATE_MAX_BYTES:
        raise StateCorrupt("bans.json is larger than 32 MiB", raw)
    return parse(raw)


def dumps(state: State) -> bytes:
    doc = {"version": SCHEMA_VERSION,
           "records": [asdict(r) for r in state.records],
           "last_rendered_hashes": dict(sorted(state.last_rendered_hashes.items())),
           "management_addresses": state.management_addresses}
    return (json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def new_manual_record(net, duration, reason, actor, now) -> Record:
    delta = DURATIONS[duration]
    return Record(id=str(uuid.uuid4()), source="manual", source_id=None,
                  scope=addr.scope_of(net), value=addr.token(net), reason=reason,
                  scenario=None, origin=None, actor=actor, created_at=iso(now),
                  expires_at=None if delta is None else iso(now + delta))


def prune_expired(state: State, now, sources=None) -> list:
    removed = [r for r in state.records
               if r.expired(now) and (sources is None or r.source in sources)]
    state.records = [r for r in state.records if r not in removed]
    return removed


def prune_management(state: State, now) -> bool:
    keep = [m for m in state.management_addresses if parse_iso(m["last_seen"]) > now - MANAGEMENT_TTL]
    changed = len(keep) != len(state.management_addresses)
    state.management_addresses = keep
    return changed


def touch_management(state: State, ip, profile: str, now) -> bool:
    if ip is None:
        return False
    value = str(ip)
    entry = next((m for m in state.management_addresses if m["value"] == value), None)
    if entry is None:
        entry = {"value": value}
        state.management_addresses.append(entry)
    entry.update(trust_profile=profile, last_seen=iso(now))
    state.management_addresses.sort(key=lambda m: m["last_seen"], reverse=True)
    del state.management_addresses[MANAGEMENT_MAX:]
    return True


def management_networks(state: State) -> list:
    return [addr.canonical(m["value"]) for m in state.management_addresses]


def quarantine(raw, error) -> object:
    """A bounded copy of unusable state for diagnosis, at most one per content."""
    name = None
    if raw is not None:
        digest = fsio.sha256_tag(raw)[7:15]
        existing = sorted(n for n in os.listdir(BACKUP_DIR)
                          if n.startswith("bans.json.quarantine-") and n.endswith("-" + digest))
        name = existing[0] if existing else (
            f"bans.json.quarantine-{utc_now().strftime('%Y%m%dT%H%M%SZ')}-{digest}")
        if not existing:
            fsio.atomic_write(os.path.join(BACKUP_DIR, name), raw[:QUARANTINE_MAX_BYTES], 0o600)
    meta = {"detected_at": iso(utc_now()), "error": str(error)[:500], "quarantine": name,
            "size": None if raw is None else len(raw)}
    fsio.atomic_write(ERROR_PATH, json.dumps(meta, sort_keys=True).encode(), 0o600)
    return name


def read_error():
    try:
        with open(ERROR_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def clear_error() -> None:
    try:
        os.remove(ERROR_PATH)
    except FileNotFoundError:
        pass


def _snapshot_id(name: str) -> str:
    return hashlib.sha256(name.encode()).hexdigest()[:16]


def save_snapshot(raw) -> None:
    """Keep the last few committed bans.json versions as restore choices for a
    later corrupt file (spec 1.6 'restore a valid backup')."""
    if not raw:
        return
    os.makedirs(SNAPSHOT_DIR, mode=0o700, exist_ok=True)
    stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    name = f"bans-{stamp}-{fsio.sha256_tag(raw)[7:19]}.json.bak"
    fsio.atomic_write(os.path.join(SNAPSHOT_DIR, name), raw, 0o600)
    names = sorted(n for n in os.listdir(SNAPSHOT_DIR) if n.endswith(".json.bak"))
    for old in names[:-SNAPSHOT_KEEP]:
        os.remove(os.path.join(SNAPSHOT_DIR, old))


def list_snapshots() -> list:
    try:
        names = sorted((n for n in os.listdir(SNAPSHOT_DIR) if n.endswith(".json.bak")), reverse=True)
    except OSError:
        return []
    out = []
    for name in names:
        try:
            state = load(os.path.join(SNAPSHOT_DIR, name))
        except StateCorrupt:
            continue
        stamp = name.split("-")[1]
        out.append({"id": _snapshot_id(name),
                    "created_at": f"{stamp[0:4]}-{stamp[4:6]}-{stamp[6:8]}T{stamp[9:11]}:{stamp[11:13]}:{stamp[13:15]}Z",
                    "records": len(state.records)})
    return out


def snapshot_bytes(snapshot_id):
    try:
        names = os.listdir(SNAPSHOT_DIR)
    except OSError:
        return None
    for name in names:
        if name.endswith(".json.bak") and _snapshot_id(name) == snapshot_id:
            return fsio.read_bytes(os.path.join(SNAPSHOT_DIR, name))
    return None
```

Note: `quarantine` file names start with `bans.json.`, never `Caddyfile.`, so the editor's backup API (`_backup_path`) can never serve them.

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run --frozen python -m unittest tests.test_bans_store -v`
Expected: all tests PASS (the unreadable-file test is skipped only when run as root).

- [ ] **Step 6: Commit**

```bash
git add src/bans/fsio.py src/bans/store.py tests/_bans.py tests/test_bans_store.py
git commit -m "feat(bans): versioned bans.json store with quarantine and snapshots"
```

---

### Task 4: Policy renderer keyed by source

**Files:**
- Create: `src/bans/render.py`
- Test: `tests/test_bans_render.py`

**Interfaces:**
- Consumes: `store.Record`, `addr.token`, `config.BANS_DIR`.
- Produces: `PolicySource(name, filename, marker, matcher)` with `.glob`, `.path`, `.import_line`; `SOURCES: dict[str, PolicySource]` (Phase 1: `"manual"` only); `HEADER`; `CapacityError(count, limit)`; `effective_prefixes(records, now, source_name) -> list[Network]` (collapsed, IPv4 then IPv6); `render_policy(source, prefixes, exclusion_tokens, limit) -> bytes`.

- [ ] **Step 1: Write the failing tests**

`tests/test_bans_render.py`:

```python
"""Generated policy bytes (spec 1.3).

Run with:  uv run --frozen python -m unittest tests.test_bans_render -v
"""
import os
import unittest
from datetime import timedelta

import tests._env as env  # noqa: F401

from src.bans import addr, protected, render, store

NOW = store.parse_iso("2026-11-23T20:00:00Z")
MANUAL = render.SOURCES["manual"]
EXCL = protected.build().exclusion_tokens()


def rec(value, duration="permanent", reason="", source="manual"):
    r = store.new_manual_record(addr.canonical(value), duration, reason, "a@example.com", NOW)
    r.source = source
    return r


class RenderTest(unittest.TestCase):
    def test_source_paths_and_import_line(self):
        self.assertEqual(MANUAL.path, os.path.join(env.BANS_DIR, "bans-manual.caddy"))
        self.assertEqual(MANUAL.glob, "bans-manual*.caddy")
        self.assertEqual(MANUAL.import_line, f"import {env.BANS_DIR}/bans-manual*.caddy")

    def test_spec_shape_with_bans(self):
        prefixes = render.effective_prefixes([rec("203.0.113.7"), rec("198.51.100.0/24")], NOW, "manual")
        self.assertEqual(render.render_policy(MANUAL, prefixes, EXCL, 100).decode(), (
            "# Managed by Caddy Console. Do not edit; changes are overwritten.\n"
            "vars caddy_console_manual_policy 1\n"
            "@caddy_console_manual_banned {\n"
            "\tclient_ip 198.51.100.0/24 203.0.113.7\n"
            "\tnot client_ip private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10\n"
            "}\n"
            "handle @caddy_console_manual_banned {\n"
            "\trespond 403\n"
            "}\n"))

    def test_empty_policy_keeps_only_the_marker(self):
        self.assertEqual(render.render_policy(MANUAL, [], EXCL, 100),
                         b"# Managed by Caddy Console. Do not edit; changes are overwritten.\n"
                         b"vars caddy_console_manual_policy 1\n")

    def test_overlaps_collapse_for_rendering_only(self):
        records = [rec("203.0.113.0/25"), rec("203.0.113.128/25"), rec("203.0.113.7"), rec("2001:db8::1")]
        self.assertEqual([addr.token(p) for p in render.effective_prefixes(records, NOW, "manual")],
                         ["203.0.113.0/24", "2001:db8::1"])
        self.assertEqual(len(records), 4)

    def test_expired_and_other_source_records_are_not_rendered(self):
        records = [rec("203.0.113.7", "4h"), rec("198.51.100.7", source="crowdsec"), rec("192.0.2.1")]
        self.assertEqual([addr.token(p) for p in render.effective_prefixes(records, NOW + timedelta(hours=5), "manual")],
                         ["192.0.2.1"])

    def test_reason_never_reaches_the_file(self):
        prefixes = render.effective_prefixes([rec("203.0.113.7", reason="<script>}\nrespond 200")], NOW, "manual")
        data = render.render_policy(MANUAL, prefixes, EXCL, 100)
        self.assertNotIn(b"script", data)
        self.assertNotIn(b"respond 200", data)

    def test_capacity_is_a_hard_limit(self):
        prefixes = render.effective_prefixes([rec("203.0.113.1"), rec("203.0.113.3"), rec("203.0.113.5")], NOW, "manual")
        with self.assertRaises(render.CapacityError) as cm:
            render.render_policy(MANUAL, prefixes, EXCL, 2)
        self.assertEqual((cm.exception.count, cm.exception.limit), (3, 2))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --frozen python -m unittest tests.test_bans_render -v`
Expected: FAIL with `ImportError: cannot import name 'render'`.

- [ ] **Step 3: Implement `src/bans/render.py`**

```python
"""Render one source's effective bans into its own Caddy policy file (spec 1.3).

Each source owns a file, a vars marker and a matcher name, so sites can import
any combination and live detection can tell them apart after adaptation
(matcher names and comments do not survive it; the marker does)."""
import ipaddress
import os
from dataclasses import dataclass

from .. import config
from . import addr

HEADER = "# Managed by Caddy Console. Do not edit; changes are overwritten.\n"


@dataclass(frozen=True)
class PolicySource:
    name: str
    filename: str
    marker: str
    matcher: str

    @property
    def glob(self) -> str:
        return self.filename[: -len(".caddy")] + "*.caddy"

    @property
    def path(self) -> str:
        return os.path.join(config.BANS_DIR, self.filename)

    @property
    def import_line(self) -> str:
        return f"import {os.path.join(config.BANS_DIR, self.glob)}"


SOURCES = {
    "manual": PolicySource("manual", "bans-manual.caddy",
                           "caddy_console_manual_policy", "caddy_console_manual_banned"),
    # Phase 2 adds: "crowdsec": PolicySource("crowdsec", "bans-crowdsec.caddy",
    #   "caddy_console_crowdsec_policy", "caddy_console_crowdsec_banned")
}


class CapacityError(Exception):
    def __init__(self, count: int, limit: int):
        super().__init__(f"{count} prefixes exceed the limit of {limit}")
        self.count, self.limit = count, limit


def effective_prefixes(records, now, source_name: str) -> list:
    nets = [r.network for r in records if r.source == source_name and not r.expired(now)]
    return (list(ipaddress.collapse_addresses([n for n in nets if n.version == 4]))
            + list(ipaddress.collapse_addresses([n for n in nets if n.version == 6])))


def render_policy(source: PolicySource, prefixes, exclusion_tokens, limit: int) -> bytes:
    if len(prefixes) > limit:
        raise CapacityError(len(prefixes), limit)
    out = [HEADER, f"vars {source.marker} 1\n"]
    if prefixes:
        out += [
            f"@{source.matcher} {{\n",
            "\tclient_ip " + " ".join(addr.token(p) for p in prefixes) + "\n",
            "\tnot client_ip " + " ".join(exclusion_tokens) + "\n",
            "}\n",
            f"handle @{source.matcher} {{\n",
            "\trespond 403\n",
            "}\n",
        ]
    return "".join(out).encode("ascii")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run --frozen python -m unittest tests.test_bans_render -v`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/bans/render.py tests/test_bans_render.py
git commit -m "feat(bans): source-keyed policy renderer with capacity limit"
```

---
### Task 5: On-disk scan and live enforcement detection

**Files:**
- Create: `src/bans/scan.py`, `src/bans/detect.py`
- Test: `tests/test_bans_detect.py`

**Interfaces:**
- Consumes: `tests/fixtures/bans/adapted-layouts.json` (Task 1), `render.PolicySource` (`.marker`).
- Produces (`scan`): `MANAGEMENT_MARK = "caddy-console: management"`; `SiteBlock(addresses, hosts, start, end, management)`; `host_of(address)`; `site_blocks(text) -> list[SiteBlock]`; `glob_matches(pattern, path) -> bool` (Caddy/Go semantics: `*` never crosses `/`); `import_targets(text) -> list[(line, token)]`; `mentions_import(text, path) -> bool`; `block_import_state(text, block, path) -> {"present", "count", "line", "first_child", "layout"}`; `management_hosts(text, server_host=None) -> set[str]`; `bans_warnings(text, path, management=frozenset()) -> list[str]`.
- Produces (`detect`): `marker_present(config, marker) -> bool`; `classify(handler) -> ("benign" | "pre" | "unknown", name | None)`; `SiteStatus(label, hosts, server, status, pre_handlers, detail)`; `site_statuses(config, source, active) -> list[SiteStatus]` with `status` in `enforced | enforced_pre_handler | imported_empty | not_imported | unknown`.
- Phase 2 calls `site_statuses(config, SOURCES["crowdsec"], ...)` unchanged; Phase 3 adds a `http.handlers.crowdsec` check beside it.

Expectations below follow Caddy's documented directive order (`redir`, `rewrite`, `basic_auth`, `forward_auth`, `request_header`, `invoke` sort before `handle`; `handle_path` and `route` after it; same-directive `handle` routes keep file order unless both have a single path matcher). The fixture is real Caddy output. If a fixture contradicts an expectation in `EXPECTED`, **stop and report**: do not edit the expectation to match, because the spec's ordering guarantee would be wrong.

- [ ] **Step 1: Write the failing tests**

`tests/test_bans_detect.py`:

```python
"""Per-site enforcement from adapted JSON, and the on-disk Caddyfile scan.

Run with:  uv run --frozen python -m unittest tests.test_bans_detect -v
"""
import json
import os
import unittest

import tests._env  # noqa: F401

from src.bans import detect, render, scan

MANUAL = render.SOURCES["manual"]
with open(os.path.join(os.path.dirname(__file__), "fixtures", "bans", "adapted-layouts.json"), encoding="utf-8") as f:
    FIXTURES = json.load(f)

EXPECTED = {
    "simple_proxy": ("enforced", []),
    "handle_catchall": ("enforced", []),
    "handle_path_specific": ("enforced", []),
    "handle_before_import": ("unknown", ["respond"]),
    "handle_path": ("enforced", []),
    "route_strict": ("enforced", []),
    "redir_before": ("enforced_pre_handler", ["redir"]),
    "rewrite_before": ("enforced_pre_handler", ["rewrite"]),
    "basic_auth_before": ("enforced_pre_handler", ["basic_auth"]),
    "forward_auth_before": ("enforced_pre_handler", ["forward_auth"]),
    "request_header_before": ("enforced_pre_handler", ["request_header"]),
    "invoke_before": ("unknown", ["invoke"]),
    "custom_order_first": ("unknown", ["respond"]),
    "not_imported": ("not_imported", []),
}


class LiveDetectionTest(unittest.TestCase):
    def test_fixture_covers_every_layout(self):
        self.assertEqual(set(FIXTURES), set(EXPECTED) | {"empty_policy"})

    def test_each_layout_gets_the_expected_status(self):
        for name, (status, pre) in EXPECTED.items():
            with self.subTest(layout=name):
                sites = detect.site_statuses(FIXTURES[name], MANUAL, active=True)
                self.assertEqual([s.label for s in sites], ["a.example.com"])
                self.assertEqual((sites[0].status, sites[0].pre_handlers), (status, pre))

    def test_empty_policy_keeps_its_marker_without_a_matcher(self):
        config = FIXTURES["empty_policy"]
        self.assertTrue(detect.marker_present(config, MANUAL.marker))
        self.assertNotIn('"client_ip"', json.dumps(config))
        self.assertEqual(detect.site_statuses(config, MANUAL, active=False)[0].status, "imported_empty")
        # Bans exist but the live config has no matcher yet: not proven.
        self.assertEqual(detect.site_statuses(config, MANUAL, active=True)[0].status, "unknown")

    def test_marker_values_and_missing_config(self):
        for value in ("1", 1):
            self.assertTrue(detect.marker_present({"x": [{"handler": "vars", MANUAL.marker: value}]}, MANUAL.marker))
        self.assertFalse(detect.marker_present({"x": [{"handler": "vars", MANUAL.marker: "0"}]}, MANUAL.marker))
        self.assertFalse(detect.marker_present(None, MANUAL.marker))
        self.assertEqual(detect.site_statuses(None, MANUAL, active=True), [])

    def test_handler_classes(self):
        self.assertEqual(detect.classify({"handler": "headers", "response": {"set": {}}}), ("benign", None))
        self.assertEqual(detect.classify({"handler": "headers", "request": {"set": {}}}), ("pre", "request_header"))
        self.assertEqual(detect.classify({"handler": "static_response", "status_code": 308, "headers": {"Location": ["/x"]}}), ("pre", "redir"))
        self.assertEqual(detect.classify({"handler": "static_response", "status_code": 200}), ("unknown", "respond"))
        self.assertEqual(detect.classify({"handler": "reverse_proxy"}), ("unknown", "reverse_proxy"))
        self.assertEqual(detect.classify({"handler": "mystery"}), ("unknown", "mystery"))

    def test_hostless_site_is_labelled_by_listener(self):
        config = {"apps": {"http": {"servers": {"srv0": {"listen": [":8080"], "routes": [{"handle": []}]}}}}}
        self.assertEqual(detect.site_statuses(config, MANUAL, active=False)[0].label, ":8080")


P = "/etc/caddy/console/bans-manual.caddy"
CF = "\n".join([
    "{", "\tadmin 0.0.0.0:2019", "}", "",                                                   # 1-4
    "(snip) {", "\theader -Server", "}", "",                                                # 5-8
    "&(app) {", "\trespond \"named\"", "}", "",                                             # 9-12
    "a.example.com {", "\timport /etc/caddy/console/bans-manual*.caddy",
    "\treverse_proxy 127.0.0.1:9", "}", "",                                                 # 13-17
    "b.example.com {", "\tencode gzip", "\timport /etc/caddy/console/*.caddy", "}", "",     # 18-22
    "c.example.com {", "\troute {", "\t\timport /etc/caddy/console/bans-manual.caddy",
    "\t\trespond 200", "\t}", "}", "",                                                      # 23-29
    "console.example.com { # caddy-console: management", "\treverse_proxy caddy-console:9090", "}", "",  # 30-33
    "d.example.com {", "\timport access_log", "\timport /etc/caddy/console/bans-manual*.caddy",
    "\timport /etc/caddy/console/bans-manual*.caddy", "\trespond 200", "}",                 # 34-39
])


class ScanTest(unittest.TestCase):
    def test_site_blocks_skip_globals_snippets_and_named_routes(self):
        self.assertEqual([(b.hosts, b.start, b.end, b.management) for b in scan.site_blocks(CF)], [
            (["a.example.com"], 13, 16, False), (["b.example.com"], 18, 21, False),
            (["c.example.com"], 23, 28, False), (["console.example.com"], 30, 32, True),
            (["d.example.com"], 34, 39, False)])

    def test_glob_matching_follows_caddy(self):
        self.assertTrue(scan.glob_matches("/etc/caddy/console/bans-manual*.caddy", P))
        self.assertTrue(scan.glob_matches("/etc/caddy/console/*.caddy", P))
        self.assertTrue(scan.glob_matches("/etc/caddy/*/bans-manual.caddy", P))
        self.assertFalse(scan.glob_matches("/etc/caddy/*.caddy", P))
        self.assertFalse(scan.glob_matches("access_log", P))
        self.assertTrue(scan.glob_matches("console/bans-manual*.caddy", P))   # relative: cannot resolve, assume yes
        self.assertFalse(scan.glob_matches("/etc/caddy/console/bans-manual*.caddy", "/etc/caddy/console/.bans-manual.caddy.ab12cd34.tmp"))

    def test_mentions_import(self):
        self.assertTrue(scan.mentions_import(CF, P))
        self.assertFalse(scan.mentions_import("x.example.com {\n\timport access_log\n}\n", P))

    def test_block_import_state(self):
        blocks = {b.hosts[0]: b for b in scan.site_blocks(CF)}
        state = lambda h: scan.block_import_state(CF, blocks[h], P)
        self.assertEqual(state("a.example.com"), {"present": True, "count": 1, "line": 14, "first_child": True, "layout": "site"})
        self.assertEqual(state("b.example.com"), {"present": True, "count": 1, "line": 20, "first_child": False, "layout": None})
        self.assertEqual(state("c.example.com"), {"present": True, "count": 1, "line": 25, "first_child": True, "layout": "strict"})
        self.assertEqual(state("console.example.com")["present"], False)
        self.assertEqual(state("d.example.com"), {"present": True, "count": 2, "line": 36, "first_child": False, "layout": None})

    def test_management_hosts(self):
        self.assertEqual(scan.management_hosts(CF), {"console.example.com"})
        self.assertEqual(scan.management_hosts(CF, "Admin.Example.com"), {"console.example.com", "admin.example.com"})

    def test_validator_warnings(self):
        warnings = scan.bans_warnings(CF, P, {"console.example.com"})
        self.assertEqual(warnings, [
            "Line 20: put the ban import first in the site block (or first inside its top-level route) so nothing runs before the ban check.",
            "Line 36: this site imports the manual ban list 2 times; keep one import.",
            "Line 36: put the ban import first in the site block (or first inside its top-level route) so nothing runs before the ban check.",
        ])
        own = "console.example.com {\n\timport /etc/caddy/console/bans-manual*.caddy\n}\n"
        self.assertIn("console's own site", scan.bans_warnings(own, P, {"console.example.com"})[0])
        custom = "x.example.com {\n\t@caddy_console_mine path /a\n\trespond @caddy_console_mine 404\n}\n"
        self.assertIn("reserved for Caddy Console", scan.bans_warnings(custom, P)[0])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --frozen python -m unittest tests.test_bans_detect -v`
Expected: FAIL with `ImportError: cannot import name 'detect'`.

- [ ] **Step 3: Implement `src/bans/scan.py`**

```python
"""On-disk Caddyfile facts the live config cannot give: which block a site is
in, whether it imports a managed policy first, and which site is the console's
own. A brace counter, not a parser, mirroring static/js/app/caddyfile-sites.js.
"""
import os
import re
from dataclasses import dataclass

MANAGEMENT_MARK = "caddy-console: management"
_COMMENT = re.compile(r"(^|\s)#.*$")
_PLACEHOLDER = re.compile(r"\{[^{}\s]*\}")
_IMPORT = re.compile(r"^import\s+(\S+)")
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://")
_USER_MATCHER = re.compile(r"^@caddy_console_\w*")
_ROUTE = re.compile(r"^route(\s|\{|$)")
FIRST_MSG = "put the ban import first in the site block (or first inside its top-level route) so nothing runs before the ban check."


@dataclass
class SiteBlock:
    addresses: list
    hosts: list
    start: int
    end: int
    management: bool = False


def host_of(address) -> str:
    a = _SCHEME.sub("", str(address).lower())
    return re.sub(r":\d+$", "", re.sub(r"/.*$", "", a))


def _strip(raw: str) -> str:
    return _COMMENT.sub("", raw).strip()


def site_blocks(text) -> list:
    blocks, depth, current = [], 0, None
    for i, raw in enumerate(str(text).split("\n"), 1):
        line = _strip(raw)
        if line and depth == 0 and line.endswith("{") and line != "{" and not line.startswith(("(", "&(")):
            addresses = [a for a in re.split(r"[\s,]+", line[:-1]) if a]
            current = SiteBlock(addresses, [h for h in map(host_of, addresses) if h], i, i)
            blocks.append(current)
        if current is not None and MANAGEMENT_MARK in raw:
            current.management = True
        if not line:
            continue
        bare = _PLACEHOLDER.sub("", line)
        depth = max(0, depth + bare.count("{") - bare.count("}"))
        if current is not None:
            current.end = i
        if depth == 0:
            current = None
    return blocks


def _glob_regex(glob: str):
    out, i = [], 0
    while i < len(glob):
        c = glob[i]
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[" and glob.find("]", i + 1) > i:
            end = glob.find("]", i + 1)
            out.append(glob[i:end + 1])
            i = end
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("".join(out) + r"\Z")


def glob_matches(pattern: str, path: str) -> bool:
    if pattern.startswith("/"):
        return bool(_glob_regex(pattern).match(path))
    if "/" not in pattern and "." not in pattern:
        return False            # a snippet or named-route name, not a file
    # Relative to Caddy's working directory, which the console cannot know.
    return bool(_glob_regex(os.path.basename(pattern)).match(os.path.basename(path)))


def import_targets(text) -> list:
    out = []
    for i, raw in enumerate(str(text).split("\n"), 1):
        m = _IMPORT.match(_strip(raw))
        if m:
            out.append((i, m.group(1)))
    return out


def mentions_import(text, path) -> bool:
    return any(glob_matches(token, path) for _, token in import_targets(text))


def _is_policy_import(line, path) -> bool:
    m = _IMPORT.match(line)
    return bool(m and glob_matches(m.group(1), path))


def block_import_state(text, block, path) -> dict:
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
    first = next(((ln, line) for ln, line, d in children if d == 1), None)
    if first and _is_policy_import(first[1], path):
        state.update(first_child=True, layout="site")
    elif first and _ROUTE.match(first[1]):
        inner = next((line for ln, line, d in children if d == 2 and ln > first[0]), None)
        if inner and _is_policy_import(inner, path):
            state.update(first_child=True, layout="strict")
    return state


def management_hosts(text, server_host=None) -> set:
    hosts = {h for b in site_blocks(text) if b.management for h in b.hosts}
    if server_host:
        hosts.add(server_host.lower())
    return hosts


def bans_warnings(text, path, management=frozenset()) -> list:
    out = []
    for i, raw in enumerate(str(text).split("\n"), 1):
        if _USER_MATCHER.match(_strip(raw)):
            out.append(f"Line {i}: matcher names starting with @caddy_console_ are reserved for "
                       "Caddy Console's generated policy; rename this matcher.")
    for block in site_blocks(text):
        st = block_import_state(text, block, path)
        if not st["present"]:
            continue
        if set(block.hosts) & set(management):
            out.append(f"Line {st['line']}: this is the console's own site; importing the ban list "
                       "here could lock you out of the console.")
        if st["count"] > 1:
            out.append(f"Line {st['line']}: this site imports the manual ban list {st['count']} times; keep one import.")
        if not st["first_child"]:
            out.append(f"Line {st['line']}: {FIRST_MSG}")
    return out
```

- [ ] **Step 4: Implement `src/bans/detect.py`**

```python
"""Is a source's policy enforced on each site of the live config? (spec "Mode
detection and health"). Source identity comes from the vars marker; effective
blocking from the client_ip matcher route with a 403 that follows it; anything
that can act on the request before that route is reported, never assumed away.
"""
from dataclasses import dataclass, field

BENIGN = {"vars", "map", "log_append", "encode", "push", "tracing", "request_body",
          "intercept", "templates", "copy_response_headers"}


@dataclass
class SiteStatus:
    label: str
    hosts: list
    server: str
    status: str
    pre_handlers: list = field(default_factory=list)
    detail: str = ""


def _is_marker(node, marker) -> bool:
    return isinstance(node, dict) and node.get("handler") == "vars" and str(node.get(marker, "")) == "1"


def marker_present(config, marker) -> bool:
    stack = [config]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if _is_marker(node, marker):
                return True
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return False


def _has_403(node) -> bool:
    if isinstance(node, dict):
        if node.get("handler") == "static_response" and str(node.get("status_code", "")) == "403":
            return True
        return any(_has_403(v) for v in node.values())
    if isinstance(node, list):
        return any(_has_403(v) for v in node)
    return False


def _is_ban_route(route) -> bool:
    matches = route.get("match") or []
    return any(isinstance(m, dict) and "client_ip" in m for m in matches) and _has_403(route.get("handle"))


def classify(h):
    name = h.get("handler")
    if name in BENIGN:
        return "benign", None
    if name == "headers":
        return ("pre", "request_header") if h.get("request") else ("benign", None)
    if name == "rewrite":
        return "pre", "rewrite"
    if name == "authentication":
        return "pre", "basic_auth"
    if name == "reverse_proxy" and h.get("handle_response") and h.get("rewrite"):
        return "pre", "forward_auth"
    if name == "static_response":
        if str(h.get("status_code", "")).startswith("3") and (h.get("headers") or {}).get("Location"):
            return "pre", "redir"
        return "unknown", "respond"
    return "unknown", name or "unnamed handler"


def _events(route, out) -> None:
    """Routes and handlers in execution order, descending into subroutes."""
    out.append(("route", route))
    for h in route.get("handle") or []:
        if not isinstance(h, dict):
            continue
        if h.get("handler") == "subroute":
            for r in h.get("routes") or []:
                if isinstance(r, dict):
                    _events(r, out)
        else:
            out.append(("handler", h))


def _status(route, source, active, label, hosts, server) -> SiteStatus:
    events = []
    _events(route, events)
    s = SiteStatus(label, hosts, server, "not_imported")
    marker_at = next((i for i, (k, v) in enumerate(events) if k == "handler" and _is_marker(v, source.marker)), None)
    if marker_at is None:
        return s
    ban_at = next((i for i, (k, v) in enumerate(events) if i > marker_at and k == "route" and _is_ban_route(v)), None)
    if ban_at is None:
        if active:
            s.status = "unknown"
            s.detail = ("The ban list is imported, but the running configuration has no ban matcher yet. "
                        "Check the reload state.")
        else:
            s.status = "imported_empty"
        return s
    pre, unknown = [], []
    for kind, h in events[:ban_at]:
        if kind != "handler" or _is_marker(h, source.marker):
            continue
        verdict, name = classify(h)
        bucket = pre if verdict == "pre" else unknown if verdict == "unknown" else None
        if bucket is not None and name not in bucket:
            bucket.append(name)
    if unknown:
        s.status, s.pre_handlers = "unknown", pre + unknown
        s.detail = ("Handlers run before the ban check that could answer the request first: "
                    + ", ".join(unknown) + ".")
    elif pre:
        s.status, s.pre_handlers = "enforced_pre_handler", pre
    else:
        s.status = "enforced"
    return s


def site_statuses(config, source, active: bool) -> list:
    servers = (((config or {}).get("apps") or {}).get("http") or {}).get("servers") or {}
    out = []
    for name, srv in sorted(servers.items()):
        if not isinstance(srv, dict):
            continue
        listen = (srv.get("listen") or [""])[0]
        for route in srv.get("routes") or []:
            if not isinstance(route, dict):
                continue
            hosts = [h for m in route.get("match") or [] if isinstance(m, dict) for h in (m.get("host") or [])]
            out.append(_status(route, source, active, hosts[0] if hosts else (listen or name), hosts, name))
    return out
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run --frozen python -m unittest tests.test_bans_detect -v`
Expected: all tests PASS. A failing `test_each_layout_gets_the_expected_status` subtest means the real Caddy order differs from the spec's assumption: stop and report the layout name and the printed status.

- [ ] **Step 6: Commit**

```bash
git add src/bans/scan.py src/bans/detect.py tests/test_bans_detect.py
git commit -m "feat(bans): detect per-site enforcement from live JSON and the on-disk Caddyfile"
```

---

### Task 6: Caddy admin client and the fake admin API

**Files:**
- Modify: `src/validator.py:112-141` (`_adapt_via_admin_api`, `_admin_error`)
- Create: `src/bans/caddy.py`
- Modify: `tests/_bans.py` (add `FakeResponse`, `FakeCaddy`, `SimulatedCrash`, `crash_at`, `manual_changes`, `apply`)
- Test: `tests/test_bans_caddy.py`

**Interfaces:**
- Produces (`validator`): `adapt_caddyfile(content) -> requests.Response | None`; `admin_error(resp) -> str` (public name for `_admin_error`; keep the old name as an alias).
- Produces (`caddy`): `CaddyUnavailable`; `AdaptResult(ok, config, message)`; `LoadResult(status, message)` with `status` in `applied | rejected | failed | unknown`; `normalize(config) -> bytes`; `config_hash(config) -> "sha256:..."`; `live_config()` (raises `CaddyUnavailable`); `adapt(text)` (raises `CaddyUnavailable` on transport failure); `load(text)`.
- Produces (`tests/_bans.py`): `fresh_audit(test)`; `FakeCaddy` knobs `down`, `adapt_status`, `load_mode` (`ok | reject | connect_timeout | read_timeout`), `live_after_load`, `hide_imports`, `live`, `calls` (list of `(kind, body)`), `.install(test)`, `.adapt_text(text)`; `SimulatedCrash(BaseException)`; `crash_at(point)` context manager; `manual_changes(*values)` -> two `txn.Change`; `apply(changes) -> Outcome` under `caddyfile_lock()`.

`txn` does not exist yet, so `manual_changes` and `apply` import it lazily inside the function.

- [ ] **Step 1: Write the failing tests**

`tests/test_bans_caddy.py`:

```python
"""Admin API calls with explicit outcomes, against the fake admin API.

Run with:  uv run --frozen python -m unittest tests.test_bans_caddy -v
"""
import unittest

import tests._env  # noqa: F401
from tests import _bans

from src.bans import caddy, detect


class NormalizeTest(unittest.TestCase):
    def test_hash_ignores_key_order_only(self):
        self.assertEqual(caddy.config_hash({"a": 1, "b": [1, 2]}), caddy.config_hash({"b": [1, 2], "a": 1}))
        self.assertNotEqual(caddy.config_hash({"b": [2, 1]}), caddy.config_hash({"b": [1, 2]}))
        self.assertTrue(caddy.config_hash(None).startswith("sha256:"))


class AdminClientTest(unittest.TestCase):
    def setUp(self):
        _bans.reset()
        self.fake = _bans.FakeCaddy({"apps": {"x": 1}}).install(self)

    def test_live_config(self):
        self.assertEqual(caddy.live_config(), {"apps": {"x": 1}})
        self.fake.down = True
        with self.assertRaises(caddy.CaddyUnavailable):
            caddy.live_config()

    def test_adapt_outcomes(self):
        result = caddy.adapt("example.com {\n\trespond 200\n}\n")
        self.assertTrue(result.ok)
        self.assertIn("apps", result.config)
        self.fake.adapt_status = 400
        result = caddy.adapt("x")
        self.assertEqual((result.ok, result.message), (False, "fake adapt rejection"))
        self.fake.down = True
        with self.assertRaises(caddy.CaddyUnavailable):
            caddy.adapt("x")

    def test_load_outcomes(self):
        for mode, status in (("ok", "applied"), ("reject", "rejected"),
                             ("connect_timeout", "failed"), ("read_timeout", "unknown")):
            with self.subTest(mode=mode):
                self.fake.load_mode = mode
                self.assertEqual(caddy.load("example.com {\n}\n").status, status)

    def test_fake_adapt_reflects_imported_files(self):
        with open(_bans.MANUAL_PATH(), "w") as f:
            f.write("vars caddy_console_manual_policy 1\n")
        with open(_bans.env.CADDYFILE) as f:
            text = f.read()
        self.assertTrue(detect.marker_present(self.fake.adapt_text(text), "caddy_console_manual_policy"))
        self.assertNotEqual(caddy.config_hash(self.fake.adapt_text(text)),
                            caddy.config_hash(self.fake.adapt_text(text + "\n")))


if __name__ == "__main__":
    unittest.main()
```


- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --frozen python -m unittest tests.test_bans_caddy -v`
Expected: FAIL with `ImportError: cannot import name 'caddy' from 'src.bans'`.

- [ ] **Step 3: Refactor `src/validator.py` to share the adapt call**

Replace `_adapt_via_admin_api` and `_admin_error` with:

```python
def adapt_caddyfile(content: str):
    """POST /adapt to the running Caddy. The response, or None when unreachable.

    Shared by Check (below) and the ban transaction (src/bans/caddy.py), so both
    ask the exact running build the same way.
    """
    try:
        return http_client.post(
            f"{CADDY_API_URL}/adapt",
            data=content.encode(),
            headers={"Content-Type": "text/caddyfile"},
            timeout=CADDY_TIMEOUT,
        )
    except Exception:
        return None


def _adapt_via_admin_api(content: str):
    """Adapt with the running Caddy without loading the result.

    This verifies Caddyfile syntax and module availability against the exact
    running build. It is not a runtime validation; POST /load performs that
    transactional check when the user saves.

    Returns (accepted, message, "adapted"), or None if the API was unreachable.
    """
    resp = adapt_caddyfile(content)
    if resp is None:
        return None
    if resp.status_code == 200:
        return (True, "Caddyfile syntax and modules were accepted by the running Caddy", "adapted")
    return (False, admin_error(resp), "adapted")


def admin_error(resp) -> str:
    """The admin API reports errors as {"error": "..."}; show just the message."""
    try:
        message = resp.json().get("error")
    except Exception:
        message = None
    return (message or resp.text or "").strip() or f"caddy rejected the config (HTTP {resp.status_code})"


_admin_error = admin_error
```

- [ ] **Step 4: Implement `src/bans/caddy.py`**

```python
"""The three admin-API calls the ban transaction needs, with explicit outcomes."""
import hashlib
import json
from dataclasses import dataclass

import requests as http_client

from .. import validator
from ..config import CADDY_API_URL

CONFIG_TIMEOUT = 5
LOAD_TIMEOUT = 10          # the editor's save path uses the same bound


class CaddyUnavailable(Exception):
    pass


@dataclass(frozen=True)
class AdaptResult:
    ok: bool
    config: object
    message: str


@dataclass(frozen=True)
class LoadResult:
    status: str            # applied | rejected | failed | unknown
    message: str


def normalize(config) -> bytes:
    return json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def config_hash(config) -> str:
    return "sha256:" + hashlib.sha256(normalize(config)).hexdigest()


def live_config():
    try:
        resp = http_client.get(f"{CADDY_API_URL}/config/", timeout=CONFIG_TIMEOUT)
    except http_client.RequestException as e:
        raise CaddyUnavailable(type(e).__name__) from e
    if resp.status_code != 200:
        raise CaddyUnavailable(f"GET /config/ returned HTTP {resp.status_code}")
    try:
        return resp.json()
    except ValueError as e:
        raise CaddyUnavailable("GET /config/ returned invalid JSON") from e


def adapt(text: str) -> AdaptResult:
    resp = validator.adapt_caddyfile(text)
    if resp is None:
        raise CaddyUnavailable("POST /adapt failed")
    if resp.status_code != 200:
        return AdaptResult(False, None, validator.admin_error(resp))
    try:
        body = resp.json()
    except ValueError:
        return AdaptResult(False, None, "Caddy returned an invalid /adapt response")
    if not isinstance(body, dict) or "result" not in body:
        return AdaptResult(False, None, "Caddy's /adapt response has no result")
    return AdaptResult(True, body["result"], "adapted")


def load(text: str) -> LoadResult:
    """POST the unchanged on-disk Caddyfile. Only a connect timeout proves the
    request never reached Caddy; any other transport error is ambiguous."""
    try:
        resp = http_client.post(f"{CADDY_API_URL}/load", data=text.encode("utf-8"),
                                headers={"Content-Type": "text/caddyfile"}, timeout=LOAD_TIMEOUT)
    except http_client.ConnectTimeout:
        return LoadResult("failed", "A connection to Caddy could not be established.")
    except http_client.RequestException as e:
        return LoadResult("unknown", f"Caddy did not confirm the reload ({type(e).__name__}).")
    if 200 <= resp.status_code < 300:
        return LoadResult("applied", "")
    return LoadResult("rejected", validator.admin_error(resp)[:2000])
```

- [ ] **Step 5: Add the fake admin API to `tests/_bans.py`**

Append:

```python
import contextlib
import glob
import json
import re
from unittest import mock

import requests


def MANUAL_PATH():
    return os.path.join(env.BANS_DIR, "bans-manual.caddy")


def fresh_audit(test):
    """tests/_env.py caps the audit log at 400 bytes to exercise rotation; ban
    tests count entries, so start empty and lift the cap for this test."""
    from src import audit
    for path in (env.AUDIT_LOG, env.AUDIT_LOG + ".1"):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
    patcher = mock.patch.object(audit, "AUDIT_LOG_MAX_BYTES", 10 ** 9)
    patcher.start()
    test.addCleanup(patcher.stop)


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or ("" if payload is None else json.dumps(payload))

    def json(self):
        if self._payload is None:
            raise ValueError("no JSON body")
        return self._payload


_IMPORT_RE = re.compile(r"(?m)^\s*import\s+(/\S+)")
_MARKER_RE = re.compile(r"(?m)^vars (caddy_console_\w+) (\S+)$")


class FakeCaddy:
    """Stands in for Caddy's admin API by patching requests.get/post.

    /adapt resolves absolute import globs from disk, so the adapted config (and
    its hash) changes exactly when an imported file or the Caddyfile changes,
    and a managed file's vars marker shows up as a real vars handler.
    """

    def __init__(self, live=None):
        self.live = {"apps": {}} if live is None else live
        self.down = False
        self.adapt_status = 200
        self.load_mode = "ok"
        self.live_after_load = None
        self.hide_imports = False
        self.calls = []

    def adapt_text(self, text):
        routes = []
        if not self.hide_imports:
            for pattern in _IMPORT_RE.findall(text):
                for path in sorted(glob.glob(pattern)):
                    with open(path, encoding="utf-8") as f:
                        body = f.read()
                    handlers = [{"handler": "vars", m.group(1): m.group(2)} for m in _MARKER_RE.finditer(body)]
                    handlers.append({"handler": "fake_import", "path": path, "body": body})
                    routes.append({"handle": handlers})
        routes.append({"handle": [{"handler": "fake_caddyfile", "body": text}]})
        return {"apps": {"http": {"servers": {"srv0": {"listen": [":80"], "routes": [
            {"match": [{"host": ["example.com"]}],
             "handle": [{"handler": "subroute", "routes": routes}], "terminal": True}]}}}}}

    def _post(self, url, data=None, headers=None, timeout=None, **kw):
        if self.down:
            raise requests.ConnectionError("fake caddy is down")
        text = data.decode("utf-8") if isinstance(data, bytes) else (data or "")
        if url.endswith("/adapt"):
            self.calls.append(("adapt", text))
            if self.adapt_status != 200:
                return FakeResponse(self.adapt_status, {"error": "fake adapt rejection"})
            return FakeResponse(200, {"result": self.adapt_text(text)})
        if url.endswith("/load"):
            self.calls.append(("load", text))
            if self.load_mode == "connect_timeout":
                raise requests.ConnectTimeout("fake connect timeout")
            if self.load_mode == "reject":
                return FakeResponse(400, {"error": "fake load rejection"})
            self.live = self.live_after_load if self.live_after_load is not None else self.adapt_text(text)
            if self.load_mode == "read_timeout":
                raise requests.ReadTimeout("fake read timeout after the config was applied")
            return FakeResponse(200, None, "")
        raise AssertionError(f"unexpected POST {url}")

    def _get(self, url, timeout=None, **kw):
        if self.down:
            raise requests.ConnectionError("fake caddy is down")
        if url.endswith("/config/"):
            self.calls.append(("config", None))
            return FakeResponse(200, self.live)
        if url.endswith("/config/apps/http/servers"):
            return FakeResponse(200, ((self.live or {}).get("apps", {}).get("http") or {}).get("servers", {}))
        raise AssertionError(f"unexpected GET {url}")

    def install(self, test):
        for name, fn in (("post", self._post), ("get", self._get)):
            patcher = mock.patch.object(requests, name, fn)
            patcher.start()
            test.addCleanup(patcher.stop)
        return self


class SimulatedCrash(BaseException):
    """Raised from txn._checkpoint; BaseException so no `except OSError` swallows it."""


@contextlib.contextmanager
def crash_at(point):
    from src.bans import txn

    def boom(name):
        if name == point:
            raise SimulatedCrash(name)
    with mock.patch.object(txn, "_checkpoint", boom):
        yield


def manual_changes(*values):
    from src.bans import addr, fsio, render, store, txn
    src = render.SOURCES["manual"]
    nets = [addr.canonical(v) for v in values]
    policy = render.render_policy(src, nets, ["private_ranges"], 100000)
    state = store.State(last_rendered_hashes={src.filename: fsio.sha256_tag(policy)})
    for n in nets:
        state.records.append(store.new_manual_record(n, "permanent", "", "t@example.com", store.utc_now()))
    return [txn.Change(src.path, "policy", policy, marker=src.marker),
            txn.Change(store.STATE_PATH, "state", store.dumps(state), owns=(src.filename,))]


def apply(changes):
    from src.bans import txn
    from src.routes.editor import caddyfile_lock
    with caddyfile_lock():
        return txn.apply_locked(changes, actor="t@example.com", source="manual")
```

Move the new `import` lines to the top of `tests/_bans.py` with the existing ones.

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run --frozen python -m unittest tests.test_bans_caddy tests.test_validator -v`
Expected: all PASS (the existing validator tests prove the refactor kept `caddy_check` behaviour).

- [ ] **Step 7: Commit**

```bash
git add src/validator.py src/bans/caddy.py tests/_bans.py tests/test_bans_caddy.py
git commit -m "feat(bans): admin API client with explicit adapt/load outcomes and a fake Caddy"
```

---

### Task 7: The journaled apply transaction

**Files:**
- Create: `src/bans/txn.py`
- Test: `tests/test_bans_txn.py`

**Interfaces:**
- Consumes: `fsio.*`, `store.iso`, `store.utc_now`, `caddy.live_config/adapt/load/config_hash`, `detect.marker_present`, `scan.mentions_import`, `caddy_api.invalidate_servers_cache`, `audit.log_action`.
- Produces: `JOURNAL_PATH`, `TXN_ROOT`, `STATE_MODE = 0o600`, `POLICY_MODE = 0o644`; `Change(path, kind, data, marker=None, owns=())`; `Outcome(ok, code, reload_status, enforcement, message, http_status=200)`; `JournalCorrupt`; `read_journal() -> dict | None`; `apply_locked(changes, *, actor, source) -> Outcome`; internal `_checkpoint(name)` seam with names `temps_written`, `backups_written`, `journal_prepared`, `replaced:<basename>`, `adapted`, `loaded`; `_restore_files(journal)`, `_finish_candidate(journal)`, `_commit(journal) -> bool`, `_cleanup(journal)` (used by Task 8).
- Outcome codes and HTTP statuses: `caddy_unreachable` 503, `write_failed` 500, `adaptation_failed` 422, `reload_rejected` 502, `reload_failed` 503, `reload_unknown` 504, `rollback_failed` 500.
- Journal document: `{version, id, phase, actor, source, created_at, entries: [{path, kind, mode, previous_hash, candidate_hash, temp_path, backup_path, candidate_path}], replaced_paths, previous_live_hash, candidate_live_hash, reload_required}`; `phase` in `preparing | prepared | adapted | reload_failed | reload_unknown | rollback_failed | committed`.

Caller contract (enforced): hold `caddyfile_lock()`, and call `resolve_pending()` (Task 8) first; `apply_locked` raises `RuntimeError` if a journal still exists.

- [ ] **Step 1: Write the failing tests**

`tests/test_bans_txn.py`:

```python
"""Spec 1.5 steps 5-15 against the fake admin API.

Run with:  uv run --frozen python -m unittest tests.test_bans_txn -v
"""
import glob
import json
import os
import stat
import unittest
from unittest import mock

import tests._env as env
from tests import _bans

from src import audit
from src.bans import fsio, render, scan, store, txn

MANUAL = render.SOURCES["manual"]
mode = lambda p: stat.S_IMODE(os.stat(p).st_mode)
GLOBS = ("bans-manual*.caddy", "bans-crowdsec*.caddy", "geo*.caddy",
         "crowdsec-plugin-protect*.caddy", "cloudflare-trusted-proxies*.caddy", "*.caddy")


def actions():
    return [e["action"] for e in audit.iter_entries()]


class ApplyTest(unittest.TestCase):
    def setUp(self):
        _bans.reset()
        _bans.fresh_audit(self)
        self.caddy = _bans.FakeCaddy().install(self)

    def baseline(self):
        out = _bans.apply(_bans.manual_changes("203.0.113.7"))
        self.assertTrue(out.ok, out.message)
        self.caddy.calls.clear()
        return fsio.read_bytes(MANUAL.path), fsio.read_bytes(store.STATE_PATH)

    def assert_clean(self):
        self.assertFalse(os.path.exists(txn.JOURNAL_PATH))
        self.assertEqual(os.listdir(txn.TXN_ROOT) if os.path.isdir(txn.TXN_ROOT) else [], [])
        self.assertEqual([n for n in os.listdir(env.BANS_DIR) if n.endswith(".tmp")], [])

    def test_success_replaces_policy_then_state_and_cleans_up(self):
        changes = _bans.manual_changes("203.0.113.7")
        order, real = [], os.replace

        def spy(src, dst):
            order.append(os.path.basename(dst))
            real(src, dst)
        with mock.patch.object(os, "replace", spy):
            out = _bans.apply(changes)
        self.assertTrue(out.ok, out.message)
        self.assertEqual((out.reload_status, out.enforcement, out.code), ("applied", "enforced", None))
        self.assertEqual([n for n in order if n in ("bans-manual.caddy", "bans.json")], ["bans-manual.caddy", "bans.json"])
        self.assertEqual(fsio.read_bytes(MANUAL.path), changes[0].data)
        self.assertEqual(fsio.read_bytes(store.STATE_PATH), changes[1].data)
        self.assertEqual((mode(MANUAL.path), mode(store.STATE_PATH)), (0o644, 0o600))
        self.assert_clean()
        self.assertEqual([c[0] for c in self.caddy.calls], ["config", "adapt", "load", "config"])
        with open(env.CADDYFILE) as f:
            self.assertEqual(self.caddy.calls[2][1], f.read())
        self.assertIn("bans_policy_applied", actions())

    def test_not_imported_commits_without_adapt_or_load(self):
        _bans.reset("example.com {\n\trespond 200\n}\n")
        out = _bans.apply(_bans.manual_changes("203.0.113.7"))
        self.assertEqual((out.ok, out.reload_status, out.enforcement), (True, "not_required", "not_enabled"))
        self.assertEqual([c[0] for c in self.caddy.calls], ["config"])
        self.assertTrue(os.path.exists(MANUAL.path))
        self.assert_clean()

    def test_live_marker_alone_requires_reload(self):
        _bans.reset("example.com {\n\trespond 200\n}\n")
        self.caddy.live = {"x": [{"handler": "vars", MANUAL.marker: "1"}]}
        out = _bans.apply(_bans.manual_changes("203.0.113.7"))
        self.assertEqual(out.reload_status, "applied")
        self.assertIn("load", [c[0] for c in self.caddy.calls])

    def test_unchanged_files_are_skipped(self):
        self.baseline()
        out = _bans.apply(_bans.manual_changes("203.0.113.7"))
        policy_unchanged = fsio.read_bytes(MANUAL.path) == _bans.manual_changes("203.0.113.7")[0].data
        self.assertTrue(policy_unchanged)
        self.assertTrue(out.ok)
        self.assertNotIn("load", [c[0] for c in self.caddy.calls])

    def test_adapt_rejection_restores_and_never_loads(self):
        before = self.baseline()
        self.caddy.adapt_status = 400
        out = _bans.apply(_bans.manual_changes("198.51.100.0/24"))
        self.assertEqual((out.ok, out.code, out.http_status), (False, "adaptation_failed", 422))
        self.assertEqual((fsio.read_bytes(MANUAL.path), fsio.read_bytes(store.STATE_PATH)), before)
        self.assertNotIn("load", [c[0] for c in self.caddy.calls])
        self.assert_clean()

    def test_first_change_rolls_back_to_absent_files(self):
        self.caddy.adapt_status = 400
        out = _bans.apply(_bans.manual_changes("203.0.113.7"))
        self.assertEqual(out.code, "adaptation_failed")
        self.assertFalse(os.path.exists(MANUAL.path))
        self.assertFalse(os.path.exists(store.STATE_PATH))
        self.assert_clean()

    def test_load_rejection_restores_previous_bytes(self):
        before = self.baseline()
        self.caddy.load_mode = "reject"
        out = _bans.apply(_bans.manual_changes("198.51.100.0/24"))
        self.assertEqual((out.code, out.reload_status, out.http_status), ("reload_rejected", "rejected", 502))
        self.assertEqual((fsio.read_bytes(MANUAL.path), fsio.read_bytes(store.STATE_PATH)), before)
        self.assertIn("bans_reload_rejected", actions())
        self.assert_clean()

    def test_connect_timeout_keeps_candidate_and_journal(self):
        self.baseline()
        changes = _bans.manual_changes("198.51.100.0/24")
        self.caddy.load_mode = "connect_timeout"
        out = _bans.apply(changes)
        self.assertEqual((out.code, out.reload_status, out.http_status), ("reload_failed", "failed", 503))
        self.assertEqual(fsio.read_bytes(MANUAL.path), changes[0].data)
        self.assertEqual(txn.read_journal()["phase"], "reload_failed")

    def test_read_timeout_keeps_candidate_and_reports_unknown(self):
        self.baseline()
        changes = _bans.manual_changes("198.51.100.0/24")
        self.caddy.load_mode = "read_timeout"
        out = _bans.apply(changes)
        self.assertEqual((out.code, out.reload_status, out.http_status), ("reload_unknown", "unknown", 504))
        self.assertEqual(fsio.read_bytes(store.STATE_PATH), changes[1].data)
        self.assertEqual(txn.read_journal()["phase"], "reload_unknown")
        self.assertIn("bans_reload_unknown", actions())

    def test_live_mismatch_after_a_200_is_unknown(self):
        self.baseline()
        self.caddy.live_after_load = {"someone": "else"}
        out = _bans.apply(_bans.manual_changes("198.51.100.0/24"))
        self.assertEqual(out.code, "reload_unknown")
        self.assertIsNotNone(txn.read_journal())

    def test_unreachable_caddy_changes_nothing(self):
        self.caddy.down = True
        out = _bans.apply(_bans.manual_changes("203.0.113.7"))
        self.assertEqual((out.code, out.http_status, out.reload_status), ("caddy_unreachable", 503, "not_attempted"))
        self.assertFalse(os.path.exists(MANUAL.path))
        self.assert_clean()

    def test_write_failure_restores_and_never_reloads(self):
        before = self.baseline()
        real = os.replace

        def failing(src, dst):
            if dst == store.STATE_PATH:
                raise OSError(28, "No space left on device")
            real(src, dst)
        with mock.patch.object(os, "replace", failing):
            out = _bans.apply(_bans.manual_changes("198.51.100.0/24"))
        self.assertEqual((out.code, out.http_status), ("write_failed", 500))
        self.assertEqual((fsio.read_bytes(MANUAL.path), fsio.read_bytes(store.STATE_PATH)), before)
        self.assertEqual([c[0] for c in self.caddy.calls], ["config"])
        self.assert_clean()

    def test_rollback_failure_keeps_the_journal(self):
        self.baseline()
        self.caddy.load_mode = "reject"
        real = fsio.atomic_write

        def failing(path, data, mode):
            if path == MANUAL.path:
                raise OSError(5, "I/O error")
            real(path, data, mode)
        with mock.patch.object(fsio, "atomic_write", failing):
            out = _bans.apply(_bans.manual_changes("198.51.100.0/24"))
        self.assertEqual((out.code, out.http_status), ("rollback_failed", 500))
        self.assertEqual(txn.read_journal()["phase"], "rollback_failed")
        self.assertIn("bans_rollback_failed", actions())

    def test_temp_files_are_hidden_and_never_match_a_managed_glob(self):
        with _bans.crash_at("temps_written"), self.assertRaises(_bans.SimulatedCrash):
            _bans.apply(_bans.manual_changes("203.0.113.7"))
        temps = [os.path.join(env.BANS_DIR, n) for n in os.listdir(env.BANS_DIR)]
        self.assertTrue(temps)
        for temp in temps:
            name = os.path.basename(temp)
            self.assertTrue(name.startswith(".") and name.endswith(".tmp"), name)
            for pattern in GLOBS:
                self.assertFalse(scan.glob_matches(os.path.join(env.BANS_DIR, pattern), temp), (pattern, name))

    def test_backups_exist_before_replace_and_stay_out_of_bans_dir(self):
        self.baseline()
        with _bans.crash_at("journal_prepared"), self.assertRaises(_bans.SimulatedCrash):
            _bans.apply(_bans.manual_changes("198.51.100.0/24"))
        journal = txn.read_journal()
        self.assertEqual(journal["phase"], "prepared")
        self.assertEqual(journal["replaced_paths"], [])
        for e in journal["entries"]:
            for key in ("backup_path", "candidate_path"):
                self.assertTrue(e[key].startswith(txn.TXN_ROOT + os.sep))
                self.assertTrue(e[key].endswith(".bak"))
                self.assertTrue(os.path.exists(e[key]))
            self.assertEqual(fsio.sha256_tag(fsio.read_bytes(e["backup_path"])), e["previous_hash"])
            self.assertEqual(set(e), {"path", "kind", "mode", "previous_hash", "candidate_hash",
                                      "temp_path", "backup_path", "candidate_path"})
        self.assertEqual(glob.glob(os.path.join(env.BANS_DIR, "*.bak")), [])
        self.assertEqual(set(journal) - {"entries"}, {"version", "id", "phase", "actor", "source", "created_at",
                                                     "replaced_paths", "previous_live_hash", "candidate_live_hash",
                                                     "reload_required"})

    def test_state_must_embed_the_candidate_policy_hash(self):
        policy, state = _bans.manual_changes("203.0.113.7")
        doc = json.loads(state.data)
        doc["last_rendered_hashes"][MANUAL.filename] = fsio.sha256_tag(b"other")
        bad = txn.Change(state.path, "state", json.dumps(doc).encode(), owns=state.owns)
        with self.assertRaises(ValueError):
            _bans.apply([policy, bad])
        with self.assertRaises(ValueError):
            _bans.apply([policy])                      # a policy no state owns
        self.assertFalse(os.path.exists(MANUAL.path))

    def test_requires_a_resolved_journal(self):
        fsio.atomic_write(txn.JOURNAL_PATH, b'{"version": 1, "entries": []}', 0o600)
        with self.assertRaises(RuntimeError):
            _bans.apply(_bans.manual_changes("203.0.113.7"))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --frozen python -m unittest tests.test_bans_txn -v`
Expected: FAIL with `ImportError: cannot import name 'txn'`.

- [ ] **Step 3: Implement `src/bans/txn.py`**

```python
"""One journaled transaction for console-managed state and policy files (spec 1.5).

Manual bans use it now; CrowdSec sync, country policy and Cloudflare ranges
(Phases 2-4) pass their own Change lists to the same functions. The caller
always holds caddyfile_lock() and has run resolve_pending(), so exactly one
transaction is ever in flight.

On disk, in order:
  1. hidden temp files beside each target (".<name>.<random>.tmp", never *.caddy)
  2. BACKUP_DIR/.policy-transactions/<id>/NN-<name>.prev.bak and .cand.bak
  3. BACKUP_DIR/bans-transaction.json, phase "prepared"
  4. os.replace() of every policy, then every state file; journal flushed after each
  5. adapt, /load, verify live == adapted; commit marks the journal, then deletes it
"""
import json
import os
import shutil
import uuid
from dataclasses import dataclass

from .. import audit
from ..caddy_api import invalidate_servers_cache
from ..config import BACKUP_DIR, CADDYFILE
from . import caddy as caddy_admin
from . import fsio
from .detect import marker_present
from .scan import mentions_import
from .store import iso, utc_now

JOURNAL_PATH = os.path.join(BACKUP_DIR, "bans-transaction.json")
TXN_ROOT = os.path.join(BACKUP_DIR, ".policy-transactions")
JOURNAL_VERSION = 1
STATE_MODE = 0o600
POLICY_MODE = 0o644
MAX_ENTRIES = 16


@dataclass(frozen=True)
class Change:
    """One file to replace. A state file names the policy files it owns; their
    candidate hashes must already be embedded in its last_rendered_hashes."""
    path: str
    kind: str                       # "state" | "policy"
    data: bytes
    marker: object = None           # policy: its live vars marker, for reload need
    owns: tuple = ()                # state: basenames of the policies it owns


@dataclass
class Outcome:
    ok: bool
    code: object
    reload_status: str              # applied | not_required | not_attempted | rejected | failed | unknown
    enforcement: str                # enforced | not_enabled | unchanged | unknown
    message: str
    http_status: int = 200


class JournalCorrupt(Exception):
    pass


def _checkpoint(name: str) -> None:
    """Crash-injection seam for tests. Does nothing in production."""


def read_journal():
    try:
        with open(JOURNAL_PATH, "rb") as f:
            raw = f.read(1024 * 1024)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise JournalCorrupt(f"Cannot read the transaction journal ({e.strerror or e})") from None
    try:
        doc = json.loads(raw.decode("utf-8"))
        if doc.get("version") != JOURNAL_VERSION or not isinstance(doc.get("entries"), list):
            raise ValueError("unknown journal format")
    except (ValueError, AttributeError, UnicodeDecodeError) as e:
        raise JournalCorrupt(f"The transaction journal is unreadable ({e})") from None
    return doc


def _write_journal(journal) -> None:
    fsio.atomic_write(JOURNAL_PATH, json.dumps(journal, sort_keys=True, indent=1).encode("utf-8"), STATE_MODE)


def _remove_quietly(path) -> None:
    if path:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass


def _check_embedded_hashes(changes) -> None:
    policies = {os.path.basename(c.path): c for c in changes if c.kind == "policy"}
    owned = set()
    for c in changes:
        if c.kind != "state":
            continue
        hashes = json.loads(c.data.decode("utf-8")).get("last_rendered_hashes", {})
        for name in c.owns:
            owned.add(name)
            if name in policies and hashes.get(name) != fsio.sha256_tag(policies[name].data):
                raise ValueError(f"{os.path.basename(c.path)} does not embed the candidate hash of {name}")
    if set(policies) - owned:
        raise ValueError(f"no state file in this transaction owns {sorted(set(policies) - owned)}")


def _restore_files(journal) -> None:
    """Put every entry back to its previous bytes (or absence). Idempotent."""
    for e in sorted(journal["entries"], key=lambda e: e["kind"] == "policy"):
        name = os.path.basename(e["path"])
        current = fsio.sha256_tag(fsio.read_bytes(e["path"]))
        if current == e["candidate_hash"]:
            if e["backup_path"] is None:
                os.remove(e["path"])
                fsio.fsync_dir(os.path.dirname(e["path"]))
            else:
                data = fsio.read_bytes(e["backup_path"])
                if fsio.sha256_tag(data) != e["previous_hash"]:
                    raise ValueError(f"the backup of {name} does not match its recorded hash")
                fsio.atomic_write(e["path"], data, e["mode"])
        elif current != e["previous_hash"]:
            raise ValueError(f"{name} changed outside this transaction")
        _remove_quietly(e["temp_path"])


def _finish_candidate(journal) -> None:
    """Put every entry at its candidate bytes (policies first). Idempotent."""
    for e in sorted(journal["entries"], key=lambda e: e["kind"] != "policy"):
        name = os.path.basename(e["path"])
        current = fsio.sha256_tag(fsio.read_bytes(e["path"]))
        if current != e["candidate_hash"]:
            if current != e["previous_hash"]:
                raise ValueError(f"{name} changed outside this transaction")
            data = fsio.read_bytes(e["candidate_path"])
            if fsio.sha256_tag(data) != e["candidate_hash"]:
                raise ValueError(f"the saved new version of {name} does not match its recorded hash")
            fsio.atomic_write(e["path"], data, e["mode"])
        _remove_quietly(e["temp_path"])


def _cleanup(journal) -> None:
    for e in journal.get("entries", []):
        _remove_quietly(e.get("temp_path"))
    shutil.rmtree(os.path.join(TXN_ROOT, journal.get("id", "")), ignore_errors=True)
    _remove_quietly(JOURNAL_PATH)
    fsio.fsync_dir(BACKUP_DIR)


def _commit(journal) -> bool:
    """Verify every final file is the candidate, mark committed, clean up."""
    if any(fsio.sha256_tag(fsio.read_bytes(e["path"])) != e["candidate_hash"] for e in journal["entries"]):
        return False
    journal["phase"] = "committed"
    _write_journal(journal)
    _cleanup(journal)
    return True


def _discard(journal) -> None:
    for e in journal["entries"]:
        _remove_quietly(e["temp_path"])
    shutil.rmtree(os.path.join(TXN_ROOT, journal["id"]), ignore_errors=True)
    current = None
    try:
        current = read_journal()
    except JournalCorrupt:
        pass
    if current and current.get("id") == journal["id"]:
        _remove_quietly(JOURNAL_PATH)


def _rollback(journal, code, message, http_status, reload_status) -> Outcome:
    try:
        _restore_files(journal)
        _cleanup(journal)
        return Outcome(False, code, reload_status, "unchanged",
                       message + " The previous files were restored.", http_status)
    except (OSError, ValueError) as e:
        journal["phase"] = "rollback_failed"
        try:
            _write_journal(journal)
        except OSError:
            pass
        audit.log_action("bans_rollback_failed", journal["actor"], f"{journal['source']}: {type(e).__name__}: {e}")
        return Outcome(False, "rollback_failed", reload_status, "unknown",
                       f"{message} Restoring the previous files also failed ({e}); open Security to recover.", 500)


def _hold_ambiguous(journal, status, message) -> Outcome:
    journal["phase"] = f"reload_{status}"
    try:
        _write_journal(journal)
    except OSError:
        pass
    audit.log_action(f"bans_reload_{status}", journal["actor"], journal["source"])
    return Outcome(False, "reload_failed" if status == "failed" else "reload_unknown", status, "unknown",
                   f"{message} The new files stay on disk and further changes wait until the running "
                   "configuration is verified.", 503 if status == "failed" else 504)


def apply_locked(changes, *, actor: str, source: str) -> Outcome:
    if read_journal() is not None:
        raise RuntimeError("apply_locked() needs resolve_pending() to clear the journal first")
    if len(changes) > MAX_ENTRIES:
        raise ValueError("too many files in one transaction")
    changes = [c for c in changes if fsio.read_bytes(c.path) != c.data]
    if not changes:
        return Outcome(True, None, "not_required", "unchanged", "Nothing to change.")
    _check_embedded_hashes(changes)

    try:
        live = caddy_admin.live_config()
    except caddy_admin.CaddyUnavailable as e:
        return Outcome(False, "caddy_unreachable", "not_attempted", "unknown",
                       f"The Caddy admin API is unreachable ({e}); nothing was changed.", 503)
    try:
        with open(CADDYFILE, encoding="utf-8", newline="") as f:
            caddyfile_text = f.read()
    except FileNotFoundError:
        caddyfile_text = ""
    except (OSError, UnicodeError) as e:
        return Outcome(False, "write_failed", "not_attempted", "unchanged", f"Cannot read the Caddyfile: {e}", 500)

    txid = uuid.uuid4().hex
    txdir = os.path.join(TXN_ROOT, txid)
    journal = {
        "version": JOURNAL_VERSION, "id": txid, "phase": "preparing", "actor": actor, "source": source,
        "created_at": iso(utc_now()), "entries": [], "replaced_paths": [],
        "previous_live_hash": caddy_admin.config_hash(live), "candidate_live_hash": None,
        "reload_required": any(marker_present(live, c.marker) or mentions_import(caddyfile_text, c.path)
                               for c in changes if c.kind == "policy"),
    }

    # Steps 6-8: temps, backups and candidate copies, then the journal.
    try:
        os.makedirs(txdir, mode=0o700)
        previous = []
        for i, c in enumerate(changes):
            prev = fsio.read_bytes(c.path)
            previous.append(prev)
            stem = os.path.join(txdir, f"{i:02d}-{os.path.basename(c.path)}")
            entry = {"path": c.path, "kind": c.kind,
                     "mode": POLICY_MODE if c.kind == "policy" else STATE_MODE,
                     "previous_hash": fsio.sha256_tag(prev), "candidate_hash": fsio.sha256_tag(c.data),
                     "temp_path": None, "backup_path": None if prev is None else stem + ".prev.bak",
                     "candidate_path": stem + ".cand.bak"}
            journal["entries"].append(entry)
            entry["temp_path"] = fsio.write_temp(os.path.dirname(c.path), os.path.basename(c.path),
                                                 c.data, entry["mode"])
        _checkpoint("temps_written")
        for c, prev, e in zip(changes, previous, journal["entries"]):
            if prev is not None:
                fsio.atomic_write(e["backup_path"], prev, STATE_MODE)
            fsio.atomic_write(e["candidate_path"], c.data, STATE_MODE)
        fsio.fsync_dir(txdir)
        _checkpoint("backups_written")
        journal["phase"] = "prepared"
        _write_journal(journal)
        _checkpoint("journal_prepared")
    except OSError as e:
        _discard(journal)
        return Outcome(False, "write_failed", "not_attempted", "unchanged", f"Could not prepare the change: {e}", 500)

    # Step 9: policies first, then state; the journal records each replace.
    try:
        for e in sorted(journal["entries"], key=lambda e: e["kind"] != "policy"):
            os.replace(e["temp_path"], e["path"])
            fsio.fsync_dir(os.path.dirname(e["path"]))
            journal["replaced_paths"].append(e["path"])
            _write_journal(journal)
            _checkpoint("replaced:" + os.path.basename(e["path"]))
    except OSError as e:
        return _rollback(journal, "write_failed", f"Could not replace the managed files: {e}.", 500, "not_attempted")

    # Step 10: nothing imports a changed policy, so Caddy has nothing to reload.
    if not journal["reload_required"]:
        if not _commit(journal):
            return _rollback(journal, "write_failed", "A managed file changed during the update.", 500, "not_attempted")
        return Outcome(True, None, "not_required", "not_enabled",
                       "Stored. No site imports this policy yet, so Caddy was not reloaded.")

    # Step 11: adapt the unchanged on-disk Caddyfile with the candidates present.
    try:
        adapted = caddy_admin.adapt(caddyfile_text)
    except caddy_admin.CaddyUnavailable as e:
        return _rollback(journal, "caddy_unreachable", f"Caddy could not adapt the configuration ({e}).", 503, "not_attempted")
    if not adapted.ok:
        audit.log_action("bans_adapt_rejected", actor, f"{source}: {adapted.message[:200]}")
        return _rollback(journal, "adaptation_failed",
                         f"Caddy rejected the generated policy: {adapted.message[:2000]}.", 422, "not_attempted")
    journal["candidate_live_hash"] = caddy_admin.config_hash(adapted.config)
    journal["phase"] = "adapted"
    try:
        _write_journal(journal)
    except OSError as e:
        return _rollback(journal, "write_failed", f"Could not update the journal: {e}.", 500, "not_attempted")
    _checkpoint("adapted")

    # Step 12-15: /load is the transactional runtime validation.
    result = caddy_admin.load(caddyfile_text)
    invalidate_servers_cache()
    _checkpoint("loaded")
    if result.status == "rejected":
        audit.log_action("bans_reload_rejected", actor, f"{source}: {result.message[:200]}")
        return _rollback(journal, "reload_rejected",
                         f"Caddy rejected the reload and keeps its running configuration: {result.message}", 502, "rejected")
    if result.status in ("failed", "unknown"):
        return _hold_ambiguous(journal, result.status, result.message)
    try:
        live_after = caddy_admin.config_hash(caddy_admin.live_config())
    except caddy_admin.CaddyUnavailable:
        live_after = None
    if live_after != journal["candidate_live_hash"]:
        return _hold_ambiguous(journal, "unknown",
                               "Caddy accepted the reload, but its running configuration does not match the generated policy.")
    if not _commit(journal):
        return _hold_ambiguous(journal, "unknown", "A managed file changed during the reload.")
    audit.log_action("bans_policy_applied", actor,
                     f"{source}: " + ", ".join(os.path.basename(e["path"]) for e in journal["entries"]))
    return Outcome(True, None, "applied", "enforced", "Applied; Caddy reloaded.")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run --frozen python -m unittest tests.test_bans_txn -v`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/bans/txn.py tests/test_bans_txn.py
git commit -m "feat(bans): journaled multi-entry transaction with adapt and transactional load"
```

---

### Task 8: Journal recovery, operator recovery actions and the editor reload hook

**Files:**
- Modify: `src/bans/txn.py` (append)
- Modify: `src/routes/editor.py` (imports; `_apply_config` success branch)
- Modify: `tests/_bans.py` (add `ApiCase`)
- Test: `tests/test_bans_recovery.py`

**Interfaces:**
- Consumes: everything Task 7 produced.
- Produces: `Pending(reason, message, journal=None)` with `reason` in `journal_corrupt | hash_mismatch | caddy_unreachable | live_mismatch | rollback_failed`; `resolve_pending() -> Pending | None` (caller holds the lock; sweeps orphans when no journal exists); `recovery_action(action, actor) -> Outcome` for `use_candidate | use_previous` (caller holds the lock; the caller audits); `reconcile_after_external_reload()` (caller holds the lock).
- Produces (`tests/_bans.py`): `ApiCase(unittest.TestCase)` with `.app` (created once), `.client`, `.csrf`, `.get(url, **kw)`, `.post(url, payload=None, **kw)`, `.put`, `.delete(url)`; patches `caddy_fmt`/`caddy_validate`/`caddy_check` like `tests/test_app.py`; installs `self.caddy = FakeCaddy()`.

- [ ] **Step 1: Write the failing tests**

Add `ApiCase` to `tests/_bans.py`:

```python
import unittest

AUTH = {"Cf-Access-Authenticated-User-Email": "admin@example.com"}


class ApiCase(unittest.TestCase):
    """Flask test client plus FakeCaddy. No test methods, so never collected itself."""
    app = None

    @classmethod
    def setUpClass(cls):
        from src import create_app
        if ApiCase.app is None:
            ApiCase.app = create_app()
            ApiCase.app.testing = True

    def setUp(self):
        from src.routes import editor as editor_mod
        reset()
        fresh_audit(self)
        self.caddy = FakeCaddy().install(self)
        for name, value in (("caddy_fmt", lambda c: c),
                            ("caddy_validate", lambda c: (True, "ok")),
                            ("caddy_check", lambda c: (True, "ok", "adapted"))):
            p = mock.patch.object(editor_mod, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.client = self.app.test_client()
        html = self.client.get("/", headers=AUTH).get_data(as_text=True)
        self.csrf = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)

    def _h(self, kw):
        return {**AUTH, "X-CSRF-Token": self.csrf, **kw.pop("headers", {})}

    def get(self, url, **kw):
        return self.client.get(url, headers={**AUTH, **kw.pop("headers", {})}, **kw)

    def post(self, url, payload=None, **kw):
        return self.client.post(url, json=payload, headers=self._h(kw), **kw)

    def put(self, url, payload=None, **kw):
        return self.client.put(url, json=payload, headers=self._h(kw), **kw)

    def delete(self, url, **kw):
        return self.client.delete(url, headers=self._h(kw), **kw)
```

`tests/test_bans_recovery.py`:

```python
"""Startup/lazy journal recovery (spec 1.5 'At startup'), operator actions and
the editor-reload hook.

Run with:  uv run --frozen python -m unittest tests.test_bans_recovery -v
"""
import json
import os
import unittest

import tests._env as env
from tests import _bans

from src import audit
from src.bans import caddy, fsio, render, store, txn
from src.routes.editor import caddyfile_lock

MANUAL = render.SOURCES["manual"]
BEFORE_LOAD = ("temps_written", "backups_written", "journal_prepared",
               "replaced:bans-manual.caddy", "replaced:bans.json", "adapted")


def files():
    return fsio.read_bytes(MANUAL.path), fsio.read_bytes(store.STATE_PATH)


def resolve():
    with caddyfile_lock():
        return txn.resolve_pending()


def act(action):
    with caddyfile_lock():
        return txn.recovery_action(action, "op@example.com")


class CrashRecoveryTest(unittest.TestCase):
    def setUp(self):
        _bans.reset()
        _bans.fresh_audit(self)
        self.caddy = _bans.FakeCaddy().install(self)
        self.assertTrue(_bans.apply(_bans.manual_changes("203.0.113.7")).ok)
        self.before = files()
        self.candidate = _bans.manual_changes("203.0.113.7", "198.51.100.0/24")

    def crash(self, point):
        with _bans.crash_at(point), self.assertRaises(_bans.SimulatedCrash):
            _bans.apply(self.candidate)

    def assert_clean(self):
        self.assertIsNone(txn.read_journal())
        self.assertEqual(os.listdir(txn.TXN_ROOT), [])
        self.assertEqual([n for n in os.listdir(env.BANS_DIR) if n.endswith(".tmp")], [])
        self.assertEqual([n for n in os.listdir(env.BACKUP_DIR) if n.startswith(".bans") and n.endswith(".tmp")], [])

    def test_a_crash_before_load_restores_previous_at_every_phase(self):
        for point in BEFORE_LOAD:
            with self.subTest(point=point):
                self.setUp()
                self.crash(point)
                self.assertIsNone(resolve())
                self.assertEqual(files(), self.before)
                self.assert_clean()

    def test_a_crash_after_caddy_applied_finishes_the_candidate(self):
        self.crash("loaded")
        self.assertIsNone(resolve())
        self.assertEqual(files(), (self.candidate[0].data, self.candidate[1].data))
        self.assert_clean()
        self.assertIn("bans_recovered", [e["action"] for e in audit.iter_entries()])

    def test_crash_between_policy_and_state_with_candidate_live(self):
        self.crash("replaced:bans-manual.caddy")
        with open(env.CADDYFILE) as f:
            self.caddy.live = self.caddy.adapt_text(f.read())      # as if Caddy had loaded it
        journal = txn.read_journal()
        journal["candidate_live_hash"] = caddy.config_hash(self.caddy.live)
        fsio.atomic_write(txn.JOURNAL_PATH, json.dumps(journal).encode(), 0o600)
        self.assertIsNone(resolve())
        self.assertEqual(fsio.read_bytes(store.STATE_PATH), self.candidate[1].data)

    def test_unmatched_live_config_waits_for_the_operator(self):
        for action, expected in (("use_candidate", (self.candidate[0].data, self.candidate[1].data)),
                                 ("use_previous", None)):
            with self.subTest(action=action):
                self.setUp()
                self.crash("adapted")
                self.caddy.live = {"edited": "elsewhere"}
                pending = resolve()
                self.assertEqual(pending.reason, "live_mismatch")
                self.assertNotIn("load", [c[0] for c in self.caddy.calls[-2:]])
                out = act(action)
                self.assertTrue(out.ok, out.message)
                self.assertEqual(files(), expected or self.before)
                self.assert_clean()

    def test_unreachable_caddy_is_degraded_until_it_answers(self):
        self.crash("adapted")
        self.caddy.down = True
        self.assertEqual(resolve().reason, "caddy_unreachable")
        self.assertIsNotNone(txn.read_journal())
        self.caddy.down = False
        self.assertIsNone(resolve())
        self.assertEqual(files(), self.before)

    def test_out_of_band_edit_blocks_recovery(self):
        self.crash("adapted")
        with open(MANUAL.path, "wb") as f:
            f.write(b"# hand edited\n")
        self.assertEqual(resolve().reason, "hash_mismatch")
        out = act("use_previous")
        self.assertEqual((out.ok, out.code, out.http_status), (False, "recovery_blocked", 409))

    def test_corrupt_journal_is_degraded(self):
        fsio.atomic_write(txn.JOURNAL_PATH, b"{junk", 0o600)
        self.assertEqual(resolve().reason, "journal_corrupt")

    def test_reload_unknown_resolves_when_live_matches_the_candidate(self):
        self.caddy.load_mode = "read_timeout"
        self.assertEqual(_bans.apply(self.candidate).code, "reload_unknown")
        self.caddy.load_mode = "ok"
        self.assertIsNone(resolve())
        self.assertEqual(files(), (self.candidate[0].data, self.candidate[1].data))

    def test_connect_timeout_resolves_to_previous(self):
        self.caddy.load_mode = "connect_timeout"
        self.assertEqual(_bans.apply(self.candidate).code, "reload_failed")
        self.assertIsNone(resolve())
        self.assertEqual(files(), self.before)

    def test_orphans_without_a_journal_are_swept(self):
        temp = fsio.write_temp(env.BANS_DIR, "bans-manual.caddy", b"partial", 0o644)
        os.makedirs(os.path.join(txn.TXN_ROOT, "deadbeef"))
        self.assertIsNone(resolve())
        self.assertFalse(os.path.exists(temp))
        self.assertEqual(os.listdir(txn.TXN_ROOT), [])

    def test_external_reload_settles_a_pending_journal(self):
        self.caddy.load_mode = "read_timeout"
        _bans.apply(self.candidate)
        with caddyfile_lock():
            txn.reconcile_after_external_reload()
        self.assertIsNone(txn.read_journal())
        self.assertEqual(files(), (self.candidate[0].data, self.candidate[1].data))


class EditorReloadTest(_bans.ApiCase):
    def test_editor_reload_commits_pending_candidate(self):
        self.assertTrue(_bans.apply(_bans.manual_changes("203.0.113.7")).ok)
        candidate = _bans.manual_changes("203.0.113.7", "198.51.100.0/24")
        self.caddy.load_mode = "read_timeout"
        _bans.apply(candidate)
        self.caddy.live = {"unknown": True}           # neither previous nor candidate
        self.caddy.load_mode = "ok"
        with open(env.CADDYFILE) as f:
            text = f.read() + "\nother.example.com {\n\trespond 200\n}\n"
        r = self.post("/api/save", {"content": text})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertIsNone(txn.read_journal())
        self.assertEqual(fsio.read_bytes(store.STATE_PATH), candidate[1].data)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --frozen python -m unittest tests.test_bans_recovery -v`
Expected: FAIL with `AttributeError: module 'src.bans.txn' has no attribute 'resolve_pending'`.

- [ ] **Step 3: Append recovery to `src/bans/txn.py`**

Add `import re` and `from .. import config` to the imports, then append:

```python
_ORPHAN_BANS_DIR = re.compile(r"^\..+\.caddy\.[A-Za-z0-9_]+\.tmp$")
_ORPHAN_BACKUP_DIR = re.compile(r"^\.(bans\.json|bans-transaction\.json)\.[A-Za-z0-9_]+\.tmp$")


@dataclass
class Pending:
    reason: str           # journal_corrupt | hash_mismatch | caddy_unreachable | live_mismatch | rollback_failed
    message: str
    journal: object = None


def _sweep_orphans() -> None:
    """With no journal, any hidden temp or transaction directory is debris from a
    crash before the journal was written. None of it can match an import glob."""
    for directory, pattern in ((config.BANS_DIR, _ORPHAN_BANS_DIR), (BACKUP_DIR, _ORPHAN_BACKUP_DIR)):
        try:
            names = os.listdir(directory)
        except OSError:
            continue
        for name in names:
            if pattern.match(name):
                _remove_quietly(os.path.join(directory, name))
    try:
        for name in os.listdir(TXN_ROOT):
            shutil.rmtree(os.path.join(TXN_ROOT, name), ignore_errors=True)
    except OSError:
        pass


def _verify_files(journal):
    for e in journal["entries"]:
        name = os.path.basename(e["path"])
        if fsio.sha256_tag(fsio.read_bytes(e["path"])) not in (e["previous_hash"], e["candidate_hash"]):
            return f"{name} changed outside the console while a transaction was pending."
        if e["backup_path"] and fsio.sha256_tag(fsio.read_bytes(e["backup_path"])) != e["previous_hash"]:
            return f"The backup of {name} is missing or damaged."
        if fsio.sha256_tag(fsio.read_bytes(e["candidate_path"])) != e["candidate_hash"]:
            return f"The saved new version of {name} is missing or damaged."
    return None


def resolve_pending():
    """Settle an unfinished journal from what Caddy is actually running.

    Runs before every mutation and on every expiry tick, so the first tick after
    a restart is the startup recovery. Never POSTs /load and never guesses:
    live == candidate finishes, live == previous restores, anything else waits
    for an operator action.
    """
    try:
        journal = read_journal()
    except JournalCorrupt as e:
        return Pending("journal_corrupt", f"{e}. Restore the managed files by hand; see docs/security.md.")
    if journal is None:
        _sweep_orphans()
        return None
    if journal.get("phase") == "committed":
        _cleanup(journal)
        return None
    problem = _verify_files(journal)
    if problem:
        return Pending("hash_mismatch", problem, journal)
    try:
        live_hash = caddy_admin.config_hash(caddy_admin.live_config())
    except caddy_admin.CaddyUnavailable as e:
        return Pending("caddy_unreachable",
                       f"A {journal['source']} change is pending and the Caddy admin API is unreachable ({e}). "
                       "It is settled automatically once Caddy answers.", journal)
    try:
        if journal.get("candidate_live_hash") and live_hash == journal["candidate_live_hash"]:
            _finish_candidate(journal)
            if not _commit(journal):
                return Pending("hash_mismatch", "A managed file changed while finishing the pending change.", journal)
            audit.log_action("bans_recovered", "system", f"{journal['source']}: Caddy runs the new policy; finished it")
            return None
        if live_hash == journal["previous_live_hash"]:
            _restore_files(journal)
            _cleanup(journal)
            audit.log_action("bans_recovered", "system", f"{journal['source']}: Caddy runs the previous policy; restored it")
            return None
    except (OSError, ValueError) as e:
        return Pending("rollback_failed", f"Settling the pending change failed: {e}", journal)
    return Pending("live_mismatch",
                   "Caddy's running configuration matches neither the previous nor the new policy. "
                   "Choose which files to keep; the console then reloads Caddy.", journal)


def recovery_action(action: str, actor: str) -> Outcome:
    """Operator choice for a pending journal: keep the candidate or the previous
    files, then adapt and /load the on-disk Caddyfile. The journal is removed
    only after Caddy confirms; the caller audits."""
    try:
        journal = read_journal()
    except JournalCorrupt as e:
        return Outcome(False, "recovery_blocked", "not_attempted", "unknown", str(e), 409)
    if journal is None:
        return Outcome(True, None, "not_required", "unchanged", "Nothing to recover.")
    problem = _verify_files(journal)
    if problem:
        return Outcome(False, "recovery_blocked", "not_attempted", "unknown",
                       problem + " Restore the files by hand; see docs/security.md.", 409)
    try:
        if action == "use_candidate":
            _finish_candidate(journal)
        elif action == "use_previous":
            _restore_files(journal)
        else:
            raise ValueError(f"unknown recovery action {action!r}")
        with open(CADDYFILE, encoding="utf-8", newline="") as f:
            text = f.read()
    except (OSError, ValueError) as e:
        return Outcome(False, "write_failed", "not_attempted", "unknown", f"Could not prepare the files: {e}", 500)
    try:
        adapted = caddy_admin.adapt(text)
    except caddy_admin.CaddyUnavailable as e:
        return Outcome(False, "caddy_unreachable", "not_attempted", "unknown", f"Caddy is unreachable ({e}).", 503)
    if not adapted.ok:
        return Outcome(False, "adaptation_failed", "not_attempted", "unknown",
                       f"Caddy rejected the configuration: {adapted.message[:2000]}", 422)
    expected = caddy_admin.config_hash(adapted.config)
    result = caddy_admin.load(text)
    invalidate_servers_cache()
    if result.status == "rejected":
        return Outcome(False, "reload_rejected", "rejected", "unknown", f"Caddy rejected the reload: {result.message}", 502)
    if result.status != "applied":
        return Outcome(False, f"reload_{result.status}", result.status, "unknown", result.message, 503)
    try:
        live = caddy_admin.config_hash(caddy_admin.live_config())
    except caddy_admin.CaddyUnavailable:
        live = None
    if live != expected:
        return Outcome(False, "reload_unknown", "unknown", "unknown",
                       "Caddy accepted the reload, but its running configuration does not match.", 504)
    if action == "use_candidate":
        _commit(journal)
    else:
        _cleanup(journal)
    return Outcome(True, None, "applied", "enforced" if action == "use_candidate" else "unchanged",
                   "Recovered; Caddy reloaded.")


def reconcile_after_external_reload() -> None:
    """The editor just loaded the on-disk Caddyfile successfully, which also
    loaded whatever managed policy is on disk. Settle a pending journal to match
    so Security is not left degraded. Mixed states wait for the operator."""
    try:
        journal = read_journal()
    except JournalCorrupt:
        return
    if journal is None:
        return
    if journal.get("phase") == "committed":
        _cleanup(journal)
        return
    if _verify_files(journal):
        return
    policies = [e for e in journal["entries"] if e["kind"] == "policy"]
    current = {e["path"]: fsio.sha256_tag(fsio.read_bytes(e["path"])) for e in policies}
    try:
        if all(current[e["path"]] == e["candidate_hash"] for e in policies):
            _finish_candidate(journal)
            if _commit(journal):
                audit.log_action("bans_recovered", "system", f"{journal['source']}: a Caddyfile reload loaded the new policy")
        elif all(current[e["path"]] == e["previous_hash"] for e in policies):
            _restore_files(journal)
            _cleanup(journal)
            audit.log_action("bans_recovered", "system", f"{journal['source']}: a Caddyfile reload kept the previous policy")
    except (OSError, ValueError):
        return
```

- [ ] **Step 4: Hook the editor's successful reload**

In `src/routes/editor.py` add imports:

```python
import logging

from .. import config
from ..bans import txn as bans_txn
```

Add the helper above `_apply_config`:

```python
def _reconcile_bans() -> None:
    """A successful /load of the on-disk Caddyfile also loaded the managed ban
    policy on disk; settle a pending ban transaction to match (src/bans/txn.py)."""
    if not config.BANS_ENABLED:
        return
    try:
        bans_txn.reconcile_after_external_reload()
    except Exception:  # noqa: BLE001 - ban bookkeeping must never fail a save
        logging.getLogger(__name__).exception("IP bans: reconciling after a reload failed")
```

In `_apply_config`, change the success branch to call it first, still inside the lock:

```python
        if resp.status_code == 200:
            _reconcile_bans()
            log_action(f"{source}_reload", user, f"backup={backup_name}{extra}")
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run --frozen python -m unittest tests.test_bans_recovery tests.test_bans_txn tests.test_app -v`
Expected: all PASS (the existing save-path tests prove the hook is inert without a journal).

- [ ] **Step 6: Commit**

```bash
git add src/bans/txn.py src/routes/editor.py tests/_bans.py tests/test_bans_recovery.py
git commit -m "feat(bans): journal recovery from live config, operator actions and editor reload hook"
```

---
### Task 9: Ban service: availability, mutations, holds, status and expiry

**Files:**
- Create: `src/bans/service.py`
- Test: `tests/test_bans_service.py`

**Interfaces:**
- Consumes: `addr`, `protected`, `store`, `render`, `scan`, `detect`, `caddy`, `txn` (all earlier tasks), `routes.editor.caddyfile_lock`, `geoip.geoip.lookup`, `audit.log_action`, `audit.tail_lines`.
- Produces (all return `(body: dict, http_status: int)` unless noted):
  - `init_config()` (raises `RuntimeError` on invalid `BANS_NEVER`), `reset_caches()`, `never_networks()`.
  - `availability(force=False) -> Availability(ok, code, message)`; codes `bans_dir_outside | bans_dir_symlink | bans_dir_not_writable | caddy_unreachable | caddy_cannot_see_bans_dir`. Never call it while holding `caddyfile_lock()`.
  - `status(remote_addr) -> dict` (always 200 data; see shape below).
  - `list_bans(covering=None)`; `add_ban(payload, actor, remote_addr)` (201 on success); `remove_ban(record_id, actor, remote_addr)`; `reapply(payload, actor, remote_addr)`; `reset(payload, actor, remote_addr)`.
  - `recovery_info() -> dict`; `recovery_post(payload, actor)`.
  - `expire_tick(now=None) -> str` in `unavailable | degraded | corrupt | idle | applied | <txn code>`.
- Response body for mutations: `{ok, code, message, reload_status, enforcement, ...}` where `enforcement` is `enforced | not_enabled | unchanged | held | unknown`; `add_ban` adds `record`; `remove_ban` adds `removed`, `value`, `still_covered_by`.
- `status()` shape (consumed by Task 12): `{enabled, available, unavailable: {code, message} | null, state_version, degraded: {kind, reason, phase, message} | null, recovery: <recovery_info()>, sources: {manual: {file, import_line, hold, hold_reason, active_records, rendered_prefixes}}, protected: [{category, label, values}], sites: [{label, hosts, status, pre_handlers, detail, source: "main" | "external", line, import}], caddy: {reachable, message}, limits: {max_prefixes}, last_apply: {time, user, detail} | null}`. Site `status` adds `management` and `not_loaded` to the detection values.
- `recovery_info()` shape: `{required, kind: "journal" | "state_corrupt" | "policy_hold" | null, recovery_id, reason, phase, summary, files, actions, backups: [{id, created_at, records}], reapply, reset, state_version}`.
- Error codes: `invalid_request`, `invalid_ip`, `invalid_range`, `invalid_duration`, `invalid_reason`, `range_too_wide`, `protected_overlap` (adds `category`), `capacity_exceeded` (409, adds `count`, `limit`), `not_found` (404), `not_manual` (403), `state_degraded` (503, adds `recovery: true`), `bans_unavailable` (503, adds `reason`), `invalid_source`, `source_not_enabled`, `confirmation_required`, `version_conflict` (409), `recovery_stale` (409), `invalid_action`, `invalid_backup`, plus every `txn.Outcome` code.

Phase 1 trust profile is `direct`: the TCP peer (`request.remote_addr`, no proxy headers) is the only verified client address. `_verified_client()` is where Phase 4's profiles plug in. The management registry is updated only inside mutation transactions, because a registry change changes the rendered `not client_ip` line and therefore needs a reload.

- [ ] **Step 1: Write the failing tests**

`tests/test_bans_service.py`:

```python
"""Ban operations end to end against the fake admin API (spec 1.2-1.7).

Run with:  uv run --frozen python -m unittest tests.test_bans_service -v
"""
import fcntl
import json
import os
import tempfile
import threading
import unittest
from datetime import timedelta
from unittest import mock

import requests

import tests._env as env
from tests import _bans

from src import audit, config
from src.bans import fsio, render, service, store

MANUAL = render.SOURCES["manual"]
with open(os.path.join(os.path.dirname(__file__), "fixtures", "bans", "adapted-layouts.json"), encoding="utf-8") as f:
    FIXTURES = json.load(f)


def actions():
    return [e["action"] for e in audit.iter_entries()]


def policy():
    return fsio.read_bytes(MANUAL.path) or b""


class ServiceCase(unittest.TestCase):
    def setUp(self):
        _bans.reset()
        _bans.fresh_audit(self)
        service.reset_caches()
        self.caddy = _bans.FakeCaddy().install(self)

    def tearDown(self):
        service.reset_caches()

    def ban(self, value="203.0.113.7", duration="24h", reason="", remote="127.0.0.1"):
        return service.add_ban({"value": value, "duration": duration, "reason": reason}, "admin@example.com", remote)

    def patch_config(self, **values):
        for name, value in values.items():
            p = mock.patch.object(config, name, value)
            p.start()
            self.addCleanup(p.stop)
        service.reset_caches()


class AddRemoveTest(ServiceCase):
    def test_ban_renders_policy_with_embedded_hash_and_audits(self):
        body, status = self.ban(" 203.0.113.7 ", reason="Repeated login attempts")
        self.assertEqual(status, 201, body)
        self.assertEqual((body["ok"], body["enforcement"], body["reload_status"]), (True, "enforced", "applied"))
        self.assertEqual((body["record"]["value"], body["record"]["scope"]), ("203.0.113.7", "ip"))
        self.assertIn(b"\tclient_ip 203.0.113.7\n", policy())
        self.assertIn(b"\tnot client_ip private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10\n", policy())
        state = store.load()
        self.assertEqual(state.last_rendered_hashes[MANUAL.filename], fsio.sha256_tag(policy()))
        self.assertEqual(state.records[0].reason, "Repeated login attempts")
        self.assertIn("ban_created", actions())

    def test_protected_and_wide_targets_are_refused_and_audited(self):
        for value, code in (("10.1.2.3", "protected_overlap"), ("192.168.0.0/16", "protected_overlap"),
                            ("fe80::1", "protected_overlap"), ("203.0.0.0/15", "range_too_wide"),
                            ("2001:db8::/47", "range_too_wide"), ("nope", "invalid_ip")):
            with self.subTest(value=value):
                body, status = self.ban(value)
                self.assertEqual((status, body["code"]), (400, code))
        self.assertFalse(os.path.exists(MANUAL.path))
        self.assertEqual(actions().count("ban_refused"), 5)

    def test_own_verified_address_is_protected_immediately(self):
        body, status = self.ban("198.51.100.0/24", remote="198.51.100.20")
        self.assertEqual((status, body["code"], body["category"]), (400, "protected_overlap", "operator"))
        body, status = self.ban("203.0.113.7", remote="198.51.100.20")
        self.assertEqual(status, 201)
        self.assertEqual([m["value"] for m in store.load().management_addresses], ["198.51.100.20"])
        self.assertIn(b" 198.51.100.20\n", policy())

    def test_private_peer_is_not_registered(self):
        self.ban(remote="172.18.0.5")
        self.assertEqual(store.load().management_addresses, [])

    def test_bans_never_in_both_directions(self):
        self.patch_config(BANS_NEVER="203.0.113.9")
        for value in ("203.0.113.0/24", "203.0.113.9"):
            body, status = self.ban(value)
            self.assertEqual((status, body["code"], body["category"]), (400, "protected_overlap", "never"))

    def test_capacity_never_drops_an_active_ban(self):
        self.patch_config(BANS_MAX=2)
        self.assertEqual(self.ban("203.0.113.1")[1], 201)
        self.assertEqual(self.ban("203.0.113.3")[1], 201)
        body, status = self.ban("203.0.113.5")
        self.assertEqual((status, body["code"], body["count"], body["limit"]), (409, "capacity_exceeded", 3, 2))
        self.assertEqual(len(store.load().records), 2)
        self.assertIn(b"client_ip 203.0.113.1 203.0.113.3\n", policy())

    def test_overlapping_records_are_independent(self):
        first = self.ban("203.0.113.7", "4h")[0]["record"]["id"]
        second = self.ban("203.0.113.7", "permanent")[0]["record"]["id"]
        body, status = service.remove_ban(first, "admin@example.com", "127.0.0.1")
        self.assertEqual((status, body["still_covered_by"]), (200, ["203.0.113.7"]))
        self.assertIn(b"client_ip 203.0.113.7", policy())
        service.remove_ban(second, "admin@example.com", "127.0.0.1")
        self.assertNotIn(b"client_ip", policy())
        self.assertIn(b"vars caddy_console_manual_policy 1\n", policy())
        self.assertIn("ban_removed", actions())

    def test_remove_errors(self):
        self.assertEqual(service.remove_ban("nope", "a@example.com", None)[1], 404)
        self.ban()
        state = store.load()
        state.records.append(store.Record(id="cs-1", source="crowdsec", source_id="42", scope="ip",
                                          value="192.0.2.1", reason="", scenario="crowdsecurity/http-probing",
                                          origin="crowdsec", actor="system", created_at=state.records[0].created_at,
                                          expires_at=None))
        fsio.atomic_write(store.STATE_PATH, store.dumps(state), 0o600)
        body, status = service.remove_ban("cs-1", "a@example.com", None)
        self.assertEqual((status, body["code"]), (403, "not_manual"))

    def test_mutations_hold_the_cross_process_lock_through_load(self):
        real, seen = requests.post, []

        def checking(url, *a, **kw):
            if url.endswith("/load"):
                fd = os.open(os.path.join(env.BACKUP_DIR, ".lock"), os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    seen.append(True)
                finally:
                    os.close(fd)
            return real(url, *a, **kw)
        service.availability()                     # warm the probe outside the patch
        with mock.patch.object(requests, "post", checking):
            self.assertEqual(self.ban()[1], 201)
        self.assertEqual(seen, [True])

    def test_concurrent_bans_are_serialized(self):
        service.availability()
        threads = [threading.Thread(target=self.ban, args=(f"203.0.113.{i}",)) for i in (1, 3, 5, 7)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(r.value for r in store.load().records),
                         ["203.0.113.1", "203.0.113.3", "203.0.113.5", "203.0.113.7"])
        self.assertIn(b"client_ip 203.0.113.1 203.0.113.3 203.0.113.5 203.0.113.7\n", policy())


class LookupTest(ServiceCase):
    def test_covering_lookup_accepts_mapped_ipv6(self):
        self.ban("203.0.113.7/24")
        exact = self.ban("::ffff:203.0.113.8")[0]["record"]
        self.assertEqual(exact["value"], "203.0.113.8")
        body, status = service.list_bans("::ffff:203.0.113.8")
        self.assertEqual((status, body["ip"], body["protected"]), (200, "203.0.113.8", None))
        self.assertEqual(sorted(r["value"] for r in body["records"]), ["203.0.113.0/24", "203.0.113.8"])
        self.assertEqual(body["exact_ids"], [exact["id"]])
        self.assertEqual(service.list_bans("203.0.113.0/24")[0]["code"], "invalid_ip")
        self.assertEqual(service.list_bans("10.0.0.1")[0]["protected"], "private")

    def test_record_overlapping_new_never_is_flagged_and_excluded(self):
        self.ban("203.0.113.0/24")
        self.patch_config(BANS_NEVER="203.0.113.9")
        body, _ = service.list_bans()
        self.assertEqual(body["records"][0]["protected"], "never")
        self.assertEqual(self.ban("192.0.2.1")[1], 201)
        self.assertIn(b" 203.0.113.9\n", policy())


class CorruptStateTest(ServiceCase):
    def corrupt(self):
        with open(store.STATE_PATH, "wb") as f:
            f.write(b"{broken")

    def test_corrupt_state_is_read_only_and_keeps_the_policy(self):
        self.ban()
        before = policy()
        self.corrupt()
        body, status = self.ban("192.0.2.1")
        self.assertEqual((status, body["code"], body["recovery"]), (503, "state_degraded", True))
        self.assertEqual(policy(), before)
        self.assertTrue(any(n.startswith("bans.json.quarantine-") for n in os.listdir(env.BACKUP_DIR)))
        self.assertIsNotNone(store.read_error())
        self.assertEqual(service.status("127.0.0.1")["degraded"]["kind"], "state_corrupt")
        self.assertEqual(service.expire_tick(), "corrupt")
        self.assertEqual(service.list_bans()[1], 503)
        self.assertEqual(policy(), before)

    def test_restore_backup_then_reapply(self):
        self.ban("203.0.113.7")
        self.ban("192.0.2.1")                       # snapshot of the one-ban state is kept
        self.corrupt()
        info = service.recovery_info()
        self.assertEqual((info["kind"], info["actions"]), ("state_corrupt", ["restore_backup"]))
        body, status = service.recovery_post({"recovery_id": info["recovery_id"], "action": "restore_backup",
                                              "backup_id": info["backups"][0]["id"]}, "op@example.com")
        self.assertEqual(status, 200, body)
        self.assertIsNone(store.read_error())
        self.assertEqual([r.value for r in store.load().records], ["203.0.113.7"])
        info = service.recovery_info()
        self.assertEqual(info["kind"], "policy_hold")
        body, status = service.reapply({"source": "manual"}, "op@example.com", None)
        self.assertEqual(status, 200, body)
        self.assertFalse(service.recovery_info()["required"])
        self.assertNotIn(b"192.0.2.1", policy())

    def test_reset_contract(self):
        self.ban()
        self.corrupt()
        version = service.recovery_info()["state_version"]
        self.assertEqual(service.reset({"source": "manual", "version": version}, "op", None)[0]["code"], "confirmation_required")
        self.assertEqual(service.reset({"source": "manual", "version": "x", "confirm": True}, "op", None)[1], 409)
        self.assertEqual(service.reset({"source": "crowdsec", "version": version, "confirm": True}, "op", None)[0]["code"], "source_not_enabled")
        self.assertEqual(service.reset({"source": "everything", "version": version, "confirm": True}, "op", None)[0]["code"], "invalid_source")
        body, status = service.reset({"source": "manual", "version": version, "confirm": True}, "op", None)
        self.assertEqual(status, 200, body)
        self.assertEqual(store.load().records, [])
        self.assertNotIn(b"client_ip", policy())
        self.assertIsNone(store.read_error())
        self.assertIn("bans_reset", actions())


class HoldTest(ServiceCase):
    def test_truncated_policy_enters_hold_until_reapply(self):
        self.ban("203.0.113.7")
        with open(MANUAL.path, "wb"):
            pass                                    # host recovery: ": > bans-manual.caddy"
        status = service.status("127.0.0.1")
        self.assertEqual((status["sources"]["manual"]["hold"], status["recovery"]["kind"]), (True, "policy_hold"))
        body, code = self.ban("192.0.2.1")
        self.assertEqual((code, body["enforcement"]), (201, "held"))
        self.assertEqual(policy(), b"")
        self.assertEqual(service.expire_tick(now=store.utc_now() + timedelta(days=2)), "idle")
        self.assertEqual(policy(), b"")
        body, code = service.reapply({"source": "manual"}, "op@example.com", None)
        self.assertEqual(code, 200, body)
        self.assertIn(b"client_ip 192.0.2.1 203.0.113.7", policy())
        self.assertFalse(service.status("127.0.0.1")["sources"]["manual"]["hold"])

    def test_missing_state_with_an_existing_policy_is_a_hold(self):
        fsio.atomic_write(MANUAL.path, b"vars caddy_console_manual_policy 1\n", 0o644)
        self.assertEqual(service.recovery_info()["kind"], "policy_hold")


class ExpiryTest(ServiceCase):
    def test_expiry_regenerates_and_reloads_keeping_the_registry(self):
        self.ban("203.0.113.7", "4h", remote="198.51.100.20")
        self.ban("203.0.113.8", "permanent")
        self.caddy.calls.clear()
        self.assertEqual(service.expire_tick(now=store.utc_now() + timedelta(hours=5)), "applied")
        self.assertNotIn(b"203.0.113.7", policy())
        self.assertIn(b"client_ip 203.0.113.8\n", policy())
        self.assertIn(b" 198.51.100.20\n", policy())
        self.assertIn("load", [c[0] for c in self.caddy.calls])
        self.assertIn("ban_expired", actions())

    def test_idle_tick_does_nothing(self):
        self.ban("203.0.113.8", "permanent")
        self.caddy.calls.clear()
        self.assertEqual(service.expire_tick(), "idle")
        self.assertNotIn("load", [c[0] for c in self.caddy.calls])


class AvailabilityTest(ServiceCase):
    def test_bans_dir_must_be_inside_the_caddyfile_dir(self):
        self.patch_config(BANS_DIR=tempfile.mkdtemp())
        self.assertEqual(service.availability().code, "bans_dir_outside")
        body, status = self.ban()
        self.assertEqual((status, body["code"]), (503, "bans_unavailable"))
        self.assertFalse(service.status("127.0.0.1")["available"])

    def test_bans_dir_must_not_traverse_a_symlink(self):
        link = os.path.join(env.ROOT, "linked")
        if not os.path.islink(link):
            os.symlink(tempfile.mkdtemp(), link)
        self.patch_config(BANS_DIR=os.path.join(link, "console"))
        self.assertEqual(service.availability().code, "bans_dir_symlink")

    def test_caddy_must_see_the_managed_directory(self):
        self.caddy.hide_imports = True
        self.assertEqual(service.availability(force=True).code, "caddy_cannot_see_bans_dir")
        self.assertEqual([n for n in os.listdir(env.BANS_DIR) if "probe" in n], [])
        self.caddy.hide_imports = False
        self.caddy.down = True
        self.assertEqual(service.availability(force=True).code, "caddy_unreachable")
        self.caddy.down = False
        self.assertTrue(service.availability(force=True).ok)


class StatusTest(ServiceCase):
    def test_sites_merge_live_detection_with_the_file(self):
        self.ban()
        self.caddy.live = FIXTURES["simple_proxy"]
        _bans.write_caddyfile(f"a.example.com {{\n\timport {env.BANS_DIR}/bans-manual*.caddy\n\treverse_proxy 127.0.0.1:9\n}}\n"
                              "b.example.com {\n\trespond 200\n}\n")
        status = service.status("127.0.0.1")
        sites = {s["label"]: s for s in status["sites"]}
        self.assertEqual((sites["a.example.com"]["status"], sites["a.example.com"]["source"],
                          sites["a.example.com"]["import"]["first_child"]), ("enforced", "main", True))
        self.assertEqual(sites["b.example.com"]["status"], "not_loaded")
        self.assertEqual(status["sources"]["manual"]["active_records"], 1)
        self.assertIn("loopback", [p["category"] for p in status["protected"]])
        self.assertEqual(status["last_apply"]["user"], "admin@example.com")

    def test_external_and_management_sites(self):
        self.caddy.live = FIXTURES["simple_proxy"]
        _bans.write_caddyfile("other.example.com {\n\trespond 200\n}\n")
        self.assertEqual(service.status(None)["sites"][0]["source"], "external")
        _bans.write_caddyfile("a.example.com { # caddy-console: management\n\treverse_proxy 127.0.0.1:9\n}\n")
        self.assertEqual(service.status(None)["sites"][0]["status"], "management")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --frozen python -m unittest tests.test_bans_service -v`
Expected: FAIL with `ImportError: cannot import name 'service'`.

- [ ] **Step 3: Implement `src/bans/service.py`**

```python
"""IP-ban operations behind the Security API (spec 1.5-1.8).

Every write: availability() -> caddyfile_lock() -> txn.resolve_pending() ->
load state -> build every candidate in memory -> txn.apply_locked().
availability() takes the lock for its probe, so it is never called while the
lock is held (flock is per fd, not re-entrant).
"""
import ipaddress
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .. import audit, config
from ..geoip import geoip
from ..routes.editor import caddyfile_lock
from . import addr, detect, fsio, protected, render, scan, store, txn
from . import caddy as caddy_admin

AVAILABLE_TTL = 300.0
UNAVAILABLE_TTL = 30.0
RESET_SOURCES = ("manual", "crowdsec", "country", "cloudflare")
RECOVERY_ACTIONS = ("use_candidate", "use_previous", "restore_backup")
_lock = threading.Lock()
_cache = {}
_CORE = protected.build()


class BanError(Exception):
    def __init__(self, code, message, http_status=400, audit_events=(), **extra):
        super().__init__(message)
        self.code, self.http_status, self.audit_events, self.extra = code, http_status, list(audit_events), extra


@dataclass
class Mutation:
    body: dict = field(default_factory=dict)
    status: int = 200
    audit: list = field(default_factory=list)


@dataclass(frozen=True)
class Availability:
    ok: bool
    code: object = None
    message: object = None


def _error(code, message, status, **extra):
    return {"ok": False, "code": code, "message": message, **extra}, status


def _outcome_body(o):
    return {"ok": o.ok, "code": o.code, "message": o.message,
            "reload_status": o.reload_status, "enforcement": o.enforcement}


def reset_caches() -> None:
    with _lock:
        _cache.clear()


def never_networks():
    with _lock:
        if "never" not in _cache:
            _cache["never"] = protected.parse_never(config.BANS_NEVER)
        return _cache["never"]


def init_config() -> None:
    """create_app() calls this: an invalid BANS_NEVER token refuses startup."""
    try:
        never_networks()
    except protected.ConfigError as e:
        raise RuntimeError(f"BANS_NEVER has an {e}") from None


# --- availability (spec 1.1) ------------------------------------------------------

def _path_problem():
    caddy_dir = os.path.dirname(os.path.abspath(config.CADDYFILE))
    bans_dir = os.path.abspath(config.BANS_DIR)
    if bans_dir == caddy_dir or os.path.commonpath([caddy_dir, bans_dir]) != caddy_dir:
        return Availability(False, "bans_dir_outside",
                            f"BANS_DIR ({bans_dir}) must be a directory inside {caddy_dir}, "
                            "the directory that holds the Caddyfile and is mounted into Caddy.")
    current = caddy_dir
    for part in os.path.relpath(bans_dir, caddy_dir).split(os.sep):
        current = os.path.join(current, part)
        if os.path.islink(current):
            return Availability(False, "bans_dir_symlink", f"{current} is a symlink; BANS_DIR must not traverse one.")
    try:
        os.makedirs(bans_dir, mode=0o755, exist_ok=True)
        os.remove(fsio.write_temp(bans_dir, "write-check", b"", 0o600))
    except OSError as e:
        return Availability(False, "bans_dir_not_writable",
                            f"The console cannot write to {bans_dir} ({e.strerror or e}). "
                            "Mount the Caddyfile directory read-write in the console container.")
    return None


def _probe() -> Availability:
    token = secrets.token_hex(8)
    stem = os.path.join(config.BANS_DIR, f"console-probe-{token}")
    text = f"http://caddy-console-probe.invalid {{\n\timport {stem}*.caddy\n}}\n"
    try:
        fsio.atomic_write(stem + ".caddy", f"vars caddy_console_probe {token}\n".encode(), 0o644)
        try:
            result = caddy_admin.adapt(text)
        finally:
            os.remove(stem + ".caddy")
    except caddy_admin.CaddyUnavailable:
        return Availability(False, "caddy_unreachable",
                            "The Caddy admin API is unreachable, so the managed directory cannot be verified yet.")
    except OSError as e:
        return Availability(False, "bans_dir_not_writable", f"Writing a probe file failed ({e.strerror or e}).")
    if result.ok and token in caddy_admin.normalize(result.config).decode("utf-8"):
        return Availability(True)
    return Availability(False, "caddy_cannot_see_bans_dir",
                        f"Caddy cannot read {config.BANS_DIR}. Mount the same host directory at the same "
                        "path in the Caddy container (read-only is enough).")


def availability(force=False) -> Availability:
    now = time.monotonic()
    with _lock:
        hit = _cache.get("availability")
        if hit and not force and now - hit[1] < (AVAILABLE_TTL if hit[0].ok else UNAVAILABLE_TTL):
            return hit[0]
    result = _path_problem()
    if result is None:
        with caddyfile_lock():
            result = _probe()
    with _lock:
        _cache["availability"] = (result, time.monotonic())
    return result


# --- building blocks ----------------------------------------------------------------

def _verified_client(remote_addr):
    """Trust profile `direct`: only the TCP peer is verified. Behind cloudflared
    or a front proxy that peer is a private Docker address, already protected,
    so nothing is registered; operators put their WAN address in BANS_NEVER."""
    ip = addr.client_address(remote_addr)
    if ip is None or _CORE.overlap(ipaddress.ip_network(ip)) is not None:
        return None
    return ip


def protected_for(state, client=None):
    management = store.management_networks(state)
    if client is not None:
        management.append(ipaddress.ip_network(client))
    return protected.build(never=never_networks(), management=management,
                           docker=protected.read_docker_networks())


def _holds(state) -> dict:
    """Sources whose file differs from the hash recorded at their last render:
    an out-of-band recovery override (spec 1.6). Not regenerated until Re-apply."""
    out = {}
    for name, src in render.SOURCES.items():
        recorded = state.last_rendered_hashes.get(src.filename)
        actual = fsio.sha256_tag(fsio.read_bytes(src.path))
        if recorded != actual:
            out[name] = "missing" if actual is None else "differs"
    return out


def _candidates(state, prot, holds, now) -> list:
    changes, owns = [], []
    for name, src in render.SOURCES.items():
        if name in holds:
            continue
        data = render.render_policy(src, render.effective_prefixes(state.records, now, name),
                                    prot.exclusion_tokens(), config.BANS_MAX)
        state.last_rendered_hashes[src.filename] = fsio.sha256_tag(data)
        changes.append(txn.Change(src.path, "policy", data, marker=src.marker))
        owns.append(src.filename)
    changes.append(txn.Change(store.STATE_PATH, "state", store.dumps(state), owns=tuple(owns)))
    return changes


def _corrupt_version(e) -> str:
    return fsio.sha256_tag(e.raw or b"")[7:23]


def _transact(actor, client, mutate, *, source="manual", force=(), allow_corrupt=False):
    """mutate(state, now, version) edits state in place and returns a Mutation,
    or raises BanError. Everything between load and apply runs under the lock."""
    avail = availability()
    if not avail.ok:
        return _error("bans_unavailable", avail.message, 503, reason=avail.code)
    with caddyfile_lock():
        pending = txn.resolve_pending()
        if pending is not None:
            return _error("state_degraded", pending.message, 503, recovery=True)
        corrupt = None
        try:
            state = store.load()
        except store.StateCorrupt as e:
            store.quarantine(e.raw, str(e))
            if not allow_corrupt:
                return _error("state_degraded", f"{e}. The last generated policy stays enforced; "
                              "open Security to recover.", 503, recovery=True)
            corrupt, state = e, store.State()
        previous_raw = state.raw
        version = _corrupt_version(corrupt) if corrupt else state.version
        holds = {} if corrupt else {k: v for k, v in _holds(state).items() if k not in force}
        now = store.utc_now()
        store.prune_expired(state, now, sources=[n for n in render.SOURCES if n not in holds])
        store.prune_management(state, now)
        store.touch_management(state, client, "direct", now)
        try:
            result = mutate(state, now, version)
            changes = _candidates(state, protected_for(state), holds, now)
        except BanError as e:
            for action, detail in e.audit_events:
                audit.log_action(action, actor, detail)
            return _error(e.code, str(e), e.http_status, **e.extra)
        except render.CapacityError as e:
            return _error("capacity_exceeded", f"This would render {e.count} prefixes; the limit (BANS_MAX) is {e.limit}. "
                          "Remove or merge bans first.", 409, count=e.count, limit=e.limit)
        outcome = txn.apply_locked(changes, actor=actor, source=source)
    if outcome.ok:
        try:
            store.save_snapshot(previous_raw)
        except OSError:
            pass
        if corrupt:
            store.clear_error()
        for action, detail in result.audit:
            audit.log_action(action, actor, detail)
    body = {**_outcome_body(outcome), **result.body}
    if outcome.ok and holds:
        body["enforcement"] = "held"
        body["message"] = ("Stored. The ban file differs from the stored state, so it was not regenerated; "
                           "use Re-apply in Security.")
    return body, (result.status if outcome.ok else outcome.http_status)


def _public(r, now, prot) -> dict:
    out = {k: getattr(r, k) for k in ("id", "source", "scope", "value", "reason", "actor",
                                      "created_at", "expires_at", "scenario", "origin")}
    out.update(expired=r.expired(now), protected=prot.overlap(r.network), geo=_geo(r))
    return out


def _geo(r):
    if r.scope != "ip":
        return None
    found = geoip.lookup(r.value) or {}
    loc, asn = found.get("location") or {}, found.get("asn") or {}
    if not loc and not asn:
        return None
    return {"country_code": loc.get("country_code"), "country": loc.get("country"), "asn_org": asn.get("org")}


# --- mutations ------------------------------------------------------------------------

def add_ban(payload, actor, remote_addr):
    if not isinstance(payload, dict):
        return _error("invalid_request", "Send a JSON object.", 400)
    try:
        net = addr.canonical(payload.get("value"))
        duration = store.validate_duration(payload.get("duration"))
        reason = store.validate_reason(payload.get("reason"))
    except (addr.AddressError, store.InputError) as e:
        return _error(e.code, str(e), 400)
    try:
        addr.check_width(net)
    except addr.AddressError as e:
        audit.log_action("ban_refused", actor, f"{addr.token(net)} too wide")
        return _error(e.code, str(e), 400)
    client = _verified_client(remote_addr)
    value = addr.token(net)

    def mutate(state, now, version):
        category = protected_for(state, client).overlap(net)
        if category:
            raise BanError("protected_overlap", f"{value} overlaps a protected range ({protected.LABELS[category]}).",
                           400, [("ban_refused", f"{value} protected={category}")], category=category)
        r = store.new_manual_record(net, duration, reason, actor, now)
        state.records.append(r)
        return Mutation({"record": _public(r, now, protected_for(state))}, 201,
                        [("ban_created", f"{value} {duration} id={r.id}")])
    return _transact(actor, client, mutate)


def remove_ban(record_id, actor, remote_addr):
    def mutate(state, now, version):
        r = next((x for x in state.records if x.id == record_id), None)
        if r is None:
            raise BanError("not_found", "No ban with that ID.", 404)
        if r.source != "manual":
            raise BanError("not_manual", "Only manual bans can be removed here; CrowdSec decisions are read-only.", 403)
        state.records.remove(r)
        still = sorted({x.value for x in state.records if not x.expired(now)
                        and protected.overlaps(x.network, r.network)})
        return Mutation({"removed": r.id, "value": r.value, "still_covered_by": still}, 200,
                        [("ban_removed", f"{r.value} id={r.id}")])
    return _transact(actor, _verified_client(remote_addr), mutate)


def reapply(payload, actor, remote_addr):
    source = payload.get("source", "manual") if isinstance(payload, dict) else None
    if source not in render.SOURCES:
        return _error("invalid_source", "Unknown policy source.", 400)

    def mutate(state, now, version):
        return Mutation({"source": source}, 200, [("bans_reapply", source)])
    return _transact(actor, _verified_client(remote_addr), mutate, force=(source,), source="reapply")


def reset(payload, actor, remote_addr):
    if not isinstance(payload, dict):
        return _error("invalid_request", "Send a JSON object.", 400)
    source = payload.get("source")
    if source not in RESET_SOURCES:
        return _error("invalid_source", "source must be manual, crowdsec, country or cloudflare.", 400)
    if source not in render.SOURCES:
        return _error("source_not_enabled", f"The {source} source is not part of this version.", 400)
    if payload.get("confirm") is not True:
        return _error("confirmation_required", "Resetting deletes every manual ban; send confirm: true.", 400)
    expected = payload.get("version")

    def mutate(state, now, version):
        if expected != version:
            raise BanError("version_conflict", "The ban list changed since you loaded it; reload the Security view.", 409)
        removed = [r for r in state.records if r.source == source]
        state.records = [r for r in state.records if r.source != source]
        return Mutation({"removed": len(removed)}, 200, [("bans_reset", f"{source}: removed {len(removed)} records")])
    return _transact(actor, _verified_client(remote_addr), mutate, force=(source,), allow_corrupt=True, source="reset")


# --- reads ------------------------------------------------------------------------------

def list_bans(covering=None):
    try:
        state = store.load()
    except store.StateCorrupt as e:
        return _error("state_degraded", f"{e}. Open Security to recover.", 503, recovery=True)
    now = store.utc_now()
    prot = protected_for(state)
    if covering is not None:
        try:
            ip = addr.canonical(covering)
        except addr.AddressError as e:
            return _error(e.code, str(e), 400)
        if addr.scope_of(ip) != "ip":
            return _error("invalid_ip", "Look up a single IP address.", 400)
        hits = [r for r in state.records if not r.expired(now) and protected.overlaps(r.network, ip)]
        token = addr.token(ip)
        return {"ip": token, "protected": prot.overlap(ip),
                "records": [_public(r, now, prot) for r in hits],
                "exact_ids": [r.id for r in hits if r.source == "manual" and r.value == token]}, 200
    records = sorted(state.records, key=lambda r: r.created_at, reverse=True)
    return {"records": [_public(r, now, prot) for r in records], "state_version": state.version,
            "rendered_prefixes": len(render.effective_prefixes(state.records, now, "manual")),
            "max_prefixes": config.BANS_MAX}, 200


def _rid(*parts) -> str:
    return fsio.sha256_tag("|".join(str(p) for p in parts).encode())[7:23]


def _recovery_info_locked() -> dict:
    base = {"required": True, "phase": None, "backups": [], "reapply": False, "reset": False, "state_version": None}
    pending = txn.resolve_pending()
    if pending is not None:
        j = pending.journal or {}
        return {**base, "kind": "journal", "recovery_id": _rid("journal", j.get("id"), pending.reason),
                "reason": pending.reason, "phase": j.get("phase"), "summary": pending.message,
                "files": [os.path.basename(e["path"]) for e in j.get("entries", [])],
                "actions": [] if pending.reason in ("journal_corrupt", "hash_mismatch") else ["use_candidate", "use_previous"]}
    try:
        state = store.load()
    except store.StateCorrupt as e:
        store.quarantine(e.raw, str(e))
        backups = store.list_snapshots()
        return {**base, "kind": "state_corrupt", "recovery_id": _rid("state", _corrupt_version(e)),
                "reason": "state_corrupt", "files": ["bans.json"], "backups": backups,
                "summary": f"{e}. The last generated ban policy stays enforced; nothing is regenerated "
                           "until you restore a backup or reset the list.",
                "actions": ["restore_backup"] if backups else [], "reset": True,
                "state_version": _corrupt_version(e)}
    holds = _holds(state)
    if holds:
        return {**base, "kind": "policy_hold", "recovery_id": _rid("hold", sorted(holds.items()), state.version),
                "reason": "policy_differs", "files": [render.SOURCES[n].filename for n in holds], "actions": [],
                "summary": "A managed ban file differs from the stored state, for example after host recovery. "
                           "It is not regenerated and its expiry is paused until you fix the records and Re-apply.",
                "reapply": True, "reset": True, "state_version": state.version}
    return {**base, "required": False, "kind": None, "recovery_id": None, "reason": None, "summary": "",
            "files": [], "actions": [], "state_version": state.version}


def recovery_info() -> dict:
    with caddyfile_lock():
        return _recovery_info_locked()


def recovery_post(payload, actor):
    if not isinstance(payload, dict):
        return _error("invalid_request", "Send a JSON object.", 400)
    action = payload.get("action")
    if action not in RECOVERY_ACTIONS:
        return _error("invalid_action", "Unknown recovery action.", 400)
    with caddyfile_lock():
        info = _recovery_info_locked()
        if not info["required"] or payload.get("recovery_id") != info["recovery_id"]:
            return _error("recovery_stale", "The recovery situation changed; reload the Security view.", 409)
        if action not in info["actions"]:
            return _error("invalid_action", "That action is not available here.", 400)
        if action == "restore_backup":
            backup_id = payload.get("backup_id")
            if backup_id not in {b["id"] for b in info["backups"]}:
                return _error("invalid_backup", "Unknown backup.", 400)
            raw = store.snapshot_bytes(backup_id)
            try:
                store.parse(raw)
            except store.StateCorrupt as e:
                return _error("invalid_backup", f"That backup is not usable ({e}).", 400)
            outcome = txn.apply_locked([txn.Change(store.STATE_PATH, "state", raw)], actor=actor, source="recovery")
            if outcome.ok:
                store.clear_error()
        else:
            outcome = txn.recovery_action(action, actor)
    if outcome.ok:
        audit.log_action("bans_recovered", actor, action)
    return _outcome_body(outcome), (200 if outcome.ok else outcome.http_status)


def _read_caddyfile() -> str:
    try:
        with open(config.CADDYFILE, encoding="utf-8", newline="") as f:
            return f.read()
    except (OSError, UnicodeError):
        return ""


def _server_host():
    return urlsplit(config.SERVER_URL).hostname if config.SERVER_URL_CONFIGURED else None


def _site_rows(live, text, active) -> list:
    src = render.SOURCES["manual"]
    blocks = scan.site_blocks(text)
    management = scan.management_hosts(text, _server_host())
    rows, seen = [], set()
    for s in detect.site_statuses(live, src, bool(active)) if live is not None else []:
        block = next((b for b in blocks if set(b.hosts) & set(s.hosts)), None) if s.hosts \
            else next((b for b in blocks if s.label in b.addresses), None)
        if block is not None:
            seen.add(block.start)
        rows.append({"label": s.label, "hosts": s.hosts,
                     "status": "management" if set(s.hosts) & management else s.status,
                     "pre_handlers": s.pre_handlers, "detail": s.detail,
                     "source": "main" if block else "external", "line": block.start if block else None,
                     "import": scan.block_import_state(text, block, src.path) if block else None})
    for b in blocks:
        if b.start not in seen:
            rows.append({"label": b.hosts[0] if b.hosts else b.addresses[0], "hosts": b.hosts,
                         "status": "management" if set(b.hosts) & management else "not_loaded",
                         "pre_handlers": [], "detail": "This site block is not in Caddy's running configuration.",
                         "source": "main", "line": b.start, "import": scan.block_import_state(text, b, src.path)})
    return rows


def _last_apply():
    """Newest successful apply, from the audit log (the state file is never
    rewritten after commit, so it cannot carry this)."""
    for path in (config.AUDIT_LOG, audit.rotated_path()):
        for line in reversed(audit.tail_lines(path, 500)):
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict) and entry.get("action") == "bans_policy_applied":
                return {"time": entry.get("time"), "user": entry.get("user"), "detail": entry.get("detail")}
    return None


def status(remote_addr) -> dict:
    avail = availability()
    info = recovery_info()
    try:
        state = store.load()
    except store.StateCorrupt:
        state = None
    now = store.utc_now()
    src = render.SOURCES["manual"]
    prefixes = render.effective_prefixes(state.records, now, "manual") if state else []
    holds = _holds(state) if state else {}
    try:
        live, caddy = caddy_admin.live_config(), {"reachable": True, "message": None}
    except caddy_admin.CaddyUnavailable as e:
        live, caddy = None, {"reachable": False, "message": f"The Caddy admin API is unreachable ({e})."}
    degraded = None
    if info["required"] and info["kind"] in ("journal", "state_corrupt"):
        degraded = {"kind": info["kind"], "reason": info["reason"], "phase": info["phase"], "message": info["summary"]}
    return {
        "enabled": True, "available": avail.ok,
        "unavailable": None if avail.ok else {"code": avail.code, "message": avail.message},
        "state_version": info["state_version"], "degraded": degraded, "recovery": info,
        "sources": {"manual": {
            "file": src.path, "import_line": src.import_line, "hold": "manual" in holds,
            "hold_reason": holds.get("manual"), "rendered_prefixes": len(prefixes),
            "active_records": sum(1 for r in (state.records if state else []) if r.source == "manual" and not r.expired(now)),
        }},
        "protected": protected_for(state or store.State(), _verified_client(remote_addr)).summary(),
        "sites": _site_rows(live, _read_caddyfile(), prefixes),
        "caddy": caddy, "limits": {"max_prefixes": config.BANS_MAX}, "last_apply": _last_apply(),
    }


# --- expiry (spec 1.5 'The expiry cleanup job') -------------------------------------------

def expire_tick(now=None) -> str:
    if not availability().ok:
        return "unavailable"
    with caddyfile_lock():
        if txn.resolve_pending() is not None:
            return "degraded"
        try:
            state = store.load()
        except store.StateCorrupt as e:
            store.quarantine(e.raw, str(e))
            return "corrupt"
        now = now or store.utc_now()
        holds = _holds(state)
        previous_raw = state.raw
        removed = store.prune_expired(state, now, sources=[n for n in render.SOURCES if n not in holds])
        aged = store.prune_management(state, now)
        if not removed and not aged:
            return "idle"
        outcome = txn.apply_locked(_candidates(state, protected_for(state), holds, now), actor="system", source="expiry")
    if not outcome.ok:
        return outcome.code
    try:
        store.save_snapshot(previous_raw)
    except OSError:
        pass
    for r in removed[:20]:
        audit.log_action("ban_expired", "system", f"{r.value} id={r.id}")
    if len(removed) > 20:
        audit.log_action("ban_expired", "system", f"and {len(removed) - 20} more")
    return "applied"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run --frozen python -m unittest tests.test_bans_service -v`
Expected: all tests PASS. Then run the whole suite: `uv run --frozen python -m unittest discover -s tests -t .`.

- [ ] **Step 5: Commit**

```bash
git add src/bans/service.py tests/test_bans_service.py
git commit -m "feat(bans): ban service with availability probe, holds, recovery and expiry"
```

---

### Task 10: HTTP API, feature gate, snippets metadata and validator warnings

**Files:**
- Create: `src/routes/security.py`
- Modify: `src/__init__.py` (import `config` module; register the blueprint when enabled)
- Modify: `src/routes/editor.py` (`index()`, `get_snippets()`, `validate()`)
- Modify: `src/snippets.json` (append two entries)
- Test: `tests/test_bans_api.py`

**Interfaces:**
- Consumes: `service.*` (Task 9), `scan.bans_warnings`, `scan.management_hosts`, `render.SOURCES`.
- Produces routes (all `login_required`; mutations under `/api/` so the existing CSRF hook applies): `GET /security` (page), `GET /api/security`, `GET /api/security/recovery`, `POST /api/security/recovery`, `POST /api/security/reapply`, `POST /api/security/reset`, `GET /api/bans[?covering=<ip>]`, `POST /api/bans`, `DELETE /api/bans/<record_id>`. Phase 4's `client-ip-profile`, `country-policy` and `cloudflare-ranges/refresh` routes are not added.
- Produces template variables `bans_enabled` (bool) for `index.html`; `GET /api/snippets` now returns `{snippets, context: {bans_dir, management_hosts}}` (context empty when disabled).
- Snippet metadata keys used by Task 14: `id`, `phase`, `scope`, `insert` (`site-first | copy-only`), `supported_modes`, `prerequisites`, `code`.

- [ ] **Step 1: Write the failing tests**

`tests/test_bans_api.py`:

```python
"""Security API: auth, CSRF, contracts and the BANS_ENABLED gate.

Run with:  uv run --frozen python -m unittest tests.test_bans_api -v
"""
import os
import re
import tempfile
import unittest
from unittest import mock

import tests._env as env
from tests import _bans

from src import config, create_app
from src.bans import service, store
from src.routes import editor as editor_mod

AUTH = _bans.AUTH
MUTATIONS = (("post", "/api/bans"), ("delete", "/api/bans/some-id"), ("post", "/api/security/reapply"),
             ("post", "/api/security/reset"), ("post", "/api/security/recovery"))


class SecurityApiTest(_bans.ApiCase):
    def setUp(self):
        super().setUp()
        service.reset_caches()

    def test_reads_need_login(self):
        for url in ("/api/security", "/api/security/recovery", "/api/bans"):
            self.assertEqual(self.client.get(url).status_code, 401, url)
        self.assertEqual(self.client.get("/security").status_code, 403)

    def test_mutations_need_login_and_csrf(self):
        for method, url in MUTATIONS:
            with self.subTest(url=url):
                call = getattr(self.client, method)
                self.assertEqual(call(url, json={}, headers=AUTH).status_code, 403)          # no CSRF token
                self.assertEqual(call(url, json={}, headers={"X-CSRF-Token": self.csrf}).status_code, 401)

    def test_ban_round_trip_over_http(self):
        r = self.post("/api/bans", {"value": "203.0.113.7", "duration": "4h", "reason": "<b>probe</b>"})
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        record = r.get_json()["record"]
        self.assertEqual(record["reason"], "<b>probe</b>")             # stored as plain data
        listed = self.get("/api/bans").get_json()["records"]
        self.assertEqual([x["id"] for x in listed], [record["id"]])
        self.assertEqual(self.get("/api/bans?covering=203.0.113.7").get_json()["exact_ids"], [record["id"]])
        self.assertEqual(self.delete(f"/api/bans/{record['id']}").status_code, 200)
        self.assertEqual(self.get("/api/bans").get_json()["records"], [])

    def test_payload_validation_codes(self):
        cases = ((["x"], "invalid_request"),
                 ({"value": "203.0.113.7", "duration": "1h"}, "invalid_duration"),
                 ({"value": "203.0.113.7", "duration": "4h", "reason": "x" * 501}, "invalid_reason"),
                 ({"value": "127.0.0.1", "duration": "4h"}, "protected_overlap"),
                 ({"value": "203.0.113.0/33", "duration": "4h"}, "invalid_range"))
        for payload, code in cases:
            with self.subTest(code=code):
                r = self.post("/api/bans", payload)
                self.assertEqual((r.status_code, r.get_json()["code"]), (400, code))

    def test_recovery_contract(self):
        r = self.post("/api/security/recovery", {"recovery_id": "x", "action": "drop_tables"})
        self.assertEqual(r.get_json()["code"], "invalid_action")
        r = self.post("/api/security/recovery", {"recovery_id": "x", "action": "use_previous"})
        self.assertEqual((r.status_code, r.get_json()["code"]), (409, "recovery_stale"))
        self.post("/api/bans", {"value": "203.0.113.7", "duration": "4h"})
        self.post("/api/bans", {"value": "192.0.2.1", "duration": "4h"})
        with open(store.STATE_PATH, "wb") as f:
            f.write(b"{broken")
        info = self.get("/api/security/recovery").get_json()
        self.assertEqual(info["kind"], "state_corrupt")
        for backup_id in ("../../etc/passwd", store.STATE_PATH, ""):
            r = self.post("/api/security/recovery", {"recovery_id": info["recovery_id"],
                                                     "action": "restore_backup", "backup_id": backup_id})
            self.assertEqual(r.get_json()["code"], "invalid_backup")

    def test_status_shape(self):
        body = self.get("/api/security").get_json()
        self.assertTrue({"enabled", "available", "degraded", "recovery", "sources", "protected",
                         "sites", "caddy", "limits", "last_apply", "state_version"} <= set(body))
        self.assertEqual(body["sources"]["manual"]["import_line"], f"import {env.BANS_DIR}/bans-manual*.caddy")

    def test_page_has_the_security_tab(self):
        html = self.get("/").get_data(as_text=True)
        self.assertIn('data-view="security"', html)
        self.assertIn('data-bans="on"', html)
        self.assertEqual(self.get("/security").status_code, 200)

    def test_snippets_carry_context_and_bans_dir(self):
        body = self.get("/api/snippets").get_json()
        site = next(s for s in body["snippets"] if s.get("id") == "manual-bans-site")
        self.assertEqual(site["code"], f"import {env.BANS_DIR}/bans-manual*.caddy\n")
        self.assertEqual((site["scope"], site["insert"]), ("site", "site-first"))
        self.assertEqual(body["context"]["bans_dir"], env.BANS_DIR)
        self.assertIsInstance(body["context"]["management_hosts"], list)

    def test_validate_reports_ban_import_problems(self):
        text = f"a.example.com {{\n\trespond 200\n\timport {env.BANS_DIR}/bans-manual*.caddy\n}}\n"
        warnings = self.post("/api/validate", {"content": text}).get_json()["warnings"]
        self.assertTrue(any("put the ban import first" in w for w in warnings), warnings)

    def test_editor_still_saves_while_bans_are_unavailable(self):
        with mock.patch.object(config, "BANS_DIR", tempfile.mkdtemp()):
            service.reset_caches()
            self.assertFalse(self.get("/api/security").get_json()["available"])
            r = self.post("/api/save", {"content": "example.com {\n\trespond 200\n}\n"})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))


class DisabledTest(unittest.TestCase):
    def test_everything_is_absent_and_nothing_is_checked(self):
        with mock.patch.object(config, "BANS_ENABLED", False), \
                mock.patch.object(config, "BANS_NEVER", "not-an-ip"), \
                mock.patch.object(service, "availability", side_effect=AssertionError("must not run")):
            app = create_app()
            app.testing = True
            client = app.test_client()
            html = client.get("/", headers=AUTH).get_data(as_text=True)
            csrf = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
            self.assertNotIn('data-view="security"', html)
            self.assertIn('data-bans="off"', html)
            for url in ("/security", "/api/security", "/api/security/recovery", "/api/bans"):
                self.assertEqual(client.get(url, headers=AUTH).status_code, 404, url)
            for method, url in MUTATIONS:
                r = getattr(client, method)(url, json={}, headers={**AUTH, "X-CSRF-Token": csrf})
                self.assertEqual(r.status_code, 404, url)
            ids = [s.get("id") for s in client.get("/api/snippets", headers=AUTH).get_json()["snippets"]]
            self.assertNotIn("manual-bans-site", ids)
            self.assertNotIn("manual-bans-recovery", ids)
            from src.bans import jobs
            self.assertIsNone(jobs.start_background())

    def test_invalid_bans_never_refuses_startup_when_enabled(self):
        with mock.patch.object(config, "BANS_NEVER", "203.0.113.7, nope"):
            service.reset_caches()
            with self.assertRaisesRegex(RuntimeError, "BANS_NEVER"):
                create_app()
        service.reset_caches()


if __name__ == "__main__":
    unittest.main()
```

`DisabledTest` imports `src.bans.jobs`, which Task 11 completes. Create it in this task as a stub so the gate is testable now:

```python
"""Background jobs for IP bans; see Task 11."""
from .. import config


def start_background():
    if not config.BANS_ENABLED:
        return None
    return None
```

Task 11 replaces it.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --frozen python -m unittest tests.test_bans_api -v`
Expected: FAIL (`/api/security` returns 404 while enabled; `data-bans` missing).

- [ ] **Step 3: Implement `src/routes/security.py`**

```python
"""Security view and IP-ban API (docs/security.md). Registered only when
BANS_ENABLED; every mutation is under /api/ so the app's CSRF hook covers it."""
from flask import Blueprint, jsonify, render_template, request, session

from ..auth import get_or_create_csrf, login_required
from ..bans import service

security_bp = Blueprint("security", __name__)


def _actor() -> str:
    return session.get("user", {}).get("email", "unknown")


def _payload():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def _reply(result):
    body, status = result
    return jsonify(body), status


@security_bp.route("/security")
@login_required
def page():
    return render_template("index.html", csrf_token=get_or_create_csrf(), bans_enabled=True)


@security_bp.route("/api/security", methods=["GET"])
@login_required
def security_status():
    return jsonify(service.status(request.remote_addr))


@security_bp.route("/api/security/recovery", methods=["GET"])
@login_required
def recovery_get():
    return jsonify(service.recovery_info())


@security_bp.route("/api/security/recovery", methods=["POST"])
@login_required
def recovery_post():
    return _reply(service.recovery_post(_payload(), _actor()))


@security_bp.route("/api/security/reapply", methods=["POST"])
@login_required
def reapply():
    return _reply(service.reapply(_payload() or {}, _actor(), request.remote_addr))


@security_bp.route("/api/security/reset", methods=["POST"])
@login_required
def reset():
    return _reply(service.reset(_payload(), _actor(), request.remote_addr))


@security_bp.route("/api/bans", methods=["GET"])
@login_required
def list_bans():
    return _reply(service.list_bans(request.args.get("covering")))


@security_bp.route("/api/bans", methods=["POST"])
@login_required
def add_ban():
    return _reply(service.add_ban(_payload(), _actor(), request.remote_addr))


@security_bp.route("/api/bans/<record_id>", methods=["DELETE"])
@login_required
def remove_ban(record_id):
    return _reply(service.remove_ban(record_id, _actor(), request.remote_addr))
```

Note `add_ban` receives `None` for a non-object body and answers `invalid_request`.

- [ ] **Step 4: Register the blueprint and gate it in `src/__init__.py`**

Add `from . import config as app_config` to the imports. After `app.register_blueprint(ops_bp)`:

```python
    # IP bans (docs/security.md). Disabled means no routes, checks or jobs at all.
    if app_config.BANS_ENABLED:
        from .bans import service as bans_service
        from .routes.security import security_bp
        bans_service.init_config()
        app.register_blueprint(security_bp)
```

- [ ] **Step 5: Template flag, snippets and validator warnings in `src/routes/editor.py`**

Add imports: `from urllib.parse import urlsplit` (already imports `urlparse`; add `urlsplit` to that line) and `from ..bans import render as bans_render, scan as bans_scan`.

Add a helper:

```python
def _console_host():
    """The console's own hostname, never offered the ban import."""
    return urlsplit(config.SERVER_URL).hostname if config.SERVER_URL_CONFIGURED else None
```

`index()` renders `render_template("index.html", csrf_token=get_or_create_csrf(), bans_enabled=config.BANS_ENABLED)`.

In `validate()`, after `warnings += upstream_resolve_warnings(content)`:

```python
    if config.BANS_ENABLED:
        warnings += bans_scan.bans_warnings(content, bans_render.SOURCES["manual"].path,
                                            bans_scan.management_hosts(content, _console_host()))
```

Replace `get_snippets()`:

```python
@editor_bp.route("/api/snippets", methods=["GET"])
@login_required
def get_snippets():
    snippets_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "snippets.json")
    with open(snippets_path) as f:
        snippets = json.load(f)
    if not config.BANS_ENABLED:
        return jsonify({"snippets": [s for s in snippets if "BANS_ENABLED" not in s.get("prerequisites", [])],
                        "context": {}})
    bans_dir = config.BANS_DIR.rstrip("/")
    for s in snippets:
        if s.get("phase"):
            s["code"] = s["code"].replace("/etc/caddy/console/", bans_dir + "/")
    try:
        with open(CADDYFILE, encoding="utf-8", newline="") as f:
            text = f.read()
    except (OSError, UnicodeError):
        text = ""
    return jsonify({"snippets": snippets, "context": {
        "bans_dir": bans_dir,
        "management_hosts": sorted(bans_scan.management_hosts(text, _console_host())),
    }})
```

The recovery snippet's host path `/opt/caddy/console/` is not touched by the replacement (it does not contain `/etc/caddy/console/`).

- [ ] **Step 6: Append the two Phase 1 snippets to `src/snippets.json`**

```json
  {
    "id": "manual-bans-site",
    "name": "Manual bans: protect this site",
    "description": "Answer 403 to addresses banned in Security. Goes first in a site block.",
    "phase": "manual",
    "scope": "site",
    "insert": "site-first",
    "supported_modes": ["direct", "cloudflare-proxied", "cloudflare-tunnel"],
    "prerequisites": ["BANS_ENABLED"],
    "code": "import /etc/caddy/console/bans-manual*.caddy\n"
  },
  {
    "id": "manual-bans-recovery",
    "name": "Manual bans: host recovery",
    "description": "Shell commands to clear manual bans from the host if you lock yourself out. Copy only.",
    "phase": "manual",
    "scope": "host",
    "insert": "copy-only",
    "supported_modes": ["direct", "cloudflare-proxied", "cloudflare-tunnel"],
    "prerequisites": ["BANS_ENABLED"],
    "code": "docker compose -f docker-compose.prod.yaml stop caddy-console\nsudo sh -c ': > /opt/caddy/console/bans-manual.caddy'\ndocker compose -f docker-compose.prod.yaml exec caddy sh -c \\\n  'caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile \\\n   --address \"${CADDY_ADMIN_ADDRESS:-localhost:2019}\"'\ndocker compose -f docker-compose.prod.yaml start caddy-console\n"
  }
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `uv run --frozen python -m unittest tests.test_bans_api tests.test_app -v`
Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add src/routes/security.py src/__init__.py src/routes/editor.py src/snippets.json \
  src/bans/jobs.py tests/test_bans_api.py
git commit -m "feat(bans): Security API behind BANS_ENABLED, ban snippets and import warnings"
```

---

### Task 11: Per-worker expiry job

**Files:**
- Modify: `src/bans/jobs.py` (replace the Task 10 stub)
- Modify: `gunicorn.conf.py` (add `post_worker_init`)
- Modify: `app.py` (dev server start)
- Test: `tests/test_bans_jobs.py`

**Interfaces:**
- Consumes: `service.expire_tick()`.
- Produces: `TICK_SECONDS = 30`; `start_background() -> threading.Event | None` (None when disabled or already started); `_loop(stop)` runs one tick immediately (this is the startup journal recovery) and then every `TICK_SECONDS`.

The thread runs in every gunicorn worker, never in the master: `caddyfile_lock()` is an `flock` on a fresh fd, and a master thread holding it while gunicorn forks a worker would leave the lock held through the child's inherited fd. Ticks from several workers are serialized by the lock and an idle tick only reads files, so no leader election is needed.

- [ ] **Step 1: Write the failing tests**

`tests/test_bans_jobs.py`:

```python
"""Expiry job wiring.

Run with:  uv run --frozen python -m unittest tests.test_bans_jobs -v
"""
import importlib.util
import inspect
import os
import threading
import unittest
from unittest import mock

import tests._env  # noqa: F401

from src import config
from src.bans import jobs, service

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class JobsTest(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(jobs, "_started", False)
        p.start()
        self.addCleanup(p.stop)

    def test_tick_runs_at_least_once_a_minute(self):
        self.assertLessEqual(jobs.TICK_SECONDS, 60)

    def test_disabled_starts_nothing(self):
        with mock.patch.object(config, "BANS_ENABLED", False):
            self.assertIsNone(jobs.start_background())

    def test_starts_once_per_process(self):
        with mock.patch.object(jobs, "_loop", lambda stop: None):
            self.assertIsInstance(jobs.start_background(), threading.Event)
            self.assertIsNone(jobs.start_background())

    def test_loop_ticks_immediately_and_survives_a_crash(self):
        calls, stop = [], threading.Event()

        def tick():
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("boom")
            stop.set()
        with mock.patch.object(service, "expire_tick", tick), mock.patch.object(jobs, "TICK_SECONDS", 0.01):
            jobs._loop(stop)
        self.assertEqual(len(calls), 2)

    def test_gunicorn_starts_jobs_in_workers_not_the_master(self):
        spec = importlib.util.spec_from_file_location("gconf", os.path.join(ROOT, "gunicorn.conf.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertNotIn("bans", inspect.getsource(module.when_ready))
        with mock.patch("src.bans.jobs.start_background") as start:
            module.post_worker_init(object())
        start.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --frozen python -m unittest tests.test_bans_jobs -v`
Expected: FAIL with `AttributeError: module 'src.bans.jobs' has no attribute 'TICK_SECONDS'`.

- [ ] **Step 3: Implement `src/bans/jobs.py`**

```python
"""Expiry cleanup at least once per minute, in every gunicorn worker.

Started from gunicorn's post_worker_init, never in the master: the master
would fork workers while its thread could hold caddyfile_lock(), and the
inherited fd would keep that flock held. Ticks from several workers are
serialized by the lock; an idle tick only reads files. The first tick runs
immediately, which is the startup recovery of an unfinished journal.
"""
import logging
import threading

from .. import config

log = logging.getLogger(__name__)
TICK_SECONDS = 30
_started = False


def _loop(stop) -> None:
    from . import service
    while True:
        try:
            service.expire_tick()
        except Exception:  # noqa: BLE001 - the thread must survive anything
            log.exception("IP bans: expiry tick crashed")
        if stop.wait(TICK_SECONDS):
            return


def start_background():
    global _started
    if _started or not config.BANS_ENABLED:
        return None
    _started = True
    stop = threading.Event()
    threading.Thread(target=_loop, args=(stop,), name="bans-expiry", daemon=True).start()
    return stop
```

- [ ] **Step 4: Wire gunicorn and the dev server**

Append to `gunicorn.conf.py`:

```python
def post_worker_init(worker):
    # Per worker, after fork; see src/bans/jobs.py for why never in the master.
    from src.bans.jobs import start_background as start_bans_jobs
    start_bans_jobs()
```

In `app.py`, inside `if __name__ == "__main__":` after `start_background()`:

```python
    from src.bans.jobs import start_background as start_bans_jobs
    start_bans_jobs()
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run --frozen python -m unittest tests.test_bans_jobs tests.test_bans_api -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add src/bans/jobs.py gunicorn.conf.py app.py tests/test_bans_jobs.py
git commit -m "feat(bans): per-worker expiry job that also settles journals at startup"
```

---
### Task 12: Security view

**Files:**
- Modify: `src/templates/index.html` (body flag, fourth tab, view section)
- Modify: `src/static/js/app/router.js`, `src/static/js/app/caddyfile.js`, `src/static/js/app/main.js`
- Create: `src/static/js/app/security-model.js`, `src/static/js/app/security.js`
- Modify: `src/static/css/style.css` (append a "Security view" section)
- Test: `tests/security-model.test.mjs` (new), `tests/shell.test.mjs` (edit the tab check), `tests/router.test.mjs` (append)

**Interfaces:**
- Consumes: `GET /api/security` and `GET /api/bans` shapes (Task 9), `POST /api/bans`, `DELETE /api/bans/<id>`, `POST /api/security/{recovery,reapply,reset}`; `confirmDialog` (`ui/dialog.js`), `toast` (`ui/toast.js`), `absoluteTime` (`format.js`), `Icon` (`icons.js`, name `shield` exists), `revealLine` (`core.js`).
- Produces (`security-model.js`): `DURATIONS`, `REASON_MAX`, `protectedLabel(category)`, `durationLabel(id)`, `expiryLabel(expiresAt, now)`, `banPayload({value, duration, reason})` (throws `Error` with a user message), `errorMessage(body, status)`, `outcomeText(body, verb)` -> `{kind, text}` (`verb` is `ban` or `unban`), `siteStatus(site)` -> `{label, tone, detail}`, `siteActions(site)` -> subset of `['insert', 'copy']`, `overallState(status, recordCount)` -> `{tone, title, body}`, `recoveryActionLabel(action)`. Task 13 adds `banState(lookup)`.
- Produces (`security.js`): `mountSecurity()`. Dispatches `app:insert-ban-import` with `{line}`; `main.js` handles it (reveals the line now; Task 14 upgrades it to an insertion).
- `<body data-bans="on|off">` tells plain modules whether bans exist.

- [ ] **Step 1: Write the failing tests**

`tests/security-model.test.mjs`:

```js
// Tests for src/static/js/app/security-model.js, plus a scan that no Security
// file writes HTML. Run with: node tests/security-model.test.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const APP = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app');
const M = await import(path.join(APP, 'security-model.js'));

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };
const NOW = Date.parse('2026-11-23T20:00:00Z');

console.log('\n--- durations and expiry ---');
check('durations are exactly the four spec values', () =>
  assert.deepEqual(M.DURATIONS.map(d => d.id), ['4h', '24h', '7d', 'permanent']));
check('expiry labels', () => {
  assert.equal(M.expiryLabel(null, NOW), 'Never expires');
  assert.equal(M.expiryLabel('2026-11-23T19:00:00Z', NOW), 'Expired');
  assert.equal(M.expiryLabel('2026-11-23T20:30:00Z', NOW), 'Expires in 30 min');
  assert.equal(M.expiryLabel('2026-11-24T01:00:00Z', NOW), 'Expires in 5 h');
  assert.equal(M.expiryLabel('2026-11-26T20:00:00Z', NOW), 'Expires in 3 days');
  assert.equal(M.expiryLabel('garbage', NOW), '');
});

console.log('\n--- input and errors ---');
check('banPayload trims and validates', () => {
  assert.deepEqual(M.banPayload({ value: ' 203.0.113.7 ', duration: '4h', reason: '' }),
    { value: '203.0.113.7', duration: '4h', reason: '' });
  assert.throws(() => M.banPayload({ value: ' ', duration: '4h' }), /IP address or CIDR/);
  assert.throws(() => M.banPayload({ value: '203.0.113.7', duration: '1h' }), /duration/);
  assert.equal(M.banPayload({ value: 'x', duration: '7d', reason: '😀'.repeat(500) }).reason.length, 1000);
  assert.throws(() => M.banPayload({ value: 'x', duration: '7d', reason: '😀'.repeat(501) }), /500/);
});
check('errorMessage returns plain text unchanged', () => {
  assert.equal(M.errorMessage({ message: '<img src=x onerror=alert(1)>' }, 400), '<img src=x onerror=alert(1)>');
  assert.equal(M.errorMessage({ error: 'csrf token missing or invalid' }, 403), 'csrf token missing or invalid');
  assert.equal(M.errorMessage(null, 502), 'Request failed (HTTP 502).');
});
check('outcome wording follows enforcement', () => {
  assert.deepEqual(M.outcomeText({ enforcement: 'enforced', record: { value: '203.0.113.7' } }, 'ban'),
    { kind: 'ok', text: 'Banned 203.0.113.7. Caddy reloaded.' });
  assert.equal(M.outcomeText({ enforcement: 'not_enabled', record: { value: 'x' } }, 'ban').kind, 'info');
  assert.equal(M.outcomeText({ enforcement: 'held', record: { value: 'x' } }, 'ban').kind, 'warn');
  assert.match(M.outcomeText({ enforcement: 'enforced', value: '203.0.113.8', still_covered_by: ['203.0.113.0/24'] }, 'unban').text,
    /still banned by 203\.0\.113\.0\/24/);
});

console.log('\n--- state and sites ---');
const site = (status, extra = {}) => ({ label: 'a.example.com', status, pre_handlers: [], detail: '', source: 'main', import: { present: false }, ...extra });
check('overall state, worst first', () => {
  assert.equal(M.overallState({ available: false, unavailable: { message: 'm' } }).title, 'Unavailable, not enforced');
  assert.equal(M.overallState({ available: true, degraded: { reason: 'live_mismatch', message: 'm' } }).title, 'Reload state unknown');
  assert.equal(M.overallState({ available: true, degraded: { reason: 'state_corrupt', message: 'm' } }).title, 'Degraded');
  assert.equal(M.overallState({ available: true, sources: { manual: { hold: true } }, sites: [] }).title, 'Policy differs from state');
  assert.equal(M.overallState({ available: true, sources: { manual: {} }, sites: [site('enforced'), site('not_imported')] }).title, 'Enforced on 1 site');
  assert.equal(M.overallState({ available: true, sources: { manual: {} }, sites: [site('not_imported')] }, 2).title, 'Stored but not imported');
  assert.equal(M.overallState({ available: true, sources: { manual: {} }, sites: [] }, 0).title, 'No site imports the ban list');
});
check('pre-handler sites name what runs first', () => {
  const s = M.siteStatus(site('enforced_pre_handler', { pre_handlers: ['redir', 'basic_auth'] }));
  assert.equal(s.label, 'Protected, pre-handler present');
  assert.match(s.detail, /redir, basic_auth/);
});
check('site actions: external is copy only, enforced and console sites get none', () => {
  assert.deepEqual(M.siteActions(site('not_imported')), ['insert', 'copy']);
  assert.deepEqual(M.siteActions(site('not_imported', { source: 'external' })), ['copy']);
  assert.deepEqual(M.siteActions(site('enforced')), []);
  assert.deepEqual(M.siteActions(site('management')), []);
  assert.deepEqual(M.siteActions(site('not_loaded', { import: { present: true } })), []);
});
check('protected labels', () => {
  assert.equal(M.protectedLabel('private'), 'private network');
  assert.equal(M.protectedLabel('nope'), 'protected range');
});

console.log('\n--- no HTML sinks ---');
for (const f of ['security.js', 'security-model.js', 'ban-dialog.js', 'ip-popover.js', 'snippet-insert.js', 'panels.js', 'ui/dialog.js']) {
  const p = path.join(APP, f);
  if (!fs.existsSync(p)) continue;
  check(`${f} never writes HTML`, () =>
    assert.doesNotMatch(fs.readFileSync(p, 'utf8'), /innerHTML|outerHTML|insertAdjacentHTML|dangerouslySetInnerHTML/));
}
console.log(`\n${passed} passed`);
```

In `tests/shell.test.mjs`, replace the first `check('tabs are Dashboard, Explore, Editor', ...)` with:

```js
check('tabs are Dashboard, Explore, Editor, then Security', () => assert.deepEqual(
  [...html.matchAll(/class="tab" data-view="(\w+)"/g)].map(m => m[1]), ['dashboard', 'explore', 'editor', 'security']));
check('the Security tab and view render only when bans are enabled', () => {
  for (const marker of ['data-view="security"', 'id="tab-security"']) {
    const at = html.indexOf(marker);
    const open = html.lastIndexOf('{% if bans_enabled %}', at);
    const close = html.lastIndexOf('{% endif %}', at);
    assert.ok(at > 0 && open >= 0 && open > close, `${marker} is not inside {% if bans_enabled %}`);
  }
});
```

In `tests/router.test.mjs`, insert before the final `console.log(`\n${passed} passed`);`:

```js
console.log('\n--- security ---');
check('security has its own path', () => {
  assert.equal(viewFromPath('/security'), 'security');
  assert.equal(viewFromPath('/security/'), 'security');
  assert.equal(pathFor('security'), '/security');
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node tests/security-model.test.mjs; node tests/shell.test.mjs; node tests/router.test.mjs`
Expected: FAIL (`Cannot find module .../security-model.js`; shell tab list mismatch; `viewFromPath('/security')` is `dashboard`).

- [ ] **Step 3: Implement `src/static/js/app/security-model.js`**

```js
// Wording and state for the Security view and the IP popover, kept DOM-free so
// node can test it. Everything returned is plain text; callers render it as
// text children, never as HTML.

export const DURATIONS = [
  { id: '4h', label: '4 hours' },
  { id: '24h', label: '24 hours' },
  { id: '7d', label: '7 days' },
  { id: 'permanent', label: 'Permanent' },
];
export const REASON_MAX = 500;

const PROTECTED = {
  loopback: 'loopback', private: 'private network', link_local: 'link-local', cgnat: 'carrier-grade NAT',
  ula: 'IPv6 unique local', special: 'reserved or multicast', docker: 'Docker network', never: 'BANS_NEVER',
  operator: 'your verified console address', profile: 'client-IP profile',
};
export const protectedLabel = (category) => PROTECTED[category] || 'protected range';
export const durationLabel = (id) => (DURATIONS.find(d => d.id === id) || {}).label || '';

export function expiryLabel(expiresAt, now = Date.now()) {
  if (!expiresAt) return 'Never expires';
  const t = Date.parse(expiresAt);
  if (!Number.isFinite(t)) return '';
  const left = t - now;
  if (left <= 0) return 'Expired';
  const min = Math.round(left / 60000);
  if (min < 60) return `Expires in ${Math.max(1, min)} min`;
  const hours = Math.round(min / 60);
  if (hours < 48) return `Expires in ${hours} h`;
  return `Expires in ${Math.round(hours / 24)} days`;
}

export function banPayload({ value, duration, reason } = {}) {
  const v = String(value ?? '').trim();
  if (!v) throw new Error('Enter an IP address or CIDR range.');
  if (!DURATIONS.some(d => d.id === duration)) throw new Error('Choose a duration.');
  const r = String(reason ?? '');
  if ([...r].length > REASON_MAX) throw new Error(`Keep the reason to ${REASON_MAX} characters.`);
  return { value: v, duration, reason: r };
}

export function errorMessage(body, status) {
  if (body && typeof body.message === 'string' && body.message) return body.message;
  if (body && typeof body.error === 'string' && body.error) return body.error;
  return status ? `Request failed (HTTP ${status}).` : 'Request failed.';
}

export function outcomeText(body, verb) {
  const value = body?.record?.value || body?.value || '';
  const done = `${verb === 'unban' ? 'Unbanned' : 'Banned'} ${value}`.trim();
  const covered = body?.still_covered_by || [];
  const still = verb === 'unban' && covered.length ? ` It is still banned by ${covered.join(', ')}.` : '';
  switch (body?.enforcement) {
    case 'enforced': return { kind: 'ok', text: `${done}. Caddy reloaded.${still}` };
    case 'not_enabled': return { kind: 'info', text: `${done}. No site imports the ban list yet, so it is not enforced.${still}` };
    case 'held': return { kind: 'warn', text: `${done}, but the ban file differs from the stored state. Re-apply in Security.` };
    case 'unchanged': return { kind: 'ok', text: `${done}. The effective ban list did not change.${still}` };
    default: return { kind: 'warn', text: `${done}. ${body?.message || ''}`.trim() };
  }
}

const SITE = {
  enforced: ['Protected', 'ok'],
  enforced_pre_handler: ['Protected, pre-handler present', 'warn'],
  imported_empty: ['Imported, no active bans', 'ok'],
  not_imported: ['Not enforced', 'none'],
  not_loaded: ['Not loaded yet', 'none'],
  unknown: ['Enforcement not verified', 'warn'],
  management: ['Console site, never banned', 'none'],
};

export function siteStatus(site) {
  const [label, tone] = SITE[site.status] || ['Unknown', 'warn'];
  const detail = {
    enforced_pre_handler: `These run before the ban check: ${(site.pre_handlers || []).join(', ')}. They do not serve the application, but they may redirect or contact an auth service first.`,
    not_imported: 'This site does not import the ban list.',
    not_loaded: 'Save & Reload to load this site into Caddy.',
    management: 'The console is excluded so a ban cannot lock you out.',
  }[site.status] || site.detail || '';
  return { label, tone, detail };
}

export function siteActions(site) {
  if (['enforced', 'enforced_pre_handler', 'imported_empty', 'management'].includes(site.status)) return [];
  if (site.import?.present) return [];
  return site.source === 'external' ? ['copy'] : ['insert', 'copy'];
}

const RELOAD_UNKNOWN = ['live_mismatch', 'caddy_unreachable'];

export function overallState(status, recordCount = 0) {
  if (!status) return { tone: 'none', title: 'Loading…', body: '' };
  if (!status.available) return { tone: 'crit', title: 'Unavailable, not enforced', body: status.unavailable?.message || '' };
  const d = status.degraded;
  if (d && (RELOAD_UNKNOWN.includes(d.reason) || ['reload_unknown', 'reload_failed'].includes(d.phase))) {
    return { tone: 'crit', title: 'Reload state unknown', body: d.message || '' };
  }
  if (d) return { tone: 'crit', title: 'Degraded', body: d.message || '' };
  if (status.sources?.manual?.hold) {
    return { tone: 'warn', title: 'Policy differs from state', body: 'The ban file was changed outside the console. Fix the records, then Re-apply.' };
  }
  const n = (status.sites || []).filter(s => ['enforced', 'enforced_pre_handler', 'imported_empty'].includes(s.status)).length;
  if (n) return { tone: 'ok', title: `Enforced on ${n} ${n === 1 ? 'site' : 'sites'}`, body: '' };
  if (recordCount > 0) return { tone: 'warn', title: 'Stored but not imported', body: 'No site imports the ban list, so these bans are not enforced yet.' };
  return { tone: 'none', title: 'No site imports the ban list', body: 'Add the import line to a site to enforce bans there.' };
}

export const recoveryActionLabel = (action) => ({
  use_candidate: 'Keep the new files and reload',
  use_previous: 'Restore the previous files and reload',
  restore_backup: 'Restore this backup',
}[action] || action);
```

- [ ] **Step 4: Router, view switch and template**

`src/static/js/app/router.js`: add `'security'` to `VIEWS`, `security: '/security'` to `PATHS`, and in `viewFromPath` add `if (clean === '/security') return 'security';`. Update the header comment's view list with `/security  IP bans (only when BANS_ENABLED)`.

`src/static/js/app/caddyfile.js`: import `{ mountSecurity } from './security.js'`, then in `showView` replace the first line with:

```js
  const known = ['dashboard', 'editor', 'explore'];
  // The Security view exists only when the server rendered it (BANS_ENABLED).
  if (document.getElementById('tab-security')) known.push('security');
  const view = known.includes(name) ? name : 'dashboard';
```

and after `if (view === 'explore') mountExplore();` add `if (view === 'security') mountSecurity();`.

`src/static/js/app/main.js`: import `revealLine` with `revealSite` from `./core.js`, and after the `app:open-site` listener add:

```js
// Security "Add import in editor": Task 14 turns this into a context-aware insertion.
document.addEventListener('app:insert-ban-import', (e) => {
  showView('editor');
  revealLine(e.detail.line);
});
```

`src/templates/index.html`: change `<body>` to `<body data-bans="{{ 'on' if bans_enabled else 'off' }}">`. After the Editor tab anchor add:

```html
    {% if bans_enabled %}<a class="tab" data-view="security" href="/security"><svg class="icon" width="16" height="16" aria-hidden="true" focusable="false"><use href="#i-shield"/></svg>Security</a>{% endif %}
```

After the `tab-editor` section's closing `</section>` add:

```html
  {% if bans_enabled %}<section class="tab-content" id="tab-security" aria-label="Security"><div id="security-root"></div></section>{% endif %}
```

- [ ] **Step 5: Implement `src/static/js/app/security.js`**

```js
// Security view at /security: manual IP bans, where they are enforced, and
// recovery. Wording lives in security-model.js. Every string that came from a
// record or the API is a text child, which Preact writes as a text node.
import { h, htm, render, useEffect, useState } from '../explore-vendor.js';
import { Icon } from './icons.js';
import { absoluteTime } from './format.js';
import { confirmDialog } from './ui/dialog.js';
import { toast } from './ui/toast.js';
import {
  DURATIONS, banPayload, errorMessage, expiryLabel, outcomeText, overallState,
  protectedLabel, recoveryActionLabel, siteActions, siteStatus,
} from './security-model.js';

const html = htm.bind(h);
const REFRESH_MS = 30000;
const SEV = { crit: 'critical', warn: 'warn', ok: 'ok', none: 'ok' };

async function call(url, method = 'GET', payload) {
  const opts = { method };
  if (payload !== undefined) {
    opts.headers = { 'Content-Type': 'application/json' };
    opts.body = JSON.stringify(payload);
  }
  const r = await fetch(url, opts);
  const body = await r.json().catch(() => null);
  return { ok: r.ok && body?.ok !== false, status: r.status, body };
}

function copy(text, what) {
  navigator.clipboard.writeText(text).then(
    () => toast(`${what} copied`, { kind: 'ok' }),
    () => toast('Could not copy to the clipboard', { kind: 'error' }));
}

function Verdict({ status, records }) {
  const v = overallState(status, records);
  return html`
    <section class=${'verdict sev-' + SEV[v.tone]} role=${v.tone === 'crit' ? 'alert' : 'status'} aria-labelledby="sec-h">
      <h1 id="sec-h">${v.title}</h1>
      ${v.body && html`<p>${v.body}</p>`}
    </section>`;
}

function AddBan({ onDone }) {
  const [value, setValue] = useState('');
  const [duration, setDuration] = useState('24h');
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const submit = async (e) => {
    e.preventDefault();
    let payload;
    try { payload = banPayload({ value, duration, reason }); } catch (err) { setError(err.message); return; }
    setBusy(true); setError('');
    const r = await call('/api/bans', 'POST', payload);
    setBusy(false);
    if (!r.ok) { setError(errorMessage(r.body, r.status)); return; }
    const t = outcomeText(r.body, 'ban');
    toast(t.text, { kind: t.kind });
    setValue(''); setReason('');
    onDone();
  };
  return html`
    <form class="sec-add" onSubmit=${submit}>
      <label>IP address or CIDR range
        <input type="text" spellcheck="false" autocomplete="off" value=${value} onInput=${e => setValue(e.currentTarget.value)} /></label>
      <label>Duration
        <select value=${duration} onChange=${e => setDuration(e.currentTarget.value)}>
          ${DURATIONS.map(d => html`<option key=${d.id} value=${d.id}>${d.label}</option>`)}
        </select></label>
      <label class="grow">Reason (optional)
        <input type="text" value=${reason} onInput=${e => setReason(e.currentTarget.value)} /></label>
      <button class="btn btn-primary" type="submit" disabled=${busy}><${Icon} name="shield" size=${16} />Ban</button>
      ${error && html`<p class="sec-error" role="alert">${error}</p>`}
    </form>`;
}

function BanList({ records, onDone }) {
  if (!records.length) return html`<p class="metrics-hint">No manual bans.</p>`;
  const unban = async (r) => {
    const ok = await confirmDialog({ title: `Unban ${r.value}?`, body: 'New requests from this address are allowed again once Caddy reloads.', confirmLabel: 'Unban', danger: true });
    if (!ok) return;
    const res = await call(`/api/bans/${encodeURIComponent(r.id)}`, 'DELETE');
    if (!res.ok) { toast(errorMessage(res.body, res.status), { kind: 'error' }); return; }
    const t = outcomeText(res.body, 'unban');
    toast(t.text, { kind: t.kind });
    onDone();
  };
  return html`
    <table class="sec-table">
      <thead><tr><th>Address</th><th>Location</th><th>Reason</th><th>By</th><th>Created</th><th>Expiry</th><th><span class="sr">Actions</span></th></tr></thead>
      <tbody>${records.map(r => html`
        <tr key=${r.id} class=${r.expired ? 'expired' : ''}>
          <td class="mono">${r.value}${r.protected && html` <span class="sec-tag" title=${'Protected: ' + protectedLabel(r.protected)}>ignored, protected</span>`}</td>
          <td>${r.geo ? [r.geo.country_code, r.geo.asn_org].filter(Boolean).join(' · ') : ''}</td>
          <td class="sec-reason">${r.reason}</td>
          <td>${r.actor}</td>
          <td>${absoluteTime(r.created_at)}</td>
          <td>${r.expired ? 'Expired, removed at the next cleanup' : expiryLabel(r.expires_at)}</td>
          <td>${r.source === 'manual'
            ? html`<button class="btn sm" type="button" onClick=${() => unban(r)}>Unban</button>`
            : html`<span class="muted">Read-only</span>`}</td>
        </tr>`)}</tbody>
    </table>`;
}

function Sites({ sites, importLine }) {
  if (!sites.length) return html`<p class="metrics-hint">No sites in the running configuration.</p>`;
  return html`
    <ul class="sec-sites">${sites.map(s => {
      const st = siteStatus(s);
      const acts = siteActions(s);
      return html`
        <li key=${s.label + ':' + (s.line || '')} class=${'tone-' + st.tone}>
          <span class="mono">${s.label}</span>
          <span class="sec-state">${st.label}</span>
          ${st.detail && html`<span class="muted small">${st.detail}</span>`}
          <span class="acts">
            ${acts.includes('insert') && html`<button class="btn sm" type="button"
                onClick=${() => document.dispatchEvent(new CustomEvent('app:insert-ban-import', { detail: { line: s.line } }))}>Add import in editor</button>`}
            ${acts.includes('copy') && html`<button class="btn sm btn-quiet" type="button" onClick=${() => copy(importLine, 'Import line')}><${Icon} name="copy" size=${14} />Copy import</button>`}
          </span>
        </li>`;
    })}</ul>`;
}

function Protected({ groups }) {
  return html`
    <dl class="sec-protected">${groups.map(g => html`
      <div key=${g.category}><dt>${g.label}</dt><dd class="mono">${g.values.join(' ')}</dd></div>`)}
    </dl>`;
}

function Recovery({ info, onDone }) {
  if (!info?.required) return null;
  const finish = (r, okText) => {
    toast(r.ok ? okText : errorMessage(r.body, r.status), { kind: r.ok ? 'ok' : 'error' });
    onDone();
  };
  const run = async (action, backupId) => {
    const ok = await confirmDialog({ title: recoveryActionLabel(action), body: 'The console rewrites the managed files and reloads Caddy.', confirmLabel: 'Continue', danger: action !== 'use_candidate' });
    if (ok) finish(await call('/api/security/recovery', 'POST', { recovery_id: info.recovery_id, action, backup_id: backupId }), 'Recovered.');
  };
  const reapply = async () => finish(await call('/api/security/reapply', 'POST', { source: 'manual' }), 'Re-applied; Caddy reloaded.');
  const reset = async () => {
    const ok = await confirmDialog({ title: 'Delete every manual ban?', body: 'The list is emptied and Caddy reloads. This cannot be undone.', confirmLabel: 'Reset manual bans', danger: true });
    if (ok) finish(await call('/api/security/reset', 'POST', { source: 'manual', version: info.state_version, confirm: true }), 'Manual bans reset.');
  };
  return html`
    <section class="sec-recovery" aria-labelledby="sec-rec-h">
      <h2 id="sec-rec-h"><${Icon} name="warning" size=${16} />Recovery</h2>
      <p>${info.summary}</p>
      ${info.files.length > 0 && html`<p class="muted small">Files: ${info.files.join(', ')}</p>`}
      <div class="acts">
        ${info.actions.filter(a => a !== 'restore_backup').map(a => html`<button class="btn" type="button" key=${a} onClick=${() => run(a)}>${recoveryActionLabel(a)}</button>`)}
        ${info.reapply && html`<button class="btn btn-primary" type="button" onClick=${reapply}>Re-apply</button>`}
        ${info.reset && html`<button class="btn btn-danger" type="button" onClick=${reset}>Reset manual bans</button>`}
      </div>
      ${info.actions.includes('restore_backup') && html`
        <ul class="sec-backups">${info.backups.map(b => html`
          <li key=${b.id}>${absoluteTime(b.created_at)}, ${b.records} ${b.records === 1 ? 'record' : 'records'}
            <button class="btn sm" type="button" onClick=${() => run('restore_backup', b.id)}>${recoveryActionLabel('restore_backup')}</button></li>`)}
        </ul>`}
      <p class="muted small">If the console itself is unreachable, use the host recovery commands in docs/security.md.</p>
    </section>`;
}

function App() {
  const [status, setStatus] = useState(null);
  const [bans, setBans] = useState(null);
  const [error, setError] = useState(null);
  const load = async () => {
    const [s, b] = await Promise.all([call('/api/security'), call('/api/bans')]);
    if (!s.ok) { setError(errorMessage(s.body, s.status)); return; }
    setError(null);
    setStatus(s.body);
    setBans(b.ok ? b.body : { records: [], error: errorMessage(b.body, b.status) });
  };
  useEffect(() => {
    load();
    const t = setInterval(() => {
      if (document.getElementById('tab-security')?.classList.contains('active')) load();
    }, REFRESH_MS);
    return () => clearInterval(t);
  }, []);

  if (error && !status) return html`<div class="page"><p class="metrics-hint error">Could not load Security: ${error}</p></div>`;
  if (!status) return html`<div class="page"><p class="metrics-hint">Loading…</p></div>`;
  const records = bans?.records || [];
  const manual = status.sources.manual;
  const writable = status.available && !status.degraded;
  return html`
    <div class="page sec">
      <${Verdict} status=${status} records=${records.length} />
      <${Recovery} info=${status.recovery} onDone=${load} />
      <section aria-labelledby="sec-bans-h">
        <div class="h-sec"><h2 id="sec-bans-h">Manual bans</h2>
          <p>${manual.active_records} active, ${manual.rendered_prefixes} of ${status.limits.max_prefixes} prefixes rendered.</p></div>
        ${writable ? html`<${AddBan} onDone=${load} />` : html`<p class="metrics-hint">Changes are paused until the problem above is resolved.</p>`}
        ${bans?.error ? html`<p class="metrics-hint error">${bans.error}</p>` : html`<${BanList} records=${records} onDone=${load} />`}
      </section>
      <section aria-labelledby="sec-sites-h">
        <div class="h-sec"><h2 id="sec-sites-h">Sites</h2><p>Proven from Caddy's running configuration.</p></div>
        <p class="sec-import">Import line: <code>${manual.import_line}</code></p>
        <${Sites} sites=${status.sites} importLine=${manual.import_line} />
      </section>
      <section aria-labelledby="sec-prot-h">
        <div class="h-sec"><h2 id="sec-prot-h">Never banned</h2><p>Refused at input and excluded again by the generated policy.</p></div>
        <${Protected} groups=${status.protected} />
      </section>
      ${status.last_apply && html`<div class="foot">Last applied ${absoluteTime(status.last_apply.time)} by ${status.last_apply.user}.</div>`}
    </div>`;
}

let mounted = false;

export function mountSecurity() {
  const root = document.getElementById('security-root');
  if (!root || mounted) return;
  render(html`<${App} />`, root);
  mounted = true;
}
```

- [ ] **Step 6: Append minimal styles to `src/static/css/style.css`**

```css
/* Security view (src/static/js/app/security.js) */
.sec-add{display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end;margin-bottom:16px}
.sec-add label{display:flex;flex-direction:column;gap:4px;font-size:var(--t-sm);color:var(--ink-2)}
.sec-add label.grow{flex:1 1 220px}
.sec-error{flex-basis:100%;margin:0;color:var(--crit);font-size:var(--t-sm)}
.sec-table{width:100%;border-collapse:collapse;font-size:var(--t-sm)}
.sec-table th,.sec-table td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
.sec-table tr.expired{color:var(--ink-3)}
.sec-reason{white-space:pre-wrap;overflow-wrap:anywhere;max-width:32ch}
.sec-tag{font-size:var(--t-xs);color:var(--warn)}
.sec-sites{list-style:none;margin:0;padding:0}
.sec-sites li{display:grid;grid-template-columns:minmax(160px,1fr) minmax(160px,auto) auto;gap:4px 12px;padding:10px 0;border-bottom:1px solid var(--line)}
.sec-sites li .muted{grid-column:1/-1}
.sec-sites .tone-ok .sec-state{color:var(--good)} .sec-sites .tone-warn .sec-state{color:var(--warn)}
.sec-protected{display:grid;gap:8px;margin:0}
.sec-protected div{display:grid;grid-template-columns:220px 1fr;gap:12px}
.sec-protected dt{color:var(--ink-3)} .sec-protected dd{margin:0;overflow-wrap:anywhere}
.sec-recovery{padding:14px 18px;border-radius:var(--r-md);border:1px solid color-mix(in srgb,var(--crit) 25%,transparent);margin-bottom:20px}
.sec-recovery .acts{display:flex;gap:8px;flex-wrap:wrap}
@media (max-width:640px){.sec-table thead{display:none}.sec-table td{display:block;border:0;padding:2px 0}.sec-table tr{display:block;padding:8px 0;border-bottom:1px solid var(--line)}.sec-protected div,.sec-sites li{grid-template-columns:1fr}}
```

If a token used above (`--line`, `--t-xs`, `--good`) is not defined in `src/static/css/tokens.css`, use the nearest existing token from that file instead of adding a new one (`tests/tokens.test.mjs` checks contrast for defined text tokens).

- [ ] **Step 7: Run tests to verify they pass**

Run: `for t in tests/*.test.mjs; do node "$t" || exit 1; done`
Expected: every script ends with `N passed`.

- [ ] **Step 8: Check the view in the dev stack**

Run `./dev/run.sh up`, open http://localhost:8888/security, ban `203.0.113.7`, then unban it. Check at 1440 px and 390 px in light and dark themes: the empty state ("No site imports the ban list"), a healthy state after adding the import to `hello.example.com` by hand and saving, a degraded state (`docker compose -f docker-compose.dev.yaml stop caddy-target`, reload the view: "Unavailable, not enforced" after the 30 s probe cache, or "Reload state unknown" if a change was pending), then `start caddy-target`. A reason containing `<b>x</b>` must show the literal characters.

- [ ] **Step 9: Commit**

```bash
git add src/templates/index.html src/static/js/app/router.js src/static/js/app/caddyfile.js \
  src/static/js/app/main.js src/static/js/app/security-model.js src/static/js/app/security.js \
  src/static/css/style.css tests/security-model.test.mjs tests/shell.test.mjs tests/router.test.mjs
git commit -m "feat(bans): Security view with ban list, per-site status and recovery"
```

---

### Task 13: Ban and Unban from the Explore IP popover

**Files:**
- Modify: `src/static/js/app/ui/dialog.js` (add `formDialog`)
- Create: `src/static/js/app/ban-dialog.js`
- Modify: `src/static/js/app/ip-popover.js`
- Modify: `src/static/js/app/security-model.js` (add `banState`)
- Modify: `src/static/css/style.css` (dialog form and popover badge)
- Test: `tests/security-model.test.mjs` (append)

**Interfaces:**
- Consumes: `GET /api/bans?covering=<ip>` -> `{ip, protected, records, exact_ids}`; `POST /api/bans`; `DELETE /api/bans/<id>`; `DURATIONS`, `banPayload`, `errorMessage`, `outcomeText`, `protectedLabel`.
- Produces: `formDialog({title, body, fields, confirmLabel, cancelLabel, danger, validate}) -> Promise<object | null>` where `fields` is `[{name, label, type: 'text' | 'select' | 'textarea', options?, value?, hint?}]`; `banAddress(value) -> Promise<body | null>`; `unbanRecords(ids, label) -> Promise<body | null>`; `banState(lookup) -> {banned, exact, coveredBy, coveredText, protectedText, canBan, canUnban}`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/security-model.test.mjs` before the "no HTML sinks" block:

```js
console.log('\n--- popover ban state ---');
const look = (records, exact, prot = null) => ({ ip: '203.0.113.8', protected: prot, records, exact_ids: exact });
const exactRec = { id: 'e1', value: '203.0.113.8' };
const rangeRec = { id: 'r1', value: '203.0.113.0/24' };
check('a protected address offers no Ban', () => {
  const s = M.banState(look([], [], 'private'));
  assert.equal(s.canBan, false);
  assert.match(s.protectedText, /private network/);
});
check('an exact record offers Unban', () => {
  const s = M.banState(look([exactRec], ['e1']));
  assert.deepEqual([s.banned, s.canUnban, s.canBan], [true, true, false]);
});
check('banState after removing the exact record still reports the covering range', () => {
  const s = M.banState(look([rangeRec], []));
  assert.deepEqual([s.banned, s.canUnban, s.canBan], [true, false, true]);
  assert.equal(s.coveredText, 'Banned by 203.0.113.0/24');
});
check('both exact and range', () => {
  assert.equal(M.banState(look([exactRec, rangeRec], ['e1'])).coveredText, 'Also covered by 203.0.113.0/24');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node tests/security-model.test.mjs`
Expected: FAIL with `TypeError: M.banState is not a function`.

- [ ] **Step 3: Add `banState` to `security-model.js`**

```js
/** What the IP popover can offer for one address, from GET /api/bans?covering=. */
export function banState(lookup) {
  const records = lookup?.records || [];
  const exact = lookup?.exact_ids || [];
  const coveredBy = [...new Set(records.filter(r => !exact.includes(r.id)).map(r => r.value))];
  const prot = lookup?.protected || null;
  return {
    banned: records.length > 0,
    exact,
    coveredBy,
    coveredText: coveredBy.length ? `${exact.length ? 'Also covered by' : 'Banned by'} ${coveredBy.join(', ')}` : '',
    protectedText: prot ? `Protected (${protectedLabel(prot)}), cannot be banned` : '',
    canBan: !prot && exact.length === 0,
    canUnban: exact.length > 0,
  };
}
```

- [ ] **Step 4: Add `formDialog` to `src/static/js/app/ui/dialog.js`**

```js
/** A small form in a dialog. Resolves to {name: value} on confirm, or null.
 *  `validate(values)` returns an error message to show, or null to accept. */
export function formDialog({ title, body = '', fields, confirmLabel = 'OK', cancelLabel = 'Cancel', danger = false, validate = null }) {
  const { d, ft } = build({ title, body });
  const bd = el('div', 'dlg-bd dlg-form');
  const inputs = {};
  for (const f of fields) {
    const id = 'fld-' + Math.random().toString(36).slice(2, 9);
    const label = el('label', 'dlg-label', f.label);
    label.htmlFor = id;
    let input;
    if (f.type === 'select') {
      input = el('select');
      for (const o of f.options) {
        const opt = el('option', '', o.label);
        opt.value = o.value;
        input.append(opt);
      }
    } else if (f.type === 'textarea') {
      input = el('textarea');
      input.rows = 3;
    } else {
      input = el('input');
      input.type = 'text';
      input.spellcheck = false;
      input.autocomplete = 'off';
    }
    input.id = id;
    input.name = f.name;
    if (f.value != null) input.value = f.value;
    inputs[f.name] = input;
    bd.append(label, input);
    if (f.hint) bd.append(el('p', 'dlg-hint', f.hint));
  }
  const error = el('p', 'dlg-error');
  error.setAttribute('role', 'alert');
  error.hidden = true;
  bd.append(error);
  d.insertBefore(bd, ft);
  const cancel = button(cancelLabel, 'btn-quiet');
  const ok = button(confirmLabel, danger ? 'btn-danger-solid' : 'btn-primary');
  ft.append(cancel, ok);
  return show(d, inputs[fields[0].name], (finish) => {
    const submit = () => {
      const values = Object.fromEntries(Object.entries(inputs).map(([k, v]) => [k, v.value]));
      const problem = validate ? validate(values) : null;
      if (problem) { error.textContent = problem; error.hidden = false; return; }
      finish(values);
    };
    ok.addEventListener('click', submit);
    cancel.addEventListener('click', () => finish(null));
    d.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && e.target.tagName === 'INPUT') { e.preventDefault(); submit(); }
    });
  }, null);
}
```

- [ ] **Step 5: Implement `src/static/js/app/ban-dialog.js`**

```js
// Ban and Unban flows shared by the IP popover. Confirmation and input use the
// app's own dialogs; results are toasts with plain-text messages.
import { confirmDialog, formDialog } from './ui/dialog.js';
import { toast } from './ui/toast.js';
import { DURATIONS, banPayload, errorMessage, outcomeText } from './security-model.js';

async function send(url, method, payload) {
  const opts = { method };
  if (payload) { opts.headers = { 'Content-Type': 'application/json' }; opts.body = JSON.stringify(payload); }
  const r = await fetch(url, opts);
  const body = await r.json().catch(() => null);
  if (!r.ok || !body?.ok) { toast(errorMessage(body, r.status), { kind: 'error' }); return null; }
  return body;
}

export async function banAddress(value) {
  const values = await formDialog({
    title: `Ban ${value}`,
    body: 'Caddy answers 403 to this address on every site that imports the ban list.',
    confirmLabel: 'Ban',
    danger: true,
    fields: [
      { name: 'value', label: 'IP address or CIDR range', type: 'text', value },
      { name: 'duration', label: 'Duration', type: 'select', value: '24h', options: DURATIONS.map(d => ({ value: d.id, label: d.label })) },
      { name: 'reason', label: 'Reason (optional)', type: 'textarea' },
    ],
    validate: (v) => { try { banPayload(v); return null; } catch (e) { return e.message; } },
  });
  if (!values) return null;
  const body = await send('/api/bans', 'POST', banPayload(values));
  if (body) { const t = outcomeText(body, 'ban'); toast(t.text, { kind: t.kind }); }
  return body;
}

export async function unbanRecords(ids, label) {
  const ok = await confirmDialog({ title: `Unban ${label}?`, body: 'New requests from this address are allowed again once Caddy reloads.', confirmLabel: 'Unban', danger: true });
  if (!ok) return null;
  let body = null;
  for (const id of ids) {
    body = await send(`/api/bans/${encodeURIComponent(id)}`, 'DELETE');
    if (!body) return null;
  }
  const t = outcomeText(body, 'unban');
  toast(t.text, { kind: t.kind });
  return body;
}
```

- [ ] **Step 6: Add the ban section to `src/static/js/app/ip-popover.js`**

Add imports:

```js
import { banAddress, unbanRecords } from './ban-dialog.js';
import { banState, errorMessage } from './security-model.js';
```

Add above `IpPopover`:

```js
const bansOn = () => typeof document !== 'undefined' && document.body?.dataset.bans === 'on';

function BanSection({ ip }) {
  const [look, setLook] = useState(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let live = true;
    fetch('/api/bans?covering=' + encodeURIComponent(ip))
      .then(r => r.json().then(body => ({ ok: r.ok, status: r.status, body })))
      .then(({ ok, status, body }) => { if (live) setLook(ok ? body : { error: errorMessage(body, status) }); })
      .catch(e => live && setLook({ error: e.message }));
    return () => { live = false; };
  }, [ip, tick]);
  if (!look) return null;
  if (look.error) return html`<div class="sect muted small">${look.error}</div>`;
  const s = banState(look);
  const refresh = (body) => { if (body) setTick(t => t + 1); };
  return html`
    <div class="sect ban-sect">
      ${s.banned && html`<span class="ban-badge"><${Icon} name="shield" size=${12} />Banned</span>`}
      ${s.coveredText && html`<span class="muted small">${s.coveredText}</span>`}
      ${s.protectedText && html`<span class="muted small">${s.protectedText}</span>`}
      ${s.canBan && html`<button class="btn sm" type="button" onClick=${async () => refresh(await banAddress(ip))}><${Icon} name="shield" size=${14} />Ban…</button>`}
      ${s.canUnban && html`<button class="btn sm" type="button" onClick=${async () => refresh(await unbanRecords(s.exact, ip))}>Unban</button>`}
    </div>`;
}
```

In the `IpPopover` template, immediately before `<div class="sect acts">`, add:

```js
      ${bansOn() && info && info.kind === 'public' && html`<${BanSection} ip=${ip} />`}
```

Non-public kinds are always protected, so the section is not shown for them.

- [ ] **Step 7: Styles**

Append to `src/static/css/style.css`:

```css
.dlg-form{display:flex;flex-direction:column;gap:6px}
.dlg-form .dlg-label{font-size:var(--t-sm);color:var(--ink-2);margin-top:8px}
.dlg-form .dlg-error{color:var(--crit);font-size:var(--t-sm);margin:8px 0 0}
.ban-sect{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.ban-badge{display:inline-flex;gap:4px;align-items:center;font-weight:600;color:var(--crit)}
```

- [ ] **Step 8: Run tests and check in the dev stack**

Run: `for t in tests/*.test.mjs; do node "$t" || exit 1; done`
Expected: all pass, including `no-native-dialogs` and the HTML-sink scan of the new files.

In the dev stack, seed logs (`docs/development.md`), open Explore, expand an event with a public client IP, use **Ban…**, see **Banned** and **Unban**; ban `203.0.113.0/24` in Security, unban the exact IP and confirm the popover now reads "Banned by 203.0.113.0/24".

- [ ] **Step 9: Commit**

```bash
git add src/static/js/app/ui/dialog.js src/static/js/app/ban-dialog.js src/static/js/app/ip-popover.js \
  src/static/js/app/security-model.js src/static/css/style.css tests/security-model.test.mjs
git commit -m "feat(bans): ban and unban from the IP popover with a Banned badge"
```

---

### Task 14: Context-aware ban snippet insertion

**Files:**
- Create: `src/static/js/app/snippet-insert.js`
- Modify: `src/static/js/app/caddyfile-sites.js` (`&(name)` named routes are not sites)
- Modify: `src/static/js/app/panels.js`
- Modify: `src/static/js/app/main.js` (upgrade the `app:insert-ban-import` handler)
- Test: `tests/snippet-insert.test.mjs` (new), `tests/caddyfile-sites.test.mjs` (append)

**Interfaces:**
- Consumes: `siteBlocks` (`caddyfile-sites.js`); `GET /api/snippets` -> `{snippets, context: {bans_dir, management_hosts}}` (Task 10); snippet fields `insert`, `scope`, `code`, `id`.
- Produces: `globToRegExp(glob)`, `importMatches(token, target)`, `planSiteInsertion(text, cursorLine, code, {target, managementHosts}) -> {ok: true, block, line, text} | {ok: false, reason: 'outside-site' | 'duplicate' | 'management-site', block?, line?}`; `panels.insertSiteFirst(snippet, cursorLine) -> boolean`; `panels.insertBanImportAtLine(siteLine) -> Promise<boolean>`.

The editor buffer is the only thing that changes; the operator reviews the diff and uses Check and Save & Reload as usual.

- [ ] **Step 1: Write the failing tests**

`tests/snippet-insert.test.mjs`:

```js
// Tests for src/static/js/app/snippet-insert.js and the shipped ban snippets.
// Run with: node tests/snippet-insert.test.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.join(import.meta.dirname, '..');
const { globToRegExp, importMatches, planSiteInsertion } = await import(path.join(ROOT, 'src', 'static', 'js', 'app', 'snippet-insert.js'));
let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };

const T = '/etc/caddy/console/bans-manual.caddy';
const CODE = 'import /etc/caddy/console/bans-manual*.caddy\n';
const OPTS = { target: T, managementHosts: ['console.example.com'] };
const CF = [
  '{', '\tadmin 0.0.0.0:2019', '}', '',                                   // 1-4
  '(snip) {', '\theader -Server', '}', '',                                // 5-8
  '&(app) {', '\trespond "x"', '}', '',                                   // 9-12
  'a.example.com {', '\treverse_proxy 127.0.0.1:9', '}', '',              // 13-16
  'b.example.com {', '    encode gzip', '    reverse_proxy 127.0.0.1:9', '}', '',   // 17-21
  'c.example.com {', '\troute {', '\t\timport /etc/caddy/console/*.caddy', '\t}', '}', '',  // 22-27
  'console.example.com {', '\treverse_proxy caddy-console:9090', '}',    // 28-30
].join('\n');
const applyPlan = (text, plan) => {
  const lines = text.split('\n');
  lines.splice(plan.line - 1, 0, plan.text.replace(/\n$/, ''));
  return lines.join('\n');
};

check('inserts first in the site, with the block indentation', () => {
  for (const cursor of [13, 14, 15]) {
    const p = planSiteInsertion(CF, cursor, CODE, OPTS);
    assert.deepEqual([p.ok, p.line, p.text], [true, 14, '\timport /etc/caddy/console/bans-manual*.caddy\n']);
  }
  const b = planSiteInsertion(CF, 18, CODE, OPTS);
  assert.deepEqual([b.line, b.text], [18, '    import /etc/caddy/console/bans-manual*.caddy\n']);
});
check('outside a site block nothing is inserted', () => {
  for (const cursor of [2, 6, 10, 16]) assert.equal(planSiteInsertion(CF, cursor, CODE, OPTS).reason, 'outside-site', `line ${cursor}`);
});
check('an equivalent import is never inserted twice', () => {
  assert.deepEqual([planSiteInsertion(CF, 23, CODE, OPTS).reason, planSiteInsertion(CF, 23, CODE, OPTS).line], ['duplicate', 24]);
  const once = applyPlan(CF, planSiteInsertion(CF, 14, CODE, OPTS));
  assert.equal(planSiteInsertion(once, 14, CODE, OPTS).reason, 'duplicate');
});
check('the console site is never offered the import', () =>
  assert.equal(planSiteInsertion(CF, 29, CODE, OPTS).reason, 'management-site'));
check('glob matching follows Caddy', () => {
  assert.equal(importMatches('access_log', T), false);
  assert.equal(importMatches('/etc/caddy/*.caddy', T), false);
  assert.equal(importMatches('/etc/caddy/console/*.caddy', T), true);
  assert.equal(importMatches('console/bans-manual*.caddy', T), true);
  assert.equal(globToRegExp('/a/b?.caddy').test('/a/bx.caddy'), true);
});

const snippets = JSON.parse(fs.readFileSync(path.join(ROOT, 'src', 'snippets.json'), 'utf8'));
check('the site snippet carries the spec metadata', () => {
  const s = snippets.find(x => x.id === 'manual-bans-site');
  assert.deepEqual({ id: s.id, phase: s.phase, scope: s.scope, supported_modes: s.supported_modes, prerequisites: s.prerequisites, code: s.code }, {
    id: 'manual-bans-site', phase: 'manual', scope: 'site',
    supported_modes: ['direct', 'cloudflare-proxied', 'cloudflare-tunnel'], prerequisites: ['BANS_ENABLED'],
    code: 'import /etc/caddy/console/bans-manual*.caddy\n',
  });
});
check('scopes: site snippets insert first, host snippets are copy only', () => {
  for (const s of snippets.filter(x => x.scope)) {
    assert.equal(s.insert, s.scope === 'site' ? 'site-first' : 'copy-only', s.id);
  }
  assert.doesNotMatch(snippets.find(x => x.id === 'manual-bans-recovery').code, /^import /m);
});
console.log(`\n${passed} passed`);
```

Append to `tests/caddyfile-sites.test.mjs` before its final `console.log`:

```js
check('named routes are not site blocks', () =>
  assert.deepEqual(siteBlocks('&(app) {\n\trespond 200\n}\na.example.com {\n}\n').map(b => b.hosts), [['a.example.com']]));
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node tests/snippet-insert.test.mjs; node tests/caddyfile-sites.test.mjs`
Expected: FAIL (`Cannot find module .../snippet-insert.js`; `&(app)` reported as a site).

- [ ] **Step 3: Fix named routes in `caddyfile-sites.js`**

Change the block-start condition to:

```js
    if (depth === 0 && line.endsWith('{') && line !== '{' && !line.startsWith('(') && !line.startsWith('&(')) {
```

and extend the comment above it: `` `&(name) {` opens a named route (invoke). ``

- [ ] **Step 4: Implement `src/static/js/app/snippet-insert.js`**

```js
// Where a site-scoped snippet goes: first inside the site block under the
// cursor, never twice, never into the console's own site. Pure, so node can
// test it; panels.js applies the plan to the editor buffer only.
import { siteBlocks } from './caddyfile-sites.js';

/** Caddy/Go glob semantics: `*` and `?` never cross a `/`. */
export function globToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') re += '[^/]*';
    else if (c === '?') re += '[^/]';
    else if (c === '[' && glob.indexOf(']', i + 1) > i) { const end = glob.indexOf(']', i + 1); re += glob.slice(i, end + 1); i = end; }
    else re += c.replace(/[.+^${}()|\\\]]/g, '\\$&');
  }
  return new RegExp('^' + re + '$');
}

export function importMatches(token, target) {
  if (!token) return false;
  if (token.startsWith('/')) return globToRegExp(token).test(target);
  if (!token.includes('/') && !token.includes('.')) return false;   // a snippet or named-route name
  const base = (p) => p.slice(p.lastIndexOf('/') + 1);
  return globToRegExp(base(token)).test(base(target));             // relative: Caddy's cwd is unknown
}

const stripComment = (raw) => String(raw ?? '').replace(/(^|\s)#.*$/, '').trim();

export function planSiteInsertion(text, cursorLine, code, { target, managementHosts = [] } = {}) {
  const lines = String(text).split('\n');
  const block = siteBlocks(text).find(b => cursorLine >= b.start && cursorLine <= b.end);
  if (!block) return { ok: false, reason: 'outside-site' };
  if (block.hosts.some(h => managementHosts.includes(h))) return { ok: false, reason: 'management-site', block };
  // Interior lines are block.start + 1 .. block.end - 1 (1-based); lines[] is 0-based.
  for (let n = block.start + 1; n <= block.end - 1; n++) {
    const m = stripComment(lines[n - 1]).match(/^import\s+(\S+)/);
    if (m && importMatches(m[1], target)) return { ok: false, reason: 'duplicate', block, line: n };
  }
  const firstChild = lines.slice(block.start, block.end - 1).find(l => stripComment(l));
  const indent = (firstChild && firstChild.match(/^\s*/)[0]) || '\t';
  return { ok: true, block, line: block.start + 1, text: indent + String(code).trim() + '\n' };
}
```

- [ ] **Step 5: Use it from `src/static/js/app/panels.js`**

Add imports `import { planSiteInsertion } from './snippet-insert.js';`. Replace `loadSnippets` and `insertSnippet` with:

```js
let snippetData = null;

async function loadSnippetData() {
  if (!snippetData) snippetData = await fetchJson('/api/snippets');
  return snippetData;
}

export async function loadSnippets() {
  const list = document.getElementById('snippets-list');
  snippetData = null;            // the console site list comes from the file on disk; refresh on open
  let data;
  try { data = await loadSnippetData(); }
  catch (e) { snippetData = null; showError(list, 'Could not load snippets', e); return; }
  list.textContent = '';
  data.snippets.forEach((s) => {
    const card = document.createElement('button');
    card.type = 'button';
    card.className = 'snip';
    const name = document.createElement('b');
    name.textContent = s.name;
    const desc = document.createElement('span');
    desc.textContent = s.insert === 'copy-only' ? `${s.description} (copies to the clipboard)` : s.description;
    card.append(name, desc);
    card.addEventListener('click', () => insertSnippet(s));
    list.appendChild(card);
  });
}

const REFUSED = {
  'outside-site': 'Put the cursor inside a site block first; the import goes first in that site.',
  duplicate: 'This site already imports the ban list.',
  'management-site': "This is the console's own site; a ban there could lock you out, so the import is not offered.",
};

function copySnippet(s) {
  navigator.clipboard.writeText(s.code).then(
    () => toast(`Copied "${s.name}"`, { kind: 'ok' }),
    () => toast('Could not copy to the clipboard', { kind: 'error' }));
}

export function insertSiteFirst(s, cursorLine) {
  const ctx = snippetData?.context || {};
  const plan = planSiteInsertion(editorView.state.doc.toString(), cursorLine, s.code, {
    target: `${ctx.bans_dir || '/etc/caddy/console'}/bans-manual.caddy`,
    managementHosts: ctx.management_hosts || [],
  });
  if (!plan.ok) {
    toast(REFUSED[plan.reason], { kind: 'warn', action: { label: 'Copy', run: () => copySnippet(s) } });
    return false;
  }
  editorView.dispatch({ changes: { from: editorView.state.doc.line(plan.line).from, insert: plan.text } });
  setDot('yellow');
  closePanel('snippets');
  toast(`Inserted "${s.name}" at line ${plan.line}. Review it, then Save & Reload.`, { kind: 'ok' });
  return true;
}

export async function insertBanImportAtLine(siteLine) {
  let data;
  try { data = await loadSnippetData(); }
  catch (e) { snippetData = null; toast(`Could not load snippets: ${e.message}`, { kind: 'error' }); return false; }
  const s = data.snippets.find(x => x.id === 'manual-bans-site');
  return s ? insertSiteFirst(s, siteLine) : false;
}

function insertSnippet(s) {
  if (s.insert === 'copy-only') { copySnippet(s); return; }
  const pos = editorView.state.selection.main.head;
  const line = editorView.state.doc.lineAt(pos).number;
  if (s.insert === 'site-first') { insertSiteFirst(s, line); return; }
  editorView.dispatch({ changes: { from: pos, insert: s.code } });
  setDot('yellow');
  closePanel('snippets');
  toast(`Inserted "${s.name}" at line ${line}`, { kind: 'ok' });
}
```

- [ ] **Step 6: Upgrade the Security handler in `main.js`**

Import `insertBanImportAtLine` from `./panels.js` and replace the Task 12 handler body:

```js
document.addEventListener('app:insert-ban-import', async (e) => {
  showView('editor');
  if (!(await insertBanImportAtLine(e.detail.line))) revealLine(e.detail.line);
});
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `for t in tests/*.test.mjs; do node "$t" || exit 1; done`
Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add src/static/js/app/snippet-insert.js src/static/js/app/caddyfile-sites.js src/static/js/app/panels.js \
  src/static/js/app/main.js tests/snippet-insert.test.mjs tests/caddyfile-sites.test.mjs
git commit -m "feat(bans): insert the ban import first in the current site, never twice"
```

---

### Task 15: Stock Caddy integration suite and CI job

**Files:**
- Create: `tests/integration/_env.py`, `tests/integration/bans_caddy_it.py`, `tests/integration/bans_recovery_prep.py`
- Create: `dev/bans-it.sh` (executable)
- Modify: `.github/workflows/docker-publish.yml` (new `test-integration` job; `build-and-push.needs`)
- Modify: `docs/development.md` (Tests section)

**Interfaces:**
- Consumes: the dev stack (`docker-compose.dev.yaml`, `./tests` mounted read-only at `/app/tests` by Task 1), the real service/txn/caddy modules.
- Produces: `tests.integration.bans_caddy_it.CADDYFILE`, `reset_itest()`, `get(host, path="/", ip=ALLOWED)`, `BANNED`, `ALLOWED` (used by Task 16's benchmark); `dev/bans-it.sh` exit status as the Phase 1 integration gate.

The suite runs inside the console container: only it shares `/etc/caddy` with `caddy-target` and reaches port 2019. It uses its own Caddyfile at `/etc/caddy/itest/Caddyfile` (`dev/run/itest/` on the host, git-ignored) and its own `BACKUP_DIR` in `/tmp`, loads it into `caddy-target`, and restores `/etc/caddy/Caddyfile` afterwards. The test Caddyfile trusts private peers' `X-Forwarded-For` so the suite can act as public clients from inside Docker; that fixture belongs to the test only. CI runners have Docker (the build job already uses buildx), so CI runs the same script.

- [ ] **Step 1: Write the environment and the suite**

`tests/integration/_env.py`:

```python
"""Environment for the stock-Caddy suite. Import before anything from src."""
import os

ROOT = "/etc/caddy/itest"
BACKUP_DIR = "/tmp/bans-itest/backups"
BANS_DIR = f"{ROOT}/console"
API = os.environ.get("CADDY_API_URL", "http://caddy-target:2019")
DATA_URL = os.environ.get("CADDY_DATA_URL", "http://caddy-target:80")
for d in (ROOT, BACKUP_DIR, BANS_DIR, "/tmp/bans-itest/geoip"):
    os.makedirs(d, exist_ok=True)
os.environ.update({
    "BACKUP_DIR": BACKUP_DIR, "CADDYFILE_PATH": f"{ROOT}/Caddyfile", "BANS_DIR": BANS_DIR,
    "AUDIT_LOG": f"{BACKUP_DIR}/audit.log", "CADDY_API_URL": API, "AUTH_MODE": "cloudflare",
    "UNSAFE_ALLOW_UNVERIFIED_CF_HEADER": "true", "ALLOWED_EMAILS": "it@example.com",
    "SESSION_COOKIE_SECURE": "false", "GEOIP_AUTO_UPDATE": "false", "GEOIP_DIR": "/tmp/bans-itest/geoip",
    "BANS_ENABLED": "true", "BANS_NEVER": "", "SERVER_URL": "http://console.it.example.com",
})
```

`tests/integration/bans_caddy_it.py`:

```python
"""Manual file mode against stock caddy:2.11.9-alpine (spec "Caddy integration tests").

  docker compose -f docker-compose.dev.yaml exec -T caddy-console \
    /app/.venv/bin/python -m unittest tests.integration.bans_caddy_it -v
"""
import tests.integration._env as itenv  # noqa: I001  (must precede src imports)

import contextlib
import json
import os
import re
import shutil
import unittest
from datetime import timedelta
from unittest import mock

import requests

from src import create_app
from src.bans import addr, caddy as caddy_admin, detect, fsio, render, service, store, txn
from src.routes.editor import caddyfile_lock

D = itenv.BANS_DIR
SITE_LOG = "/var/log/caddy/itest-access.log"
BANNED, ALLOWED = "203.0.113.7", "203.0.113.8"
AUTH = {"Cf-Access-Authenticated-User-Email": "it@example.com"}
IMP = f"import {D}/bans-manual*.caddy"
HASH = "$2a$14$Zkx19XLiW6VYouLHR5NmfOFU0z2GTNmpkT/5qqR7hx4IjWJPDhjvG"
CADDYFILE = f"""{{
\tadmin 0.0.0.0:2019
\tservers {{
\t\ttrusted_proxies static private_ranges
\t\tclient_ip_headers X-Forwarded-For
\t}}
}}

&(named) {{
\trespond "named" 200
}}

http://proxy.it.example.com {{
\t{IMP}
\tlog {{
\t\toutput file {SITE_LOG} {{
\t\t\tmode 0644
\t\t}}
\t\tformat json
\t}}
\treverse_proxy 127.0.0.1:80 {{
\t\theader_up Host plain.it.example.com
\t}}
}}

http://plain.it.example.com {{
\trespond "plain" 200
}}

http://handle.it.example.com {{
\t{IMP}
\thandle /api/* {{
\t\trespond "api" 200
\t}}
\thandle {{
\t\trespond "app" 200
\t}}
}}

http://path.it.example.com {{
\t{IMP}
\thandle_path /static/* {{
\t\trespond "static" 200
\t}}
\thandle {{
\t\trespond "app" 200
\t}}
}}

http://route.it.example.com {{
\t{IMP}
\troute {{
\t\trespond "app" 200
\t}}
}}

http://strict.it.example.com {{
\troute {{
\t\t{IMP}
\t\tredir /old /new
\t\trespond "app" 200
\t}}
}}

http://redir.it.example.com {{
\t{IMP}
\tredir /old /new
\trespond "app" 200
}}

http://rewrite.it.example.com {{
\t{IMP}
\trewrite /old /new
\trespond "app" 200
}}

http://basicauth.it.example.com {{
\t{IMP}
\tbasic_auth {{
\t\tBob {HASH}
\t}}
\trespond "app" 200
}}

http://fwdauth.it.example.com {{
\t{IMP}
\tforward_auth 127.0.0.1:80 {{
\t\turi /verify
\t\theader_up Host auth.it.example.com
\t}}
\trespond "app" 200
}}

http://auth.it.example.com {{
\trespond 200
}}

http://invoke.it.example.com {{
\t{IMP}
\tinvoke named
}}

http://console.it.example.com {{
\treverse_proxy caddy-console:9090
}}
"""
BROKEN = CADDYFILE + "\nhttp://bad.it.example.com {\n\tlog {\n\t\toutput file /nonexistent-dir/x.log\n\t}\n\trespond 200\n}\n"


def write_caddyfile(text):
    with open(f"{itenv.ROOT}/Caddyfile", "w", encoding="utf-8") as f:
        f.write(text)


def reset_itest(load=True):
    for name in os.listdir(itenv.BACKUP_DIR):
        if name.startswith(("bans", ".bans", ".policy-transactions", "audit.log")):
            path = os.path.join(itenv.BACKUP_DIR, name)
            shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)
    shutil.rmtree(D, ignore_errors=True)
    os.makedirs(D)
    write_caddyfile(CADDYFILE)
    service.reset_caches()
    if load:
        assert caddy_admin.load(CADDYFILE).status == "applied"


def get(host, path="/", ip=ALLOWED):
    return requests.get(itenv.DATA_URL + path, headers={"Host": host, "X-Forwarded-For": ip},
                        allow_redirects=False, timeout=5)


@contextlib.contextmanager
def crash_at(point):
    class Crash(BaseException):
        pass

    def boom(name):
        if name == point:
            raise Crash(name)
    with mock.patch.object(txn, "_checkpoint", boom):
        try:
            yield
        except Crash:
            pass


class StockCaddyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open("/etc/caddy/Caddyfile", encoding="utf-8") as f:
            cls.dev_caddyfile = f.read()
        cls.app = create_app()
        cls.app.testing = True

    @classmethod
    def tearDownClass(cls):
        caddy_admin.load(cls.dev_caddyfile)

    def setUp(self):
        reset_itest()
        self.client = self.app.test_client()
        page = self.client.get("/", headers=AUTH).get_data(as_text=True)
        self.h = {**AUTH, "X-CSRF-Token": re.search(r'name="csrf-token" content="([^"]+)"', page).group(1)}

    def ban(self, value=BANNED, duration="4h"):
        r = self.client.post("/api/bans", json={"value": value, "duration": duration, "reason": ""}, headers=self.h)
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        return r.get_json()

    def sites(self):
        return {s["label"]: s for s in self.client.get("/api/security", headers=AUTH).get_json()["sites"]}

    def test_ban_and_unban_on_a_reverse_proxy_site(self):
        self.assertEqual(get("proxy.it.example.com", ip=BANNED).status_code, 200)
        body = self.ban()
        self.assertEqual(body["enforcement"], "enforced")
        self.assertEqual(get("proxy.it.example.com", ip=BANNED).status_code, 403)
        self.assertEqual(get("proxy.it.example.com").text, "plain")
        r = self.client.delete(f"/api/bans/{body['record']['id']}", headers=self.h)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(get("proxy.it.example.com", ip=BANNED).status_code, 200)

    def test_enforced_before_handle_handle_path_and_route(self):
        self.ban()
        for host, paths in (("handle.it.example.com", ("/", "/api/x")),
                            ("path.it.example.com", ("/", "/static/x")),
                            ("route.it.example.com", ("/",))):
            for p in paths:
                with self.subTest(host=host, path=p):
                    self.assertEqual(get(host, p, BANNED).status_code, 403)
                    self.assertEqual(get(host, p).status_code, 200)

    def test_path_specific_handle_does_not_bypass(self):
        self.ban()
        self.assertEqual(get("handle.it.example.com", "/api/x", BANNED).status_code, 403)
        self.assertEqual(get("handle.it.example.com", "/api/x").text, "api")

    def test_pre_handlers_are_reported_and_strict_route_enforces_first(self):
        self.ban()
        sites = self.sites()
        expect = {"proxy.it.example.com": ("enforced", []), "strict.it.example.com": ("enforced", []),
                  "redir.it.example.com": ("enforced_pre_handler", ["redir"]),
                  "rewrite.it.example.com": ("enforced_pre_handler", ["rewrite"]),
                  "basicauth.it.example.com": ("enforced_pre_handler", ["basic_auth"]),
                  "fwdauth.it.example.com": ("enforced_pre_handler", ["forward_auth"]),
                  "invoke.it.example.com": ("unknown", ["invoke"]),
                  "plain.it.example.com": ("not_imported", []),
                  "console.it.example.com": ("management", [])}
        for host, (status, pre) in expect.items():
            with self.subTest(host=host):
                self.assertEqual((sites[host]["status"], sites[host]["pre_handlers"]), (status, pre))
        self.assertEqual(get("strict.it.example.com", "/old", BANNED).status_code, 403)
        self.assertIn(get("redir.it.example.com", "/old", BANNED).status_code, (301, 302, 307, 308))
        self.assertEqual(get("redir.it.example.com", "/", BANNED).status_code, 403)
        self.assertEqual(get("rewrite.it.example.com", "/old", BANNED).status_code, 403)
        self.assertEqual(get("fwdauth.it.example.com", "/", BANNED).status_code, 403)
        self.assertEqual(get("fwdauth.it.example.com").status_code, 200)
        self.assertNotEqual(get("basicauth.it.example.com", "/", BANNED).status_code, 200)
        # Reported as not verified because the named route answers before the ban check:
        self.assertEqual(get("invoke.it.example.com", "/", BANNED).text, "named")

    def test_expiry_regenerates_and_reloads(self):
        self.ban(duration="4h")
        self.assertEqual(service.expire_tick(now=store.utc_now() + timedelta(hours=5)), "applied")
        self.assertEqual(get("proxy.it.example.com", ip=BANNED).status_code, 200)

    def test_crash_between_policy_and_state_replacement_recovers(self):
        self.ban("203.0.113.9", "permanent")
        before = fsio.read_bytes(store.STATE_PATH)
        with crash_at("replaced:bans-manual.caddy"):
            service.add_ban({"value": BANNED, "duration": "4h"}, "it@example.com", None)
        with caddyfile_lock():
            self.assertIsNone(txn.resolve_pending())
        self.assertEqual(fsio.read_bytes(store.STATE_PATH), before)
        self.assertEqual(get("proxy.it.example.com", ip=BANNED).status_code, 200)
        with crash_at("loaded"):
            service.add_ban({"value": BANNED, "duration": "4h"}, "it@example.com", None)
        with caddyfile_lock():
            self.assertIsNone(txn.resolve_pending())
        self.assertIn(BANNED, [r.value for r in store.load().records])
        self.assertEqual(get("proxy.it.example.com", ip=BANNED).status_code, 403)

    def test_protected_addresses_bypass_at_runtime(self):
        self.ban()
        state = store.load()
        state.records.append(store.new_manual_record(addr.canonical("10.0.0.0/16"), "permanent", "", "it", store.utc_now()))
        fsio.atomic_write(store.STATE_PATH, store.dumps(state), 0o600)
        r = self.client.post("/api/security/reapply", json={"source": "manual"}, headers=self.h)
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertIn(b"client_ip 10.0.0.0/16 203.0.113.7", fsio.read_bytes(render.SOURCES["manual"].path))
        self.assertEqual(get("proxy.it.example.com", ip="10.0.0.5").status_code, 200)
        self.assertEqual(get("proxy.it.example.com", ip=BANNED).status_code, 403)

    def test_exact_file_absence_fails_but_glob_absence_does_not(self):
        self.assertFalse(os.path.exists(render.SOURCES["manual"].path))
        self.assertEqual(get("proxy.it.example.com", ip=BANNED).status_code, 200)   # setUp loaded the glob
        exact = CADDYFILE.replace(f"{D}/bans-manual*.caddy", f"{D}/bans-manual.caddy", 1)
        self.assertFalse(caddy_admin.adapt(exact).ok)

    def test_empty_policy_keeps_its_marker_without_a_matcher(self):
        body = self.ban()
        self.client.delete(f"/api/bans/{body['record']['id']}", headers=self.h)
        live = caddy_admin.live_config()
        self.assertTrue(detect.marker_present(live, render.SOURCES["manual"].marker))
        self.assertNotIn('"client_ip":{"ranges"', caddy_admin.normalize(live).decode())
        self.assertEqual(self.sites()["proxy.it.example.com"]["status"], "imported_empty")

    def test_rejected_then_accepted_reload(self):
        write_caddyfile(BROKEN)                         # adapts, but cannot provision the log file
        policy_before = fsio.read_bytes(render.SOURCES["manual"].path)
        r = self.client.post("/api/bans", json={"value": BANNED, "duration": "4h"}, headers=self.h)
        self.assertEqual((r.status_code, r.get_json()["code"]), (502, "reload_rejected"))
        self.assertEqual(fsio.read_bytes(render.SOURCES["manual"].path), policy_before)
        self.assertEqual(get("proxy.it.example.com", ip=BANNED).status_code, 200)
        write_caddyfile(CADDYFILE)
        self.ban()
        self.assertEqual(get("proxy.it.example.com", ip=BANNED).status_code, 403)

    def test_403_appears_in_the_access_log(self):
        self.ban()
        self.assertEqual(get("proxy.it.example.com", "/probe-403", BANNED).status_code, 403)
        with open(SITE_LOG, encoding="utf-8") as f:
            last = [json.loads(line) for line in f if "/probe-403" in line][-1]
        self.assertEqual((last["status"], last["request"]["client_ip"]), (403, BANNED))

    def test_console_site_stays_reachable_and_is_never_offered_the_import(self):
        self.ban()
        self.assertEqual(get("console.it.example.com", "/health", BANNED).status_code, 200)
        self.assertEqual(self.sites()["console.it.example.com"]["status"], "management")
        context = self.client.get("/api/snippets", headers=AUTH).get_json()["context"]
        self.assertIn("console.it.example.com", context["management_hosts"])

    def test_shipped_site_snippet_adapts(self):
        snippets = self.client.get("/api/snippets", headers=AUTH).get_json()["snippets"]
        code = next(s["code"] for s in snippets if s.get("id") == "manual-bans-site")
        text = "{\n\tadmin 0.0.0.0:2019\n}\nhttp://snippet.it.example.com {\n\t" + code.strip() + "\n\trespond 200\n}\n"
        self.assertTrue(caddy_admin.adapt(text).ok)


if __name__ == "__main__":
    unittest.main()
```

`tests/integration/bans_recovery_prep.py` (leaves one enforced ban for the host-recovery check):

```python
"""Load the integration Caddyfile with 203.0.113.7 banned; used by dev/bans-it.sh."""
import tests.integration._env  # noqa: F401  (must precede src imports)

from src.bans import service
from tests.integration.bans_caddy_it import BANNED, reset_itest

reset_itest()
body, status = service.add_ban({"value": BANNED, "duration": "permanent"}, "it@example.com", None)
assert status == 201 and body["enforcement"] == "enforced", body
print("prepared: 203.0.113.7 banned")
```

- [ ] **Step 2: Write `dev/bans-it.sh`**

```bash
#!/usr/bin/env bash
# Stock-Caddy integration suite for IP bans (spec Phase 1 gate). Needs Docker.
# Leaves the dev stack running with its own Caddyfile restored.
set -euo pipefail
cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f docker-compose.dev.yaml)
PY=(/app/.venv/bin/python)
code() { curl -s -o /dev/null -w '%{http_code}' -H 'Host: proxy.it.example.com' -H 'X-Forwarded-For: 203.0.113.7' http://127.0.0.1:8081/; }

./dev/run.sh up
"${COMPOSE[@]}" exec -T caddy-console "${PY[@]}" -m unittest tests.integration.bans_caddy_it -v

# Host recovery exactly as documented: stop the console, truncate the policy,
# reload through the admin address inside the Caddy container, start again.
for address in localhost:2019 127.0.0.1:2019; do
  "${COMPOSE[@]}" exec -T caddy-console "${PY[@]}" -m tests.integration.bans_recovery_prep
  test "$(code)" = 403
  "${COMPOSE[@]}" stop caddy-console
  : > dev/run/itest/console/bans-manual.caddy
  "${COMPOSE[@]}" exec -T caddy-target caddy reload --config /etc/caddy/itest/Caddyfile \
    --adapter caddyfile --address "$address"
  test "$(code)" = 200
  "${COMPOSE[@]}" start caddy-console
  for _ in $(seq 1 30); do curl -sf -o /dev/null http://localhost:8888/health && break; sleep 1; done
  echo "host recovery via $address: ok"
done

"${COMPOSE[@]}" exec -T caddy-target caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --address localhost:2019
echo "bans integration: all passed"
```

Run `chmod +x dev/bans-it.sh`.

- [ ] **Step 3: Run the suite**

Run: `./dev/bans-it.sh`
Expected: `Ran 13 tests ... OK`, two `host recovery via ...: ok` lines and `bans integration: all passed`. If `test_rejected_then_accepted_reload` sees the `BROKEN` Caddyfile accepted (Caddy defers opening the log file), replace the `bad.it.example.com` block with an `https://bad.it.example.com` site using `tls /nonexistent/cert.pem /nonexistent/key.pem`, which adapts but cannot provision. A failure in `test_pre_handlers_are_reported_and_strict_route_enforces_first` or `test_path_specific_handle_does_not_bypass` means the spec's ordering guarantee does not hold on this Caddy build: stop and report.

- [ ] **Step 4: Add the CI job**

In `.github/workflows/docker-publish.yml`, add after `test-js`:

```yaml
  test-integration:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Stock Caddy integration (IP bans)
        run: ./dev/bans-it.sh

      - name: Logs on failure
        if: failure()
        run: docker compose -f docker-compose.dev.yaml logs --tail 200

      - name: Stop the dev stack
        if: always()
        run: ./dev/run.sh down
```

and change `build-and-push` to `needs: [test-python, test-js, test-integration]`.

- [ ] **Step 5: Document it**

In `docs/development.md`, under "## Tests", add after the existing block:

````markdown
The IP-ban integration suite needs Docker and runs against the stock Caddy in
the dev stack (CI runs it too):

```bash
./dev/bans-it.sh   # brings the stack up, runs tests/integration/bans_caddy_it.py
                   # inside the console container, then checks host recovery
```

It loads its own Caddyfile from `dev/run/itest/` and restores the dev one when
it finishes.
````

- [ ] **Step 6: Commit**

```bash
git add tests/integration/_env.py tests/integration/bans_caddy_it.py tests/integration/bans_recovery_prep.py \
  dev/bans-it.sh .github/workflows/docker-publish.yml docs/development.md
git commit -m "test(bans): stock Caddy integration suite with host recovery, run in CI"
```

---

### Task 16: Benchmark, released `BANS_MAX`, Compose passthrough and `docs/security.md`

**Files:**
- Create: `tests/integration/bans_benchmark.py`, `dev/check-compose.sh` (executable), `docs/security.md`
- Modify: `src/config.py` (`BANS_MAX` default), `tests/test_bans_config.py` (append the docs pin)
- Modify: `docker-compose.prod.yaml`, `docker-compose.tunnel.yaml`, `docker-compose.internal.yaml`, `docker-compose.nas.yaml` (console environment)
- Modify: `.github/workflows/docker-publish.yml` (`test-integration` gains a compose check step)
- Modify: `docs/setup.md` (link and environment rows)

**Interfaces:**
- Consumes: `tests.integration.bans_caddy_it.CADDYFILE`, `get`, `reset_itest`; `render`, `protected`, `fsio`, `caddy`.
- Produces: the measured default for `config.BANS_MAX` and a `docs/security.md` row `| \`BANS_MAX\` | \`<N>\` | ...` that `tests/test_bans_config.py` keeps in step.

Budgets (the spec names the dimensions, not the numbers; these are the plan's): at the chosen size, adaptation at most 2.0 s, `/load` at most 3.0 s, Caddy RSS at most 150 MiB above the 0-prefix run, and allowed-client p95 latency at most 2 ms above the 0-prefix run. The released default is `min(10000, largest size whose run and every smaller run meet all four)`. If 1,000 already fails, stop and report.

- [ ] **Step 1: Write the benchmark**

`tests/integration/bans_benchmark.py`:

```python
"""Manual file mode at 1,000 / 10,000 / 20,000 prefixes (spec Phase 1 gate).

  docker compose -f docker-compose.dev.yaml exec -T caddy-console \
    /app/.venv/bin/python -m tests.integration.bans_benchmark

Adaptation and reload time through the admin API, Caddy's resident memory from
its /metrics, and allowed-client latency, against stock caddy-target. Prints a
Markdown table and the BANS_MAX it supports.
"""
import tests.integration._env as itenv  # noqa: I001  (must precede src imports)

import ipaddress
import re
import statistics
import time

import requests

from src.bans import caddy as caddy_admin, fsio, protected, render
from tests.integration.bans_caddy_it import CADDYFILE, get, reset_itest

SIZES = (0, 1000, 10000, 20000)
BUDGET = {"adapt_s": 2.0, "load_s": 3.0, "rss_delta_mib": 150.0, "p95_delta_ms": 2.0}
REQUESTS = 300


def prefixes(n):
    base = int(ipaddress.ip_address("198.18.0.0"))         # benchmark range, not protected
    return [ipaddress.ip_network(base + 2 * i) for i in range(n)]   # gaps, so nothing collapses


def rss_mib():
    text = requests.get(f"{itenv.API}/metrics", timeout=5).text
    return float(re.search(r"^process_resident_memory_bytes (\S+)$", text, re.M).group(1)) / 2 ** 20


def latency():
    samples = []
    for _ in range(REQUESTS):
        t = time.perf_counter()
        assert get("proxy.it.example.com", ip="203.0.113.200").status_code == 200
        samples.append((time.perf_counter() - t) * 1000)
    samples.sort()
    return statistics.median(samples), samples[int(len(samples) * 0.95) - 1]


def measure(n):
    src = render.SOURCES["manual"]
    data = render.render_policy(src, prefixes(n), protected.build().exclusion_tokens(), 100000)
    fsio.atomic_write(src.path, data, 0o644)
    t = time.perf_counter()
    adapted = caddy_admin.adapt(CADDYFILE)
    adapt_s = time.perf_counter() - t
    assert adapted.ok, adapted.message
    t = time.perf_counter()
    loaded = caddy_admin.load(CADDYFILE)
    load_s = time.perf_counter() - t
    assert loaded.status == "applied", loaded.message
    time.sleep(2)
    if n:
        assert get("proxy.it.example.com", ip="198.18.0.0").status_code == 403
    p50, p95 = latency()
    return {"n": n, "kib": len(data) / 1024, "adapt_s": adapt_s, "load_s": load_s, "rss": rss_mib(), "p50": p50, "p95": p95}


def main():
    reset_itest()
    rows = [measure(n) for n in SIZES]
    base, best = rows[0], None
    print("| Prefixes | File | Adapt | Reload | Caddy RSS | p50 | p95 | Within budget |")
    print("|---:|---:|---:|---:|---:|---:|---:|:---|")
    for r in rows:
        r["ok"] = (r["adapt_s"] <= BUDGET["adapt_s"] and r["load_s"] <= BUDGET["load_s"]
                   and r["rss"] - base["rss"] <= BUDGET["rss_delta_mib"]
                   and r["p95"] - base["p95"] <= BUDGET["p95_delta_ms"])
        print(f"| {r['n']:,} | {r['kib']:.0f} KiB | {r['adapt_s']:.2f} s | {r['load_s']:.2f} s | "
              f"{r['rss']:.0f} MiB | {r['p50']:.2f} ms | {r['p95']:.2f} ms | {'yes' if r['ok'] else 'no'} |")
    for r in rows[1:]:
        if not r["ok"]:
            break
        best = r["n"]
    print(f"\nLargest size within budget: {best if best else 'none: stop and report'}")
    print(f"Released BANS_MAX: {min(10000, best) if best else 'none'}")
    with open("/etc/caddy/Caddyfile", encoding="utf-8") as f:
        caddy_admin.load(f.read())


main()
```

- [ ] **Step 2: Run it twice**

Run (twice, keep the worse value of each cell):
```bash
./dev/run.sh up
docker compose -f docker-compose.dev.yaml exec -T caddy-console \
  /app/.venv/bin/python -m tests.integration.bans_benchmark
```
Expected: a 4-row table and `Released BANS_MAX: <N>`. Record the host (CPU, RAM, Docker version) alongside the table.

- [ ] **Step 3: Pin the documented default with a failing test**

Add `import re` to the imports of `tests/test_bans_config.py` and append:

```python
class BansMaxDocumentedTest(unittest.TestCase):
    def test_default_matches_docs_security(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "docs", "security.md"), encoding="utf-8") as f:
            text = f.read()
        m = re.search(r"\| `BANS_MAX` \| `(\d+)` \|", text)
        self.assertIsNotNone(m, "docs/security.md has no BANS_MAX row")
        self.assertEqual(config.BANS_MAX, int(m.group(1)))
```

Run: `uv run --frozen python -m unittest tests.test_bans_config -v`
Expected: FAIL (`docs/security.md` does not exist yet).

- [ ] **Step 4: Set the default and write `docs/security.md`**

In `src/config.py`, replace `10000` in `bounded_int("BANS_MAX", 10000, 1, 100000)` with the released value N and update its comment to `# Measured by tests/integration/bans_benchmark.py; see docs/security.md.`

Create `docs/security.md` (fill N and the measured table from Step 2; everything else is final text):

````markdown
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
ban is never dropped silently. Measured on <host description>, stock Caddy
2.11.9, against the budgets adaptation ≤ 2 s, reload ≤ 3 s, +150 MiB RSS and
+2 ms p95:

<paste the benchmark table here>

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
   --address "${CADDY_ADMIN_ADDRESS:-localhost:2019}"'
docker compose -f docker-compose.prod.yaml start caddy-console
```

| Stack | Compose file | Host directory | Admin address for `--address` |
|---|---|---|---|
| Production | `docker-compose.prod.yaml` | `/opt/caddy` | `localhost:2019` |
| Internal | `docker-compose.internal.yaml` | `/opt/caddy` | `localhost:2019` |
| Tunnel | `docker-compose.tunnel.yaml` | `/opt/caddy` | `172.30.250.2:2019` (the fixed `admin` bind) |
| NAS | `docker-compose.nas.yaml` | `/volume2/docker/caddy/caddy` | `localhost:2019` |

When the console starts again, Security shows **Policy differs from state**.
Remove or correct the record that caused the lockout, then use **Re-apply**.
Recovery never needs port 2019 published.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `BANS_ENABLED` | `true` | Security API, background job and view. Sites are unchanged until they import the file. |
| `BANS_DIR` | `/etc/caddy/console` | Directory for generated Caddy files, inside the Caddyfile directory. |
| `BANS_MAX` | `N` | Maximum prefixes rendered into Caddy (measured above). |
| `BANS_NEVER` | empty | Extra protected IPs/CIDRs, comma or space separated. An invalid entry stops startup. |
````

Replace the `N` in the `BANS_MAX` row with the released value (for example `` `10000` ``) so the pin test matches.

- [ ] **Step 5: Pass the variables through every baseline Compose file**

In `docker-compose.prod.yaml`, `docker-compose.tunnel.yaml` and `docker-compose.internal.yaml`, add to the `caddy-console` `environment:` list (after `GEOIP_AUTO_UPDATE`):

```yaml
      - BANS_ENABLED
      - BANS_DIR
      - BANS_MAX
      - BANS_NEVER
```

In `docker-compose.nas.yaml` (mapping style), add:

```yaml
      BANS_ENABLED: "true"
      BANS_DIR: "/etc/caddy/console"
      BANS_NEVER: ""
```

`dev/check-compose.sh`:

```bash
#!/usr/bin/env bash
# Phase 1 gate: every baseline Compose file renders, passes BANS_* through and
# needs nothing from CrowdSec.
set -euo pipefail
cd "$(dirname "$0")/.."
export CADDY_CONSOLE_IMAGE=ghcr.io/example/caddy-console:sha-0000000 CLOUDFLARE_TUNNEL_TOKEN=dummy \
  SERVER_URL=https://console.example.com SECRET_KEY=dummy GOOGLE_CLIENT_ID=dummy \
  GOOGLE_CLIENT_SECRET=dummy ALLOWED_EMAILS=a@example.com BANS_ENABLED=true
for f in docker-compose.prod.yaml docker-compose.tunnel.yaml docker-compose.internal.yaml \
         docker-compose.nas.yaml docker-compose.dev.yaml; do
  out=$(docker compose -f "$f" config)
  if grep -qi crowdsec <<<"$out"; then echo "$f mentions CrowdSec" >&2; exit 1; fi
  grep -q 'BANS_ENABLED' <<<"$out" || { echo "$f does not pass BANS_ENABLED" >&2; exit 1; }
  echo "$f: ok"
done
```

Run `chmod +x dev/check-compose.sh`, then add a step to the `test-integration` CI job before the integration step:

```yaml
      - name: Baseline Compose files render without CrowdSec
        run: ./dev/check-compose.sh
```

- [ ] **Step 6: Link from `docs/setup.md`**

Add a section before "## Environment variables":

```markdown
## IP bans (optional)

Ban an IP or range from the **Security** view or the Explore IP popover; stock
Caddy enforces it on the sites that import the managed file. Setup, the
protected ranges, capacity and host recovery are in
[docs/security.md](security.md). No extra service is required.
```

and add the four rows from the `docs/security.md` Configuration table to the environment-variable table, matching its column layout.

- [ ] **Step 7: Run every gate**

Run:
```bash
uv run --frozen python -m unittest discover -s tests -t .
for t in tests/*.test.mjs; do node "$t" || exit 1; done
npm run build && git diff --exit-code -- src/static/js/
./dev/check-compose.sh
./dev/bans-it.sh
```
Expected: all green; `git diff` empty (no bundle changes).

Phase 1 gate checklist (spec "Delivery gates"): stock Caddy integration tests pass (Task 15); `handle`/`route` ordering tests pass (Task 15); corrupt state, journal crash recovery, expiry reload and ambiguous reload tests pass (Tasks 8, 9, 15); the benchmark set `BANS_MAX` and its budgets are in `docs/security.md` (this task); the console site stays reachable without the import (Task 15); baseline Compose renders and starts without CrowdSec variables (`check-compose.sh`, and `bans-it.sh` starts the dev stack).

- [ ] **Step 8: Commit**

```bash
git add tests/integration/bans_benchmark.py dev/check-compose.sh docs/security.md docs/setup.md \
  src/config.py tests/test_bans_config.py docker-compose.prod.yaml docker-compose.tunnel.yaml \
  docker-compose.internal.yaml docker-compose.nas.yaml .github/workflows/docker-publish.yml
git commit -m "docs(bans): measured BANS_MAX, security guide and Compose passthrough"
```

---

## Spec decisions this plan makes

Where the spec is silent or leaves a choice, the plan picks one. Reviewers should check these:

1. **Verified client IP in Phase 1** is the TCP peer only (`direct` profile). Behind cloudflared or a front proxy, nothing is registered; docs tell operators to use `BANS_NEVER`. Phase 4 adds header trust per profile.
2. **The management registry** changes only inside mutation transactions, not on every authenticated request, because a registry change changes the rendered exclusion and needs a reload.
3. **"Docker network ranges"** are the console container's IPv4 networks from `/proc/net/route`; the shipped stacks' networks are inside RFC 1918 already.
4. **Restorable backups for a corrupt `bans.json`** are the last 5 committed versions in `BACKUP_DIR/.bans-snapshots/` (transaction backups are deleted at commit, as spec step 13 says).
5. **During a policy hold**, ban and unban still update `bans.json` (state-only transaction, response `enforcement: held`); only Re-apply regenerates the file. A missing file with a recorded hash is also a hold, so "recreate only from valid stored state" happens through Re-apply's adapt and `/load`.
6. **`invoke`, a responder or an unknown handler** before the ban route make a site "Enforcement not verified"; `redir`, `rewrite`, `basic_auth`, `forward_auth`, `request_header` make it "Protected, pre-handler present". A custom `order` is judged by the live result, not by its presence.
7. **The editor's successful Save & Reload settles a pending ban journal** when every policy file is wholly at its candidate or previous version.
8. **Startup check and recovery are lazy and per worker**: the availability probe is cached (5 min ok, 30 s failure), and every worker's first expiry tick runs journal recovery. No thread runs in the gunicorn master.
9. **Host recovery is integration-tested** with `--address localhost:2019` and `127.0.0.1:2019` against the dev stack's wildcard listener; the tunnel stack's fixed `172.30.250.2:2019` is documented, and fixed-bind testing belongs to the Phase 3 plugin overlay.
10. **Benchmark budgets** (2 s adapt, 3 s reload, +150 MiB RSS, +2 ms p95) are this plan's numbers; the released `BANS_MAX` never exceeds the spec's 10,000 candidate.
11. **Error HTTP statuses**: input problems 400, capacity and version conflicts 409, adapt rejection 422, reload rejection 502, reload failed or degraded or unavailable 503, reload unknown 504, write or rollback failure 500.
