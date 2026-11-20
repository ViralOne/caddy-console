# UI Redesign to Direction A Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the whole Caddy Console UI to the approved "A · Refined" design, including every new data line the mockup shows, without changing any existing API field or behaviour.

**Architecture:** Backend gains six additive fields and warnings (Flask routes in `src/routes/`, pure helpers in `src/`). The frontend keeps its split: plain-DOM chrome modules and Preact+htm views (Dashboard, Explore). The design is ported, not reinvented. The mockup's custom properties become the app's tokens, the mockup's component CSS is copied into `style.css` section by section, and markup is changed to the mockup's class names. Logic that can be tested without a DOM goes into small pure modules with node tests.

**Tech Stack:** Python 3 / Flask / gunicorn, `unittest`; CodeMirror 6 (committed IIFE bundle `editor.bundle.js`), Preact + htm (committed ESM bundle `explore-vendor.js`), plain ES modules under `src/static/js/app/`, node `assert` test scripts; esbuild for bundles only.

**Spec:** `docs/superpowers/specs/2026-11-20-ui-direction-a-design.md` (authoritative). Design source: `poc-ui/a-refined/index.html` (called "the mockup" below; line numbers refer to that file as committed in `1e240f6`), audit: `poc-ui/AUDIT.md`.

## Global Constraints

- No new runtime dependencies: nothing added to `pyproject.toml` dependencies or `package.json` (Python stdlib, Flask/markupsafe and the existing npm devDependencies only).
- Every existing API field stays as it is (name, type, meaning). New fields are additive only.
- CSP stays strict: `script-src 'self'` plus exactly one `'sha256-…'` source for the inline theme script. No `'unsafe-inline'` in `script-src`. The hash is computed in Python from the same string the template renders (`src/theme_boot.py`), so the two cannot drift.
- Commit author is already configured. Do not run `git config`. One commit per task, conventional message given in the task.
- No native `alert()` or `confirm()` remains in `src/static/js/` (enforced by `tests/no-native-dialogs.test.mjs`).
- Status is never colour-only. Every state colour comes with an icon shape and/or a word.
- Works at 1440, 1024 and 390 px wide. No hover-only controls (exclude buttons, field menus and row toggles are always visible and keyboard-reachable).
- Hidden when null. A new data line whose source field is missing or `null` is not rendered, and is never shown as `0`.
- WCAG AA contrast in both themes for text tokens on all three surfaces (enforced by `tests/tokens.test.mjs`).
- Type scale 12/13/14/17/22/30, base 14 px, `font-variant-numeric: tabular-nums` on figures, no uppercase labels.
- Accent (`--accent`) only marks interactive things. 3xx uses `--info` as a data colour.
- Bundles (`src/static/js/editor.bundle.js`, `src/static/js/explore-vendor.js`) are committed. `npm run build` must leave `git diff -- src/static/js/` empty at the end (CI checks this).
- Test commands: `uv run --frozen python -m unittest discover -s tests -t .` and `for t in tests/*.test.mjs; do node "$t" || exit 1; done`. Existing tests are not edited.
- Dev stack: `./dev/run.sh up` serves http://localhost:8888, signed in as `dev@local`. If gunicorn `--reload` misses a Python change, run `docker compose -f docker-compose.dev.yaml restart caddy-console`. CSS, JS and template edits show on refresh.

## Review Focus

1. **Theme = System while the OS switches light/dark with the page open.** The page and the CodeMirror editor should follow without a reload. Pinned by `theme.test.mjs` "watchSystemTheme follows the OS only while the preference is system" (Task 9).
2. **An upstream that recovers and later fails again.** `unhealthy_since` should be the time of the new failure, not the old one. Pinned by `test_recovery_clears_and_a_new_failure_restarts_the_clock` (Task 2).
3. **Site addresses with a scheme, a port, comma lists or a wildcard** (`http://a.example.com, b.example.com:8443 {`, `*.example.com {`). "Open <site> block" should still land on the right line. Pinned by `caddyfile-sites.test.mjs` (Task 13).
4. **Save when the only warning is "not formatted".** Save formats on the server anyway, so no "Save with warnings?" dialog should appear. Pinned by `warnings.test.mjs` "blockingWarnings drops the format warning" (Task 11).
5. **Audit entries with Python microsecond timestamps, or with no time at all.** Recent changes should show a relative time, or nothing, but never "NaN" or "Invalid Date". Pinned by `format.test.mjs` "toMs accepts Python isoformat with microseconds" and "relativeTime of garbage is empty" (Task 10).

---

## File Structure

**Backend (new):**
- `src/upstream_health.py`: persisted upstream health transitions (`record()`), atomic JSON file plus flock.
- `src/theme_boot.py`: the inline `<head>` theme script string and its CSP hash.

**Backend (modified):**
- `src/eventindex.py`: `site_summary()` adds `previous_total`.
- `src/routes/ops.py`: `/api/upstreams` adds `unhealthy_since` and `configured_sites`. `/api/status` adds `last_change`.
- `src/audit.py`: `last_change()`.
- `src/validator.py`: `fmt_warning()`, `upstream_resolve_warnings()`, `resolve_hosts()`.
- `src/routes/editor.py`: `/api/validate` emits the two new warnings.
- `src/__init__.py`: CSP hash plus a template context processor.
- `src/config.py`: `SERVER_URL_CONFIGURED`.
- `src/auth.py`: `server_host()`. `/welcome` and the Cloudflare 403 page render `welcome.html`.
- `src/templates/index.html`, `src/templates/welcome.html`, `src/templates/_icons.html`.

**Frontend (new, under `src/static/js/app/`):**
- `theme.js`: theme preference, apply, follow the OS.
- `format.js`: time, size, duration, country, HTTP status text, backup-name dates.
- `ui/dialog.js`: `confirmDialog`, `alertDialog` on native `<dialog>`.
- `ui/toast.js`: `toast()`.
- `ui/seg.js`: `segmented()` radio group.
- `warnings.js`: parse "Line N: …" warnings.
- `caddyfile-sites.js`: site blocks by line.
- `dashboard-model.js`: verdict, KPIs, config card, health, tags, audit rows (pure).
- `histogram-axis.js`: tick placement and keyboard stepping (pure).

**Frontend (modified):** `core.js`, `main.js`, `caddyfile.js`, `usermenu.js`, `validate.js`, `backups.js`, `panels.js`, `search.js`, `csrf.js`, `dashboard.js`, `explore.js`, `histogram.js`, `ip-popover.js`, `diff.js`, `icons.js`, CSS `tokens.css`, `style.css`.

**Tests (new):** `tests/test_upstream_health.py`; new classes appended to `tests/test_eventindex.py`, `tests/test_app.py`, `tests/test_validator.py`; node scripts `tests/tokens.test.mjs`, `theme.test.mjs`, `format.test.mjs`, `no-native-dialogs.test.mjs`, `icons.test.mjs`, `dashboard-model.test.mjs`, `caddyfile-sites.test.mjs`, `histogram-axis.test.mjs`, `warnings.test.mjs`, `diff-summary.test.mjs`.

**Style.css section layout after this plan** (each task replaces the old rules it owns; use the `/* === name === */` markers to find them):
`base`, `buttons`, `dialogs and toasts`, `header`, `popover menus`, `layout`, `dashboard`, `explore`, `editor`, `login`, `responsive`.

---

## Part 1: Backend (additive fields and warnings)

### Task 1: `previous_total` in `site_summary` and `/api/sites`

**Files:**
- Modify: `src/eventindex.py` (`site_summary`, around lines 694-754)
- Test: `tests/test_eventindex.py` (append a new class), `tests/test_app.py` (append a new class)

**Interfaces:**
- Consumes: nothing new.
- Produces: `EventIndex.site_summary(...)` result gains `"previous_total": int | None`, the number of events (all hosts) in `[from_ts - (to_ts - from_ts), from_ts)`. It is `None` when no range is given, or when the oldest indexed event is newer than the start of that previous window. In that case the cache does not hold the window, and nothing is read to fill it. `/api/sites` passes it through unchanged.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_eventindex.py` (before the `if __name__` block if there is one, otherwise at the end):

```python
class PreviousWindowTest(unittest.TestCase):
    """site_summary's previous_total comes only from what the cache already holds."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="eventindex-prev-")
        self.path = os.path.join(self.dir, "access.log")
        self.index = EventIndex(self.path)
        with open(self.path, "a") as f:
            for i in range(120):   # one event a minute for two hours
                f.write(json.dumps(entry(ts=T0 + i * 60)) + "\n")

    def test_counts_the_equal_window_before_when_the_cache_covers_it(self):
        self.index.site_summary(T0, T0 + 7200)            # loads both hours
        r = self.index.site_summary(T0 + 3600, T0 + 7200)
        self.assertEqual(r["previous_total"], 60)

    def test_is_null_when_only_the_current_window_was_loaded(self):
        r = self.index.site_summary(T0 + 3600, T0 + 7200)
        self.assertIsNone(r["previous_total"])

    def test_is_null_without_a_range(self):
        self.assertIsNone(self.index.site_summary()["previous_total"])

    def test_previous_total_never_triggers_a_rebuild(self):
        self.index.site_summary(T0, T0 + 7200)
        before = self.index.ts
        self.index.site_summary(T0 + 3600, T0 + 7200)
        self.assertIs(self.index.ts, before, "previous_total must not read anything new")
```

Append to `tests/test_app.py`:

```python
class SitesApiTest(AppTestCase):
    def test_previous_total_is_always_present(self):
        body = self.client.get("/api/sites?range=1h", headers=AUTH).get_json()
        self.assertIn("previous_total", body)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run --frozen python -m unittest tests.test_eventindex.PreviousWindowTest tests.test_app.SitesApiTest -v`
Expected: FAIL with `KeyError: 'previous_total'` / `AssertionError: 'previous_total' not found`.

- [ ] **Step 3: Implement**

In `src/eventindex.py`, inside `site_summary`, directly after `hi = bisect.bisect_right(...)`, add:

```python
            # The equal-length window before this one, for "+12% vs previous
            # hour". Answered only from events already in memory: if the oldest
            # one is newer than that window's start, the cache does not hold it
            # and the field is null rather than an undercount.
            previous_total = None
            if from_ts is not None and to_ts is not None and n:
                prev_from = from_ts - (to_ts - from_ts)
                if self.ts[0] <= prev_from:
                    previous_total = lo - bisect.bisect_left(self.ts, prev_from)
```

and add `"previous_total": previous_total,` to the returned dict, right after `"points": points,`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run --frozen python -m unittest tests.test_eventindex tests.test_app -v`
Expected: PASS (all, including the existing ones).

- [ ] **Step 5: Commit**

```bash
git add src/eventindex.py tests/test_eventindex.py tests/test_app.py
git commit -m "feat(sites): previous_total for the equal window before the range"
```

---

### Task 2: Upstream health state file, `unhealthy_since` and `configured_sites` in `/api/upstreams`

**Files:**
- Create: `src/upstream_health.py`
- Modify: `src/routes/ops.py` (`upstreams()`, plus two helpers)
- Test: `tests/test_upstream_health.py` (new), `tests/test_app.py` (append a class)

**Interfaces:**
- Produces: `upstream_health.record(healthy: dict[str, int], now: float | None = None) -> dict[str, float]`. `healthy` maps a dial address to Caddy's `caddy_reverse_proxy_upstreams_healthy` gauge (1 or 0). It returns `{address: unhealthy_since_epoch}` for every address currently at 0. Module globals `STATE_PATH` and `LOCK_PATH` are read at call time, so tests can patch them.
- Produces: each `/api/upstreams` row gains `"unhealthy_since": float | None`. The response gains top-level `"configured_sites": int | None`, the number of distinct host matchers in Caddy's running config, or `None` when the config could not be fetched. Early error responses are unchanged.

- [ ] **Step 1: Write the failing unit tests**

Create `tests/test_upstream_health.py`:

```python
"""Upstream health transitions, shared across workers through one JSON file.

Run with:  uv run --frozen python -m unittest tests.test_upstream_health -v
"""
import importlib
import json
import os
import tempfile
import threading
import unittest
from unittest import mock

import tests._env  # noqa: F401  (sets env before src is imported)

from src import upstream_health


class RecordTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="upstream-health-")
        self.state = os.path.join(self.dir, "upstream-health.json")
        self.lock = os.path.join(self.dir, ".upstream-health.lock")
        self.patches = [
            mock.patch.object(upstream_health, "STATE_PATH", self.state),
            mock.patch.object(upstream_health, "LOCK_PATH", self.lock),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def read_state(self):
        with open(self.state) as f:
            return json.load(f)

    def test_first_observer_records_the_failure_time(self):
        self.assertEqual(upstream_health.record({"10.0.0.1:80": 0, "10.0.0.2:80": 1}, now=100.0),
                         {"10.0.0.1:80": 100.0})
        # A second worker, later: the recorded time stands.
        self.assertEqual(upstream_health.record({"10.0.0.1:80": 0, "10.0.0.2:80": 1}, now=130.0),
                         {"10.0.0.1:80": 100.0})

    def test_recovery_clears_and_a_new_failure_restarts_the_clock(self):
        upstream_health.record({"a:1": 0}, now=100.0)
        self.assertEqual(upstream_health.record({"a:1": 1}, now=160.0), {})
        self.assertEqual(self.read_state(), {})
        self.assertEqual(upstream_health.record({"a:1": 0}, now=200.0), {"a:1": 200.0})

    def test_survives_a_restart(self):
        upstream_health.record({"a:1": 0}, now=100.0)
        importlib.reload(upstream_health)          # a fresh process has no memory
        with mock.patch.object(upstream_health, "STATE_PATH", self.state), \
             mock.patch.object(upstream_health, "LOCK_PATH", self.lock):
            self.assertEqual(upstream_health.record({"a:1": 0}, now=500.0), {"a:1": 100.0})

    def test_corrupt_file_is_treated_as_empty_and_rewritten(self):
        for junk in ("{not json", "[1, 2]", '{"a:1": "yesterday"}'):
            with self.subTest(junk=junk):
                with open(self.state, "w") as f:
                    f.write(junk)
                self.assertEqual(upstream_health.record({"a:1": 0}, now=42.0), {"a:1": 42.0})
                self.assertEqual(self.read_state(), {"a:1": 42.0})

    def test_no_metrics_leaves_the_state_alone(self):
        upstream_health.record({"a:1": 0}, now=100.0)
        self.assertEqual(upstream_health.record({}, now=200.0), {})
        self.assertEqual(self.read_state(), {"a:1": 100.0})

    def test_upstreams_gone_from_the_metrics_are_forgotten(self):
        upstream_health.record({"a:1": 0, "b:2": 0}, now=100.0)
        upstream_health.record({"b:2": 0}, now=150.0)
        self.assertEqual(self.read_state(), {"b:2": 100.0})

    def test_concurrent_workers_agree_on_one_time(self):
        barrier = threading.Barrier(8)
        results = []

        def worker(i):
            barrier.wait()
            results.append(upstream_health.record({"a:1": 0}, now=1000.0 + i))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        times = {r["a:1"] for r in results}
        self.assertEqual(len(times), 1, f"workers disagreed: {times}")
        self.assertEqual(self.read_state(), {"a:1": times.pop()})


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run --frozen python -m unittest tests.test_upstream_health -v`
Expected: FAIL with `ImportError: cannot import name 'upstream_health'`.

- [ ] **Step 3: Implement `src/upstream_health.py`**

```python
"""When each upstream became unhealthy, shared by every worker and kept across restarts.

Caddy only reports whether an upstream is healthy right now. The dashboard wants
"down since 14:31", so the first worker to notice a change records it in a small
JSON file in BACKUP_DIR. The read-modify-write happens under an flock and the
write is atomic (temp file + os.replace), so concurrent workers never record a
transition twice or read a torn file. A corrupt or unreadable file is treated as
empty and rewritten. The time then means "since this console noticed", which is
the honest fallback.
"""
import fcntl
import json
import os
import tempfile
import time

from .config import BACKUP_DIR

STATE_PATH = os.path.join(BACKUP_DIR, "upstream-health.json")
LOCK_PATH = os.path.join(BACKUP_DIR, ".upstream-health.lock")


def _read(path: str) -> tuple[dict, bool]:
    """(state, needs_rewrite). Anything unusable reads as an empty state."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}, False
    except (OSError, ValueError):
        return {}, True
    if not isinstance(data, dict):
        return {}, True
    clean = {
        k: float(v) for k, v in data.items()
        if isinstance(k, str) and isinstance(v, (int, float)) and not isinstance(v, bool)
    }
    return clean, clean != data


def _write(path: str, state: dict) -> None:
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".upstream-health.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def record(healthy: dict, now: float | None = None) -> dict:
    """Fold the current health flags into the shared state.

    Returns {address: unhealthy_since} for every address currently reported
    unhealthy. An empty `healthy` (metrics unavailable) changes nothing.
    """
    now = time.time() if now is None else now
    try:
        lock_fd = os.open(LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o600)
    except OSError:
        lock_fd = None   # read-only volume: still answer, just without the lock
    try:
        if lock_fd is not None:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
        state, dirty = _read(STATE_PATH)
        if healthy:
            for address in [a for a in state if a not in healthy]:
                del state[address]          # no longer in Caddy's metrics
                dirty = True
        for address, flag in healthy.items():
            if flag == 0 and address not in state:
                state[address] = float(now)
                dirty = True
            elif flag != 0 and address in state:
                del state[address]
                dirty = True
        if dirty:
            try:
                _write(STATE_PATH, state)
            except OSError:
                pass
        return {a: state[a] for a, flag in healthy.items() if flag == 0 and a in state}
    finally:
        if lock_fd is not None:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
```

Note: `BACKUP_DIR` also holds backups, but only names starting with `Caddyfile.` are ever served (`_backup_path`), so these two files are never addressable through the API.

- [ ] **Step 4: Run to verify it passes**

Run: `uv run --frozen python -m unittest tests.test_upstream_health -v`
Expected: PASS (7 tests).

- [ ] **Step 5: Write the failing route test**

Append to `tests/test_app.py` (add `import tempfile` to the imports at the top if it is not already there):

```python
class UpstreamsApiTest(AppTestCase):
    METRICS = "\n".join([
        'caddy_reverse_proxy_upstreams_healthy{upstream="127.0.0.1:2283"} 0',
        'caddy_reverse_proxy_upstreams_healthy{upstream="127.0.0.1:8096"} 1',
    ])
    SERVERS = {"srv0": {"routes": [
        {"match": [{"host": ["photos.example.com"]}],
         "handle": [{"handler": "subroute", "routes": [{"handle": [
             {"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:2283"}]}]}]}]},
        {"match": [{"host": ["watch.example.com"]}],
         "handle": [{"handler": "subroute", "routes": [{"handle": [
             {"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:8096"}]}]}]}]},
        {"match": [{"host": ["hello.example.com"]}], "handle": [{"handler": "static_response"}]},
    ]}}

    def setUp(self):
        super().setUp()
        from src import upstream_health
        state_dir = tempfile.mkdtemp(prefix="ups-")
        self.patches += [
            mock.patch.object(upstream_health, "STATE_PATH", os.path.join(state_dir, "s.json")),
            mock.patch.object(upstream_health, "LOCK_PATH", os.path.join(state_dir, ".lock")),
        ]
        for p in self.patches[-2:]:
            p.start()

    def fake_get(self, url, timeout=None, **kw):
        if url.endswith("/reverse_proxy/upstreams"):
            return FakeResponse(200, payload=[
                {"address": "127.0.0.1:2283", "num_requests": 0, "fails": 3},
                {"address": "127.0.0.1:8096", "num_requests": 1, "fails": 0},
            ])
        if url.endswith("/metrics"):
            return FakeResponse(200, text=self.METRICS)
        raise AssertionError(url)

    def get(self, servers):
        with mock.patch.object(ops_mod.http_client, "get", self.fake_get), \
             mock.patch.object(ops_mod, "get_servers", return_value=servers):
            return self.client.get("/api/upstreams", headers=AUTH).get_json()

    def test_unhealthy_since_and_configured_sites(self):
        before = time.time()
        body = self.get(self.SERVERS)
        rows = {u["address"]: u for u in body["upstreams"]}
        self.assertGreaterEqual(rows["127.0.0.1:2283"]["unhealthy_since"], before - 1)
        self.assertIsNone(rows["127.0.0.1:8096"]["unhealthy_since"])
        self.assertEqual(rows["127.0.0.1:2283"]["domains"], ["photos.example.com"])  # existing field kept
        self.assertEqual(rows["127.0.0.1:2283"]["fails"], 3)                         # existing field kept
        self.assertEqual(body["configured_sites"], 3)

    def test_configured_sites_is_null_without_a_config(self):
        self.assertIsNone(self.get({})["configured_sites"])
```

- [ ] **Step 6: Run to verify it fails**

Run: `uv run --frozen python -m unittest tests.test_app.UpstreamsApiTest -v`
Expected: FAIL with `KeyError: 'unhealthy_since'`.

- [ ] **Step 7: Implement in `src/routes/ops.py`**

Add `from .. import upstream_health` next to the other relative imports. Replace the tail of `upstreams()`, from `detail = _get_upstream_detail()` to the final `return`, with:

```python
    detail = _get_upstream_detail()
    # Caddy only says "healthy now"; the shared state file remembers since when.
    since = upstream_health.record(_upstream_health_flags())
    enriched = []
    for row in rows if isinstance(rows, list) else []:
        info = detail.get(row.get("address"), {})
        enriched.append({
            **row,
            "domains": info.get("domains", []),
            # `fails` is only ever populated when passive health checking is on,
            # which requires fail_duration > 0 (Caddy's default is 0 = off).
            "passive_health": info.get("passive", False),
            "active_health": info.get("active", False),
            "unhealthy_since": since.get(row.get("address")),
        })
    enriched.sort(key=lambda u: (not u["domains"], u["domains"][:1], u.get("address", "")))
    return jsonify({"upstreams": enriched, "configured_sites": _configured_site_count()})


def _upstream_health_flags() -> dict:
    """address -> 1/0 from caddy_reverse_proxy_upstreams_healthy, or {} if unavailable."""
    try:
        resp = http_client.get(f"{CADDY_API_URL}/metrics", timeout=5)
    except Exception:
        return {}
    if resp.status_code != 200:
        return {}
    return parse_prometheus_metrics(resp.text)["upstreams_healthy"]


def _configured_site_count():
    """Distinct site hosts in the running config ("7 of 7 configured"), or None."""
    if not get_servers():
        return None
    domains, _ = _server_maps()
    return len({h.lower() for hosts in domains.values() for h in hosts})
```

- [ ] **Step 8: Run all Python tests**

Run: `uv run --frozen python -m unittest discover -s tests -t .`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add src/upstream_health.py src/routes/ops.py tests/test_upstream_health.py tests/test_app.py
git commit -m "feat(upstreams): unhealthy_since shared across workers, configured_sites"
```

---

### Task 3: `last_change` in `/api/status`

**Files:**
- Modify: `src/audit.py` (add `CHANGE_ACTIONS`, `last_change`), `src/routes/ops.py` (`caddy_status`)
- Test: `tests/test_app.py` (append a class)

**Interfaces:**
- Produces: `audit.last_change(scan: int = 500) -> dict | None`, returning `{"action": "save" | "restore", "user": str, "ts": float}` (epoch seconds) for the newest audit entry that changed the file on disk. That covers `save_reload`, `save_no_reload`, `save_reload_unknown`, the three `restore_*` equivalents, and `*_reload_failed` whose detail says `rolled_back=False`. It looks at the current log first, then the rotated one.
- Produces: `/api/status` gains `"last_change"`, the value above or `null`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_app.py`:

```python
class LastChangeTest(AppTestCase):
    def status(self):
        with mock.patch.object(ops_mod, "_caddy_version", return_value="v2.test"):
            return self.client.get("/api/status", headers=AUTH).get_json()

    def test_null_without_any_change(self):
        audit.log_action("login", "admin@example.com")
        self.assertIsNone(self.status()["last_change"])

    def test_newest_save_or_restore_wins_and_logins_are_ignored(self):
        audit.log_action("save_reload", "a@example.com", "backup=Caddyfile.20261120-100000")
        audit.log_action("restore_reload", "b@example.com", "backup=x, from=Caddyfile.20261119-081000")
        audit.log_action("login", "c@example.com")
        change = self.status()["last_change"]
        self.assertEqual(change["action"], "restore")
        self.assertEqual(change["user"], "b@example.com")
        self.assertAlmostEqual(change["ts"], time.time(), delta=60)

    def test_rejected_reload_counts_only_when_the_file_was_left_changed(self):
        audit.log_action("save_reload_failed", "a@example.com", "rolled_back=True, nope")
        self.assertIsNone(self.status()["last_change"])
        audit.log_action("save_reload_failed", "a@example.com", "rolled_back=False, nope")
        self.assertEqual(self.status()["last_change"]["action"], "save")

    def test_found_in_the_rotated_file(self):
        audit.log_action("save_reload", "a@example.com")
        os.replace(env.AUDIT_LOG, audit.rotated_path())
        audit.log_action("login", "b@example.com")
        self.assertEqual(self.status()["last_change"]["user"], "a@example.com")
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run --frozen python -m unittest tests.test_app.LastChangeTest -v`
Expected: FAIL with `KeyError: 'last_change'`.

- [ ] **Step 3: Implement**

Append to `src/audit.py`:

```python
# Audit actions after which the Caddyfile on disk is different. A rejected reload
# normally rolls the file back; only a failed rollback leaves it changed.
CHANGE_ACTIONS = {
    "save_reload": "save", "save_no_reload": "save", "save_reload_unknown": "save",
    "restore_reload": "restore", "restore_no_reload": "restore", "restore_reload_unknown": "restore",
}


def _as_change(entry):
    action = entry.get("action", "")
    kind = CHANGE_ACTIONS.get(action)
    if kind is None and action.endswith("_reload_failed") and "rolled_back=False" in str(entry.get("detail", "")):
        kind = action.split("_", 1)[0]
    if kind is None:
        return None
    try:
        ts = datetime.fromisoformat(entry["time"]).timestamp()
    except (KeyError, TypeError, ValueError):
        return None
    return {"action": kind, "user": entry.get("user", ""), "ts": ts}


def last_change(scan: int = 500):
    """The newest save/restore that changed the file on disk, or None."""
    for path in (AUDIT_LOG, rotated_path()):
        for line in reversed(tail_lines(path, scan)):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(entry, dict):
                change = _as_change(entry)
                if change:
                    return change
    return None
```

In `src/routes/ops.py` change `from ..audit import iter_entries, tail_lines` to `from ..audit import iter_entries, last_change, tail_lines`, and add `"last_change": last_change(),` to the dict returned by `caddy_status()`, after `"last_modified": last_modified,`.

- [ ] **Step 4: Run to verify it passes**

Run: `uv run --frozen python -m unittest tests.test_app -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/audit.py src/routes/ops.py tests/test_app.py
git commit -m "feat(status): last_change from the audit log"
```

---

### Task 4: "Not formatted" warning in `/api/validate`

**Files:**
- Modify: `src/validator.py` (add `fmt_warning`), `src/routes/editor.py` (`validate()`)
- Test: `tests/test_validator.py`, `tests/test_app.py` (append classes)

**Interfaces:**
- Produces: `validator.fmt_warning(content: str, formatted: str) -> str | None`, returning `"Line N: not formatted — Check will fix whitespace on K lines"` (singular "line" when K == 1). N is the first line of `content` that `caddy fmt` changes, 1-based and clamped to the file. K counts the changed lines. It returns `None` when nothing changes.
- Produces: `/api/validate` for a valid config lists the format warning first, then the existing `smart_validate` warnings, then (after Task 5) the resolve warnings. Invalid configs still return `"warnings": []`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_validator.py`:

```python
class FmtWarningTest(unittest.TestCase):
    def test_identical_is_none(self):
        self.assertIsNone(validator.fmt_warning("a {\n}\n", "a {\n}\n"))

    def test_points_at_the_first_changed_line_and_counts_lines(self):
        before = "a.example.com {\n    respond 200\n}\n\nb.example.com {\n  respond 201\n}\n"
        after = "a.example.com {\n\trespond 200\n}\n\nb.example.com {\n\trespond 201\n}\n"
        self.assertEqual(validator.fmt_warning(before, after),
                         "Line 2: not formatted — Check will fix whitespace on 2 lines")

    def test_singular(self):
        self.assertEqual(validator.fmt_warning("a {\n  x\n}\n", "a {\n\tx\n}\n"),
                         "Line 2: not formatted — Check will fix whitespace on 1 line")

    def test_change_past_the_end_is_clamped_to_the_last_line(self):
        self.assertEqual(validator.fmt_warning("a {\n}", "a {\n}\n"),
                         "Line 2: not formatted — Check will fix whitespace on 1 line")
```

Append to `tests/test_app.py`:

```python
class ValidateWarningsApiTest(AppTestCase):
    def test_unformatted_content_gets_a_line_linked_warning_first(self):
        with mock.patch.object(editor_mod, "caddy_fmt", lambda c: c.replace("    ", "\t")):
            body = self.post("/api/validate", {"content": ":80 {\n    respond 200\n}\n"}).get_json()
        self.assertTrue(body["valid"])
        self.assertEqual(body["warnings"][0], "Line 2: not formatted — Check will fix whitespace on 1 line")
        self.assertEqual(body["formatted"], ":80 {\n\trespond 200\n}\n")

    def test_formatted_content_has_no_format_warning(self):
        body = self.post("/api/validate", {"content": ":80 {\n\trespond 200\n}\n"}).get_json()
        self.assertEqual(body["warnings"], [])
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run --frozen python -m unittest tests.test_validator.FmtWarningTest tests.test_app.ValidateWarningsApiTest -v`
Expected: FAIL with `AttributeError: module 'src.validator' has no attribute 'fmt_warning'`.

- [ ] **Step 3: Implement**

In `src/validator.py` add `import difflib` to the imports and add:

```python
def fmt_warning(content: str, formatted: str) -> str | None:
    """'Line N: not formatted …' when `caddy fmt` would change `content`, else None.

    N is a line in `content` (what the editor shows), so the strip can link it.
    """
    if formatted == content:
        return None
    a, b = content.split("\n"), formatted.split("\n")
    first, changed = None, 0
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        if first is None:
            first = i1 + 1
        changed += max(i2 - i1, j2 - j1)
    first = min(max(first or 1, 1), max(len(a), 1))
    return f"Line {first}: not formatted — Check will fix whitespace on {changed} line{'' if changed == 1 else 's'}"
```

In `src/routes/editor.py`, add `fmt_warning` to the `from ..validator import …` line. Replace the body of `validate()` with:

```python
    data = request.get_json(silent=True) or {}
    content = data.get("content", "")

    formatted = caddy_fmt(content)
    is_valid, message, check_level = caddy_check(formatted)

    if not is_valid:
        return jsonify({"valid": False, "message": message, "warnings": [],
                        "formatted": None, "check_level": check_level})

    # Line numbers: the format warning points into `content` (what the editor
    # shows); the others into `formatted`, as before. They agree whenever the
    # file is already formatted, which every save through the console ensures.
    warnings = [w for w in (fmt_warning(content, formatted),) if w]
    warnings += smart_validate(formatted)

    return jsonify({"valid": True,
                    "message": "Caddyfile check passed, but review warnings" if warnings else message,
                    "warnings": warnings,
                    "formatted": formatted if formatted != content else None,
                    "check_level": check_level})
```

- [ ] **Step 4: Run all Python tests**

Run: `uv run --frozen python -m unittest discover -s tests -t .`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/validator.py src/routes/editor.py tests/test_validator.py tests/test_app.py
git commit -m "feat(validate): line-linked warning when caddy fmt would change the file"
```

---

### Task 5: "Upstream could not be resolved" warning

**Files:**
- Modify: `src/validator.py` (add the resolver), `src/routes/editor.py` (`validate()`)
- Test: `tests/test_validator.py`, `tests/test_app.py` (append classes)

**Interfaces:**
- Produces: `validator.resolve_hosts(hosts, lookup=socket.getaddrinfo, timeout=1.0) -> dict[str, bool | None]`. The value is True if the host resolves, False for "no such name" (`EAI_NONAME` / `EAI_NODATA`), and None when the answer is unknown (timeout or a transient error). Results are cached for 60 s per host, including None. All uncached hosts resolve in parallel under one shared `timeout`.
- Produces: `validator.upstream_resolve_warnings(content, lookup=socket.getaddrinfo, timeout=1.0) -> list[str]`, returning `"Line N: upstream <token> could not be resolved from the console container"` only for False results. It skips IP literals, `{placeholders}` (including `{$ENV}`), `unix/` sockets and `:port`-only dials. Upstreams come from `reverse_proxy` arguments (a leading matcher `@x`, `/path` or `*` is skipped) and from `to` lines inside a `reverse_proxy { }` block.
- Save never calls this, so it can never block a save.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_validator.py` (add `import socket` and `import time` at the top):

```python
class ResolveWarningTest(unittest.TestCase):
    def setUp(self):
        validator._dns_cache.clear()
        self.calls = []

    def tearDown(self):
        validator._dns_cache.clear()

    def lookup(self, answers):
        def fake(host, port):
            self.calls.append(host)
            outcome = answers.get(host, "ok")
            if outcome == "missing":
                raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
            if outcome == "again":
                raise socket.gaierror(socket.EAI_AGAIN, "Temporary failure")
            if outcome == "slow":
                time.sleep(0.5)
            return [("ok",)]
        return fake

    def warn(self, content, answers=None, timeout=1.0):
        return validator.upstream_resolve_warnings(content, lookup=self.lookup(answers or {}), timeout=timeout)

    def test_resolvable_upstream_is_quiet(self):
        self.assertEqual(self.warn("a.example.com {\n\treverse_proxy web:8080\n}\n"), [])
        self.assertEqual(self.calls, ["web"])

    def test_unresolvable_upstream_is_warned_with_its_line(self):
        self.assertEqual(
            self.warn("a.example.com {\n\treverse_proxy radarr:7878\n}\n", {"radarr": "missing"}),
            ["Line 2: upstream radarr:7878 could not be resolved from the console container"])

    def test_ip_literals_placeholders_and_sockets_are_never_looked_up(self):
        content = ("a.example.com {\n\treverse_proxy 127.0.0.1:2283 [::1]:80 ::1\n"
                   "\treverse_proxy {$UPSTREAM} {http.request.host}:80\n"
                   "\treverse_proxy unix//run/app.sock :8080\n}\n")
        self.assertEqual(self.warn(content), [])
        self.assertEqual(self.calls, [])

    def test_matchers_schemes_and_to_lines(self):
        content = ("a.example.com {\n\treverse_proxy /api/* http://api:80 {\n\t\tto backup:80\n\t}\n"
                   "\treverse_proxy @ws ws-backend:9000\n}\n")
        warnings = self.warn(content, {"api": "missing", "backup": "missing", "ws-backend": "missing"})
        self.assertEqual(warnings, [
            "Line 2: upstream http://api:80 could not be resolved from the console container",
            "Line 3: upstream backup:80 could not be resolved from the console container",
            "Line 5: upstream ws-backend:9000 could not be resolved from the console container",
        ])

    def test_timeout_and_transient_errors_are_not_failures(self):
        started = time.monotonic()
        self.assertEqual(self.warn("a {\n\treverse_proxy slow:1 flaky:2\n}\n",
                                   {"slow": "slow", "flaky": "again"}, timeout=0.05), [])
        self.assertLess(time.monotonic() - started, 0.4, "must not wait for the slow lookup")

    def test_results_are_cached(self):
        content = "a {\n\treverse_proxy web:1\n}\nb {\n\treverse_proxy web:2\n}\n"
        self.warn(content)
        self.warn(content)
        self.assertEqual(self.calls, ["web"])
```

Append to `tests/test_app.py`:

```python
class ValidateResolveApiTest(AppTestCase):
    def test_validate_reports_unresolvable_upstreams(self):
        with mock.patch.object(editor_mod, "upstream_resolve_warnings",
                               return_value=["Line 2: upstream nope:80 could not be resolved from the console container"]):
            body = self.post("/api/validate", {"content": "a.example.com {\n\treverse_proxy nope:80\n}\n"}).get_json()
        self.assertIn("Line 2: upstream nope:80 could not be resolved from the console container", body["warnings"])

    def test_save_never_resolves(self):
        with mock.patch.object(editor_mod, "upstream_resolve_warnings", side_effect=AssertionError("save resolved")), \
             mock.patch.object(editor_mod.http_client, "post", lambda *a, **k: FakeResponse(200)):
            r = self.post("/api/save", {"content": "a.example.com {\n\treverse_proxy nope:80\n}\n"})
        self.assertEqual(r.status_code, 200)
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run --frozen python -m unittest tests.test_validator.ResolveWarningTest tests.test_app.ValidateResolveApiTest -v`
Expected: FAIL with `AttributeError: … has no attribute '_dns_cache'` / `upstream_resolve_warnings`.

- [ ] **Step 3: Implement in `src/validator.py`**

Add the imports `import ipaddress`, `import socket` and `from concurrent.futures import ThreadPoolExecutor, wait`. Then append:

```python
# --- Upstream DNS check (warning only, never blocks a save) ----------------------
#
# "could not be resolved from the console container": the console and Caddy may
# sit on different networks, so this is evidence, not proof. Unknown answers
# (timeouts, transient resolver errors) produce no warning at all.

_DNS_TTL = 60.0
_DNS_TIMEOUT = 1.0
_DNS_CACHE_MAX = 256
_dns_cache: dict[str, tuple[float, bool | None]] = {}
_dns_lock = threading.Lock()
_dns_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="dns-check")
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_PLACEHOLDER_RE = re.compile(r"\{[^{}\s]*\}")
_NOT_FOUND = {getattr(socket, n) for n in ("EAI_NONAME", "EAI_NODATA") if hasattr(socket, n)}


def _upstream_tokens(content: str) -> list[tuple[int, str]]:
    """(line, token) for each upstream in reverse_proxy lines and their `to` lines."""
    out = []
    stack = []   # one entry per open brace: True if it opened a reverse_proxy block
    for number, raw in enumerate(content.split("\n"), 1):
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()
        if not line:
            continue
        words = line.split()
        if words[0] == "reverse_proxy":
            args = [w for w in words[1:] if w != "{"]
            if args and args[0][0] in "@/*":
                args = args[1:]
            out += [(number, a) for a in args]
        elif words[0] == "to" and stack and stack[-1]:
            out += [(number, a) for a in words[1:] if a != "{"]
        bare = _PLACEHOLDER_RE.sub("", line)
        for _ in range(bare.count("}")):
            if stack:
                stack.pop()
        for _ in range(bare.count("{")):
            stack.append(words[0] == "reverse_proxy")
    return out


def _dial_host(token: str) -> str | None:
    """The DNS name an upstream token dials, or None when there is nothing to resolve."""
    if "{" in token or token.startswith("unix/"):
        return None
    token = _SCHEME_RE.sub("", token).split("/", 1)[0]
    if not token or token.startswith("["):
        return None
    host = token.rsplit(":", 1)[0] if token.count(":") == 1 else token
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        return host.lower()


def _check_host(host, lookup):
    try:
        lookup(host, None)
        return True
    except socket.gaierror as e:
        return False if e.errno in _NOT_FOUND else None
    except (OSError, UnicodeError):
        return None


def resolve_hosts(hosts, lookup=socket.getaddrinfo, timeout=_DNS_TIMEOUT) -> dict:
    """host -> True (resolves), False (no such name) or None (unknown)."""
    now = time.monotonic()
    result, pending = {}, {}
    with _dns_lock:
        for h in hosts:
            hit = _dns_cache.get(h)
            if hit and hit[0] > now:
                result[h] = hit[1]
    for h in hosts:
        if h not in result and h not in pending:
            pending[h] = _dns_pool.submit(_check_host, h, lookup)
    if pending:
        done, _ = wait(list(pending.values()), timeout=timeout)
        expires = time.monotonic() + _DNS_TTL
        with _dns_lock:
            for h, fut in pending.items():
                ok = fut.result() if fut in done else None
                result[h] = ok
                _dns_cache[h] = (expires, ok)
            while len(_dns_cache) > _DNS_CACHE_MAX:
                del _dns_cache[next(iter(_dns_cache))]
    return result


def upstream_resolve_warnings(content: str, lookup=socket.getaddrinfo, timeout=_DNS_TIMEOUT) -> list[str]:
    found = [(line, token, host) for line, token in _upstream_tokens(content)
             if (host := _dial_host(token))]
    if not found:
        return []
    status = resolve_hosts(sorted({h for _, _, h in found}), lookup=lookup, timeout=timeout)
    warnings, seen = [], set()
    for line, token, host in found:
        if status.get(host) is False and (line, token) not in seen:
            seen.add((line, token))
            warnings.append(f"Line {line}: upstream {token} could not be resolved from the console container")
    return warnings
```

In `src/routes/editor.py` add `upstream_resolve_warnings` to the validator import, and in `validate()` add, right after `warnings += smart_validate(formatted)`:

```python
    warnings += upstream_resolve_warnings(formatted)
```

- [ ] **Step 4: Run all Python tests**

Run: `uv run --frozen python -m unittest discover -s tests -t .`
Expected: PASS. `test_timeout_and_transient_errors_are_not_failures` finishes in well under 0.4 s.

- [ ] **Step 5: Commit**

```bash
git add src/validator.py src/routes/editor.py tests/test_validator.py tests/test_app.py
git commit -m "feat(validate): warn when an upstream cannot be resolved from the console"
```

---

### Task 6: Inline theme boot script with a CSP hash

**Files:**
- Create: `src/theme_boot.py`
- Modify: `src/__init__.py` (context processor, CSP `script-src`), `src/templates/index.html` (`<head>`)
- Test: `tests/test_app.py` (append a class and a module-level helper)

**Interfaces:**
- Produces: `theme_boot.THEME_BOOT_JS: str` (the exact inline script), `theme_boot.THEME_BOOT_HASH: str` (`"sha256-…"`), and `theme_boot.THEME_STORAGE_KEY = "ui.theme"`. Every template gets `theme_boot_js` (a `Markup`) and renders it as `<script>{{ theme_boot_js }}</script>` on one line, with nothing else inside the tag.
- Contract with Task 9 (`theme.js`): localStorage key `ui.theme`. Stored values are only `dark` or `light`. "System" means the key is absent. The attribute is `data-theme="dark|light"` on `<html>`.

- [ ] **Step 1: Write the failing test**

In `tests/test_app.py` add `import base64` and `import hashlib` to the imports, then append:

```python
def assert_inline_script_allowed(test, response):
    """Exactly one inline <script>, allowed by its sha256 and nothing looser."""
    html = response.get_data(as_text=True)
    inline = re.findall(r"<script>(.*?)</script>", html, re.S)
    test.assertEqual(len(inline), 1, "exactly one inline script")
    digest = "sha256-" + base64.b64encode(hashlib.sha256(inline[0].encode()).digest()).decode()
    script_src = re.search(r"script-src ([^;]+)", response.headers["Content-Security-Policy"]).group(1)
    test.assertIn(f"'{digest}'", script_src)
    test.assertNotIn("unsafe-inline", script_src)


class ThemeBootCspTest(AppTestCase):
    def test_app_page_theme_script_is_allowed_by_hash(self):
        assert_inline_script_allowed(self, self.client.get("/", headers=AUTH))

    def test_script_uses_the_shared_storage_key(self):
        from src import theme_boot
        self.assertIn(f"'{theme_boot.THEME_STORAGE_KEY}'", theme_boot.THEME_BOOT_JS)
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run --frozen python -m unittest tests.test_app.ThemeBootCspTest -v`
Expected: FAIL with `AssertionError: 0 != 1 : exactly one inline script`.

- [ ] **Step 3: Implement**

Create `src/theme_boot.py`:

```python
"""The one inline script the app serves, and the CSP hash that allows it.

It runs in <head> before the stylesheets apply, so the stored theme (or the OS
preference) is on <html data-theme> before first paint, with no flash of the
wrong theme. CSP allows it by hash, computed here from the exact string the
templates render, so the two cannot drift. theme.js owns everything after first
paint and must agree on the storage key and its values (dark, light, or absent
for "follow the system").
"""
import base64
import hashlib

THEME_STORAGE_KEY = "ui.theme"

THEME_BOOT_JS = (
    "(function(){var t;try{t=localStorage.getItem('ui.theme')}catch(e){}"
    "if(t!=='dark'&&t!=='light'){t=window.matchMedia&&"
    "window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark'}"
    "document.documentElement.setAttribute('data-theme',t)})();"
)

THEME_BOOT_HASH = "sha256-" + base64.b64encode(
    hashlib.sha256(THEME_BOOT_JS.encode("utf-8")).digest()
).decode("ascii")
```

In `src/__init__.py`, add `from markupsafe import Markup` and `from .theme_boot import THEME_BOOT_HASH, THEME_BOOT_JS`. Before `@app.before_request` add:

```python
    @app.context_processor
    def theme_boot():
        # Markup, so autoescaping cannot touch it: the bytes on the page must be
        # exactly the bytes that were hashed into the CSP.
        return {"theme_boot_js": Markup(THEME_BOOT_JS)}
```

and change the CSP line `"script-src 'self'; "` to:

```python
            f"script-src 'self' '{THEME_BOOT_HASH}'; "
```

In `src/templates/index.html`, insert directly after `<title>Caddy Console</title>`:

```html
<script>{{ theme_boot_js }}</script>
```

- [ ] **Step 4: Run all Python tests**

Run: `uv run --frozen python -m unittest discover -s tests -t .`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/theme_boot.py src/__init__.py src/templates/index.html tests/test_app.py
git commit -m "feat(theme): inline theme boot script allowed by a CSP hash"
```

---

### Task 7: Sign-in page: server host line, Cloudflare variant, on-system markup

**Files:**
- Modify: `src/config.py`, `src/auth.py` (`server_host`, `_sign_in_page`, `welcome`, the Cloudflare branch of `login_required`), `src/templates/welcome.html` (rewrite)
- Test: `tests/test_app.py` (append a class)

**Interfaces:**
- Produces: `config.SERVER_URL_CONFIGURED: bool`, true when the `SERVER_URL` env var is set and non-empty. `auth.server_host() -> str` returns the hostname of `SERVER_URL` when it is configured, else the hostname of the request's `Host` header.
- Produces: `welcome.html` takes `auth_mode` (`"google"` / `"cloudflare"`) and `server_host`. In Cloudflare mode, a page request without a valid Access identity now gets this page with HTTP 403 instead of a plain-text 403. API requests still get JSON 401.
- The page uses only classes styled in Task 16 (`login`, `login-card`, `mark`, `gbtn`, `cf`, `fine`, `mono`, `muted`) plus the shared `btn` classes. Until Task 16 it renders unstyled but works.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_app.py` (add `import flask` to the imports):

```python
class SignInPageTest(AppTestCase):
    def test_cloudflare_page_without_identity(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 403)
        html = r.get_data(as_text=True)
        self.assertIn("Protected by Cloudflare Access", html)
        self.assertIn("Manage the Caddy server at", html)
        self.assertIn(">localhost<", html)
        self.assertIn("allowed list", html)
        assert_inline_script_allowed(self, r)

    def test_api_still_answers_json(self):
        r = self.client.get("/api/me")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.get_json(), {"error": "unauthorized"})

    def test_server_url_wins_when_configured(self):
        with mock.patch.object(auth, "SERVER_URL_CONFIGURED", True), \
             mock.patch.object(auth, "SERVER_URL", "https://console.example.com"):
            html = self.client.get("/").get_data(as_text=True)
        self.assertIn(">console.example.com<", html)

    def test_google_variant(self):
        with self.app.test_request_context("/welcome"):
            html = flask.render_template("welcome.html", auth_mode="google",
                                         server_host="console.example.com")
        self.assertIn('href="/login"', html)
        self.assertIn("Sign in with Google", html)
        self.assertNotIn("Cloudflare Access", html)
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run --frozen python -m unittest tests.test_app.SignInPageTest -v`
Expected: FAIL (`AssertionError: 'Protected by Cloudflare Access' not found`, `AttributeError: … SERVER_URL_CONFIGURED`).

- [ ] **Step 3: Implement**

`src/config.py`, directly under `SERVER_URL = …`:

```python
# Whether SERVER_URL was set explicitly (the default above is only a dev
# fallback). The sign-in page names that host, else the request's own.
SERVER_URL_CONFIGURED = bool(os.environ.get("SERVER_URL", "").strip())
```

`src/auth.py`: add `SERVER_URL_CONFIGURED` to the `from .config import (…)` list and `from urllib.parse import urlsplit` to the imports. Add above `login_required`:

```python
def server_host() -> str:
    """The server the sign-in page names: SERVER_URL's host when set, else the request's.

    The request host comes from the client. That is fine here because it is only
    echoed back, autoescaped, to the same client, and never used to build a URL.
    """
    if SERVER_URL_CONFIGURED:
        host = urlsplit(SERVER_URL).hostname
        if host:
            return host
    return urlsplit("//" + (request.host or "")).hostname or ""


def _sign_in_page(status: int = 200):
    return render_template("welcome.html", auth_mode=AUTH_MODE, server_host=server_host()), status
```

In `login_required`, replace `return "Access denied. Not authenticated via Cloudflare Access.", 403` with `return _sign_in_page(403)`. In `welcome()`, replace `return render_template("welcome.html")` with `return _sign_in_page()`.

Replace `src/templates/welcome.html` entirely:

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in · Caddy Console</title>
<script>{{ theme_boot_js }}</script>
<link rel="icon" href="/static/img/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/static/css/tokens.css">
<link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
{% include "_icons.html" %}
<main class="login" aria-labelledby="login-h">
  <div class="login-card">
    <svg class="mark" width="44" height="44" aria-hidden="true" focusable="false"><use href="#i-mark"/></svg>
    <h1 id="login-h">Sign in to Caddy Console</h1>
    <p>Manage the Caddy server at <span class="mono">{{ server_host }}</span>: health, access logs and the Caddyfile.</p>
    {% if auth_mode == "cloudflare" %}
    <div class="cf">
      <svg class="icon" width="20" height="20" aria-hidden="true" focusable="false"><use href="#i-shield"/></svg>
      <div>
        <b>Protected by Cloudflare Access</b>
        <div class="muted">Sign in through your Access login page, then reload. Your session is checked at the edge.</div>
      </div>
    </div>
    <a class="btn btn-primary gbtn" href="/">Reload after signing in</a>
    {% else %}
    <a class="btn btn-primary gbtn" href="/login">
      <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" focusable="false"><path fill="currentColor" d="M21.6 12.2c0-.7-.1-1.4-.2-2H12v3.8h5.4a4.6 4.6 0 0 1-2 3v2.5h3.2c1.9-1.7 3-4.3 3-7.3zM12 22c2.7 0 5-.9 6.6-2.4l-3.2-2.5c-.9.6-2 1-3.4 1-2.6 0-4.8-1.8-5.6-4.1H3.1v2.6A10 10 0 0 0 12 22zm-5.6-8c-.2-.6-.3-1.3-.3-2s.1-1.4.3-2V7.4H3.1a10 10 0 0 0 0 9.2zM12 6c1.5 0 2.8.5 3.8 1.5l2.9-2.9A10 10 0 0 0 3.1 7.4L6.4 10C7.2 7.7 9.4 6 12 6z"/></svg>
      Sign in with Google</a>
    {% endif %}
    <p class="fine">Only accounts on this server's allowed list can sign in. Ask the server admin to add yours.</p>
  </div>
</main>
</body>
</html>
```

(`#i-mark` and `#i-shield` are added to the sprite in Task 12. Until then those two icons are blank.)

- [ ] **Step 4: Run all Python tests**

Run: `uv run --frozen python -m unittest discover -s tests -t .`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/config.py src/auth.py src/templates/welcome.html tests/test_app.py
git commit -m "feat(login): server host line and a Cloudflare Access sign-in page"
```

---

## Part 2: Frontend foundation

### Task 8: Design tokens from the mockup

**Files:**
- Modify: `src/static/css/tokens.css` (rewrite), `src/static/css/style.css` (variable renames only), `src/static/js/app/core.js`, `src/static/js/app/histogram.js` (variable renames, 3xx colour)
- Test: `tests/tokens.test.mjs` (new)

**Interfaces:**
- Produces the token names every later task uses (the mockup's own names, so its CSS can be copied verbatim): surfaces `--bg --bg-2 --bg-3 --bg-4`; lines `--line --line-2`; ink `--ink --ink-2 --ink-3`; accent `--accent --accent-hi --accent-ink --accent-soft`; status `--good --warn --serious --crit --info --other` and `--good-soft --warn-soft --crit-soft`; diff `--add-bg --del-bg`; syntax `--code-kw --code-site --code-str --code-num --code-com --code-mt --code-ph`; editor `--selection-bg --selection-ink --active-line-bg`; `--scrim`; type `--sans --mono --t-xs(12) --t-sm(13) --t-md(14) --t-lg(17) --t-xl(22) --t-2xl(30) --leading --leading-tight`; shape `--r-sm --r-md --r-lg --r-pill`; space `--space-1..5`; `--shadow`; `--hdr`.
- Old to new names (applied by the script in Step 3): `surface-raised→bg-3, surface→bg-2, border-strong→line-2, border→line, ink-secondary→ink-2, ink-muted→ink-3, accent-hover→accent-hi, accent-quiet→accent-soft, status-good-bg→good-soft, status-warn-bg→warn-soft, status-critical-bg→crit-soft, status-good→good, status-warn→warn, status-serious→serious, status-critical→crit, status-none→other, font-mono→mono, font→sans, text-sm→t-xs, text-md→t-md, text-lg→t-lg, text-xl→t-xl, radius-sm→r-sm, radius-pill→r-pill, radius→r-md, shadow-lg→shadow`.

- [ ] **Step 1: Write the failing test**

Create `tests/tokens.test.mjs`:

```js
// Tests for src/static/css/tokens.css
//
// Every var(--x) the app uses must be defined, and every text colour must meet
// WCAG AA (4.5:1) on all three surfaces in both themes.
// Run with: node tests/tokens.test.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.join(import.meta.dirname, '..', 'src');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const tokens = read('static/css/tokens.css');

function block(selectorRe) {
  const m = tokens.match(new RegExp(selectorRe + '\\s*\\{([^}]*)\\}'));
  assert.ok(m, `missing block ${selectorRe}`);
  return Object.fromEntries([...m[1].matchAll(/--([\w-]+)\s*:\s*([^;]+);/g)].map(x => [x[1], x[2].trim()]));
}
const dark = block(':root,\\s*\\[data-theme="dark"\\]');
const light = block('\\[data-theme="light"\\]');

function lum(hex) {
  const v = hex.replace('#', '');
  const [r, g, b] = [0, 2, 4].map(i => parseInt(v.slice(i, i + 2), 16) / 255)
    .map(c => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };

console.log('\n--- contrast ---');
for (const [name, theme] of [['dark', dark], ['light', light]]) {
  for (const fg of ['ink', 'ink-2', 'ink-3', 'accent', 'good', 'warn', 'serious', 'crit', 'info', 'other']) {
    for (const bg of ['bg', 'bg-2', 'bg-3']) {
      check(`${name}: --${fg} on --${bg} >= 4.5`, () => {
        const r = ratio(theme[fg], theme[bg]);
        assert.ok(r >= 4.5, `${theme[fg]} on ${theme[bg]} is ${r.toFixed(2)}`);
      });
    }
  }
  check(`${name}: --accent-ink on --accent >= 4.5`, () => assert.ok(ratio(theme['accent-ink'], theme.accent) >= 4.5));
  check(`${name}: --selection-ink on --selection-bg >= 4.5`, () => assert.ok(ratio(theme['selection-ink'], theme['selection-bg']) >= 4.5));
}

console.log('\n--- every referenced variable is defined ---');
const defined = new Set([...tokens.matchAll(/--([\w-]+)\s*:/g)].map(m => m[1]));
const style = read('static/css/style.css');
for (const m of style.matchAll(/(?:^|[;{\s])--([\w-]+)\s*:/g)) defined.add(m[1]);   // component-local custom props
const sources = [
  ['static/css/style.css', style],
  ...fs.readdirSync(path.join(ROOT, 'static/js/app'), { recursive: true })
    .filter(f => String(f).endsWith('.js'))
    .map(f => [`static/js/app/${f}`, read(`static/js/app/${f}`)]),
  ...fs.readdirSync(path.join(ROOT, 'templates')).map(f => [`templates/${f}`, read(`templates/${f}`)]),
];
for (const [file, text] of sources) {
  const missing = [...new Set([...text.matchAll(/var\(--([\w-]+)/g)].map(m => m[1]))].filter(v => !defined.has(v));
  check(`${file} uses only defined variables`, () => assert.deepEqual(missing, []));
}

console.log(`\n${passed} passed`);
```

- [ ] **Step 2: Run to verify it fails**

Run: `node tests/tokens.test.mjs`
Expected: FAIL with `missing block :root,\s*\[data-theme="dark"\]`.

- [ ] **Step 3: Implement**

Replace `src/static/css/tokens.css` with a short header comment followed by the mockup's token blocks: **copy mockup lines 28–58 verbatim** (`:root, [data-theme="dark"]{…}`, `[data-theme="light"]{…}` and the shared `:root{…}`). Then add these declarations. They go inside the dark block before `color-scheme:dark;`, inside the light block before `color-scheme:light;`, and inside the shared `:root{…}` respectively:

```css
/* dark block additions */
  --selection-bg:#c8bdff; --selection-ink:#17132b; --active-line-bg:rgba(178,164,255,.06);
  --scrim:rgba(8,8,14,.55);
/* light block additions */
  --selection-bg:#c9c1ff; --selection-ink:#18171f; --active-line-bg:rgba(84,64,208,.05);
  --scrim:rgba(24,23,31,.35);
/* shared :root additions */
  --r-pill:999px;
  --space-1:4px; --space-2:8px; --space-3:12px; --space-4:16px; --space-5:24px;
  --leading-tight:1.35; --leading:1.5;
```

The header comment for `tokens.css`:

```css
/* Design tokens, from the approved "A · Refined" mockup (poc-ui/a-refined).
 *
 * Two themes share every name: dark (graphite with a violet tint) and light
 * (cool paper), switched by data-theme on <html>. The accent is for things you
 * can act on (links, focus, selected tab, primary buttons) and nothing else.
 * Status hues never stand alone: each ships with an icon shape or a word.
 * 3xx uses --info, a data colour distinct from the accent.
 */
```

Rename the old variables everywhere with this one-off script. Run it from the repo root. It is a heredoc, so no file is left behind:

```bash
python3 - <<'EOF'
import pathlib, re
RENAMES = {
    "surface-raised": "bg-3", "surface": "bg-2", "border-strong": "line-2", "border": "line",
    "ink-secondary": "ink-2", "ink-muted": "ink-3", "accent-hover": "accent-hi", "accent-quiet": "accent-soft",
    "status-good-bg": "good-soft", "status-warn-bg": "warn-soft", "status-critical-bg": "crit-soft",
    "status-good": "good", "status-warn": "warn", "status-serious": "serious",
    "status-critical": "crit", "status-none": "other",
    "font-mono": "mono", "font": "sans",
    "text-sm": "t-xs", "text-md": "t-md", "text-lg": "t-lg", "text-xl": "t-xl",
    "radius-sm": "r-sm", "radius-pill": "r-pill", "radius": "r-md", "shadow-lg": "shadow",
}
names = sorted(RENAMES, key=len, reverse=True)
pattern = re.compile(r"--(" + "|".join(map(re.escape, names)) + r")(?![\w-])")
files = [pathlib.Path("src/static/css/style.css"), *pathlib.Path("src/static/js/app").glob("*.js")]
for p in files:
    s = p.read_text()
    out = pattern.sub(lambda m: "--" + RENAMES[m.group(1)], s)
    if out != s:
        p.write_text(out)
        print("renamed in", p)
EOF
```

Then in `src/static/js/app/histogram.js` change the 3xx entry's token from `var(--accent)` to `var(--info)` (3xx is data, not an affordance). In `core.js`'s `editorTheme`, change `fontSize: 'var(--t-xs)'` (the result of the rename) to `fontSize: 'var(--t-sm)'` in both places (`.cm-content` and `.cm-vim-panel`), so the editor uses the mockup's 13 px code size.

- [ ] **Step 4: Run the tests**

Run: `node tests/tokens.test.mjs && for t in tests/*.test.mjs; do node "$t" || exit 1; done`
Expected: PASS. Then open http://localhost:8888 and check that every view still renders, recoloured (the layout is still the old one).

- [ ] **Step 5: Commit**

```bash
git add src/static/css/tokens.css src/static/css/style.css src/static/js/app tests/tokens.test.mjs
git commit -m "feat(ui): Direction A design tokens, dark and light"
```

---

### Task 9: `theme.js`, follow-the-OS, and a theme-aware editor

**Files:**
- Create: `src/static/js/app/theme.js`
- Modify: `src/static/js/app/core.js` (theme compartment, `applyEditorTheme`, syntax token colours), `src/static/js/app/main.js` (apply and watch on boot)
- Test: `tests/theme.test.mjs` (new)

**Interfaces:**
- Produces (`theme.js`): `THEMES: {id:'system'|'dark'|'light', label, icon}[]`, `getThemePref(): 'system'|'dark'|'light'`, `setThemePref(pref)` (throws on unknown values; `'system'` removes the key), `resolveTheme(pref, prefersLight: boolean): 'dark'|'light'`, `applyTheme(pref = getThemePref()): 'dark'|'light'` (sets `data-theme` and dispatches `themechange` with `{detail:{theme}}` on `window` when it changes), `currentTheme(): 'dark'|'light'`, `watchSystemTheme(): void`.
- Produces (`core.js`): `applyEditorTheme(theme: 'dark'|'light')`. `core.js` listens for `themechange` itself.
- Consumed by Task 12 (`usermenu.js` theme picker).

- [ ] **Step 1: Write the failing test**

Create `tests/theme.test.mjs`:

```js
// Tests for src/static/js/app/theme.js
//
// Run with: node tests/theme.test.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const store = new Map();
globalThis.localStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
};
const attrs = {};
globalThis.document = { documentElement: { getAttribute: (k) => attrs[k] ?? null, setAttribute: (k, v) => { attrs[k] = v; } } };
let mqListener = null;
let osLight = false;
globalThis.matchMedia = () => ({ get matches() { return osLight; }, addEventListener: (_, fn) => { mqListener = fn; } });
const events = [];
globalThis.dispatchEvent = (e) => events.push(e);

const SRC = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app', 'theme.js');
const { THEMES, getThemePref, setThemePref, resolveTheme, applyTheme, currentTheme, watchSystemTheme } = await import(SRC);

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };

console.log('\n--- theme preference ---');
check('offers system, dark and light', () => assert.deepEqual(THEMES.map(t => t.id), ['system', 'dark', 'light']));
check('defaults to system', () => assert.equal(getThemePref(), 'system'));
check('stores dark and light, and system removes the key', () => {
  setThemePref('light'); assert.equal(store.get('ui.theme'), 'light'); assert.equal(getThemePref(), 'light');
  setThemePref('system'); assert.equal(store.has('ui.theme'), false); assert.equal(getThemePref(), 'system');
});
check('refuses unknown values', () => assert.throws(() => setThemePref('sepia')));
check('an unknown stored value reads as system', () => { store.set('ui.theme', 'sepia'); assert.equal(getThemePref(), 'system'); store.delete('ui.theme'); });
check('resolveTheme: explicit wins, system follows the OS', () => {
  assert.equal(resolveTheme('dark', true), 'dark');
  assert.equal(resolveTheme('light', false), 'light');
  assert.equal(resolveTheme('system', true), 'light');
  assert.equal(resolveTheme('system', false), 'dark');
});
check('applyTheme sets data-theme and announces a change once', () => {
  events.length = 0;
  assert.equal(applyTheme('light'), 'light');
  assert.equal(attrs['data-theme'], 'light');
  assert.equal(currentTheme(), 'light');
  applyTheme('light');
  assert.equal(events.length, 1);
  assert.equal(events[0].detail.theme, 'light');
});
check('watchSystemTheme follows the OS only while the preference is system', () => {
  watchSystemTheme();
  setThemePref('system'); osLight = false; applyTheme();
  osLight = true; mqListener();
  assert.equal(attrs['data-theme'], 'light');
  setThemePref('dark'); applyTheme();
  osLight = false; mqListener(); osLight = true; mqListener();
  assert.equal(attrs['data-theme'], 'dark');
});
check('blocked storage falls back to system without throwing', () => {
  const saved = globalThis.localStorage;
  globalThis.localStorage = { getItem() { throw new Error('denied'); }, setItem() { throw new Error('denied'); }, removeItem() { throw new Error('denied'); } };
  try {
    assert.equal(getThemePref(), 'system');
    assert.doesNotThrow(() => setThemePref('dark'));
  } finally { globalThis.localStorage = saved; }
});
check('the inline boot script uses the same key', () => {
  const py = fs.readFileSync(path.join(import.meta.dirname, '..', 'src', 'theme_boot.py'), 'utf8');
  assert.match(py, /localStorage\.getItem\('ui\.theme'\)/);
});

console.log(`\n${passed} passed`);
```

- [ ] **Step 2: Run to verify it fails**

Run: `node tests/theme.test.mjs`
Expected: FAIL with `Cannot find module …/theme.js`.

- [ ] **Step 3: Implement `src/static/js/app/theme.js`**

```js
// Theme preference: System (follow the OS), Dark or Light, kept per browser.
//
// The inline script in <head> (src/theme_boot.py) applies the stored choice
// before first paint; this module owns every change after that. The two agree
// on the storage key and its values: "dark", "light", or absent for System.
// Storage can be blocked (private mode, policy); the page then follows the OS.

const KEY = 'ui.theme';

export const THEMES = [
  { id: 'system', label: 'System', icon: 'monitor' },
  { id: 'dark', label: 'Dark', icon: 'moon' },
  { id: 'light', label: 'Light', icon: 'sun' },
];

const isKnown = (id) => THEMES.some(t => t.id === id);

export function getThemePref() {
  try {
    const v = localStorage.getItem(KEY);
    return v === 'dark' || v === 'light' ? v : 'system';
  } catch {
    return 'system';
  }
}

export function setThemePref(pref) {
  if (!isKnown(pref)) throw new Error(`unknown theme: ${pref}`);
  try {
    if (pref === 'system') localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, pref);
  } catch {
    // Not persisted; applyTheme() still switches this page.
  }
}

export function resolveTheme(pref, prefersLight) {
  if (pref === 'dark' || pref === 'light') return pref;
  return prefersLight ? 'light' : 'dark';
}

function osPrefersLight() {
  try { return !!globalThis.matchMedia?.('(prefers-color-scheme: light)').matches; } catch { return false; }
}

export function currentTheme() {
  return globalThis.document?.documentElement?.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
}

/** Put the theme on <html>; announce it with a `themechange` event if it changed. */
export function applyTheme(pref = getThemePref()) {
  const theme = resolveTheme(pref, osPrefersLight());
  const root = globalThis.document?.documentElement;
  if (root && root.getAttribute('data-theme') !== theme) {
    root.setAttribute('data-theme', theme);
    globalThis.dispatchEvent?.(new CustomEvent('themechange', { detail: { theme } }));
  }
  return theme;
}

/** While the preference is System, follow OS changes live. */
export function watchSystemTheme() {
  const mq = globalThis.matchMedia?.('(prefers-color-scheme: light)');
  mq?.addEventListener?.('change', () => { if (getThemePref() === 'system') applyTheme('system'); });
}
```

- [ ] **Step 4: Make the editor follow the theme (`core.js`)**

1. Add `import { currentTheme } from './theme.js';`.
2. Turn the theme object into a spec plus a compartment. Rename `const editorTheme = EditorView.theme({` to `const EDITOR_THEME_SPEC = {`, and change its closing `}, { dark: true });` to `};`. Then add below it:

```js
// The colours are CSS variables, so they follow data-theme by themselves; the
// `dark` flag only picks CodeMirror's own base styles, so it lives in a
// compartment and is swapped when the theme changes.
const themeSlot = new Compartment();
const themeExtension = (theme) => EditorView.theme(EDITOR_THEME_SPEC, { dark: theme === 'dark' });

export function applyEditorTheme(theme) {
  if (!editorView) return;
  editorView.dispatch({ effects: themeSlot.reconfigure(themeExtension(theme)) });
}
window.addEventListener('themechange', (e) => applyEditorTheme(e.detail.theme));
```

3. In `initEditor`'s extension list, replace `editorTheme,` with `themeSlot.of(themeExtension(currentTheme())),`.
4. Recolour the syntax from the mockup's code tokens. Replace `editorHighlight` with:

```js
// Syntax colours come from the --code-* tokens, which both themes define.
const editorHighlight = HighlightStyle.define([
  { tag: tags.comment, color: 'var(--code-com)', fontStyle: 'italic' },
  { tag: tags.keyword, color: 'var(--code-kw)' },
  { tag: tags.atom, color: 'var(--code-mt)' },
  { tag: tags.labelName, color: 'var(--code-mt)' },
  { tag: tags.heading, color: 'var(--code-site)', fontWeight: '600' },
  { tag: tags.variableName, color: 'var(--code-ph)' },
  { tag: tags.string, color: 'var(--code-str)' },
  { tag: tags.number, color: 'var(--code-num)' },
  { tag: tags.bracket, color: 'var(--ink-3)' },
]);
```

5. Give the Caddyfile language site addresses, matchers and placeholders. Replace `caddyfileLanguage` with:

```js
const caddyfileLanguage = StreamLanguage.define({
  startState: () => ({ depth: 0 }),
  token(stream, state) {
    if (stream.sol() && state.depth === 0 && stream.match(/^[^\s{#(][^\s{]*/)) return 'heading';
    if (stream.match(/^#.*/)) return 'comment';
    if (stream.match(/^"[^"]*"/)) return 'string';
    if (stream.match(/^\{[^{}\s]+\}/)) return 'variableName';
    if (stream.match(/^\{/)) { state.depth++; return 'bracket'; }
    if (stream.match(/^\}/)) { state.depth = Math.max(0, state.depth - 1); return 'bracket'; }
    if (stream.match(/^@[\w-]+/)) return 'labelName';
    if (stream.match(/^\b(reverse_proxy|header|encode|file_server|root|try_files|redir|respond|log|basicauth|basic_auth|rate_limit|import|tls|route|handle|handle_path|rewrite|uri|request_body)\b/)) return 'keyword';
    if (stream.match(/^\b(email|auto_https|servers|admin|debug|order|storage|acme_ca|on_demand_tls|metrics)\b/)) return 'atom';
    if (stream.match(/^\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b/)) return 'number';
    if (stream.match(/^\blocalhost:\d+\b/)) return 'number';
    stream.next();
    return null;
  },
});
```

6. In `main.js`, add `import { applyTheme, watchSystemTheme } from './theme.js';` and, before `syncViewFromUrl();`, add:

```js
applyTheme();          // matches what the <head> script already set; arms the change event
watchSystemTheme();
```

- [ ] **Step 5: Run the tests and check in the browser**

Run: `for t in tests/*.test.mjs; do node "$t" || exit 1; done`
Expected: PASS.
Browser: open http://localhost:8888/editor. Site addresses show in `--code-site`, directives in `--code-kw`. In DevTools run `localStorage.setItem('ui.theme','light'); location.reload()`. The page is light from first paint, with no dark flash, and the editor is light. Then run `localStorage.removeItem('ui.theme')`, reload, and toggle the OS appearance: the page follows.

- [ ] **Step 6: Commit**

```bash
git add src/static/js/app/theme.js src/static/js/app/core.js src/static/js/app/main.js tests/theme.test.mjs
git commit -m "feat(theme): system/dark/light preference, editor follows the theme"
```

---

### Task 10: `format.js` (times, sizes, countries, HTTP status text)

**Files:**
- Create: `src/static/js/app/format.js`
- Test: `tests/format.test.mjs` (new)

**Interfaces:**
- Produces: `SLOW_MS = 2000`; `toMs(value): number` (accepts epoch s, epoch ms, ISO string with up to 6 fractional digits, or a Date; returns `NaN` otherwise); `relativeTime(value, now = Date.now()): string` ('' when invalid); `absoluteTime(value): string` (`YYYY-MM-DD HH:MM:SS` local); `clockTime(value, now): string` (`HH:MM` today, else `19 Nov, 08:10`); `dayLabel(value, now): string` (`Today, 14:24` / `Yesterday, 18:12` / `18 Nov, 09:41` / `12 Nov 2025, 22:03`); `shortDateTime(value): string` (always `19 Nov, 08:10`, never relative); `backupDate(name): Date | null`; `backupLabel(name, now): string`; `countryName(code): string`; `statusText(code): string`; `durationNote(status): string`; `formatBytes(n)`, `formatMs(ms)`, `formatCount(n)`, `formatPercent(p, digits = 1)`; `percentChange(current, previous): number | null`; `shortHost(host): string`.

- [ ] **Step 1: Write the failing test**

Create `tests/format.test.mjs`:

```js
// Tests for src/static/js/app/format.js
//
// Dates are built with local-time constructors, so the expectations hold in any
// time zone. Run with: node tests/format.test.mjs
import assert from 'node:assert/strict';
import path from 'node:path';

const SRC = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app', 'format.js');
const f = await import(SRC);

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };
const at = (...a) => new Date(...a).getTime();
const NOW = at(2026, 10, 20, 15, 0, 0);

console.log('\n--- toMs ---');
check('epoch seconds become ms', () => assert.equal(f.toMs(1790000000), 1790000000000));
check('epoch ms pass through', () => assert.equal(f.toMs(1790000000123), 1790000000123));
check('toMs accepts Python isoformat with microseconds', () =>
  assert.equal(f.toMs('2026-11-20T14:24:10.123456'), at(2026, 10, 20, 14, 24, 10, 123)));
check('a Date is accepted', () => assert.equal(f.toMs(new Date(NOW)), NOW));
check('garbage is NaN', () => { assert.ok(Number.isNaN(f.toMs('soon'))); assert.ok(Number.isNaN(f.toMs(null))); });

console.log('\n--- relativeTime ---');
check('under a minute', () => assert.equal(f.relativeTime(NOW - 30000, NOW), 'just now'));
check('minutes', () => assert.equal(f.relativeTime(NOW - 16 * 60000, NOW), '16 min ago'));
check('hours and minutes under 6h', () => assert.equal(f.relativeTime(NOW - 100 * 60000, NOW), '1h 40m ago'));
check('whole hours drop the minutes', () => assert.equal(f.relativeTime(NOW - 3 * 3600000, NOW), '3h ago'));
check('hours only past 6h', () => assert.equal(f.relativeTime(NOW - (8 * 60 + 20) * 60000, NOW), '8h ago'));
check('yesterday', () => assert.equal(f.relativeTime(NOW - 30 * 3600000, NOW), 'yesterday'));
check('days', () => assert.equal(f.relativeTime(NOW - 3 * 86400000, NOW), '3 days ago'));
check('older shows the date', () => assert.equal(f.relativeTime(at(2026, 10, 10, 9, 0), NOW), '10 Nov'));
check('a clock slightly ahead reads as just now', () => assert.equal(f.relativeTime(NOW + 5000, NOW), 'just now'));
check('relativeTime of garbage is empty', () => { assert.equal(f.relativeTime('soon', NOW), ''); assert.equal(f.relativeTime(undefined, NOW), ''); });
check('seconds input works too', () => assert.equal(f.relativeTime(NOW / 1000 - 120, NOW), '2 min ago'));

console.log('\n--- absolute, clock and day labels ---');
check('absoluteTime', () => assert.equal(f.absoluteTime(at(2026, 10, 20, 14, 24, 10)), '2026-11-20 14:24:10'));
check('absoluteTime of garbage is empty', () => assert.equal(f.absoluteTime('x'), ''));
check('clockTime today', () => assert.equal(f.clockTime(at(2026, 10, 20, 14, 31) / 1000, NOW), '14:31'));
check('clockTime another day', () => assert.equal(f.clockTime(at(2026, 10, 19, 8, 10), NOW), '19 Nov, 08:10'));
check('dayLabel today / yesterday / earlier / other year', () => {
  assert.equal(f.dayLabel(at(2026, 10, 20, 14, 24), NOW), 'Today, 14:24');
  assert.equal(f.dayLabel(at(2026, 10, 19, 18, 12), NOW), 'Yesterday, 18:12');
  assert.equal(f.dayLabel(at(2026, 10, 18, 9, 41), NOW), '18 Nov, 09:41');
  assert.equal(f.dayLabel(at(2025, 10, 12, 22, 3), NOW), '12 Nov 2025, 22:03');
});

console.log('\n--- backup names ---');
check('backupDate parses the name, with or without a counter', () => {
  assert.equal(f.backupDate('Caddyfile.20261120-142410').getTime(), at(2026, 10, 20, 14, 24, 10));
  assert.equal(f.backupDate('Caddyfile.20261120-142410-3').getTime(), at(2026, 10, 20, 14, 24, 10));
  assert.equal(f.backupDate('Caddyfile.weird'), null);
});
check('backupLabel', () => {
  assert.equal(f.backupLabel('Caddyfile.20261120-142410', NOW), 'Today, 14:24');
  assert.equal(f.backupLabel('Caddyfile.weird', NOW), 'weird');
});

console.log('\n--- countries and status text ---');
check('country names via Intl.DisplayNames', () => {
  assert.equal(f.countryName('GB'), 'United Kingdom');
  assert.equal(f.countryName('de'), 'Germany');
});
check('Cloudflare specials and fallbacks', () => {
  assert.equal(f.countryName('T1'), 'Tor network');
  assert.equal(f.countryName('XX'), 'Unknown country');
  assert.equal(f.countryName(''), '');
  assert.equal(f.countryName('1'), '1');
});
check('statusText', () => {
  assert.equal(f.statusText(504), 'Gateway timeout');
  assert.equal(f.statusText('404'), 'Not found');
  assert.equal(f.statusText(599), '');
});
check('durationNote only for 504', () => { assert.equal(f.durationNote(504), 'upstream timeout'); assert.equal(f.durationNote(502), ''); });

console.log('\n--- numbers ---');
check('formatBytes', () => {
  assert.equal(f.formatBytes(0), '0 B'); assert.equal(f.formatBytes(512), '512 B');
  assert.equal(f.formatBytes(1536), '1.5 KB'); assert.equal(f.formatBytes(31457280), '30.0 MB');
});
check('formatMs', () => {
  assert.equal(f.formatMs(141), '141 ms'); assert.equal(f.formatMs(2.5), '2.5 ms');
  assert.equal(f.formatMs(12400), '12.4 s'); assert.equal(f.formatMs(125000), '125 s');
  assert.equal(f.formatMs(null), '—');
});
check('formatCount', () => { assert.equal(f.formatCount(857), '857'); assert.equal(f.formatCount(1319), '1,319'); assert.equal(f.formatCount(48211), '48.2k'); });
check('formatPercent', () => { assert.equal(f.formatPercent(3.3333), '3.3%'); assert.equal(f.formatPercent(32.31, 0), '32%'); });
check('percentChange', () => {
  assert.equal(f.percentChange(112, 100), 12); assert.equal(f.percentChange(88, 100), -12);
  assert.equal(f.percentChange(5, 0), null); assert.equal(f.percentChange(5, null), null);
});
check('shortHost', () => assert.equal(f.shortHost('torrent.example.com'), 'torrent'));
check('shortDateTime is never relative', () => {
  assert.equal(f.shortDateTime(at(2026, 10, 20, 14, 24)), '20 Nov, 14:24');
  assert.equal(f.shortDateTime('nope'), '');
});

console.log(`\n${passed} passed`);
```

- [ ] **Step 2: Run to verify it fails**

Run: `node tests/format.test.mjs`
Expected: FAIL with `Cannot find module …/format.js`.

- [ ] **Step 3: Implement `src/static/js/app/format.js`**

```js
// Display formatting shared by the views: times, sizes, durations, countries and
// HTTP status text. Pure functions with no DOM, so tests import this directly.

export const SLOW_MS = 2000;   // a duration or p95 at or above this is "slow"

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const pad = (n) => String(n).padStart(2, '0');
const ok = (ms) => typeof ms === 'number' && Number.isFinite(ms);
const hm = (d) => `${pad(d.getHours())}:${pad(d.getMinutes())}`;
const dayMonth = (d) => `${d.getDate()} ${MONTHS[d.getMonth()]}`;
const sameDay = (a, b) => a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();

/** Epoch seconds, epoch ms, an ISO string or a Date -> epoch ms (NaN if none of those). */
export function toMs(value) {
  if (value instanceof Date) return value.getTime();
  if (typeof value === 'number') return value < 1e12 ? value * 1000 : value;
  if (typeof value === 'string' && value) {
    // Python's isoformat() writes microseconds; keep the milliseconds every engine parses.
    return Date.parse(value.replace(/(\.\d{3})\d+/, '$1'));
  }
  return NaN;
}

export function relativeTime(value, now = Date.now()) {
  const ms = toMs(value);
  if (!ok(ms)) return '';
  const secs = Math.max(0, Math.round((now - ms) / 1000));
  if (secs < 60) return 'just now';
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.floor(mins / 60);
  const rem = mins % 60;
  if (hours < 6) return rem ? `${hours}h ${rem}m ago` : `${hours}h ago`;
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days === 1) return 'yesterday';
  if (days < 7) return `${days} days ago`;
  return dayMonth(new Date(ms));
}

export function absoluteTime(value) {
  const ms = toMs(value);
  if (!ok(ms)) return '';
  const d = new Date(ms);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${hm(d)}:${pad(d.getSeconds())}`;
}

export function clockTime(value, now = Date.now()) {
  const ms = toMs(value);
  if (!ok(ms)) return '';
  const d = new Date(ms);
  return sameDay(d, new Date(now)) ? hm(d) : `${dayMonth(d)}, ${hm(d)}`;
}

export function dayLabel(value, now = Date.now()) {
  const ms = toMs(value);
  if (!ok(ms)) return '';
  const d = new Date(ms);
  const today = new Date(now);
  const yesterday = new Date(today.getFullYear(), today.getMonth(), today.getDate() - 1);
  if (sameDay(d, today)) return `Today, ${hm(d)}`;
  if (sameDay(d, yesterday)) return `Yesterday, ${hm(d)}`;
  const year = d.getFullYear() === today.getFullYear() ? '' : ` ${d.getFullYear()}`;
  return `${dayMonth(d)}${year}, ${hm(d)}`;
}

/** "Caddyfile.20261120-142410[-N]" -> that local time, or null. */
export function backupDate(name) {
  const m = /^Caddyfile\.(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})(?:-\d+)?$/.exec(name || '');
  if (!m) return null;
  const [y, mo, d, h, mi, s] = m.slice(1).map(Number);
  return new Date(y, mo - 1, d, h, mi, s);
}

export function backupLabel(name, now = Date.now()) {
  const d = backupDate(name);
  return d ? dayLabel(d, now) : String(name || '').replace(/^Caddyfile\./, '');
}

// Cloudflare's CF-IPCountry specials, which are not ISO regions.
const COUNTRY_SPECIAL = { XX: 'Unknown country', T1: 'Tor network' };
let regionNames = null;

export function countryName(code) {
  if (!code) return '';
  const up = String(code).toUpperCase();
  if (COUNTRY_SPECIAL[up]) return COUNTRY_SPECIAL[up];
  try {
    regionNames ||= new Intl.DisplayNames(['en'], { type: 'region' });
    const name = regionNames.of(up);
    return name && name !== up ? name : up;
  } catch {
    return up;   // not a region code, or Intl without region names
  }
}

const STATUS_TEXT = {
  100: 'Continue', 101: 'Switching protocols', 200: 'OK', 201: 'Created', 202: 'Accepted',
  204: 'No content', 206: 'Partial content', 301: 'Moved permanently', 302: 'Found',
  303: 'See other', 304: 'Not modified', 307: 'Temporary redirect', 308: 'Permanent redirect',
  400: 'Bad request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not found',
  405: 'Method not allowed', 408: 'Request timeout', 409: 'Conflict', 410: 'Gone',
  413: 'Content too large', 414: 'URI too long', 415: 'Unsupported media type',
  421: 'Misdirected request', 429: 'Too many requests', 499: 'Client closed request',
  500: 'Internal server error', 501: 'Not implemented', 502: 'Bad gateway',
  503: 'Service unavailable', 504: 'Gateway timeout', 505: 'HTTP version not supported',
};
export function statusText(code) { return STATUS_TEXT[Number(code)] || ''; }
export function durationNote(status) { return Number(status) === 504 ? 'upstream timeout' : ''; }

export function formatBytes(n) {
  if (!Number.isFinite(n) || n <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${units[i]}`;
}

export function formatMs(ms) {
  if (ms == null || !Number.isFinite(ms)) return '—';
  if (ms < 1000) return `${ms < 10 ? ms.toFixed(1) : Math.round(ms)} ms`;
  const s = ms / 1000;
  return `${s >= 100 ? Math.round(s) : s.toFixed(1)} s`;
}

export function formatCount(n) {
  if (!Number.isFinite(n)) return '0';
  return n >= 10000 ? `${(n / 1000).toFixed(1)}k` : n.toLocaleString('en-US');
}

export function formatPercent(p, digits = 1) {
  return `${(Number.isFinite(p) ? p : 0).toFixed(digits)}%`;
}

/** Whole-percent change, or null when there is no meaningful baseline. */
export function percentChange(current, previous) {
  if (previous == null || !(previous > 0) || !Number.isFinite(current)) return null;
  return Math.round(((current - previous) / previous) * 100);
}

export function shortHost(host) { return String(host || '').split('.')[0]; }

/** "19 Nov, 08:10" whatever today is: for naming a backup inside a sentence. */
export function shortDateTime(value) {
  const ms = toMs(value);
  if (!ok(ms)) return '';
  const d = new Date(ms);
  return `${dayMonth(d)}, ${hm(d)}`;
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node tests/format.test.mjs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/static/js/app/format.js tests/format.test.mjs
git commit -m "feat(ui): shared formatting for times, sizes, countries and status text"
```

---

### Task 11: In-design dialogs and toasts, replacing every `alert()` / `confirm()`

**Files:**
- Create: `src/static/js/app/ui/dialog.js`, `src/static/js/app/ui/toast.js`, `src/static/js/app/warnings.js`
- Modify: `src/static/js/app/validate.js` (rewrite), `src/static/js/app/backups.js`, `src/static/js/app/csrf.js`, `src/static/js/app/main.js` (Escape handler), `src/static/js/app/icons.js` (new names), `src/templates/_icons.html` (new symbols), `src/templates/index.html` (save-diff `<dialog>`), `src/static/css/style.css` (buttons, dialogs and toasts)
- Test: `tests/no-native-dialogs.test.mjs`, `tests/icons.test.mjs`, `tests/warnings.test.mjs` (new)

**Interfaces:**
- Produces: `confirmDialog({ title, body = '', detail = null, confirmLabel = 'OK', cancelLabel = 'Cancel', danger = false }): Promise<boolean>` and `alertDialog({ title, body = '', detail = null, okLabel = 'OK' }): Promise<void>`. Each builds a native `<dialog>`, shows it modally, returns focus to the opener, and treats Esc as Cancel. `detail` renders in a monospace, pre-wrapped block. With `danger: true` the confirm button is `btn-danger-solid` and initial focus goes to Cancel.
- Produces: `toast(message, { kind = 'ok' | 'info' | 'warn' | 'error', action = { label, run } | null, timeout }) : { dismiss }`. Default timeouts: 5 s, 8 s with an action, and errors stay until dismissed. Every toast has an icon by kind (check / info / warning / status-down) and a close button. At most 3 are on screen.
- Produces: `parseWarning(text): { line: number|null, text: string, kind: 'fmt'|'dns'|'other' }` and `withoutFormat(list: string[]): string[]`.
- Produces: icon names `status-ok status-down status-none status-unknown info save key restore sun moon monitor blocks chevron-right chevron-left chevron-up minus-circle shield mark`.
- `validate.js` keeps `doValidate()`, `doSave()` and `resolveSaveModal(value)`, and adds `showWarnings(list: string[])` and `hideWarnings()`. Task 15 extends these.

- [ ] **Step 1: Write the failing tests**

Create `tests/no-native-dialogs.test.mjs`:

```js
// No native alert()/confirm()/prompt() anywhere in the app's own scripts: they
// block the page, ignore the theme and cannot carry consequence copy.
// Run with: node tests/no-native-dialogs.test.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const JS = path.join(import.meta.dirname, '..', 'src', 'static', 'js');
const BUNDLES = new Set(['editor.bundle.js', 'explore-vendor.js']);
const files = fs.readdirSync(JS, { recursive: true })
  .map(String).filter(f => f.endsWith('.js') && !BUNDLES.has(path.basename(f)));
const NATIVE = /(?<![\w$.])(?:window\.)?(alert|confirm|prompt)\s*\(/;

let passed = 0;
for (const f of files) {
  const code = fs.readFileSync(path.join(JS, f), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:'"`])\/\/.*$/gm, '$1');
  const hit = code.split('\n').find(line => NATIVE.test(line));
  assert.equal(hit, undefined, `${f} still calls a native dialog: ${hit && hit.trim()}`);
  passed++;
  console.log(`  ok  ${f}`);
}
console.log(`\n${passed} passed`);
```

Create `tests/icons.test.mjs`:

```js
// Every icon name the app uses has a symbol in the sprite.
// Run with: node tests/icons.test.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const SRC = path.join(import.meta.dirname, '..', 'src');
const sprite = fs.readFileSync(path.join(SRC, 'templates', '_icons.html'), 'utf8');
const symbols = new Set([...sprite.matchAll(/<symbol id="i-([\w-]+)"/g)].map(m => m[1]));
const iconsJs = fs.readFileSync(path.join(SRC, 'static', 'js', 'app', 'icons.js'), 'utf8');
const listed = [...iconsJs.match(/export const ICONS = \[([\s\S]*?)\];/)[1].matchAll(/'([\w-]+)'/g)].map(m => m[1]);

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };

check('every ICONS entry has a sprite symbol', () => assert.deepEqual(listed.filter(n => !symbols.has(n)), []));
for (const f of fs.readdirSync(path.join(SRC, 'static', 'js', 'app'), { recursive: true }).map(String).filter(f => f.endsWith('.js'))) {
  const text = fs.readFileSync(path.join(SRC, 'static', 'js', 'app', f), 'utf8');
  const used = [
    ...text.matchAll(/<\$\{Icon\} name="([\w-]+)"/g),
    ...text.matchAll(/iconEl\('([\w-]+)'/g),
    ...text.matchAll(/\bicon: '([\w-]+)'/g),
  ].map(m => m[1]);
  check(`${f} uses only listed icons`, () => assert.deepEqual(used.filter(n => !listed.includes(n)), []));
}
for (const f of fs.readdirSync(path.join(SRC, 'templates'))) {
  const text = fs.readFileSync(path.join(SRC, 'templates', f), 'utf8');
  const used = [...text.matchAll(/href="#i-([\w-]+)"/g)].map(m => m[1]);
  check(`templates/${f} references existing symbols`, () => assert.deepEqual(used.filter(n => !symbols.has(n)), []));
}
console.log(`\n${passed} passed`);
```

Create `tests/warnings.test.mjs`:

```js
// Tests for src/static/js/app/warnings.js
// Run with: node tests/warnings.test.mjs
import assert from 'node:assert/strict';
import path from 'node:path';

const SRC = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app', 'warnings.js');
const { parseWarning, withoutFormat } = await import(SRC);

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };
const FMT = 'Line 12: not formatted — Check will fix whitespace on 2 lines';
const DNS = 'Line 58: upstream radarr:7878 could not be resolved from the console container';

check('line-linked format warning', () => assert.deepEqual(parseWarning(FMT),
  { line: 12, text: 'Not formatted — Check will fix whitespace on 2 lines', kind: 'fmt' }));
check('line-linked resolve warning', () => assert.deepEqual(parseWarning(DNS),
  { line: 58, text: 'Upstream radarr:7878 could not be resolved from the console container', kind: 'dns' }));
check('a warning without a line keeps its text', () => assert.deepEqual(
  parseWarning("Access logging is enabled without 'format filter'"),
  { line: null, text: "Access logging is enabled without 'format filter'", kind: 'other' }));
check('blockingWarnings drops the format warning', () => assert.deepEqual(withoutFormat([FMT, DNS]), [DNS]));
console.log(`\n${passed} passed`);
```

- [ ] **Step 2: Run to verify they fail**

Run: `node tests/no-native-dialogs.test.mjs; node tests/icons.test.mjs; node tests/warnings.test.mjs`
Expected: the first fails on `csrf.js` or `validate.js` ("still calls a native dialog"); `icons.test.mjs` passes for now; `warnings.test.mjs` fails with `Cannot find module`.

- [ ] **Step 3: Icons**

In `src/templates/_icons.html`, add these symbols inside `<defs>` (24-grid stroke icons, copied from the mockup's sprite, plus `monitor` and `info`):

```html
    <!-- Status shapes: each state has its own outline, so colour is never the only cue. -->
    <symbol id="i-status-ok" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="m8.3 12.2 2.5 2.5 5-5"/></symbol>
    <symbol id="i-status-down" viewBox="0 0 24 24"><path d="M8.2 3.5h7.6l5.7 5.7v7.6l-5.7 5.7H8.2l-5.7-5.7V9.2z"/><path d="m9 9 6 6M15 9l-6 6"/></symbol>
    <symbol id="i-status-none" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5" stroke-dasharray="3 3"/></symbol>
    <symbol id="i-status-unknown" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="M12 8v4M12 16h0"/></symbol>
    <symbol id="i-info" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="M12 11v5M12 8h0"/></symbol>
    <!-- Actions -->
    <symbol id="i-save" viewBox="0 0 24 24"><path d="M5 4h11l3 3v13H5z"/><path d="M8 4v5h7V4M8 20v-6h8v6"/></symbol>
    <symbol id="i-key" viewBox="0 0 24 24"><circle cx="8" cy="15" r="4"/><path d="m11 12 8.5-8.5M16 7l2.5 2.5"/></symbol>
    <symbol id="i-restore" viewBox="0 0 24 24"><path d="M4 12a8 8 0 1 0 2.4-5.7L4 8.5"/><path d="M4 4v4.5h4.5"/></symbol>
    <symbol id="i-blocks" viewBox="0 0 24 24"><rect x="3.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.5"/><path d="M17 14v6M14 17h6"/></symbol>
    <symbol id="i-minus-circle" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="M8 12h8"/></symbol>
    <symbol id="i-chevron-right" viewBox="0 0 24 24"><path d="m9 6 6 6-6 6"/></symbol>
    <symbol id="i-chevron-left" viewBox="0 0 24 24"><path d="m15 6-6 6 6 6"/></symbol>
    <symbol id="i-chevron-up" viewBox="0 0 24 24"><path d="m6 15 6-6 6 6"/></symbol>
    <!-- Theme -->
    <symbol id="i-sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M4.6 4.6l1.4 1.4M18 18l1.4 1.4M2.5 12h2M19.5 12h2M4.6 19.4 6 18M18 6l1.4-1.4"/></symbol>
    <symbol id="i-moon" viewBox="0 0 24 24"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/></symbol>
    <symbol id="i-monitor" viewBox="0 0 24 24"><rect x="3" y="4.5" width="18" height="12" rx="2"/><path d="M8.5 20h7M12 16.5V20"/></symbol>
    <!-- Sign-in and brand -->
    <symbol id="i-shield" viewBox="0 0 24 24"><path d="M12 3 4.5 6v5.5c0 4.5 3.2 8 7.5 9.5 4.3-1.5 7.5-5 7.5-9.5V6z"/></symbol>
    <symbol id="i-mark" viewBox="0 0 32 32"><rect x="1" y="1" width="30" height="30" rx="9" fill="var(--accent)" stroke="none"/><path d="M13 9.5c-2.6 0-3.5 1.3-3.5 3.3v1.4c0 1.1-.6 1.8-1.8 1.8 1.2 0 1.8.7 1.8 1.8v1.4c0 2 .9 3.3 3.5 3.3M19 9.5c2.6 0 3.5 1.3 3.5 3.3v1.4c0 1.1.6 1.8 1.8 1.8-1.2 0-1.8.7-1.8 1.8v1.4c0 2-.9 3.3-3.5 3.3" stroke="var(--accent-ink)" stroke-width="2.2" fill="none"/><circle cx="16" cy="16" r="1.8" fill="var(--accent-ink)" stroke="none"/></symbol>
```

In `src/static/js/app/icons.js` replace the `ICONS` array with:

```js
export const ICONS = [
  'dashboard', 'editor', 'explore',
  'box', 'box-check', 'box-x',
  'more', 'chevron-down', 'chevron-right', 'chevron-left', 'chevron-up', 'close', 'copy', 'clock', 'filter', 'live',
  'check', 'warning', 'info', 'external', 'logout', 'globe',
  'status-ok', 'status-down', 'status-none', 'status-unknown',
  'save', 'key', 'restore', 'blocks', 'minus-circle',
  'sun', 'moon', 'monitor', 'shield', 'mark',
];
```

- [ ] **Step 4: `warnings.js`, `ui/dialog.js`, `ui/toast.js`**

`src/static/js/app/warnings.js`:

```js
// Validation warnings arrive as plain strings, many as "Line N: …". Parsed here
// so the strip can link the line, and so Save can tell a cosmetic warning
// ("not formatted", fixed by the save itself) from one worth confirming.

const LINE_RE = /^Line (\d+):\s*/;

export function parseWarning(text) {
  const m = LINE_RE.exec(text);
  const rest = m ? text.slice(m[0].length) : text;
  const kind = /^not formatted\b/.test(rest) ? 'fmt'
    : /could not be resolved from the console container/.test(rest) ? 'dns' : 'other';
  return { line: m ? Number(m[1]) : null, text: rest.charAt(0).toUpperCase() + rest.slice(1), kind };
}

/** The warnings that should make Save ask first: everything but "not formatted". */
export function withoutFormat(list) {
  return (list || []).filter(w => parseWarning(w).kind !== 'fmt');
}
```

`src/static/js/app/ui/dialog.js`:

```js
// In-design replacements for alert() and confirm(), on the native <dialog>.
//
// showModal() gives focus containment, an inert page behind and Esc-to-cancel
// for free. Each call builds its own dialog and removes it when done, so two
// flows can never fight over one shared element.

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text) e.textContent = text;
  return e;
}

function build({ title, body, detail }) {
  const d = el('dialog');
  const id = 'dlg-' + Math.random().toString(36).slice(2, 9);
  d.setAttribute('aria-labelledby', id + '-h');
  const hd = el('div', 'dlg-hd');
  const h = el('h2', '', title);
  h.id = id + '-h';
  hd.append(h);
  if (body) hd.append(el('p', '', body));
  d.append(hd);
  if (detail) {
    const bd = el('div', 'dlg-bd');
    bd.append(el('pre', 'dlg-detail', detail));
    d.append(bd);
  }
  const ft = el('div', 'dlg-ft');
  d.append(ft);
  return { d, ft };
}

function button(label, cls) {
  const b = el('button', 'btn ' + cls, label);
  b.type = 'button';
  return b;
}

function show(d, focusEl, wire, cancelValue) {
  const opener = document.activeElement;
  document.body.append(d);
  return new Promise((resolve) => {
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      if (d.open) d.close();
      d.remove();
      if (opener && typeof opener.focus === 'function' && opener.isConnected) opener.focus();
      resolve(value);
    };
    wire(finish);
    d.addEventListener('cancel', (e) => { e.preventDefault(); finish(cancelValue); });
    d.showModal();
    focusEl.focus();
  });
}

export function confirmDialog({ title, body = '', detail = null, confirmLabel = 'OK', cancelLabel = 'Cancel', danger = false }) {
  const { d, ft } = build({ title, body, detail });
  const cancel = button(cancelLabel, 'btn-quiet');
  const ok = button(confirmLabel, danger ? 'btn-danger-solid' : 'btn-primary');
  ft.append(cancel, ok);
  // A destructive default would turn a stray Enter into data loss.
  return show(d, danger ? cancel : ok, (finish) => {
    ok.addEventListener('click', () => finish(true));
    cancel.addEventListener('click', () => finish(false));
  }, false);
}

export function alertDialog({ title, body = '', detail = null, okLabel = 'OK' }) {
  const { d, ft } = build({ title, body, detail });
  const ok = button(okLabel, 'btn-primary');
  ft.append(ok);
  return show(d, ok, (finish) => { ok.addEventListener('click', () => finish(undefined)); }, undefined);
}
```

`src/static/js/app/ui/toast.js`:

```js
// Transient results ("Saved and reloaded", "Copied"), bottom centre.
//
// Each toast carries an icon for its kind, so success and failure differ in
// shape, not only in wording. Errors stay until dismissed; the rest time out.
import { iconEl } from '../icons.js';

const ICON = { ok: 'check', info: 'info', warn: 'warning', error: 'status-down' };
const MAX = 3;
let host = null;

function container() {
  if (!host || !host.isConnected) {
    host = document.createElement('div');
    host.className = 'toasts';
    host.setAttribute('aria-live', 'polite');
    document.body.append(host);
  }
  return host;
}

export function toast(message, { kind = 'ok', action = null, timeout } = {}) {
  const t = document.createElement('div');
  t.className = 'toast toast-' + kind;
  t.setAttribute('role', kind === 'error' ? 'alert' : 'status');
  t.append(iconEl(ICON[kind] || 'check', { size: 16 }));
  const text = document.createElement('span');
  text.textContent = message;
  t.append(text);
  let timer = null;
  const dismiss = () => { clearTimeout(timer); t.remove(); };
  if (action) {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = action.label;
    b.addEventListener('click', () => { dismiss(); action.run(); });
    t.append(b);
  }
  const close = document.createElement('button');
  close.type = 'button';
  close.className = 'toast-x';
  close.setAttribute('aria-label', 'Dismiss');
  close.append(iconEl('close', { size: 14 }));
  close.addEventListener('click', dismiss);
  t.append(close);
  const box = container();
  box.append(t);
  while (box.children.length > MAX) box.firstChild.remove();
  const ms = timeout ?? (kind === 'error' ? 0 : action ? 8000 : 5000);
  if (ms > 0) timer = setTimeout(dismiss, ms);
  return { dismiss };
}
```

- [ ] **Step 5: The save-diff dialog markup**

In `src/templates/index.html`, replace the whole `<!-- Save Diff Modal -->` block (the `<div class="modal-overlay" id="save-diff-modal">…</div>`) with:

```html
<dialog class="wide" id="save-diff-modal" aria-labelledby="save-diff-h">
  <div class="dlg-hd">
    <h2 id="save-diff-h">Review changes before saving</h2>
    <p>Comparing your editor (new) against the live config on disk.</p>
  </div>
  <div class="dlg-bd">
    <div class="dsum" id="save-diff-summary"></div>
    <div class="diff" id="save-diff-content"></div>
  </div>
  <div class="dlg-ft">
    <span class="note">Caddy reloads gracefully; open connections are kept.</span>
    <button class="btn btn-quiet" type="button" data-act="cancel-save">Cancel</button>
    <button class="btn btn-primary" type="button" data-act="confirm-save"><svg class="icon" width="16" height="16" aria-hidden="true" focusable="false"><use href="#i-save"/></svg>Save &amp; Reload</button>
  </div>
</dialog>
```

- [ ] **Step 6: Rewrite `validate.js`**

Replace `src/static/js/app/validate.js` with:

```js
// Validate / Save flow, the pre-save diff dialog, and the warnings strip.
import { loadCaddyfile } from './caddyfile.js';
import {
  fetchJson, getContent, getVersion, isDirty, markSaved, originalContent,
  setContent, setDot, setOriginal, setStatus, setVersion,
} from './core.js';
import { renderDiffInto } from './diff.js';
import { alertDialog, confirmDialog } from './ui/dialog.js';
import { toast } from './ui/toast.js';
import { withoutFormat } from './warnings.js';

const plural = (n, one) => `${n} ${one}${n === 1 ? '' : 's'}`;

async function _validateRequest(content) {
  const res = await fetch('/api/validate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ content }) });
  if (!res.ok) {
    // 401 is already being handled by the fetch wrapper; anything else is a
    // server problem, not a config problem, and must not read as "invalid".
    let msg = `HTTP ${res.status}`;
    try { const d = await res.json(); msg = d.error || d.message || msg; } catch (e) {}
    throw new Error(`Validation request failed: ${msg}`);
  }
  return res.json();
}

export async function doValidate() {
  setStatus('Checking and formatting…', 'info');
  let data;
  try { data = await _validateRequest(getContent()); }
  catch (e) { setStatus(e.message, 'err'); setDot('red'); toast(e.message, { kind: 'error' }); return; }
  if (!data.valid) {
    hideWarnings();
    setStatus(data.message, 'err'); setDot('red');
    toast('Check failed. Caddy’s message is in the status bar.', { kind: 'error' });
    return;
  }
  const passed = data.check_level === 'adapted'
    ? 'Syntax and modules accepted; the full check runs on save'
    : 'Config passed local validation';
  // The formatted text is applied now, so "not formatted" no longer applies.
  const warnings = data.formatted ? withoutFormat(data.warnings) : data.warnings;
  if (data.formatted) setContent(data.formatted);
  showWarnings(warnings);
  setDot(warnings.length || isDirty() ? 'yellow' : 'green');
  if (warnings.length) {
    setStatus(`Check passed with ${plural(warnings.length, 'warning')}`, 'warn');
    toast('Check passed, with warnings', { kind: 'warn' });
  } else {
    setStatus(data.formatted ? `Formatted. ${passed}` : passed, 'ok');
    toast(data.formatted ? 'Check passed and the file was formatted' : 'Check passed', { kind: 'ok' });
  }
}

// Only one save flow at a time: a second Cmd+S while the diff dialog is open
// used to start a second validation and orphan the first dialog's promise.
let _saving = false;

export async function doSave() {
  if (_saving) return;
  _saving = true;
  try { await _doSave(); }
  finally { _saving = false; }
}

async function _doSave() {
  setStatus('Validating before save…', 'info');
  const content = getContent();
  let valData;
  try { valData = await _validateRequest(content); }
  catch (e) { setStatus(e.message, 'err'); setDot('red'); toast(e.message, { kind: 'error' }); return; }
  if (!valData.valid) {
    setStatus(valData.message, 'err'); setDot('red');
    await alertDialog({ title: 'Cannot save: the config is invalid', body: 'Nothing was written. Caddy reported:', detail: valData.message });
    return;
  }
  const all = valData.warnings || [];
  showWarnings(all);
  // Save formats on the server, so "not formatted" is not worth a question.
  const blocking = withoutFormat(all);
  if (blocking.length) {
    setDot('yellow'); setStatus('Warnings found (review before saving)', 'warn');
    const go = await confirmDialog({
      title: `Save with ${plural(blocking.length, 'warning')}?`,
      body: 'The config is valid, but these look wrong:',
      detail: blocking.join('\n'),
      confirmLabel: 'Save anyway',
    });
    if (!go) { setStatus('Save cancelled', 'info'); return; }
  }

  // Pre-save live diff: editor (new) against the config currently on disk.
  setStatus('Building diff preview…', 'info');
  let live = originalContent;
  try { const ld = await fetchJson('/api/caddyfile'); live = ld.content; } catch (e) {}
  // Yield a frame so the status above paints before the synchronous diff.
  await new Promise(r => requestAnimationFrame(() => setTimeout(r, 0)));
  const summary = renderDiffInto(document.getElementById('save-diff-content'), live, content);
  const proceed = await openSaveModal(summary, live, content);
  if (!proceed) { setStatus('Save cancelled', 'info'); return; }

  setStatus('Saving…', 'info');
  let res;
  try {
    res = await fetch('/api/save', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ content, version: getVersion() }) });
  } catch (e) { setStatus(`Save failed: ${e.message}`, 'err'); setDot('red'); toast(`Save failed: ${e.message}`, { kind: 'error' }); return; }
  let data = null;
  try { data = await res.json(); } catch (e) {}
  if (res.status === 409) {
    setStatus('Save blocked: file changed on disk', 'err'); setDot('red');
    const reload = await confirmDialog({
      title: 'The Caddyfile changed on disk',
      body: `${(data && data.message) || 'Someone saved a newer version.'} Reloading replaces your unsaved edits with the version on disk.`,
      confirmLabel: 'Reload the latest version',
      cancelLabel: 'Keep my edits',
      danger: true,
    });
    if (reload) { await loadCaddyfile(); toast('Loaded the latest version from disk', { kind: 'info' }); }
    return;
  }
  if (!data) {
    setStatus(`Save failed: HTTP ${res.status}`, 'err'); setDot('red');
    toast(`Save failed: HTTP ${res.status}`, { kind: 'error' });
    return;
  }
  if (data.ok) {
    if (data.content) setContent(data.content);
    setOriginal(data.content || content);
    if (data.version) setVersion(data.version);
    setStatus(data.message, 'ok'); setDot('green');
    markSaved(); hideWarnings();
    toast('Saved and reloaded. Caddy accepted the new config.', { kind: 'ok' });
  } else if (data.saved) {
    // Written to disk, but Caddy could not reload or did not confirm. Keep the
    // editor in step with disk without claiming the running config matches.
    if (data.content) setContent(data.content);
    setOriginal(data.content || content);
    if (data.version) setVersion(data.version);
    setStatus(data.message, 'warn'); setDot('yellow');
    toast(data.message, { kind: 'warn' });
  } else {
    // Caddy rejected it and the server rolled the file back; keep its version
    // so a retry after fixing the config isn't reported as a conflict.
    if (data.version) setVersion(data.version);
    const msg = data.message || data.error || `Save failed: HTTP ${res.status}`;
    setStatus(msg, 'err'); setDot('red');
    toast('Caddy rejected the config; the file on disk was restored.', { kind: 'error' });
  }
}

// --- Save diff dialog (promise-based) ---
let _saveResolver = null;
const saveDialog = () => document.getElementById('save-diff-modal');

// `summary`, `live` and `next` are used by Task 15 to name the affected sites.
function openSaveModal(summary, live, next) {
  saveDialog().showModal();
  saveDialog().querySelector('[data-act="confirm-save"]').focus();
  return new Promise(resolve => { _saveResolver = resolve; });
}

export function resolveSaveModal(value) {
  if (saveDialog().open) saveDialog().close();
  // Drop the rendered diff (tens of thousands of rows for a big file).
  document.getElementById('save-diff-content').textContent = '';
  if (_saveResolver) { _saveResolver(value); _saveResolver = null; }
}

// Esc on a native dialog fires `cancel`: treat it as Cancel so the flow never hangs.
saveDialog().addEventListener('cancel', (e) => { e.preventDefault(); resolveSaveModal(false); });

export function showWarnings(warnings) {
  const box = document.getElementById('warnings');
  box.textContent = '';
  (warnings || []).forEach(w => { const div = document.createElement('div'); div.textContent = w; box.appendChild(div); });
  box.classList.toggle('show', !!(warnings && warnings.length));
}
export function hideWarnings() { document.getElementById('warnings').classList.remove('show'); }
```

(`showWarnings` is restyled into the line-linked strip in Task 15. This version keeps today's `#warnings` behaviour.)

In `src/static/js/app/diff.js`, make `renderDiffInto` return a summary, and replace the inline grey with a class. Change `d.style.cssText = 'color:#555';` to `d.className = 'diff-eq';`, and replace the function's final `container.appendChild(frag);` with:

```js
  container.appendChild(frag);
  return summarizeOps(ops);
```

Then add below `renderDiffInto`:

```js
/** Counts and line numbers of a diff: removed lines in the old text, added in the new. */
export function summarizeOps(ops) {
  let a = 1, b = 1;
  const out = { added: 0, removed: 0, oldLines: [], newLines: [] };
  for (const op of ops) {
    if (op.type === 'equal') { a++; b++; }
    else if (op.type === 'delete') { out.removed++; out.oldLines.push(a); a++; }
    else { out.added++; out.newLines.push(b); b++; }
  }
  return out;
}
```

- [ ] **Step 7: `backups.js` and `csrf.js`**

In `src/static/js/app/backups.js`, add the imports `import { alertDialog, confirmDialog } from './ui/dialog.js';`, `import { toast } from './ui/toast.js';` and `import { backupLabel } from './format.js';`. Replace the `delBtn.onclick` handler with:

```js
    delBtn.onclick = async (e) => {
      e.stopPropagation();
      const label = backupLabel(b);
      const ok = await confirmDialog({
        title: `Delete the backup from ${label}?`,
        body: 'The file is removed from disk and cannot be restored. Your live Caddyfile is not affected.',
        confirmLabel: 'Delete backup',
        danger: true,
      });
      if (!ok) return;
      try {
        await fetchJson(`/api/backups/${encodeURIComponent(b)}`, { method: 'DELETE' });
        toast(`Deleted the backup from ${label}`, { kind: 'ok' });
        loadBackups();
      } catch (err) { toast(`Delete failed: ${err.message}`, { kind: 'error' }); }
    };
```

Replace `restoreFromPreview` and `rollbackFromPreview` with:

```js
export function restoreFromPreview() {
  setContent(previewBackupContent);
  setStatus('Backup loaded (unsaved)', 'info'); setDot('yellow');
  toast(`Loaded the backup from ${backupLabel(currentPreviewName)} into the editor. Save & Reload to apply it.`, { kind: 'info' });
  closePanel('backups');
}

export async function rollbackFromPreview() {
  if (!currentPreviewName) return;
  const name = currentPreviewName;
  const label = backupLabel(name);
  const go = await confirmDialog({
    title: `Roll back to the backup from ${label}?`,
    body: 'This writes the backup to the live Caddyfile and reloads Caddy. The current file is backed up first, and unsaved editor changes are discarded.',
    confirmLabel: 'Roll back and reload',
    danger: true,
  });
  if (!go) return;
  setStatus('Restoring and reloading…', 'info'); setDot('yellow');
  let res, data = null;
  try {
    res = await fetch(`/api/backups/${encodeURIComponent(name)}/restore`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ version: getVersion() }),
    });
    try { data = await res.json(); } catch (e) {}
  } catch (e) {
    setStatus(`Restore failed: ${e.message}`, 'err'); setDot('red');
    toast(`Restore failed: ${e.message}`, { kind: 'error' });
    return;
  }
  if (data && data.ok) {
    const restored = data.content || previewBackupContent;
    setContent(restored); setOriginal(restored); if (data.version) setVersion(data.version);
    setStatus(data.message, 'ok'); setDot('green');
    markSaved();
    toast(`Rolled back to ${label}. Caddy reloaded.`, { kind: 'ok' });
    closePanel('backups');
  } else if (data && data.conflict) {
    if (data.version) setVersion(data.version);
    setStatus('Restore blocked: file changed on disk', 'err'); setDot('red');
    await alertDialog({ title: 'Restore blocked: the file changed on disk', body: data.message || 'The live Caddyfile changed. Reload it before restoring a backup.' });
  } else if (data && data.saved) {
    const restored = data.content || previewBackupContent;
    setContent(restored); setOriginal(restored); if (data.version) setVersion(data.version);
    setStatus(data.message, 'warn'); setDot('yellow');
    toast(data.message, { kind: 'warn' });
    closePanel('backups');
  } else {
    const msg = (data && (data.message || data.error)) || `HTTP ${res.status}`;
    if (data && data.version) setVersion(data.version);
    setStatus(msg, 'err'); setDot('red');
    await alertDialog({ title: 'Restore failed', body: 'The live Caddyfile was not changed.', detail: msg });
  }
}
```

In `src/static/js/app/csrf.js`, add `import { alertDialog } from './ui/dialog.js';` and replace the `alert(…); window.location.href = '/welcome';` pair with:

```js
    alertDialog({
      title: 'Your session has expired',
      body: 'Sign in again to continue. If you have unsaved changes, copy them somewhere first.',
      okLabel: 'Sign in again',
    }).then(() => { window.location.href = '/welcome'; });
```

In `src/static/js/app/main.js`, in the Escape `keydown` listener, add `if (document.querySelector('dialog[open]')) return;` directly after `if (e.key !== 'Escape') return;`, and delete the two lines that resolve the save modal (the comment and `if (document.getElementById('save-diff-modal')…) resolveSaveModal(false);`). The dialog's `cancel` event handles that now.

- [ ] **Step 8: CSS for buttons, dialogs and toasts**

In `src/static/css/style.css`, delete the rules under `/* Buttons */` (through `.btn-sm`) and under `/* Modal (save diff) */`, and put this in their place:

1. A `/* === buttons === */` marker, then **mockup lines 79–99 verbatim** (`.btn` through `.seg button[aria-checked="true"]`).
2. A `/* === dialogs and toasts === */` marker, then **mockup lines 342–361 verbatim** (`dialog{…}` through `@keyframes tin`).
3. Then these app additions:

```css
/* Old class names still used by markup that later tasks rewrite. */
.btn-sm{height:28px;padding:0 10px;font-size:var(--t-xs)}
.btn-tool{background:transparent;border-color:transparent;color:var(--ink-2)}
.btn-tool:hover,.btn-tool.panel-active,.btn-quiet[aria-pressed="true"]{background:var(--bg-3);color:var(--ink)}
/* .btn-save was referenced but never defined; it is the primary action. */
.btn-save{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}
.btn-save:hover{background:var(--accent-hi)}
.btn-tab{background:transparent;border-color:transparent;color:var(--ink-2)}
.btn-tab.active{background:var(--bg-4);color:var(--ink)}
.btn:disabled{cursor:default;opacity:.6}
.btn-primary:disabled{opacity:1}
.dlg-detail{margin:0;padding:10px 12px;border-radius:var(--r-md);background:var(--bg);font:12.5px/1.6 var(--mono);color:var(--ink-2);white-space:pre-wrap;overflow-wrap:anywhere;max-height:40vh;overflow:auto}
.toast .icon{color:var(--bg)}
.toast .toast-x{display:inline-grid;place-items:center;width:24px;height:24px;border-radius:var(--r-sm);text-decoration:none}
.diff-eq{color:var(--ink-3)}
a.btn,a.btn:hover{text-decoration:none}
```

In every rule you copied from the mockup, replace the class selector `.ic` with `.icon` (regex `\.ic(?![\w-])` → `.icon`). The app's icon helpers emit `class="icon"`.

- [ ] **Step 9: Run all JS tests and check in the browser**

Run: `for t in tests/*.test.mjs; do node "$t" || exit 1; done`
Expected: PASS (`no-native-dialogs`, `icons` and `warnings` included).
Browser, http://localhost:8888/editor:
- Make a change and press Save & Reload. The diff opens as a centred dialog. Esc closes it and the status reads "Save cancelled". Save again and confirm: the toast says "Saved and reloaded…".
- Type `foo {` on a new line and save: the "Cannot save: the config is invalid" dialog shows Caddy's message in monospace. Press OK and focus returns to the editor.
- Backups → open one → Delete: the dialog is red-buttoned with focus on Cancel.

- [ ] **Step 10: Commit**

```bash
git add src/static/js/app src/templates src/static/css/style.css tests/no-native-dialogs.test.mjs tests/icons.test.mjs tests/warnings.test.mjs
git commit -m "feat(ui): in-design dialogs and toasts replace alert() and confirm()"
```

---

## Part 3: Views

### Task 12: App shell, header, account menu, and a status bar that lives in the Editor

**Files:**
- Create: `src/static/js/app/ui/seg.js`
- Modify: `src/templates/index.html` (header and view containers), `src/static/js/app/usermenu.js` (rewrite), `src/static/js/app/caddyfile.js` (`showView`), `src/static/js/app/core.js` (`setDot`), `src/static/js/app/panels.js` (`aria-pressed`), `src/static/js/app/search.js` (`aria-pressed` on Find), `src/static/css/style.css`
- Test: `tests/shell.test.mjs` (new)

**Interfaces:**
- Consumes: `THEMES`, `getThemePref`, `setThemePref`, `applyTheme` (Task 9); icons (Task 11).
- Produces: `segmented({ label, options: {id, label, icon?}[], value, onChange }): { el: HTMLElement, set(value) }`. This is a `role="radiogroup"` where the arrow keys move and select, and only the checked button is in the Tab order.
- Produces the DOM contract later tasks rely on. `#tab-dashboard`, `#tab-explore` and `#tab-editor` are `section.tab-content`, and the shown one has class `active`. `#tab-editor` also has class `editor` and contains `.ed-col`. The status bar (`.sbar`, with `#status-line[data-state=ok|modified|error]`, `#status-icon`, `#status-msg`, `#last-saved`, `#doc-stats`, `#cursor-pos`) sits inside `#tab-editor`. Header tabs are `a.tab[data-view]` with `aria-current="page"` on the active one. Editor tools are `.etools[data-for-view="editor"]`, toggled with `hidden`. The account menu is `#user-menu > .acct-btn + #acct-menu.pop.acct-menu`.
- `setDot('green'|'yellow'|'red')` keeps its signature. It now sets `#status-line[data-state]` and swaps the icon shape (status-ok / warning / status-down).

- [ ] **Step 1: Write the failing test**

Create `tests/shell.test.mjs`:

```js
// Structural checks on the app shell template.
// Run with: node tests/shell.test.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const html = fs.readFileSync(path.join(import.meta.dirname, '..', 'src', 'templates', 'index.html'), 'utf8');
let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };

check('tabs are Dashboard, Explore, Editor', () => assert.deepEqual(
  [...html.matchAll(/class="tab" data-view="(\w+)"/g)].map(m => m[1]), ['dashboard', 'explore', 'editor']));
check('the status bar lives inside the editor view', () => {
  const start = html.indexOf('id="tab-editor"');
  const end = html.indexOf('</section>', start);
  const sbar = html.indexOf('class="sbar"');
  assert.ok(start > 0 && sbar > start && sbar < end, 'status bar outside #tab-editor');
});
check('editor tools start hidden', () => assert.match(html, /class="etools" data-for-view="editor" hidden/));
check('one inline script, the hashed theme boot', () => assert.equal((html.match(/<script>/g) || []).length, 1));
check('no inline event handlers', () => assert.doesNotMatch(html, /\son[a-z]+="/));
console.log(`\n${passed} passed`);
```

- [ ] **Step 2: Run to verify it fails**

Run: `node tests/shell.test.mjs`
Expected: FAIL on "tabs are Dashboard, Explore, Editor" (today: dashboard, editor, explore).

- [ ] **Step 3: New shell markup**

In `src/templates/index.html`, replace everything from `<div class="header">` up to (not including) `<!-- Snippets Panel -->` with the markup below. The snippets and backups panels and the save dialog stay where they are until Task 15.

```html
<header class="hdr" id="hdr">
  <a class="brand" data-view="dashboard" href="/" aria-label="Caddy Console home">
    <svg class="brand-mark" width="26" height="26" aria-hidden="true" focusable="false"><use href="#i-mark"/></svg>
    <b>Caddy <span>Console</span></b>
  </a>
  <nav class="tabs" aria-label="Views">
    <a class="tab" data-view="dashboard" href="/"><svg class="icon" width="16" height="16" aria-hidden="true" focusable="false"><use href="#i-dashboard"/></svg>Dashboard</a>
    <a class="tab" data-view="explore" href="/explore"><svg class="icon" width="16" height="16" aria-hidden="true" focusable="false"><use href="#i-explore"/></svg>Explore</a>
    <a class="tab" data-view="editor" href="/editor"><svg class="icon" width="16" height="16" aria-hidden="true" focusable="false"><use href="#i-editor"/></svg>Editor</a>
  </nav>
  <span class="hdr-spacer"></span>
  <!-- Editor-only actions, hidden on the other views where none of them apply. -->
  <div class="etools" data-for-view="editor" hidden>
    <div class="grp">
      <button class="btn btn-quiet" type="button" data-act="find" aria-pressed="false" title="Find and replace (Cmd/Ctrl + F)"><svg class="icon" width="16" height="16" aria-hidden="true" focusable="false"><use href="#i-explore"/></svg><span class="lbl">Find</span></button>
      <button class="btn btn-quiet" type="button" id="panel-btn-snippets" data-panel="snippets" aria-pressed="false" title="Insert a Caddyfile snippet"><svg class="icon" width="16" height="16" aria-hidden="true" focusable="false"><use href="#i-blocks"/></svg><span class="lbl">Snippets</span></button>
      <button class="btn btn-quiet" type="button" id="panel-btn-backups" data-panel="backups" aria-pressed="false" title="Browse and restore backups"><svg class="icon" width="16" height="16" aria-hidden="true" focusable="false"><use href="#i-clock"/></svg><span class="lbl">Backups</span></button>
    </div>
    <button class="btn" type="button" data-act="validate" title="Format and check syntax and modules without saving"><svg class="icon" width="16" height="16" aria-hidden="true" focusable="false"><use href="#i-check"/></svg>Check</button>
    <button class="btn btn-primary" type="button" data-act="save" id="btn-save" title="Save and reload Caddy (Cmd/Ctrl + S)"><span class="dirty-dot" aria-hidden="true"></span><span id="save-label">Save &amp; Reload</span></button>
  </div>
  <div class="user-menu" id="user-menu"></div>
  <!-- Kept for the save/rollback paths, which read the signed-in email from it. -->
  <span class="user-info" id="user-info" hidden></span>
</header>

<main id="main">
  <section class="tab-content" id="tab-dashboard" aria-label="Dashboard"><div id="dashboard-root"></div></section>
  <section class="tab-content" id="tab-explore" aria-label="Explore"><div id="explore-root"></div></section>
  <section class="tab-content editor" id="tab-editor" aria-label="Editor">
    <div class="ed-col">
      <div class="warnings" id="warnings"></div>
      <div class="search-bar" id="search-bar">
        <input type="text" id="search-input" placeholder="Find... (Enter next, Shift+Enter previous, Esc to close)">
        <button class="btn btn-secondary btn-sm" data-act="search-prev" title="Previous match (Shift+Enter)">&uarr;</button>
        <button class="btn btn-secondary btn-sm" data-act="search-next" title="Next match (Enter)">&darr;</button>
        <span class="match-count" id="match-count"></span>
        <input type="text" id="replace-input" placeholder="Replace with...">
        <button class="btn btn-secondary btn-sm" data-act="replace-one">Replace</button>
        <button class="btn btn-secondary btn-sm" data-act="replace-all">Replace All</button>
        <button class="btn btn-secondary btn-sm" data-act="search-close">&times;</button>
      </div>
      <div class="editor-wrap" id="cm-editor"></div>
      <div class="sbar">
        <span class="msg" id="status-line" data-state="ok" role="status"><svg class="icon" width="14" height="14" aria-hidden="true" focusable="false"><use id="status-icon" href="#i-status-ok"/></svg><span class="status-msg" id="status-msg">Loading…</span></span>
        <span class="hide-sm" id="last-saved"></span>
        <span class="r"><span class="hide-sm" id="doc-stats"></span><span id="cursor-pos">Ln 1, Col 1</span></span>
      </div>
    </div>
  </section>
</main>
```

- [ ] **Step 4: `ui/seg.js`**

```js
// A segmented radio group (Theme, Editor keys, Preview / Diff). Arrow keys move
// and select, as in any radio group; Tab enters and leaves it as one stop.
import { iconEl } from '../icons.js';

export function segmented({ label, options, value, onChange }) {
  const el = document.createElement('div');
  el.className = 'seg';
  el.setAttribute('role', 'radiogroup');
  el.setAttribute('aria-label', label);
  const buttons = options.map((o) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.setAttribute('role', 'radio');
    b.dataset.v = o.id;
    if (o.icon) b.append(iconEl(o.icon, { size: 14 }));
    b.append(document.createTextNode(o.label));
    return b;
  });
  const set = (v) => buttons.forEach((b) => {
    const on = b.dataset.v === v;
    b.setAttribute('aria-checked', String(on));
    b.tabIndex = on ? 0 : -1;
  });
  const pick = (b) => {
    if (b.getAttribute('aria-checked') === 'true') return;
    set(b.dataset.v);
    onChange(b.dataset.v);
  };
  el.addEventListener('click', (e) => { const b = e.target.closest('[role="radio"]'); if (b) pick(b); });
  el.addEventListener('keydown', (e) => {
    if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(e.key)) return;
    e.preventDefault();
    const i = buttons.findIndex((b) => b.getAttribute('aria-checked') === 'true');
    const step = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? 1 : -1;
    const next = buttons[(i + step + buttons.length) % buttons.length];
    pick(next);
    next.focus();
  });
  el.append(...buttons);
  set(value);
  return { el, set };
}
```

- [ ] **Step 5: Rewrite `usermenu.js`**

```js
// Account menu: avatar + email in the header, opening a panel with the session,
// the Theme and Editor-keys pickers, shortcuts and log out.
//
// Chrome rather than a data view, so plain DOM; Preact is reserved for the
// dashboard and Explore, where derived state actually earns it.
import { applyEditorKeymap } from './core.js';
import { KEYMAPS, getKeymap, setKeymap } from './editor-prefs.js';
import { iconEl } from './icons.js';
import { THEMES, applyTheme, getThemePref, setThemePref } from './theme.js';
import { segmented } from './ui/seg.js';

const SHORTCUTS = [
  ['Save & reload', ['Ctrl/⌘', 'S']],
  ['Find in config', ['Ctrl/⌘', 'F']],
  ['Next / previous match', ['Enter', 'Shift+Enter']],
  ['Close panel, find bar or dialog', ['Esc']],
];
const VIM_SHORTCUTS = [
  ['Save & reload (Vim)', [':w']],
  ['Normal mode (Vim)', ['Esc']],
];
const shortcutsFor = (id) => (id === 'vim' ? [...SHORTCUTS, ...VIM_SHORTCUTS] : SHORTCUTS);

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text) e.textContent = text;
  return e;
}

/** Initials from an email: "dev@local" -> "DE", "a.b@x.com" -> "AB". */
function initialsOf(email) {
  const local = (email || '?').split('@')[0];
  const parts = local.split(/[._\-+]/).filter(Boolean);
  const letters = parts.length > 1 ? parts[0][0] + parts[1][0] : local.slice(0, 2);
  return letters.toUpperCase();
}

/** [what, via] for the session row. Cloudflare Access owns its session, so no expiry. */
function sessionLine(user) {
  if (user.auth_mode === 'cloudflare') return ['Signed in via Cloudflare Access', 'Cloudflare'];
  if (!user.session_expires_at) return ['Signed in', 'Google'];
  const ms = user.session_expires_at * 1000 - Date.now();
  if (ms <= 0) return ['Session expired. Reload to sign in again.', 'Google'];
  const hours = Math.floor(ms / 3600000);
  const mins = Math.round((ms % 3600000) / 60000);
  return [`Session ends in ${hours ? hours + 'h ' : ''}${mins}m`, 'Google'];
}

function avatar(email) {
  const a = el('span', 'avatar', initialsOf(email));
  a.setAttribute('aria-hidden', 'true');
  return a;
}

function renderShortcuts(dl, keymap) {
  dl.textContent = '';
  for (const [label, keys] of shortcutsFor(keymap)) {
    const dd = el('dd');
    keys.forEach((k) => dd.append(el('span', 'kbd', k)));
    dl.append(el('dt', '', label), dd);
  }
}

export function initUserMenu(user) {
  const host = document.getElementById('user-menu');
  if (!host) return;
  host.textContent = '';
  const name = user.name && user.name !== user.email ? user.name : '';

  const button = el('button', 'acct-btn');
  button.type = 'button';
  button.setAttribute('aria-haspopup', 'dialog');
  button.setAttribute('aria-controls', 'acct-menu');
  button.append(avatar(user.email), el('span', 'em', user.email),
    iconEl('chevron-down', { size: 14 }), el('span', 'sr', 'Account menu'));

  const menu = el('div', 'pop acct-menu');
  menu.id = 'acct-menu';
  menu.setAttribute('role', 'dialog');
  menu.setAttribute('aria-label', 'Account');

  const idSection = el('section', 'acct-id');
  const who = el('div');
  who.append(el('b', '', name || user.email));
  if (name) who.append(el('span', 'muted', user.email));
  idSection.append(avatar(user.email), who);

  const session = el('section', 'acct-session');
  const sessionRow = el('div', 'row');
  const refreshSession = () => {
    const [text, via] = sessionLine(user);
    sessionRow.textContent = '';
    sessionRow.append(el('span', '', text), el('span', 'muted', via));
  };
  session.append(sessionRow);

  const themeSection = el('section');
  const themeRow = el('div', 'row');
  const themeSeg = segmented({
    label: 'Theme', options: THEMES, value: getThemePref(),
    onChange: (pref) => { setThemePref(pref); applyTheme(pref); },
  });
  themeRow.append(el('h2', '', 'Theme'), themeSeg.el);
  themeSection.append(themeRow);

  const keysSection = el('section');
  const keysRow = el('div', 'row');
  const dl = el('dl', 'shortcuts');
  const keySeg = segmented({
    label: 'Editor keymap', options: KEYMAPS, value: getKeymap(),
    onChange: (id) => { setKeymap(id); renderShortcuts(dl, id); applyEditorKeymap(id); },
  });
  keysRow.append(el('h2', '', 'Editor keys'), keySeg.el);
  renderShortcuts(dl, getKeymap());
  keysSection.append(keysRow, el('h2', 'acct-sub', 'Shortcuts'), dl);

  const foot = el('section', 'acct-foot');
  const logout = el('a', 'menu-item');
  logout.href = '/logout';
  logout.append(iconEl('logout'), document.createTextNode('Log out'));
  foot.append(logout, el('div', 'version', `Caddy Console ${user.version || ''}`.trim()));

  menu.append(idSection, session, themeSection, keysSection, foot);
  host.append(button, menu);

  // The remaining session time is recomputed when the menu opens, so it is
  // never shown stale and no timer runs while it is closed.
  const setOpen = (open, { focusButton = false } = {}) => {
    menu.hidden = !open;
    button.setAttribute('aria-expanded', String(open));
    if (open) { refreshSession(); themeSeg.el.querySelector('[aria-checked="true"]')?.focus(); }
    else if (focusButton) button.focus();
  };
  setOpen(false);
  button.addEventListener('click', (e) => { e.stopPropagation(); setOpen(menu.hidden); });
  document.addEventListener('click', (e) => { if (!menu.hidden && !host.contains(e.target)) setOpen(false); });
  document.addEventListener('keydown', (e) => {
    if (!menu.hidden && e.key === 'Escape') { e.stopPropagation(); setOpen(false, { focusButton: true }); }
  });
}
```

- [ ] **Step 6: Wire the shell (`caddyfile.js`, `core.js`, `panels.js`, `search.js`)**

`caddyfile.js`, in `showView`, replace the two lines that toggle `.tab` `active` and `[data-for-view]` `visible` with:

```js
  document.querySelectorAll('.tab').forEach(t => {
    if (t.dataset.view === view) t.setAttribute('aria-current', 'page');
    else t.removeAttribute('aria-current');
  });
  // Only show actions that do something here: Check, Save, Find, Snippets and
  // Backups all act on the editor.
  document.querySelectorAll('[data-for-view]').forEach(n => { n.hidden = n.dataset.forView !== view; });
```

(Keep the `.tab-content` `active` toggling as it is.) In the same function, the line that clears `panel-active` should also reset the pressed state: `document.querySelectorAll('[id^="panel-btn-"]').forEach(b => { b.classList.remove('panel-active'); b.setAttribute('aria-pressed', 'false'); });`.

`core.js`, replace `setDot` with:

```js
// The status line's state, as a shape and a colour (never colour alone): the
// message text beside it always says the same thing in words.
const DOT_STATE = { green: ['ok', 'status-ok'], yellow: ['modified', 'warning'], red: ['error', 'status-down'] };
export function setDot(c) {
  const [state, icon] = DOT_STATE[c] || DOT_STATE.green;
  const line = document.getElementById('status-line');
  if (line) line.dataset.state = state;
  document.getElementById('status-icon')?.setAttribute('href', '#i-' + icon);
}
```

`panels.js`, in `togglePanel` and `closePanel`, after every `classList.remove('panel-active')` / `classList.add('panel-active')` also set `aria-pressed` to `'false'` / `'true'` on the same button.

`search.js`, at the end of `toggleSearch()` add `document.querySelector('[data-act="find"]')?.setAttribute('aria-pressed', String(bar.classList.contains('open')));`, and at the end of `closeSearch()` add `document.querySelector('[data-act="find"]')?.setAttribute('aria-pressed', 'false');`.

- [ ] **Step 7: CSS: base, header, popover menus, layout, status bar**

In `src/static/css/style.css`, delete the old rules under these comments: the top of the file through `body { … }`, `/* Header */`, `/* Icons … */` (keep the `@keyframes icon-pulse` and `.icon-pulse` rules), `/* Actions scoped to one view … */`, `/* Tabs */`, `/* Main layout */`, `/* Editor */`, `/* Footer */`, `.user-info`, and `/* --- Account menu --- */` (through `.menu-version`). Insert at the top, in this order:

1. `/* === base === */` and **mockup lines 59–71**, with these edits: insert `*{margin:0;padding:0}` after line 59 (the older views' markup still relies on the reset until Tasks 13–15), and replace the `.ic{…}` and `.ic.sm{…}` rules with:

```css
.icon{flex:none;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;vertical-align:-3px}
.icon-sprite{display:none}
::selection{background:var(--selection-bg);color:var(--selection-ink)}
```

2. `/* === header === */` and **mockup lines 100–119** verbatim, plus:

```css
.brand-mark{flex:none}
.btn-primary:disabled .dirty-dot{display:none}
.acct-btn>.icon{color:var(--ink-3)}
```

3. `/* === popover menus === */` and **mockup lines 120–136** verbatim, plus:

```css
.acct-menu .acct-sub{margin:14px 0 8px}
.acct-menu .acct-foot{padding:6px}
a.menu-item:hover{text-decoration:none}
```

4. `/* === layout === */` and **mockup lines 137–143**, with `main{min-height:calc(100vh - var(--hdr) - 30px)}` changed to `main{min-height:calc(100vh - var(--hdr))}` (the 30 px was the mockup's own switcher bar). Then:

```css
.tab-content{display:none}
.tab-content.active{display:block}
.editor.tab-content.active{display:grid}
.editor{grid-template-columns:minmax(0,1fr) auto;height:calc(100vh - var(--hdr))}
.ed-col{display:flex;flex-direction:column;min-width:0;min-height:0}
#cm-editor{flex:1;min-height:0;overflow:hidden}
#cm-editor .cm-editor{height:100%}
```

5. `/* === editor === */` with **mockup lines 314–317** (`.sbar` through `.sbar .r`) verbatim, plus:

```css
.sbar .msg[data-state="ok"] .icon{color:var(--good)}
.sbar .msg[data-state="modified"] .icon{color:var(--warn)}
.sbar .msg[data-state="error"] .icon{color:var(--crit)}
.status-msg.err{color:var(--crit)}
.status-msg.warn{color:var(--warn)}
```

Apply the `.ic` → `.icon` replacement to everything copied. Keep the old CodeMirror selection rules (`#cm-editor .cm-editor .cm-selectionLayer …` and `#cm-editor .cm-content ::selection`) where they are.

- [ ] **Step 8: Run the tests and check in the browser**

Run: `for t in tests/*.test.mjs; do node "$t" || exit 1; done`
Expected: PASS.
Browser at 1440 px, both themes:
- The header has the brand mark, three tabs (underline on the current one), and the account button with initials.
- On Dashboard and Explore there is no status bar and no editor tools. On Editor the tools and the status bar both appear.
- Account menu: Theme System / Dark / Light switches live, and the arrow keys move the selection. Editor keys Vim adds the two Vim shortcuts. Esc closes the menu and focus returns to the button.
- Make an edit: the status icon changes shape (status-ok → warning) and the colour changes too.

- [ ] **Step 9: Commit**

```bash
git add src/templates/index.html src/static/js/app src/static/css/style.css tests/shell.test.mjs
git commit -m "feat(ui): new header and account menu with theme picker, status bar only in the Editor"
```

---

### Task 13: Dashboard (verdict, config card, figures, notice, sites table, recent changes)

**Files:**
- Create: `src/static/js/app/dashboard-model.js`, `src/static/js/app/caddyfile-sites.js`
- Modify: `src/static/js/app/dashboard.js` (rewrite), `src/static/js/app/core.js` (`revealLine`, `revealSite`), `src/static/js/app/main.js` (open-site event), `src/static/css/style.css` (dashboard section)
- Test: `tests/dashboard-model.test.mjs`, `tests/caddyfile-sites.test.mjs` (new)

**Interfaces:**
- Consumes: `/api/sites` `previous_total` (Task 1), `/api/upstreams` `unhealthy_since` and `configured_sites` (Task 2), `/api/status` `last_change` (Task 3); `format.js` (Task 10), including `shortDateTime` (added in Task 10); `toast` (Task 11).
- Produces (`dashboard-model.js`): `RANGE`, `HIGH_5XX = 10`, `SLOW_P95_MS = 2000`, `exploreHref(query): string`, `healthOf(host, upstreams): {state:'up'|'down'|'none'|'unknown', label, icon}`, `siteTags(site): ('high'|'slow')[]`, `totalsOf(sites)`, `verdict({sites, upstreams, upstreamsError, configuredSites, status, now}): {severity:'critical'|'serious'|'warn'|'ok', sev: string|null, title, body: ({text}|{mono})[], primary: {label, href}|null, secondary: {label, host}|null}`, `kpis({sites, previousTotal, configuredSites}): {key, label, value, of, sub, bad, href}[]`, `configCard(status, now): {state:'ok'|'bad'|'unknown', label, checks, version, changed: {rel, abs, by}|null, path}|null`, `auditRow(entry, now): {verb, icon, user, detail, rel, abs}`.
- Produces (`caddyfile-sites.js`): `hostOf(address)`, `siteBlocks(text): {addresses, hosts, start, end}[]` (1-based lines), `findSiteBlockLine(text, host): number|null` (exact host first, then a one-label `*.` wildcard), `sitesForLines(text, lineNumbers): string[]`.
- Produces (`core.js`): `revealLine(n): boolean` (cursor to the start of line n, scrolled to the centre, editor focused) and `revealSite(host)` (finds the block. If the editor is not loaded yet it waits for the load. If the host has no block it shows a warning toast).
- Event: `document` `app:open-site` with `{detail:{host}}`. `main.js` switches to the Editor and calls `revealSite`.

- [ ] **Step 1: Write the failing tests**

Create `tests/caddyfile-sites.test.mjs`:

```js
// Tests for src/static/js/app/caddyfile-sites.js
// Run with: node tests/caddyfile-sites.test.mjs
import assert from 'node:assert/strict';
import path from 'node:path';

const SRC = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app', 'caddyfile-sites.js');
const { hostOf, siteBlocks, findSiteBlockLine, sitesForLines } = await import(SRC);

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };

const CF = [
  '{', '\temail ops@example.com', '}', '',                              // 1-4 global options
  '(security_headers) {', '\theader -Server', '}', '',                  // 5-8 snippet
  'nas.example.com {', '\treverse_proxy 127.0.0.1:5000', '}', '',       // 9-12
  'http://a.example.com, b.example.com:8443 {',                         // 13
  '\trespond "hi {remote_host}" 200', '}', '',                          // 14-16
  '*.wild.example.com {', '\trespond 200', '}',                         // 17-19
  '# photos.example.com {', '',                                         // 20-21 commented out
].join('\n');

check('hostOf strips scheme, port and path', () => {
  assert.equal(hostOf('http://A.example.com:8443/x'), 'a.example.com');
  assert.equal(hostOf(':8080'), '');
});
check('site blocks skip global options and snippets', () => assert.deepEqual(
  siteBlocks(CF).map(b => [b.hosts, b.start, b.end]),
  [[['nas.example.com'], 9, 11], [['a.example.com', 'b.example.com'], 13, 15], [['*.wild.example.com'], 17, 19]]));
check('finds a host in a comma list with a scheme and a port', () => assert.equal(findSiteBlockLine(CF, 'b.example.com'), 13));
check('is case-insensitive', () => assert.equal(findSiteBlockLine(CF, 'NAS.example.com'), 9));
check('falls back to a one-label wildcard', () => {
  assert.equal(findSiteBlockLine(CF, 'x.wild.example.com'), 17);
  assert.equal(findSiteBlockLine(CF, 'a.b.wild.example.com'), null);
});
check('commented-out and unknown hosts are not found', () => {
  assert.equal(findSiteBlockLine(CF, 'photos.example.com'), null);
  assert.equal(findSiteBlockLine(CF, ''), null);
});
check('sitesForLines names each touched block once', () => assert.deepEqual(
  sitesForLines(CF, [10, 14, 15, 2]), ['nas.example.com', 'a.example.com']));
console.log(`\n${passed} passed`);
```

Create `tests/dashboard-model.test.mjs`:

```js
// Tests for src/static/js/app/dashboard-model.js
// Run with: node tests/dashboard-model.test.mjs
import assert from 'node:assert/strict';
import path from 'node:path';

const SRC = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app', 'dashboard-model.js');
const m = await import(SRC);

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };
const plain = (parts) => parts.map(p => p.text ?? p.mono).join('');
const at = (...a) => new Date(...a).getTime();
const NOW = at(2026, 10, 20, 15, 0, 0);

const site = (host, requests, errors, p95 = 120, bytes = 1000) =>
  ({ host, requests, errors, error_rate: requests ? Math.round(errors / requests * 10000) / 100 : 0, p95_latency_ms: p95, bytes_out: bytes, series: [] });
const SITES = [
  site('nas.example.com', 279, 3, 141, 10_000_000), site('photos.example.com', 172, 2, 61, 6_500_000),
  site('watch.example.com', 163, 1, 180, 5_600_000), site('grafana.example.com', 78, 0, 272, 3_000_000),
  site('torrent.example.com', 65, 21, 12400, 1_300_000), site('ha.example.com', 59, 0, 92, 2_300_000),
  site('radarr.example.com', 41, 1, 306, 1_300_000),
];
const UP = (address, domains, healthy, since = null) => ({ address, domains, healthy, unhealthy_since: since });
const HEALTHY = [UP('127.0.0.1:5000', ['nas.example.com'], 1), UP('127.0.0.1:2283', ['photos.example.com'], 1)];

console.log('\n--- verdict ---');
check('calm when nothing is wrong', () => {
  const v = m.verdict({ sites: SITES.map(s => (s.host.startsWith('torrent') ? site(s.host, 65, 0) : s)), upstreams: HEALTHY, configuredSites: 7, now: NOW });
  assert.equal(v.severity, 'ok'); assert.equal(v.title, 'All 7 sites are serving'); assert.equal(v.sev, null);
});
check('a down upstream names the site, the check, the time and the others', () => {
  const since = at(2026, 10, 20, 14, 31) / 1000;
  const v = m.verdict({ sites: SITES, upstreams: [HEALTHY[0], UP('127.0.0.1:2283', ['photos.example.com'], 0, since)], configuredSites: 7, now: NOW });
  assert.equal(v.severity, 'critical');
  assert.equal(v.sev, 'Critical, 1 unhealthy upstream');
  assert.equal(v.title, 'photos.example.com is down');
  assert.equal(plain(v.body), "Caddy's health check to 127.0.0.1:2283 has failed since 14:31. The other 6 sites are serving; torrent.example.com is answering 32% of requests with 5xx.");
  assert.deepEqual(v.secondary, { label: 'Open photos.example.com block', host: 'photos.example.com' });
  assert.equal(v.primary.href, '/explore?range=1h&q=host%3Aphotos.example.com');
});
check('without unhealthy_since the time is left out, not invented', () => {
  const v = m.verdict({ sites: [], upstreams: [UP('10.0.0.9:80', ['a.example.com'], 0)], configuredSites: 1, now: NOW });
  assert.equal(plain(v.body), "Caddy's health check to 10.0.0.9:80 is failing.");
});
check('an admin API outage outranks everything', () => {
  const v = m.verdict({ sites: SITES, upstreams: [], upstreamsError: 'Caddy admin API not reachable', now: NOW });
  assert.equal(v.severity, 'critical'); assert.equal(v.title, 'Caddy is not answering the console');
});
check('a failing config check is serious', () => {
  const v = m.verdict({ sites: [], upstreams: [], status: { config_valid: false, config_check_level: 'adapted', config_check_message: 'boom' }, now: NOW });
  assert.equal(v.severity, 'serious'); assert.equal(plain(v.body), 'boom');
});
check('a high 5xx rate is a warning', () => {
  const v = m.verdict({ sites: SITES, upstreams: HEALTHY, configuredSites: 7, now: NOW });
  assert.equal(v.severity, 'warn'); assert.equal(v.title, 'torrent.example.com is failing 32% of requests');
});
check('a couple of errors on a quiet site is not a verdict', () => {
  const v = m.verdict({ sites: [site('quiet.example.com', 2, 1)], upstreams: [], configuredSites: 1, now: NOW });
  assert.equal(v.severity, 'ok'); assert.equal(v.title, 'The site is serving');
});

console.log('\n--- figures ---');
check('requests compare with the previous hour when known', () => {
  const [req] = m.kpis({ sites: [site('a', 112, 0)], previousTotal: 100, configuredSites: 1 });
  assert.equal(req.sub, '+12% vs previous hour');
  assert.equal(m.kpis({ sites: [site('a', 88, 0)], previousTotal: 100 })[0].sub, '−12% vs previous hour');
});
check('no previous window means no comparison line, never 0', () => {
  assert.equal(m.kpis({ sites: [site('a', 5, 0)], previousTotal: null })[0].sub, null);
  assert.equal(m.kpis({ sites: [site('a', 5, 0)], previousTotal: 0 })[0].sub, null);
});
check('5xx names the site with most of the errors', () => {
  const k = m.kpis({ sites: SITES, previousTotal: null, configuredSites: 7 });
  assert.equal(k[1].value, '3.3%'); assert.equal(k[1].sub, '28 errors, mostly torrent'); assert.equal(k[1].bad, true);
});
check('sites with traffic "of N" only when the config count is known', () => {
  const k = m.kpis({ sites: SITES, previousTotal: null, configuredSites: 7 });
  assert.equal(k[2].of, 'of 7'); assert.equal(k[2].sub, 'all configured sites');
  const unknown = m.kpis({ sites: SITES, previousTotal: null, configuredSites: null });
  assert.equal(unknown[2].of, null); assert.equal(unknown[2].sub, null);
  assert.equal(m.kpis({ sites: SITES.slice(0, 5), configuredSites: 7 })[2].sub, '2 configured sites without traffic');
});
check('bandwidth names the biggest site', () => assert.equal(m.kpis({ sites: SITES })[3].sub, 'nas.example.com is 33%'));

console.log('\n--- config card ---');
const status = (extra) => ({ config_valid: true, config_check_level: 'adapted', caddy_version: 'v2.11.9 h1:abc=',
  config_path: '/etc/caddy/Caddyfile', last_modified: '2026-11-20T11:24:00.123456', last_change: null, ...extra });
check('valid, version without the build hash, path', () => {
  const c = m.configCard(status(), NOW);
  assert.equal(c.state, 'ok'); assert.equal(c.checks, 'Syntax and modules OK'); assert.equal(c.version, 'v2.11.9');
  assert.equal(c.changed.rel, '3h 36m ago'); assert.equal(c.changed.by, null);
});
check('"by" only when the last change matches the file time', () => {
  const ts = at(2026, 10, 20, 11, 24, 2) / 1000;
  assert.equal(m.configCard(status({ last_change: { action: 'save', user: 'ops@example.com', ts } }), NOW).changed.by, 'ops@example.com');
  assert.equal(m.configCard(status({ last_change: { action: 'save', user: 'ops@example.com', ts: ts - 3600 } }), NOW).changed.by, null);
});
check('unknown mtime hides the line', () => assert.equal(m.configCard(status({ last_modified: 'unknown' }), NOW).changed, null));

console.log('\n--- health, tags, audit ---');
check('health labels', () => {
  assert.equal(m.healthOf('nas.example.com', HEALTHY).label, 'Healthy');
  assert.equal(m.healthOf('x.example.com', HEALTHY).label, 'No upstream');
  assert.equal(m.healthOf('a', [UP('1:1', ['a'], 0)]).label, 'Unhealthy');
  assert.equal(m.healthOf('a', [UP('1:1', ['a'], undefined)]).label, 'Not checked');
});
check('tags at the thresholds', () => {
  assert.deepEqual(m.siteTags({ error_rate: 10, p95_latency_ms: 2000 }), ['high', 'slow']);
  assert.deepEqual(m.siteTags({ error_rate: 9.99, p95_latency_ms: 1999 }), []);
});
check('audit verbs and details', () => {
  const t = '2026-11-20T14:44:10.000001';
  assert.deepEqual(m.auditRow({ action: 'save_reload', user: 'ops@example.com', detail: 'backup=Caddyfile.20261120-144410', time: t }, NOW),
    { verb: 'Saved', icon: 'save', user: 'ops@example.com', detail: '', rel: '15 min ago', abs: '2026-11-20 14:44:10' });
  assert.equal(m.auditRow({ action: 'restore_reload', detail: 'backup=Caddyfile.20261120-100000, from=Caddyfile.20261119-081000', time: t }, NOW).detail, 'Backup from 19 Nov, 08:10');
  assert.equal(m.auditRow({ action: 'login', time: t }, NOW).verb, 'Signed in');
  assert.equal(m.auditRow({ action: 'frobnicate', time: 'nope' }, NOW).verb, 'Frobnicate');
  assert.equal(m.auditRow({ action: 'frobnicate', time: 'nope' }, NOW).rel, '');
});
console.log(`\n${passed} passed`);
```

- [ ] **Step 2: Run to verify they fail**

Run: `node tests/caddyfile-sites.test.mjs; node tests/dashboard-model.test.mjs`
Expected: both FAIL with `Cannot find module`.

- [ ] **Step 3: Implement `caddyfile-sites.js`**

```js
// Top-level site blocks of a Caddyfile, by line: for "Open <site> block" on the
// dashboard and for naming the sites a diff touches. A brace counter, not a
// parser. Site addresses are always the first thing on a depth-0 line that opens
// a block, which is all this needs.

const count = (s, ch) => s.split(ch).length - 1;

/** "http://a.example.com:8443/x" -> "a.example.com"; ":8080" -> "". */
export function hostOf(address) {
  return String(address).toLowerCase()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
}

export function siteBlocks(text) {
  const blocks = [];
  let depth = 0;
  let current = null;
  String(text).split('\n').forEach((raw, i) => {
    const line = raw.replace(/(^|\s)#.*$/, '').trim();
    if (!line) return;
    // `{` alone opens the global options; `(name) {` opens a snippet.
    if (depth === 0 && line.endsWith('{') && line !== '{' && !line.startsWith('(')) {
      const addresses = line.slice(0, -1).split(/[\s,]+/).filter(Boolean);
      current = { addresses, hosts: addresses.map(hostOf).filter(Boolean), start: i + 1, end: i + 1 };
      blocks.push(current);
    }
    const bare = line.replace(/\{[^{}\s]*\}/g, '');   // placeholders are not blocks
    depth = Math.max(0, depth + count(bare, '{') - count(bare, '}'));
    if (current) current.end = i + 1;
    if (depth === 0) current = null;
  });
  return blocks;
}

export function findSiteBlockLine(text, host) {
  const want = String(host || '').toLowerCase();
  if (!want) return null;
  const blocks = siteBlocks(text);
  const exact = blocks.find(b => b.hosts.includes(want));
  if (exact) return exact.start;
  const wild = blocks.find(b => b.hosts.some((h) => {
    if (!h.startsWith('*.')) return false;
    const suffix = h.slice(1);
    const prefix = want.slice(0, want.length - suffix.length);
    return want.endsWith(suffix) && prefix !== '' && !prefix.includes('.');
  }));
  return wild ? wild.start : null;
}

export function sitesForLines(text, lineNumbers) {
  const blocks = siteBlocks(text);
  const out = [];
  for (const n of lineNumbers) {
    const b = blocks.find(x => n >= x.start && n <= x.end);
    const label = b && (b.hosts[0] || b.addresses[0]);
    if (label && !out.includes(label)) out.push(label);
  }
  return out;
}
```

- [ ] **Step 4: Implement `dashboard-model.js`**

```js
// The dashboard's derived state: verdict headline, figures row, config card,
// site health and tags, audit rows. Pure functions of the API payloads, so every
// wording and threshold is unit-tested without a DOM. Missing data hides a line;
// it never turns into a 0.
import {
  SLOW_MS, absoluteTime, backupDate, clockTime, formatBytes, formatCount, formatPercent,
  percentChange, relativeTime, shortDateTime, shortHost, toMs,
} from './format.js';

export const RANGE = '1h';
export const HIGH_5XX = 10;          // percent of a site's requests
export const SLOW_P95_MS = SLOW_MS;
const MIN_ERRORS = 5;                // a verdict needs more than a couple of failures
const SAME_CHANGE_MS = 15000;        // audit entry vs file mtime: save, then reload, then log

const plural = (n, one, many = one + 's') => (n === 1 ? one : many);
const text = (t) => ({ text: t });
const mono = (t) => ({ mono: t });

export function exploreHref(query) {
  const p = new URLSearchParams({ range: RANGE });
  if (query) p.set('q', query);
  return '/explore?' + p.toString();
}

/** A site's health is its upstreams'. No upstream (respond, file_server) is not "unhealthy". */
export function healthOf(host, upstreams) {
  const mine = (upstreams || []).filter(u => (u.domains || []).includes(host));
  if (!mine.length) return { state: 'none', label: 'No upstream', icon: 'status-none' };
  if (mine.some(u => u.healthy === 0)) return { state: 'down', label: 'Unhealthy', icon: 'status-down' };
  if (mine.every(u => u.healthy === 1)) return { state: 'up', label: 'Healthy', icon: 'status-ok' };
  return { state: 'unknown', label: 'Not checked', icon: 'status-unknown' };
}

export function siteTags(site) {
  const tags = [];
  if (site.error_rate >= HIGH_5XX) tags.push('high');
  if (site.p95_latency_ms >= SLOW_P95_MS) tags.push('slow');
  return tags;
}

export function totalsOf(sites) {
  const t = (sites || []).reduce((a, s) => ({
    requests: a.requests + s.requests, errors: a.errors + s.errors, bytes: a.bytes + s.bytes_out,
  }), { requests: 0, errors: 0, bytes: 0 });
  return { ...t, errorRate: t.requests ? (t.errors / t.requests) * 100 : 0 };
}

function worstErrorSite(sites) {
  return sites.filter(s => s.error_rate >= HIGH_5XX && s.errors >= MIN_ERRORS)
    .sort((a, b) => b.error_rate - a.error_rate)[0] || null;
}

function servingTitle(total) {
  if (!total) return 'No requests in the last hour';
  return total === 1 ? 'The site is serving' : `All ${total} sites are serving`;
}

export function verdict({ sites = [], upstreams = [], upstreamsError = null, configuredSites = null, status = null, now = Date.now() }) {
  if (upstreamsError && /not reachable/i.test(upstreamsError)) {
    return {
      severity: 'critical', sev: "Critical, Caddy's admin API is unreachable",
      title: 'Caddy is not answering the console',
      body: [text('The admin API did not respond, so health, the live config and Save & Reload are unavailable. Check that the Caddy container is running.')],
      primary: { label: 'Open Explore', href: exploreHref('') }, secondary: null,
    };
  }

  const down = upstreams.filter(u => u.healthy === 0);
  if (down.length) {
    const hosts = [...new Set(down.flatMap(u => u.domains || []))];
    const first = down[0];
    const title = hosts.length === 1 ? `${hosts[0]} is down`
      : hosts.length > 1 ? `${hosts.length} sites are down` : `Upstream ${first.address} is down`;
    const body = [text("Caddy's health check to "), mono(first.address),
      text(first.unhealthy_since ? ` has failed since ${clockTime(first.unhealthy_since, now)}` : ' is failing')];
    if (down.length > 1) body.push(text(` (and ${down.length - 1} more ${plural(down.length - 1, 'upstream')})`));
    body.push(text('.'));
    const others = (configuredSites ?? sites.length) - hosts.length;
    const worst = worstErrorSite(sites.filter(s => !hosts.includes(s.host)));
    if (others > 0) body.push(text(` The other ${others} ${plural(others, 'site')} ${others === 1 ? 'is' : 'are'} serving`));
    if (worst) body.push(text(`${others > 0 ? ';' : ''} ${worst.host} is answering ${formatPercent(worst.error_rate, 0)} of requests with 5xx`));
    if (others > 0 || worst) body.push(text('.'));
    return {
      severity: 'critical', sev: `Critical, ${down.length} unhealthy ${plural(down.length, 'upstream')}`, title, body,
      primary: { label: 'Investigate in Explore', href: exploreHref(hosts[0] ? `host:${hosts[0]}` : 'status:5xx') },
      secondary: hosts[0] ? { label: `Open ${hosts[0]} block`, host: hosts[0] } : null,
    };
  }

  if (status && status.config_valid === false && status.config_check_level !== 'unavailable') {
    return {
      severity: 'serious', sev: 'Config check failed', title: 'The Caddyfile on disk does not pass Caddy’s check',
      body: [text(status.config_check_message || 'Caddy rejected the file on disk.')],
      primary: { label: 'Open the Editor', href: '/editor' }, secondary: null,
    };
  }

  const worst = worstErrorSite(sites);
  if (worst) {
    return {
      severity: 'warn', sev: 'Warning, high 5xx rate',
      title: `${worst.host} is failing ${formatPercent(worst.error_rate, 0)} of requests`,
      body: [text(`${formatCount(worst.errors)} of ${formatCount(worst.requests)} requests in the last hour were answered with 5xx.`)],
      primary: { label: 'Investigate in Explore', href: exploreHref(`host:${worst.host} status:5xx`) },
      secondary: { label: `Open ${worst.host} block`, host: worst.host },
    };
  }

  return { severity: 'ok', sev: null, title: servingTitle(configuredSites ?? sites.length), body: [], primary: null, secondary: null };
}

export function kpis({ sites = [], previousTotal = null, configuredSites = null }) {
  const tot = totalsOf(sites);
  const change = percentChange(tot.requests, previousTotal);
  const byErrors = [...sites].sort((a, b) => b.errors - a.errors)[0];
  const byBytes = [...sites].sort((a, b) => b.bytes_out - a.bytes_out)[0];
  const mostly = byErrors && tot.errors && byErrors.errors / tot.errors >= 0.5 ? `, mostly ${shortHost(byErrors.host)}` : '';
  const missing = configuredSites == null ? 0 : configuredSites - sites.length;
  return [
    {
      key: 'requests', label: 'Requests, last hour', value: formatCount(tot.requests), of: null,
      sub: change == null ? null : change === 0 ? 'Same as the previous hour' : `${change > 0 ? '+' : '−'}${Math.abs(change)}% vs previous hour`,
      bad: false, href: exploreHref(''),
    },
    {
      key: 'errors', label: '5xx rate', value: formatPercent(tot.errorRate, 1), of: null,
      sub: tot.errors ? `${formatCount(tot.errors)} ${plural(tot.errors, 'error')}${mostly}` : 'No server errors',
      bad: tot.errors > 0, href: exploreHref('status:5xx'),
    },
    {
      key: 'sites', label: 'Sites with traffic', value: String(sites.length),
      of: configuredSites == null ? null : `of ${configuredSites}`,
      sub: configuredSites == null ? null : missing <= 0 ? 'all configured sites' : `${missing} configured ${plural(missing, 'site')} without traffic`,
      bad: false, href: exploreHref(''),
    },
    {
      key: 'bytes', label: 'Bandwidth out', value: formatBytes(tot.bytes), of: null,
      sub: sites.length > 1 && tot.bytes > 0 ? `${byBytes.host} is ${Math.round((byBytes.bytes_out / tot.bytes) * 100)}%` : null,
      bad: false, href: exploreHref(sites.length > 1 && byBytes ? `host:${byBytes.host}` : ''),
    },
  ];
}

export function configCard(status, now = Date.now()) {
  if (!status) return null;
  const level = status.config_check_level;
  const state = status.config_valid === true ? 'ok' : level === 'unavailable' ? 'unknown' : 'bad';
  const label = { ok: 'Config valid', unknown: 'Config not checked', bad: 'Config check failed' }[state];
  const checks = state === 'ok' ? (level === 'adapted' ? 'Syntax and modules OK' : 'Passed local validation')
    : (status.config_check_message || null);
  const version = String(status.caddy_version || '').split(/\s+/)[0];
  const mtime = toMs(status.last_modified);
  const lc = status.last_change || null;
  // Attribute the change only if the audit entry is this file version's; an
  // edit made behind the console's back must not borrow the last user's name.
  const by = lc && Number.isFinite(mtime) && Math.abs(toMs(lc.ts) - mtime) <= SAME_CHANGE_MS ? lc.user : null;
  return {
    state, label, checks,
    version: version && version !== 'unknown' ? version : null,
    changed: Number.isFinite(mtime) ? { rel: relativeTime(mtime, now), abs: absoluteTime(mtime), by } : null,
    path: status.config_path || null,
  };
}

const VERBS = {
  login: ['Signed in', 'key'], logout: ['Signed out', 'logout'], login_denied: ['Sign-in denied', 'status-down'],
  save_reload: ['Saved', 'save'], save_no_reload: ['Saved, not reloaded', 'warning'],
  save_reload_unknown: ['Saved, reload unconfirmed', 'warning'], save_reload_failed: ['Rejected by Caddy', 'status-down'],
  save_failed: ['Save rejected', 'status-down'], save_conflict: ['Save blocked', 'warning'],
  save_write_failed: ['Write failed', 'status-down'], save_rollback_failed: ['Rollback failed', 'status-down'],
  restore_reload: ['Restored', 'restore'], restore_no_reload: ['Restored, not reloaded', 'warning'],
  restore_reload_unknown: ['Restored, reload unconfirmed', 'warning'], restore_reload_failed: ['Restore rejected by Caddy', 'status-down'],
  restore_failed: ['Restore rejected', 'status-down'], restore_write_failed: ['Write failed', 'status-down'],
  restore_rollback_failed: ['Rollback failed', 'status-down'], backup_deleted: ['Deleted backup', 'close'],
};

const backupWhen = (name) => { const d = backupDate(name); return d ? `Backup from ${shortDateTime(d)}` : ''; };

function detailOf(action, detail) {
  const from = /(?:^|,\s*)from=(Caddyfile\.[^,\s]+)/.exec(detail);
  if (from) return backupWhen(from[1]) || detail;
  if (action === 'backup_deleted') return backupWhen(detail) || detail;
  if (action === 'save_conflict') return 'The file had changed on disk';
  if (/^backup=[^,]*$/.test(detail)) return '';   // a plain save: the backup's name is noise here
  return detail;
}

export function auditRow(entry, now = Date.now()) {
  const action = String(entry.action || '');
  const [verb, icon] = VERBS[action]
    || [action ? action.charAt(0).toUpperCase() + action.slice(1).replace(/_/g, ' ') : 'Activity', 'info'];
  return {
    verb, icon, user: entry.user || '',
    detail: detailOf(action, String(entry.detail || '')),
    rel: relativeTime(entry.time, now), abs: absoluteTime(entry.time),
  };
}
```

- [ ] **Step 5: Run the model tests**

Run: `node tests/caddyfile-sites.test.mjs && node tests/dashboard-model.test.mjs`
Expected: PASS.

- [ ] **Step 6: Reveal a site in the editor (`core.js`, `main.js`)**

In `core.js` add `import { findSiteBlockLine } from './caddyfile-sites.js';` and `import { toast } from './ui/toast.js';`, then append:

```js
/** Put the cursor at the start of line n, centred, and focus the editor. */
export function revealLine(n) {
  if (!editorView) return false;
  const doc = editorView.state.doc;
  if (!Number.isInteger(n) || n < 1 || n > doc.lines) return false;
  const line = doc.line(n);
  editorView.dispatch({ selection: { anchor: line.from }, effects: EditorView.scrollIntoView(line.from, { y: 'center' }) });
  editorView.focus();
  return true;
}

let pendingSite = null;
/** "Open <site> block": waits for the first load if the editor is not there yet. */
export function revealSite(host) {
  if (!editorView) { pendingSite = host; return; }
  const line = findSiteBlockLine(getContent(), host);
  if (line == null) { toast(`No site block for ${host} in the Caddyfile.`, { kind: 'warn' }); return; }
  revealLine(line);
}
```

At the end of `initEditor`, after `refreshDocState();`, add:

```js
  if (pendingSite) { const host = pendingSite; pendingSite = null; revealSite(host); }
```

In `main.js` add `revealSite` to the `core.js` import list (`import { revealSite } from './core.js';`) and, before `syncViewFromUrl();`:

```js
// Dashboard "Open <site> block": switch to the Editor and land on that block.
document.addEventListener('app:open-site', (e) => {
  showView('editor');
  revealSite(e.detail.host);
});
```

- [ ] **Step 7: Rewrite `dashboard.js`**

```js
// Dashboard at /: is anything broken, and where do I look next.
//
// Opens on a verdict, then the figures (each one a link into Explore with the
// matching filter), then per-site rows and recent changes. All wording and
// thresholds live in dashboard-model.js; this file only lays them out.
import { h, htm, render, useEffect, useState } from '../explore-vendor.js';
import { Icon } from './icons.js';
import { toast } from './ui/toast.js';
import { formatBytes, formatCount, formatMs, formatPercent } from './format.js';
import { RANGE, auditRow, configCard, exploreHref, healthOf, kpis, siteTags, verdict } from './dashboard-model.js';

const html = htm.bind(h);
const REFRESH_MS = 15000;
const PROXY_DISMISS_KEY = 'dashboard.proxyIpDismissed';

function proxyDismissed(ip) {
  try { return localStorage.getItem(PROXY_DISMISS_KEY) === ip; } catch (e) { return false; }
}
function setProxyDismissed(ip) {
  try { if (ip) localStorage.setItem(PROXY_DISMISS_KEY, ip); else localStorage.removeItem(PROXY_DISMISS_KEY); } catch (e) { /* this page only */ }
}
const openSite = (host) => document.dispatchEvent(new CustomEvent('app:open-site', { detail: { host } }));

function Spark({ series, bad }) {
  const points = series || [];
  if (!points.length || !points.some(v => v)) return html`<span class="muted">—</span>`;
  const peak = Math.max(...points);
  const step = 108 / Math.max(1, points.length - 1);
  const pts = points.map((v, i) => `${(1 + i * step).toFixed(1)},${(24 - (v / peak) * 22).toFixed(1)}`).join(' ');
  return html`
    <svg class="spark" viewBox="0 0 110 26" aria-hidden="true" focusable="false">
      <polyline points=${pts} fill="none" stroke=${bad ? 'var(--crit)' : 'var(--ink-3)'}
                stroke-width="1.5" stroke-linejoin="round" vector-effect="non-scaling-stroke" />
    </svg>`;
}

const Parts = ({ parts }) => parts.map((p, i) => (p.mono ? html`<span class="mono" key=${i}>${p.mono}</span>` : p.text));

function ConfigCard({ card }) {
  const icon = card.state === 'ok' ? 'status-ok' : card.state === 'bad' ? 'status-down' : 'status-unknown';
  return html`
    <aside class=${'cfg cfg-' + card.state} aria-label="Config">
      <div class="ok"><${Icon} name=${icon} />${card.label}</div>
      <dl>
        ${card.checks && html`<dt>Checks</dt><dd>${card.checks}</dd>`}
        ${card.version && html`<dt>Caddy</dt><dd>${card.version}</dd>`}
        ${card.changed && html`<dt>Changed</dt><dd><time title=${card.changed.abs}>${card.changed.rel}</time>${card.changed.by ? ` by ${card.changed.by}` : ''}</dd>`}
        ${card.path && html`<dt>File</dt><dd class="mono">${card.path}</dd>`}
      </dl>
    </aside>`;
}

function Verdict({ v, card }) {
  const icon = v.severity === 'warn' ? 'warning' : 'status-down';
  return html`
    <section class=${'verdict sev-' + v.severity} role=${v.severity === 'ok' ? 'status' : 'alert'} aria-labelledby="dash-h">
      <div>
        ${v.sev && html`<span class="sev"><${Icon} name=${icon} />${v.sev}</span>`}
        <h1 id="dash-h">${v.severity === 'ok' && html`<${Icon} name="status-ok" size=${26} class="verdict-ok" />`}${v.title}</h1>
        ${v.body.length > 0 && html`<p><${Parts} parts=${v.body} /></p>`}
        ${(v.primary || v.secondary) && html`
          <div class="acts">
            ${v.primary && html`<a class="btn btn-primary" href=${v.primary.href}
                 data-view=${v.primary.href.startsWith('/explore') ? 'explore' : 'editor'}>${v.primary.label}</a>`}
            ${v.secondary && html`<button class="btn" type="button" onClick=${() => openSite(v.secondary.host)}>${v.secondary.label}</button>`}
          </div>`}
      </div>
      ${card && html`<${ConfigCard} card=${card} />`}
    </section>`;
}

function Figures({ items }) {
  return html`
    <div class="figs" aria-label="Last hour">
      ${items.map(f => html`
        <a class="fig" key=${f.key} href=${f.href} data-view="explore">
          <span class="lbl">${f.label}</span>
          <span class="fv-n">${f.value}${f.of && html` <span class="fv-of">${f.of}</span>`}</span>
          ${f.sub && html`<span class=${'sub' + (f.bad ? ' bad' : '')}>${f.bad && html`<${Icon} name="warning" size=${14} /> `}${f.sub}</span>`}
        </a>`)}
    </div>`;
}

function ProxyNotice({ p, onDismiss }) {
  return html`
    <div class="notice" role="status">
      <${Icon} name="warning" size=${20} />
      <div>
        <h2>Visitors' real IPs are not being logged</h2>
        <p>${p.share}% of the last hour's ${formatCount(p.requests)} requests came from <code>${p.ip}</code>, a Docker network address, so Caddy sees your proxy instead of your visitors. Set <code>trusted_proxies</code> and <code>client_ip_headers</code> in the global <code>servers</code> block. Until then, client IPs, IP locations and per-IP filters are unreliable.</p>
      </div>
      <div class="acts">
        <a class="btn sm" href="https://github.com/ViralOne/caddy-console/blob/master/docs/setup.md#behind-a-proxy-or-tunnel-real-client-ips" target="_blank" rel="noopener noreferrer">How to fix</a>
        <button class="btn sm btn-quiet" type="button" onClick=${onDismiss}>Dismiss</button>
      </div>
    </div>`;
}

function SitesTable({ sites, upstreams }) {
  return html`
    <table class="tbl sites">
      <thead><tr><th>Site</th><th>Health</th><th class="num">Requests</th><th class="num">5xx</th><th class="num">p95</th><th class="num">Out</th><th class="num">Last hour</th></tr></thead>
      <tbody>
        ${sites.map((s) => {
          const health = healthOf(s.host, upstreams);
          const tags = siteTags(s);
          const q = 'host:' + s.host;
          return html`
            <tr key=${s.host} class=${health.state === 'down' ? 'is-crit' : ''}>
              <td class="c-site"><a class="host" href=${exploreHref(q)} data-view="explore">${s.host}</a></td>
              <td class="c-health"><span class=${'health h-' + health.state}><${Icon} name=${health.icon} size=${14} />${health.label}</span></td>
              <td class="num" data-label="Requests"><a href=${exploreHref(q)} data-view="explore">${formatCount(s.requests)}</a></td>
              <td class="num" data-label="5xx"><a href=${exploreHref(q + ' status:5xx')} data-view="explore" title=${`${formatCount(s.errors)} server errors`}>${tags.includes('high')
                ? html`<span class="flag bad"><${Icon} name="warning" size=${14} />${formatPercent(s.error_rate, 2)} <span class="tag">high</span></span>`
                : formatPercent(s.error_rate, 2)}</a></td>
              <td class="num" data-label="p95"><a href=${exploreHref(q)} data-view="explore">${tags.includes('slow')
                ? html`<span class="flag slow"><${Icon} name="warning" size=${14} />${formatMs(s.p95_latency_ms)} <span class="tag">slow</span></span>`
                : formatMs(s.p95_latency_ms)}</a></td>
              <td class="num" data-label="Out"><a href=${exploreHref(q)} data-view="explore">${formatBytes(s.bytes_out)}</a></td>
              <td class="num c-spark"><${Spark} series=${s.series} bad=${health.state === 'down' || tags.includes('high')} /></td>
            </tr>`;
        })}
      </tbody>
    </table>`;
}

function Changes({ entries, now }) {
  if (!entries.length) return html`<p class="metrics-hint">No editor activity recorded yet.</p>`;
  return html`
    <ul class="changes">
      ${entries.map((e, i) => {
        const r = auditRow(e, now);
        return html`
          <li key=${i}>
            <span class="act"><${Icon} name=${r.icon} />${r.verb}</span>
            <span class="who">${r.user}</span>
            <span class="det" title=${e.detail || ''}>${r.detail}</span>
            <time title=${r.abs}>${r.rel}</time>
          </li>`;
      })}
    </ul>`;
}

function App() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [, setDismissTick] = useState(0);

  const load = async () => {
    try {
      const [sites, upstreams, traffic, status, audit] = await Promise.all([
        fetch(`/api/sites?range=${RANGE}`).then(r => r.json()),
        fetch('/api/upstreams').then(r => r.json()),
        fetch('/api/traffic').then(r => r.json()),
        fetch('/api/status').then(r => r.json()),
        fetch('/api/audit').then(r => r.json()),
      ]);
      // Caddy reports upstream health per address; fold it onto the upstream rows.
      const healthy = traffic.upstreams_healthy || {};
      const ups = (upstreams.upstreams || []).map(u => ({ ...u, healthy: healthy[u.address] }));
      setData({
        sites, upstreams: ups, upstreamsError: upstreams.error || null,
        configuredSites: upstreams.configured_sites ?? null, status, audit, now: Date.now(),
      });
      setError(sites.error || null);
    } catch (e) {
      setError(e.message);
    }
  };

  useEffect(() => {
    load();
    // Never unmounted (switching view only hides the root), so the tick checks
    // for itself; background polling would force the shared index to rebuild
    // whenever Explore asks for a different window.
    const t = setInterval(() => {
      if (document.getElementById('tab-dashboard')?.classList.contains('active')) load();
    }, REFRESH_MS);
    return () => clearInterval(t);
  }, []);

  if (error && !data) return html`<div class="page"><p class="metrics-hint error">Could not load the dashboard: ${error}</p></div>`;
  if (!data) return html`<div class="page"><p class="metrics-hint">Loading…</p></div>`;

  const sites = data.sites.sites || [];
  const v = verdict({ sites, upstreams: data.upstreams, upstreamsError: data.upstreamsError, configuredSites: data.configuredSites, status: data.status, now: data.now });
  const card = configCard(data.status, data.now);
  const figures = kpis({ sites, previousTotal: data.sites.previous_total ?? null, configuredSites: data.configuredSites });
  const p = data.sites.single_proxy_ip;
  const dismiss = () => {
    setProxyDismissed(p.ip);
    setDismissTick(t => t + 1);
    toast(`Notice hidden for ${p.ip} in this browser.`, {
      kind: 'info', action: { label: 'Undo', run: () => { setProxyDismissed(null); setDismissTick(t => t + 1); } },
    });
  };

  return html`
    <div class="page dash">
      ${error && html`<p class="metrics-hint error">${error}</p>`}
      <${Verdict} v=${v} card=${card} />
      <${Figures} items=${figures} />
      ${p && !proxyDismissed(p.ip) && html`<${ProxyNotice} p=${p} onDismiss=${dismiss} />`}

      <div class="h-sec"><h2>Sites</h2><p>Last hour, from the access log. Every figure opens in Explore.</p></div>
      ${sites.length
        ? html`<${SitesTable} sites=${sites} upstreams=${data.upstreams} />`
        : html`<p class="metrics-hint">No requests in the last hour${data.sites.skipped ? ` (${formatCount(data.sites.skipped)} log lines could not be indexed; check the log format)` : ''}.</p>`}

      <div class="h-sec"><h2>Recent changes</h2><p>From this console's audit log.</p></div>
      <${Changes} entries=${(data.audit?.entries || []).slice(0, 8)} now=${data.now} />

      <div class="foot"><span class="live-dot" aria-hidden="true"></span>${(data.sites.indexed || 0).toLocaleString('en-US')} events indexed. Refreshes every ${REFRESH_MS / 1000} s.${data.sites.dropped ? ` ${data.sites.dropped.toLocaleString('en-US')} oldest events were dropped at the memory cap.` : ''}</div>
    </div>`;
}

let mounted = false;

export function mountDashboard() {
  const root = document.getElementById('dashboard-root');
  if (!root || mounted) return;
  render(html`<${App} />`, root);
  mounted = true;
}
```

- [ ] **Step 8: Dashboard CSS**

In `style.css`, delete the old `/* --- Dashboard --- */` rules and, from `/* --- Metrics Tab --- */`, the `.section-title`, `.section-basis`, `.metrics-hint*` and `.metrics-footer` rules (keep `.select-inline` until Task 14). Add `/* === dashboard === */` with **mockup lines 144–192 verbatim**, then apply: `.ic` → `.icon`, `.h-good` → `.h-up`, `.h-crit` → `.h-down`, `.h-unk` → `.h-unknown`. Append:

```css
.verdict.sev-ok{background:var(--bg-2)}
.verdict.sev-ok h1{font-size:var(--t-xl);margin:0}
.verdict h1 .verdict-ok{color:var(--good);margin-right:10px;vertical-align:-4px}
.verdict.sev-warn{background:var(--warn-soft)}
.verdict.sev-warn .sev{color:var(--warn)}
.verdict.sev-serious .sev{color:var(--serious)}
.cfg-bad .ok{color:var(--crit)}
.cfg-unknown .ok{color:var(--ink-3)}
.fv-of{font-size:var(--t-md);font-weight:400;color:var(--ink-3)}
.flag .tag{font-size:11px;font-weight:600;line-height:16px;padding:0 5px;border-radius:4px;border:1px solid currentColor}
.metrics-hint{color:var(--ink-3);font-size:var(--t-sm);padding:12px 0}
.metrics-hint.error{color:var(--crit)}
/* Spec: alert blocks are a tint plus a thin border; the unhealthy row is tinted. */
.notice{border:1px solid color-mix(in srgb,var(--warn) 30%,transparent)}
.verdict.sev-critical,.verdict.sev-serious{border:1px solid color-mix(in srgb,var(--crit) 25%,transparent)}
.verdict.sev-warn{border:1px solid color-mix(in srgb,var(--warn) 30%,transparent)}
.sites tr.is-crit td{background:var(--crit-soft)}
```

- [ ] **Step 9: Run the tests and check in the browser**

Run: `for t in tests/*.test.mjs; do node "$t" || exit 1; done`
Expected: PASS.
Browser http://localhost:8888/. If the log is empty, seed it first with `python3 dev/seed-logs.py | docker compose -f docker-compose.dev.yaml exec -T caddy-target sh -c 'cat >> /var/log/caddy/access.log'`:
- The dev seed's `photos.example.com` proxies to a closed port with `health_uri`, so the verdict reads "photos.example.com is down" with "has failed since HH:MM".
- "Open photos.example.com block" lands the editor cursor on that site's line.
- Every figure and every table number opens Explore with the matching filter.
- Health shows icon plus word. The unhealthy row has a red inset edge. Tags read "high" / "slow".
- Recent changes use verbs and relative times, and the full time shows on hover.
- Dismiss the notice: a toast appears with Undo, and Undo brings the notice back.

- [ ] **Step 10: Commit**

```bash
git add src/static/js/app src/static/css/style.css tests/dashboard-model.test.mjs tests/caddyfile-sites.test.mjs
git commit -m "feat(dashboard): verdict, config card, figures with context, tagged sites, readable changes"
```

---

### Task 14: Explore (facets, query bar, histogram axis and keyboard readout, expanded row, IP popover)

**Files:**
- Create: `src/static/js/app/histogram-axis.js`
- Modify: `src/static/js/app/histogram.js`, `src/static/js/app/explore.js` (rewrite), `src/static/js/app/ip-popover.js` (render), `src/static/css/style.css` (explore section)
- Test: `tests/histogram-axis.test.mjs` (new)

**Interfaces:**
- Consumes: `format.js` (Task 10), `toast` (Task 11), `activeKeys` (existing `explore-query.js`).
- Produces (`histogram-axis.js`): `formatTick(ts, bucketSeconds)`, `formatSpan(seconds)` (both moved from `histogram.js`), `axisTicks({from, to, bucketSeconds, now, count = 5}): {pct, label, align: 'start'|'middle'|'end'}[]` (the last label reads `now, HH:MM` when `to` is within a bucket of `now`), and `stepIndex(current, delta, length): number|null` (`null` current starts at the newest bucket; clamps at both ends).
- `histogram.js` `CLASSES` entries gain `cls` (`s2 s3 s4 s5 so`). `IpPopover` gains an `onClose` prop.
- `explore.js` keeps `export function rayIdOf(rawLine)` and `mountExplore()` unchanged.

- [ ] **Step 1: Write the failing test**

Create `tests/histogram-axis.test.mjs`:

```js
// Tests for src/static/js/app/histogram-axis.js
// Run with: node tests/histogram-axis.test.mjs
import assert from 'node:assert/strict';
import path from 'node:path';

const SRC = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app', 'histogram-axis.js');
const { axisTicks, formatSpan, formatTick, stepIndex } = await import(SRC);

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };
const sec = (...a) => new Date(...a).getTime() / 1000;
const FROM = sec(2026, 10, 20, 13, 40);
const TO = sec(2026, 10, 20, 14, 40);

check('five labels, edges aligned inward so none is clipped', () => {
  const t = axisTicks({ from: FROM, to: TO, bucketSeconds: 60, now: TO });
  assert.deepEqual(t.map(x => x.label), ['13:40', '13:55', '14:10', '14:25', 'now, 14:40']);
  assert.deepEqual(t.map(x => x.align), ['start', 'middle', 'middle', 'middle', 'end']);
  assert.deepEqual(t.map(x => x.pct), [0, 25, 50, 75, 100]);
});
check('a past range does not say "now"', () =>
  assert.equal(axisTicks({ from: FROM, to: TO, bucketSeconds: 60, now: TO + 3600 }).at(-1).label, '14:40'));
check('day buckets label dates', () => assert.equal(formatTick(sec(2026, 10, 3, 12), 86400), '11/03'));
check('stepIndex starts at the newest bucket and clamps', () => {
  assert.equal(stepIndex(null, -1, 10), 9);
  assert.equal(stepIndex(5, -1, 10), 4);
  assert.equal(stepIndex(0, -1, 10), 0);
  assert.equal(stepIndex(9, 1, 10), 9);
  assert.equal(stepIndex(3, 1, 0), null);
});
check('formatSpan', () => { assert.equal(formatSpan(300), '5m'); assert.equal(formatSpan(3600), '1h'); });
console.log(`\n${passed} passed`);
```

- [ ] **Step 2: Run to verify it fails**

Run: `node tests/histogram-axis.test.mjs`
Expected: FAIL with `Cannot find module`.

- [ ] **Step 3: Implement `histogram-axis.js`**

```js
// Where the histogram's time labels go, and how the keyboard moves its readout.
// Pure, so the placement that used to clip at the edges is pinned by tests.
const pad = (n) => String(n).padStart(2, '0');

export function formatTick(ts, bucketSeconds) {
  const d = new Date(ts * 1000);
  if (bucketSeconds >= 86400) return `${d.getMonth() + 1}/${pad(d.getDate())}`;
  if (bucketSeconds >= 3600) return `${pad(d.getHours())}:00`;
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function formatSpan(seconds) {
  if (seconds >= 86400) return Math.round(seconds / 86400) + 'd';
  if (seconds >= 3600) return Math.round(seconds / 3600) + 'h';
  if (seconds >= 60) return Math.round(seconds / 60) + 'm';
  return Math.round(seconds) + 's';
}

/** Evenly spaced labels inside the plot: first left-aligned, last right-aligned. */
export function axisTicks({ from, to, bucketSeconds, now = Date.now() / 1000, count = 5 }) {
  const span = Math.max(1, to - from);
  const live = Math.abs(now - to) <= Math.max(60, bucketSeconds);
  return Array.from({ length: count }, (_, i) => {
    const f = count === 1 ? 1 : i / (count - 1);
    let label = formatTick(from + f * span, bucketSeconds);
    if (i === count - 1 && live) label = `now, ${label}`;
    return { pct: f * 100, label, align: i === 0 ? 'start' : i === count - 1 ? 'end' : 'middle' };
  });
}

/** Arrow-key stepping over buckets; from nothing, start at the newest. */
export function stepIndex(current, delta, length) {
  if (!length) return null;
  if (current == null) return length - 1;
  return Math.min(length - 1, Math.max(0, current + delta));
}
```

- [ ] **Step 4: Update `histogram.js`**

1. Replace the local `formatTick` and `formatSpan` functions with `import { axisTicks, formatSpan, formatTick, stepIndex } from './histogram-axis.js';`.
2. Replace `CLASSES` with:

```js
export const CLASSES = [
  { key: '2xx', label: '2xx', token: 'var(--good)', cls: 's2' },
  { key: '3xx', label: '3xx', token: 'var(--info)', cls: 's3' },
  { key: '4xx', label: '4xx', token: 'var(--warn)', cls: 's4' },
  { key: '5xx', label: '5xx', token: 'var(--crit)', cls: 's5' },
  { key: 'other', label: 'other', token: 'var(--other)', cls: 'so' },
];
```

3. In the empty branch, change the returned markup to `<div class=${'hist' + (loading ? ' loading' : '')}><p class="hist-empty">${loading ? 'Loading…' : 'No events in this range.'}</p></div>`.
4. Replace the `const ticks = [0, 0.5, 1].map(…)` block with:

```js
  const ticks = axisTicks({ from: spanFrom, to: spanTo, bucketSeconds: width, now: Date.now() / 1000 });
  // The readout is also driven by the keyboard, so it is not hover-only.
  const onKey = (ev) => {
    let next;
    if (ev.key === 'ArrowLeft') next = stepIndex(hover, -1, buckets.length);
    else if (ev.key === 'ArrowRight') next = stepIndex(hover, 1, buckets.length);
    else if (ev.key === 'Home') next = 0;
    else if (ev.key === 'End') next = buckets.length - 1;
    else if (ev.key === 'Escape') next = null;
    else return;
    ev.preventDefault();
    setHover(next);
  };
```

5. Replace the component's final `return html\`…\`;` with:

```js
  return html`
    <div class=${'hist' + (loading ? ' loading' : '')}>
      <div class="hist-hd">
        <b>${(total || 0).toLocaleString()} events</b>
        ${loading && html`<span class="muted">updating…</span>`}
        <ul class="legend">
          ${CLASSES.map(c => html`<li key=${c.key}><span class="sw" style=${{ background: c.token }}></span>${c.label}</li>`)}
        </ul>
        <span class="hint">Drag across bars to zoom. Arrow keys move the readout.</span>
      </div>

      <div class="chart" tabindex="0" role="group" aria-label="Requests over time, stacked by status class"
           aria-describedby="hist-readout" onKeyDown=${onKey} onBlur=${() => setHover(null)}>
        <svg class=${'hist-svg' + (drag ? ' dragging' : '')} ref=${svgRef}
             viewBox=${`0 0 100 ${HEIGHT}`} preserveAspectRatio="none" aria-hidden="true"
             onPointerDown=${onDown} onPointerMove=${onMove} onPointerUp=${onUp} onPointerLeave=${onLeave}>
          ${buckets.map((b, i) => {
            let y = HEIGHT;
            const dim = hover != null && hover !== i;
            return CLASSES.map(c => {
              const n = b[c.key] || 0;
              if (!n) return null;
              const hPx = (n / peak) * (HEIGHT - 4);
              y -= hPx;
              return html`<rect class=${'hist-bar' + (dim ? ' dim' : '')}
                x=${xOf(b.t) + slotW * 0.1} y=${y} width=${slotW * 0.8}
                height=${Math.max(0.5, hPx - GAP / 2)} fill=${c.token} />`;
            });
          })}
          ${hovered && html`<rect class="hist-hover-band" x=${xOf(hovered.t) - slotW * 0.35} y="0" width=${slotW * 1.7} height=${HEIGHT} />`}
          ${brush && html`<rect class="hist-brush" x=${brush.x} y="0" width=${Math.max(0.3, brush.w)} height=${HEIGHT} />`}
        </svg>
        ${drag && html`
          <div class="hist-brush-label" style=${{ left: Math.min(80, Math.max(2, xOf(Math.min(drag.from, drag.to)))) + '%' }}>
            ${formatSpan(Math.abs(drag.to - drag.from))} selected, release to zoom
          </div>`}
      </div>

      <div class="hist-axis" aria-hidden="true">
        ${ticks.map(t => html`<span class="hist-tick" data-align=${t.align} style=${{ left: t.pct + '%' }}>${t.label}</span>`)}
      </div>

      <div class="readout" id="hist-readout" aria-live="polite">
        ${hovered && !drag
          ? html`<b>${formatTick(hovered.t, width)}</b><span>${formatSpan(width)}</span>
                 ${CLASSES.filter(c => hovered[c.key]).map(c => html`<span class=${c.cls} key=${c.key}>${c.label} ${hovered[c.key].toLocaleString()}</span>`)}
                 <span>${hoveredTotal.toLocaleString()} total</span>`
          : html`<span class="muted">Hover or focus the chart to read one bucket.</span>`}
      </div>
    </div>`;
```

- [ ] **Step 5: Rewrite `explore.js`**

```js
// Explore: faceted search over the access log.
//
// The query string is the single source of truth: clicking a facet rewrites the
// query rather than keeping parallel state, so the search box always explains
// what is on screen. The URL mirrors query, range and live, so a pasted link
// reproduces the sender's view.
import { h, htm, render, useCallback, useEffect, useRef, useState } from '../explore-vendor.js';
import { activeKeys, cycleTerm, placeholderFor, setTermState, termState } from './explore-query.js';
import { SLOW_MS, absoluteTime, countryName, durationNote, formatBytes, formatMs, statusText } from './format.js';
import { CLASSES, Histogram } from './histogram.js';
import { Icon } from './icons.js';
import { IpPopover } from './ip-popover.js';
import { JsonView } from './jsonview.js';
import { exploreStateFromSearch, exploreStateToSearch, replaceSearch } from './router.js';
import { toast } from './ui/toast.js';

const html = htm.bind(h);

const RANGES = [
  { key: '30m', label: 'Last 30 min' },
  { key: '1h', label: 'Last 1 hour' },
  { key: '6h', label: 'Last 6 hours' },
  { key: '24h', label: 'Last 24 hours' },
  { key: '7d', label: 'Last 7 days' },
  { key: '30d', label: 'Last 30 days' },
];
const FACET_GROUPS = [
  { key: 'host', title: 'Host' },
  { key: 'status_class', title: 'Status', queryKey: 'status' },
  { key: 'status', title: 'Status code', queryKey: 'status' },
  { key: 'method', title: 'Method' },
  { key: 'path', title: 'Path' },
  // Only shown when the log has cf_country (an opt-in log_append behind Cloudflare).
  { key: 'country', title: 'Country (Cloudflare)' },
];
const FACET_SHOWN = 8;
const DEBOUNCE_MS = 250;
const FOLLOW_MS = 4000;

const pad = (n) => String(n).padStart(2, '0');
function clockTime(ts) {
  const d = new Date(ts * 1000);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
const fullTime = (ts) => `${absoluteTime(ts)}.${String(Math.floor((ts % 1) * 1000)).padStart(3, '0')}`;
const statusClass = (s) => (s >= 200 && s < 600 ? 's' + String(s)[0] : 'so');
const pathOf = (uri) => (uri || '').split('?', 1)[0];

// Which query key each field maps to. Fields absent here are copy-only:
// "Filter by" on a field the backend cannot filter would silently do nothing.
const FIELD_KEYS = { host: 'host', method: 'method', path: 'path', status: 'status', client: 'client', country: 'country' };

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch (e) { return false; }
}

function fieldsOf(e) {
  return [
    { label: 'client', display: e.client_ip || '(none)', value: e.client_ip || '', ip: e.client_ip || null },
    // Present only behind Cloudflare with the opt-in log_append.
    ...(e.cf_country ? [{ label: 'country', display: countryName(e.cf_country), value: e.cf_country, cc: e.cf_country }] : []),
    { label: 'status', display: String(e.status), value: String(e.status), note: statusText(e.status), status: e.status },
    { label: 'time', display: fullTime(e.ts), value: String(e.ts), zoom: e.ts },
    { label: 'host', display: e.host, value: e.host },
    { label: 'method', display: e.method, value: e.method },
    { label: 'path', display: e.uri, value: pathOf(e.uri) },
    { label: 'duration', display: formatMs(e.duration_ms), value: String(e.duration_ms), note: durationNote(e.status), slow: e.duration_ms >= SLOW_MS },
    { label: 'size', display: formatBytes(e.size), value: String(e.size) },
  ];
}

/** Cloudflare's Ray ID from a raw log line, or '' (not indexed: it is unique per request). */
export function rayIdOf(rawLine) {
  try {
    const ray = JSON.parse(rawLine)?.cf_ray;
    return typeof ray === 'string' ? ray : '';
  } catch (e) {
    return '';
  }
}

function App() {
  const initial = exploreStateFromSearch();
  const [query, setQuery] = useState(initial.q);
  const [draft, setDraft] = useState(initial.q);
  const [range, setRange] = useState(initial.range);
  const [custom, setCustom] = useState(initial.custom);
  const [follow, setFollow] = useState(initial.live);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(null);
  const [older, setOlder] = useState([]);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [exhausted, setExhausted] = useState(false);
  const [raw, setRaw] = useState({});              // "file:offset" -> line | {error}
  const [fieldMenu, setFieldMenu] = useState(null);
  const [ipPop, setIpPop] = useState(null);         // {id, rect}
  const [drawer, setDrawer] = useState(false);      // facets drawer at <=1024 px
  const [moreFacets, setMoreFacets] = useState(() => new Set());
  const inflight = useRef(null);

  useEffect(() => {
    if (!fieldMenu) return;
    const close = (ev) => { if (!ev.target.closest('.field-menu, .field-trigger, .field-value-click')) setFieldMenu(null); };
    const esc = (ev) => { if (ev.key === 'Escape') setFieldMenu(null); };
    document.addEventListener('click', close);
    document.addEventListener('keydown', esc);
    return () => { document.removeEventListener('click', close); document.removeEventListener('keydown', esc); };
  }, [fieldMenu]);

  // The IP popover closes the same way, but clicks inside it must not.
  useEffect(() => {
    if (!ipPop) return;
    const close = (ev) => { if (!ev.target.closest('.ip-pop, .field-value-click')) setIpPop(null); };
    const esc = (ev) => { if (ev.key === 'Escape') setIpPop(null); };
    // Fixed-position, so it would float away from its row on scroll.
    const scroll = (ev) => { if (!ev.target.closest?.('.ip-pop')) setIpPop(null); };
    document.addEventListener('click', close);
    document.addEventListener('keydown', esc);
    document.addEventListener('scroll', scroll, true);
    window.addEventListener('resize', esc);
    return () => {
      document.removeEventListener('click', close); document.removeEventListener('keydown', esc);
      document.removeEventListener('scroll', scroll, true); window.removeEventListener('resize', esc);
    };
  }, [ipPop]);

  useEffect(() => {
    if (!drawer) return;
    const esc = (ev) => { if (ev.key === 'Escape') setDrawer(false); };
    document.addEventListener('keydown', esc);
    return () => document.removeEventListener('keydown', esc);
  }, [drawer]);

  const copied = async (value, label) => {
    const ok = await copyText(value);
    toast(ok ? label : 'Copy blocked by the browser', { kind: ok ? 'ok' : 'warn' });
  };

  // mountExplore() calls this when the view is shown again (dashboard links, Back).
  useEffect(() => {
    applyUrlState = () => {
      const next = exploreStateFromSearch();
      setDraft(next.q); setQuery(next.q); setRange(next.range); setCustom(next.custom); setFollow(next.live);
    };
    return () => { applyUrlState = null; };
  }, []);

  // replaceState, not pushState: a history entry per keystroke would break Back.
  useEffect(() => {
    replaceSearch(exploreStateToSearch({ q: query, range, custom, live: follow }));
  }, [query, range, custom, follow]);

  useEffect(() => {
    const t = setTimeout(() => setQuery(draft), DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [draft]);

  const load = useCallback(async () => {
    const params = new URLSearchParams({ limit: '200' });
    if (query) params.set('q', query);
    if (custom) { params.set('from', String(custom.from)); params.set('to', String(custom.to)); }
    else params.set('range', range);
    const token = {};
    inflight.current = token;
    try {
      const res = await fetch('/api/explore?' + params);
      if (res.status === 401) return;
      const body = await res.json();
      if (inflight.current !== token) return;
      if (!res.ok) { setError(body.error || `HTTP ${res.status}`); return; }
      setError(body.error || null);
      setData(body);
    } catch (e) {
      if (inflight.current === token) setError(e.message);
    } finally {
      if (inflight.current === token) setLoading(false);
    }
  }, [query, range, custom]);

  useEffect(() => { setLoading(true); setOlder([]); setExhausted(false); load(); }, [load]);

  useEffect(() => {
    if (!follow || custom) return;
    setOlder([]); setExhausted(false);
    const t = setInterval(load, FOLLOW_MS);
    return () => clearInterval(t);
  }, [follow, custom, load]);

  // Paging walks backwards from the oldest event on screen, by timestamp and
  // offset, against the absolute bounds the first request resolved.
  const loadOlder = async () => {
    const shown = [...(data?.entries || []), ...older];
    if (!shown.length || loadingOlder || follow) return;
    setLoadingOlder(true);
    try {
      const last = shown[shown.length - 1];
      const params = new URLSearchParams({ limit: '200', before_ts: String(last.ts), before_offset: String(last.offset) });
      if (query) params.set('q', query);
      const from = custom ? custom.from : data?.range?.from;
      const to = custom ? custom.to : data?.range?.to;
      if (from != null && to != null) { params.set('from', String(Math.floor(from))); params.set('to', String(Math.ceil(to))); }
      else params.set('range', range);
      const res = await fetch('/api/explore?' + params);
      const body = await res.json().catch(() => ({}));
      if (!res.ok) { setError(body.error || `Could not load older events: HTTP ${res.status}`); return; }
      const page = body.entries || [];
      if (!page.length) setExhausted(true);
      else setOlder([...older, ...page]);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoadingOlder(false);
    }
  };

  const rawKey = (file, offset) => `${file}:${offset}`;
  const rowKey = (e) => rawKey(e.file, e.offset);

  // Fetched when a row opens, so the Ray ID can show without opening the raw
  // view. Errors are stored but refetched on the next open, so a retry works.
  const ensureRaw = async (file, offset) => {
    const key = rawKey(file, offset);
    if (typeof raw[key] === 'string') return;
    try {
      const res = await fetch(`/api/explore/raw?file=${encodeURIComponent(file)}&offset=${offset}`);
      const body = await res.json();
      setRaw(prev => ({ ...prev, [key]: body.line ? body.line : { error: body.error || 'Could not read that line' } }));
    } catch (e) {
      setRaw(prev => ({ ...prev, [key]: { error: e.message } }));
    }
  };

  const toggleRow = (e) => {
    const key = rowKey(e);
    const next = expanded === key ? null : key;
    setExpanded(next);
    if (next) ensureRaw(e.file, e.offset);
  };

  const fieldAction = async (action, field) => {
    const key = FIELD_KEYS[field.label];
    const term = key ? `${key}:${/[\s"]/.test(field.value) ? '"' + field.value + '"' : field.value}` : '';
    setFieldMenu(null);
    if (action === 'copy-value') copied(field.value, 'Value copied');
    else if (action === 'copy-term') copied(term, 'Copied ' + term);
    else if (action === 'filter' || action === 'exclude') {
      // setTermState, not append: Exclude on an included value must flip it.
      setDraft(setTermState(draft, key, field.value, action === 'filter' ? 'include' : 'exclude'));
    } else if (action === 'replace') setDraft(term);
    else if (action === 'zoom') {
      setCustom({ from: Math.floor(field.zoom) - 300, to: Math.ceil(field.zoom) + 300 });
      setFollow(false);
    }
  };

  const queryKeyFor = (key) => FACET_GROUPS.find(g => g.key === key)?.queryKey || key;
  const cycleFacet = (key, value) => setDraft(cycleTerm(draft, queryKeyFor(key), value));
  const toggleExclude = (key, value, current) =>
    setDraft(setTermState(draft, queryKeyFor(key), value, current === 'exclude' ? 'off' : 'exclude'));
  const toggleMore = (key) => setMoreFacets(prev => { const next = new Set(prev); if (next.has(key)) next.delete(key); else next.add(key); return next; });
  const pickRange = (key) => { setCustom(null); setRange(key); };
  const onDragRange = (from, to) => { setCustom({ from, to }); setFollow(false); };

  const stats = data?.stats;
  const presetLabel = (RANGES.find(r => r.key === range) || {}).label || '';
  const rangeLabel = custom ? `${clockTime(custom.from)} to ${clockTime(custom.to)}` : presetLabel;
  const hint = placeholderFor(data);
  const filterCount = activeKeys(draft).size;

  const renderFacetGroup = (group) => {
    const values = (data.facets || {})[group.key] || [];
    if (!values.length) return null;
    const other = (data.facet_other || {})[group.key] || 0;
    const qk = group.queryKey || group.key;
    const all = moreFacets.has(group.key);
    const shown = all ? values : values.slice(0, FACET_SHOWN);
    return html`
      <div class="facet" key=${group.key}>
        <h3>${group.title}<span>${values.length}${other > 0 ? '+' : ''} ${values.length === 1 && !other ? 'value' : 'values'}</span></h3>
        <ul>
          ${shown.map((v) => {
            // Values the query language cannot express: an absent field, or a status of 0.
            if (v.value === '' || (group.key === 'status' && v.value === '0')) {
              return html`
                <li class="fv fv-static" key=${v.value || '(none)'} title="Entries with no value for this field, not filterable">
                  <span class="fv-main"><span class="v muted">(none)</span><span class="n">${v.count.toLocaleString()}</span></span>
                </li>`;
            }
            const label = group.key === 'country' ? countryName(v.value) : v.value;
            const current = termState(draft, qk, v.value);
            const swatch = group.key === 'status_class' ? CLASSES.find(c => c.key === v.value) : null;
            return html`
              <li class=${'fv' + (current === 'include' ? ' is-on' : current === 'exclude' ? ' is-ex' : '')} key=${v.value}>
                <button class="fv-main" type="button" aria-pressed=${String(current === 'include')}
                        title=${current === 'exclude' ? `${label}: excluded. Click to clear.` : current === 'include' ? `${label}: only this. Click to clear.` : `${label}: click to show only this`}
                        onClick=${() => cycleFacet(group.key, v.value)}>
                  <${Icon} name=${current === 'include' ? 'box-check' : 'box'} size=${15} />
                  ${swatch && html`<span class="sw" style=${{ background: swatch.token }}></span>`}
                  <span class="v">${label}</span>
                  <span class="tag">excluded</span>
                  <span class="n">${v.count.toLocaleString()}</span>
                </button>
                <button class="ibtn sm ex" type="button" aria-pressed=${String(current === 'exclude')}
                        aria-label=${`${current === 'exclude' ? 'Stop excluding' : 'Exclude'} ${group.title} ${label}`}
                        title=${current === 'exclude' ? 'Stop excluding' : 'Exclude'}
                        onClick=${() => toggleExclude(group.key, v.value, current)}><${Icon} name="minus-circle" size=${14} /></button>
              </li>`;
          })}
        </ul>
        ${values.length > FACET_SHOWN && html`
          <button class="more" type="button" aria-expanded=${String(all)} onClick=${() => toggleMore(group.key)}>
            ${all ? 'Show fewer' : `+${values.length - FACET_SHOWN} more`}</button>`}
        ${other > 0 && html`<p class="facet-other">${other.toLocaleString()} events in other values</p>`}
      </div>`;
  };

  const renderField = (f, key) => {
    const id = key + '|' + f.label;
    const filterable = !!FIELD_KEYS[f.label] && f.value !== '';
    const menuOpen = fieldMenu === id;
    const term = `${FIELD_KEYS[f.label]}:${f.value}`;
    const toggleMenu = () => { setIpPop(null); setFieldMenu(menuOpen ? null : id); };
    const openIp = (ev) => {
      setFieldMenu(null);
      const rect = ev.currentTarget.getBoundingClientRect();
      setIpPop(ipPop?.id === id ? null : { id, rect });
    };
    return html`
      <div class="fld" key=${f.label}>
        <dt>${f.label}</dt>
        <dd>
          ${f.ip
            ? html`<button class="iplink field-value-click" type="button" aria-haspopup="dialog" aria-expanded=${String(ipPop?.id === id)}
                           title="Where is this IP from?" onClick=${openIp}><${Icon} name="globe" size=${13} />${f.display}</button>`
            : f.status != null ? html`<span class=${'st ' + statusClass(f.status)}>${f.display}</span>`
              : f.cc ? html`<span class="cc">${f.cc}</span> ${f.display}`
                : html`<span class=${f.slow ? 'dur-slow' : ''}>${f.slow && html`<${Icon} name="warning" size=${12} /> `}${f.display}</span>`}
          ${f.note && html` <span class="fld-note">${f.note}</span>`}
          ${f.ip && ipPop?.id === id && html`
            <${IpPopover} ip=${f.ip} anchor=${ipPop.rect}
                          from=${custom ? custom.from : data?.range?.from}
                          to=${custom ? custom.to : data?.range?.to}
                          query=${draft}
                          onQuery=${q => { setDraft(q); setIpPop(null); }}
                          onClose=${() => setIpPop(null)}
                          onCopy=${v => copied(v, 'IP copied')} />`}
        </dd>
        <dd class="fld-act">
          <button class="ibtn sm field-trigger" type="button" aria-haspopup="menu" aria-expanded=${String(menuOpen)}
                  aria-label=${'Actions for ' + f.label} onClick=${toggleMenu}><${Icon} name="more" size=${14} /></button>
          ${menuOpen && html`
            <div class="pop ctx field-menu" role="menu">
              <button class="menu-item" role="menuitem" type="button" onClick=${() => fieldAction('copy-value', f)}><${Icon} name="copy" />Copy value</button>
              ${filterable && html`
                <button class="menu-item" role="menuitem" type="button" onClick=${() => fieldAction('filter', f)}><${Icon} name="filter" />Filter by <b>${term}</b></button>
                <button class="menu-item" role="menuitem" type="button" onClick=${() => fieldAction('exclude', f)}><${Icon} name="minus-circle" />Exclude <b>${term}</b></button>
                <button class="menu-item" role="menuitem" type="button" onClick=${() => fieldAction('replace', f)}><${Icon} name="explore" />Replace query with <b>${term}</b></button>
                <button class="menu-item" role="menuitem" type="button" onClick=${() => fieldAction('copy-term', f)}><${Icon} name="copy" />Copy <b>${term}</b></button>`}
              ${f.zoom && html`<button class="menu-item" role="menuitem" type="button" onClick=${() => fieldAction('zoom', f)}><${Icon} name="clock" />Zoom to ±5 min around this event</button>`}
              ${!filterable && !f.zoom && html`<p class="field-menu-note">Not a filterable field</p>`}
            </div>`}
        </dd>
      </div>`;
  };

  const renderDetail = (e, key) => {
    const line = raw[rawKey(e.file, e.offset)];
    const ray = typeof line === 'string' ? rayIdOf(line) : '';
    return html`
      <div class="dwrap" onClick=${ev => ev.stopPropagation()}>
        <dl class="fields">${fieldsOf(e).map(f => renderField(f, key))}</dl>
        <div class="drow">
          ${ray && html`
            <span class="ray">Cloudflare ray <span class="mono">${ray}</span>
              <button class="ibtn sm" type="button" aria-label="Copy Ray ID" title="Look this request up in the Cloudflare dashboard"
                      onClick=${() => copied(ray, 'Ray ID copied')}><${Icon} name="copy" size=${14} /></button></span>`}
          <details class="raw" onToggle=${ev => { if (ev.currentTarget.open && typeof line !== 'string') ensureRaw(e.file, e.offset); }}>
            <summary><${Icon} name="chevron-right" size=${14} />Show original log line</summary>
            ${typeof line === 'string' ? html`<${JsonView} text=${line} />`
              : line && line.error ? html`<p class="metrics-hint error">${line.error}</p>`
                : html`<p class="metrics-hint">Loading…</p>`}
          </details>
        </div>
      </div>`;
  };

  const rows = [...(data?.entries || []), ...older];

  return html`
    <div class="explore">
      <aside class=${'facets' + (drawer ? ' open' : '')} id="facets" aria-label="Filters">
        <div class="facets-hd">
          <h2>Filters</h2>
          <button class="ibtn" type="button" aria-label="Close filters" onClick=${() => setDrawer(false)}><${Icon} name="close" /></button>
        </div>
        ${!data ? html`<p class="metrics-hint">Loading…</p>` : FACET_GROUPS.map(renderFacetGroup)}
      </aside>
      ${drawer && html`<div class="scrim" onClick=${() => setDrawer(false)}></div>`}

      <section class="ex-main">
        <div class="qbar">
          <button class="btn filters-btn" type="button" aria-controls="facets" aria-expanded=${String(drawer)}
                  onClick=${() => setDrawer(true)}><${Icon} name="filter" />Filters${filterCount > 0 && html` <span class="muted">${filterCount}</span>`}</button>
          <label class="qwrap">
            <span class="sr">Query</span>
            <${Icon} name="explore" />
            <input type="text" spellcheck="false" placeholder=${hint} value=${draft} onInput=${e => setDraft(e.target.value)} />
            ${custom && html`
              <span class="chip" title="Zoomed into a selected range">${rangeLabel}
                <button class="ibtn" type="button" aria-label="Clear the selected range" title=${'Back to ' + presetLabel}
                        onClick=${ev => { ev.preventDefault(); setCustom(null); }}><${Icon} name="close" size=${14} /></button></span>`}
            ${draft && html`<button class="btn sm btn-quiet" type="button" onClick=${ev => { ev.preventDefault(); setDraft(''); }}>Clear</button>`}
          </label>
          <label class="sr" for="explore-range">Time range</label>
          <select class="sel" id="explore-range" value=${range} onChange=${e => pickRange(e.target.value)}>
            ${RANGES.map(r => html`<option value=${r.key}>${r.label}</option>`)}
          </select>
          <button class="live" type="button" aria-pressed=${String(follow && !custom)} disabled=${!!custom}
                  title=${custom ? 'Pinned to a selected range. Pick a preset range to follow again.' : 'Stream new matching events'}
                  onClick=${() => setFollow(f => !f)}><span class="live-dot" aria-hidden="true"></span>Live</button>
        </div>

        ${error && html`<p class="metrics-hint error" role="alert">${error}</p>`}

        <${Histogram} histogram=${data?.histogram} total=${data?.total}
                      from=${data?.range?.from} to=${data?.range?.to}
                      loading=${loading} onRange=${onDragRange} />

        ${stats && stats.requests > 0 && html`
          <div class="stats">
            <div><b>${stats.requests.toLocaleString()}</b>events</div>
            <div><b class=${stats.error_rate > 5 ? 's5' : ''}>${stats.error_rate}%</b>5xx</div>
            <div><b class=${stats.avg_latency_ms >= SLOW_MS ? 'dur-slow' : ''}>${stats.avg_latency_ms >= SLOW_MS && html`<${Icon} name="warning" size=${14} /> `}${formatMs(stats.avg_latency_ms)}</b>avg</div>
            <div><b class=${stats.p95_latency_ms >= SLOW_MS ? 'dur-slow' : ''}>${stats.p95_latency_ms >= SLOW_MS && html`<${Icon} name="warning" size=${14} /> `}${formatMs(stats.p95_latency_ms)}</b>p95</div>
            <div><b>${formatBytes(stats.bytes_out)}</b>out</div>
            <span class="src">${rangeLabel}, ${data.history?.rolls_read ? `${data.history.rolls_read} archive${data.history.rolls_read > 1 ? 's' : ''} read` : 'live log only'}</span>
          </div>`}

        ${data && !data.exists && html`<p class="metrics-hint">No access log at ${data.path}. Add a log directive to your sites; the README has the snippet.</p>`}
        ${data?.range?.truncated && html`<p class="metrics-hint">This range reaches further back than the events held in memory. Earliest indexed: ${clockTime(data.range.earliest_ts)}. Narrow the range, or raise CADDY_EXPLORE_MAX_EVENTS.</p>`}
        ${data?.skipped > 0 && data?.indexed === 0 && html`<p class="metrics-hint error">${data.skipped.toLocaleString()} log lines were read but none could be indexed. Every entry needs a "ts" field and a request host; check the log format against the README snippet.</p>`}
        ${data?.dropped > 0 && html`<p class="metrics-hint">${data.dropped.toLocaleString()} oldest events were dropped to stay within the in-memory cap, so counts cover less than the bytes read.</p>`}
        ${data?.exists && data?.entries?.length === 0 && !loading && html`
          <p class="metrics-hint">${draft ? 'No events match. Try removing a filter.' : `No requests in this range (${rangeLabel.toLowerCase()}).`}</p>`}

        ${rows.length > 0 && html`
          <table class="tbl stream">
            <thead><tr><th>Time</th><th>Status</th><th>Host</th><th>Method</th><th>URI</th><th class="num">Duration</th></tr></thead>
            <tbody>
              ${rows.map((e) => {
                const key = rowKey(e);
                const open = expanded === key;
                const slow = e.duration_ms >= SLOW_MS;
                return [
                  html`<tr class=${'ev' + (open ? ' open' : '')} key=${key} onClick=${() => toggleRow(e)}>
                    <td><button class="rt" type="button" aria-expanded=${String(open)}
                                onClick=${ev => { ev.stopPropagation(); toggleRow(e); }}><${Icon} name="chevron-right" size=${14} />${clockTime(e.ts)}</button></td>
                    <td><span class=${'st ' + statusClass(e.status)}>${e.status}</span></td>
                    <td class="c-host">${e.host}</td>
                    <td>${e.method}</td>
                    <td class="c-uri" title=${e.uri}>${e.uri}</td>
                    <td class=${'num c-dur' + (slow ? ' dur-slow' : '')}>${slow && html`<${Icon} name="warning" size=${12} /> `}${formatMs(e.duration_ms)}</td>
                  </tr>`,
                  open && html`<tr class="detail" key=${key + '|d'}><td colspan="6">${renderDetail(e, key)}</td></tr>`,
                ];
              })}
            </tbody>
          </table>`}

        ${(() => {
          if (!data) return null;
          const shown = rows.length;
          if (shown >= data.total) return null;
          if (exhausted) return html`<p class="metrics-hint">No more events in this range.</p>`;
          return html`
            <div class="loadmore">
              <button class="btn" type="button" onClick=${loadOlder} disabled=${loadingOlder || follow}
                      title=${follow ? 'Pause Live to page back' : ''}>${loadingOlder ? 'Loading…' : `Load ${Math.min(200, data.total - shown).toLocaleString()} older`}</button>
              <span>Showing ${shown.toLocaleString()} of ${data.total.toLocaleString()}</span>
            </div>`;
        })()}
      </section>
    </div>`;
}

let mounted = false;
let applyUrlState = null;   // set by App while it is rendered

export function mountExplore() {
  const root = document.getElementById('explore-root');
  if (!root) return;
  if (mounted) {
    // Adopt whatever the URL now says, keeping expanded rows and loaded pages.
    applyUrlState?.();
    return;
  }
  render(html`<${App} />`, root);
  mounted = true;
}
```

- [ ] **Step 6: Restyle the IP popover (`ip-popover.js`)**

Change the signature to `export function IpPopover({ ip, anchor, from, to, query, onQuery, onCopy, onClose })`, add `const chipClass = (v) => ({ '2xx': 's2', '3xx': 's3', '4xx': 's4', '5xx': 's5' }[v] || 'so');` above it, and replace the returned markup with:

```js
  return html`
    <div class="pop ippop ip-pop" role="dialog" aria-label=${'About ' + ip} style=${style}>
      <div class="sect">
        <div class="k">${info ? kindLabel(info.kind) : 'IP address'}</div>
        <div class="ip"><span>${ip}</span>
          <button class="ibtn sm" type="button" title="Copy IP" aria-label="Copy IP" onClick=${() => onCopy(ip)}><${Icon} name="copy" size=${14} /></button></div>
      </div>
      ${error && html`<div class="sect ip-pop-error" role="alert">${error}</div>`}
      ${!info && !error && html`<div class="sect muted">Looking up…</div>`}
      ${info && info.kind !== 'public' && html`<div class="sect muted">${kindNote(info.kind)}</div>`}
      ${info && info.kind === 'public' && html`
        <div class="sect">
          <dl class="kv">
            <dt>Location</dt>
            <dd>${place ? html`<span class="cc">${info.location.country_code}</span> ${place}`
                        : html`<span class="muted">${info.source?.available ? 'Not in the database' : 'Unknown'}</span>`}</dd>
            <dt>Network</dt>
            <dd>${network || html`<span class="muted">${info.source?.available ? 'Not in the database' : 'Unknown'}</span>`}</dd>
          </dl>
        </div>`}
      ${seen && html`
        <div class="sect">
          <div class="k">In this range</div>
          ${seen.requests === 0
            ? html`<div class="muted">No requests from this IP in the range on screen.</div>`
            : html`
              <div><b>${seen.requests.toLocaleString()} ${seen.requests === 1 ? 'request' : 'requests'}</b>${seen.errors > 0 && html`, <span class="s5">${seen.errors.toLocaleString()} ${seen.errors === 1 ? 'is' : 'are'} 5xx</span>`}</div>
              <div class="muted small">First ${stamp(seen.first_ts)}, last ${stamp(seen.last_ts)}</div>
              <div class="chips">
                ${seen.status_classes.map(c => html`
                  <button class=${'schip ' + chipClass(c.value)} type="button" key=${c.value} title=${`Show ${c.value} from ${ip}`}
                          onClick=${() => only({ key: 'status', value: c.value })}>${c.value} ${c.count.toLocaleString()}</button>`)}
              </div>`}
        </div>
        ${seen.requests > 0 && (seen.hosts.length > 0 || seen.paths.length > 0) && html`
          <div class="sect toplist">
            ${[['host', 'Top hosts', seen.hosts, seen.host_count], ['path', 'Top paths', seen.paths, seen.path_count]]
              .filter(([, , list]) => list.length)
              .map(([key, title, list, count]) => html`
                <div key=${key}>
                  <span class="k">${title}${count > list.length ? `, ${list.length} of ${count}` : ''}</span>
                  <ol>${list.map(r => html`
                    <li key=${r.value}><button class="ip-row" type="button" title=${`Show ${key}:${r.value} from ${ip}`}
                        onClick=${() => only({ key, value: r.value })}><span>${r.value}</span><span>${r.count.toLocaleString()}</span></button></li>`)}</ol>
                </div>`)}
          </div>`}`}
      <div class="sect acts">
        <button class="btn btn-primary sm" type="button" onClick=${() => only(null)}><${Icon} name="filter" size=${14} />Only this IP</button>
        <button class="btn sm" type="button" onClick=${() => onQuery(setTermState(query, 'client', ip, 'exclude'))}><${Icon} name="minus-circle" size=${14} />Exclude</button>
        <button class="btn sm btn-quiet ip-close" type="button" onClick=${() => onClose && onClose()}>Close</button>
      </div>
      ${info?.source && info.kind === 'public' && html`
        <div class="src">${info.source.available
          ? html`<a href=${info.source.url} target="_blank" rel="noopener noreferrer">${sourceLine(info.source)}</a>`
          : sourceLine(info.source)}</div>`}
    </div>`;
```

Remove `flagOf` from the `ip-info.js` import (the country code chip replaces the emoji flag; `flagOf` itself stays exported for its existing test).

- [ ] **Step 7: Explore CSS**

Delete the old rules from `/* --- Explore tab --- */` through the JSON view rules (`.jv-*`, `.stream-raw`), including `.select-inline`, `.tone-*`, `.range-pin`, `.explore-*`, `.facet-*`, `.hist-*`, `.stream-*`, `.field-*` and `.ip-pop-*`. Add `/* === explore === */` with **mockup lines 193–286 verbatim**, then apply: `.ic` → `.icon`; `.fv label` → `.fv .fv-main` (both rules); delete the `.fv input{…}` rule; replace the `.ippop{…}` rule with `.ippop{position:fixed;width:340px;padding:0;font-family:var(--sans);white-space:normal;overflow:auto;z-index:70}`; and change `.explore{…min-height:calc(100vh - var(--hdr) - 30px)}` to `min-height:calc(100vh - var(--hdr))`. Append:

```css
.fv .fv-main{border:0;background:none;color:inherit;text-align:left;font:inherit}
.fv .fv-main .icon{color:var(--ink-3)}
.fv.is-on .fv-main .icon{color:var(--accent)}
.fv-static .fv-main{cursor:default}
.facet-other{margin:2px 6px 0;font-size:var(--t-xs);color:var(--ink-3)}
.hist.loading .chart{opacity:.6}
.hist-svg{touch-action:none}
.hist-svg.dragging{cursor:ew-resize}
.hist-bar.dim{opacity:.45}
.hist-hover-band{fill:var(--ink);opacity:.06}
.hist-brush{fill:var(--accent-soft);stroke:var(--accent);stroke-width:.2}
.hist-brush-label{position:absolute;top:6px;padding:2px 8px;border-radius:var(--r-sm);background:var(--bg-3);font-size:var(--t-xs);pointer-events:none}
.hist-empty{padding:28px 0;color:var(--ink-3);font-size:var(--t-sm)}
.hist-axis{position:relative;height:20px;margin-top:6px;font-size:var(--t-xs);color:var(--ink-3)}
.hist-tick{position:absolute;top:0;white-space:nowrap;transform:translateX(-50%)}
.hist-tick[data-align="start"]{transform:none}
.hist-tick[data-align="end"]{transform:translateX(-100%)}
.stream tr.ev{cursor:pointer}
.stream td.c-dur .icon{vertical-align:-2px}
.fld{position:relative}
.fld dd.fld-act{position:relative}
.fld-note{color:var(--ink-3);font-family:var(--sans);font-size:var(--t-xs)}
.field-menu{right:0;top:calc(100% + 4px)}
.field-menu b{font-family:var(--mono);font-weight:600}
.field-menu-note{padding:8px 12px;font-size:var(--t-xs);color:var(--ink-3)}
.ip-pop-error{color:var(--crit)}
.ippop .small{font-size:var(--t-xs)}
.ippop .ip-close{margin-left:auto}
.schip{border:0;cursor:pointer}
.toplist .ip-row{display:flex;justify-content:space-between;gap:8px;width:100%;padding:2px 0;border:0;background:none;color:var(--ink-2);font:inherit;text-align:left;cursor:pointer}
.toplist .ip-row:hover{color:var(--accent)}
.live:disabled{opacity:.6;cursor:default}
.jv-key{color:var(--code-kw)} .jv-string{color:var(--code-str)} .jv-number{color:var(--code-num)} .jv-bool,.jv-null{color:var(--code-mt)}
```

- [ ] **Step 8: Run the tests and check in the browser**

Run: `for t in tests/*.test.mjs; do node "$t" || exit 1; done`
Expected: PASS (`jsonview.test.mjs` and `explore-query.test.mjs` unchanged).
Browser http://localhost:8888/explore at 1440 px, both themes:
- Every facet group header reads "N values". Every row has a visible exclude button. Excluding shows strike-through, an "excluded" tag and a pressed button, and pressing it again clears the exclusion.
- The Country facet shows names. If the dev log has no `cf_country` the group is absent; append one line with `"cf_country":"GB"` to check.
- Histogram axis labels sit inside the plot, the rightmost reads "now, HH:MM", and Tab plus the arrow keys move the readout.
- Open a 504 row: "504 Gateway timeout", "upstream timeout" beside the duration, the raw JSON is collapsed behind "Show original log line", and the Ray ID shows with a copy button if the line has `cf_ray`.
- The IP popover restyles, and Close / Esc close it.

- [ ] **Step 9: Commit**

```bash
git add src/static/js/app src/static/css/style.css tests/histogram-axis.test.mjs
git commit -m "feat(explore): visible exclude, country names, readable axis, keyboard readout, clearer event detail"
```

---

### Task 15: Editor (warnings strip with line links, find bar, panels, save-diff summary)

**Files:**
- Modify: `src/templates/index.html` (editor section and panels), `src/static/js/app/validate.js` (`showWarnings`, `hideWarnings`, `lintCurrent`, the save summary), `src/static/js/app/caddyfile.js` (lint on load, panels on view change), `src/static/js/app/panels.js` (rewrite), `src/static/js/app/backups.js` (list and preview markup), `src/static/js/app/search.js` (count class), `src/static/js/app/main.js` (Escape, imports), `src/static/js/app/caddyfile-sites.js` (`affectedSites`), `src/static/css/style.css` (editor section)
- Test: `tests/diff-summary.test.mjs` (new)

**Interfaces:**
- Consumes: `parseWarning`, `withoutFormat` (Task 11); `revealLine` (Task 13); `segmented` (Task 12); `summarizeOps` (Task 11); `sitesForLines` (Task 13); `backupLabel` (Task 10).
- Produces: `affectedSites(summary, oldText, newText): string[]` in `caddyfile-sites.js`; `lintCurrent(): Promise<void>` in `validate.js` (validates the editor content quietly and fills the strip); `closeAllPanels()` in `panels.js`. Panels are toggled with the `hidden` attribute, and their header buttons carry `aria-pressed`.

- [ ] **Step 1: Write the failing test**

Create `tests/diff-summary.test.mjs`:

```js
// The save dialog's summary: counts, line numbers and the sites a change touches.
// Run with: node tests/diff-summary.test.mjs
import assert from 'node:assert/strict';
import path from 'node:path';

const APP = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app');
globalThis.document = { createElement: () => ({}), createDocumentFragment: () => ({}), getElementById: () => ({}) };
const { summarizeOps } = await import(path.join(APP, 'diff.js'));
const { affectedSites } = await import(path.join(APP, 'caddyfile-sites.js'));

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };

check('summarizeOps numbers removed lines in the old text and added lines in the new', () => {
  const ops = [{ type: 'equal' }, { type: 'delete' }, { type: 'insert' }, { type: 'equal' }, { type: 'insert' }, { type: 'insert' }];
  assert.deepEqual(summarizeOps(ops), { added: 3, removed: 1, oldLines: [2], newLines: [2, 4, 5] });
});
check('affectedSites names each site once, from both sides of the diff', () => {
  const oldText = 'a.example.com {\n\treverse_proxy 1:1\n}\nb.example.com {\n\trespond 200\n}\n';
  const newText = 'a.example.com {\n\treverse_proxy 1:2\n}\nc.example.com {\n\trespond 200\n}\n';
  assert.deepEqual(affectedSites({ oldLines: [2, 4], newLines: [2, 4] }, oldText, newText),
    ['a.example.com', 'c.example.com', 'b.example.com']);
});
check('no site blocks touched gives an empty list', () =>
  assert.deepEqual(affectedSites({ oldLines: [1], newLines: [1] }, '{\n}\n', '{\n\tdebug\n}\n'), []));
console.log(`\n${passed} passed`);
```

- [ ] **Step 2: Run to verify it fails**

Run: `node tests/diff-summary.test.mjs`
Expected: FAIL with `affectedSites is not a function`.

- [ ] **Step 3: `affectedSites`**

Append to `src/static/js/app/caddyfile-sites.js`:

```js
/** The sites a diff touches, each named once: new text first, then the old one. */
export function affectedSites(summary, oldText, newText) {
  return [...new Set([
    ...sitesForLines(newText, summary.newLines || []),
    ...sitesForLines(oldText, summary.oldLines || []),
  ])];
}
```

- [ ] **Step 4: Editor markup**

In `src/templates/index.html`, replace the whole `<section class="tab-content editor" id="tab-editor" …>…</section>` with the block below. Then delete the old `<!-- Snippets Panel -->` and `<!-- Backups Panel -->` blocks and the empty `<!-- Audit Panel -->` / `<!-- Status Panel -->` comments that follow `</main>`.

```html
  <section class="tab-content editor" id="tab-editor" aria-label="Editor">
    <div class="ed-col">
      <ul class="warns" id="warnings" aria-label="Validation warnings" hidden></ul>
      <div class="search-bar findbar" id="search-bar" role="search" aria-label="Find and replace">
        <label class="finput"><svg class="icon" width="14" height="14" aria-hidden="true" focusable="false"><use href="#i-explore"/></svg><span class="sr">Find</span><input type="text" id="search-input" spellcheck="false" placeholder="Find"></label>
        <button class="ibtn sm" type="button" data-act="search-prev" aria-label="Previous match" title="Previous match (Shift+Enter)"><svg class="icon" width="16" height="16" aria-hidden="true" focusable="false"><use href="#i-chevron-up"/></svg></button>
        <button class="ibtn sm" type="button" data-act="search-next" aria-label="Next match" title="Next match (Enter)"><svg class="icon" width="16" height="16" aria-hidden="true" focusable="false"><use href="#i-chevron-down"/></svg></button>
        <span class="fcount match-count" id="match-count" aria-live="polite"></span>
        <label class="finput"><span class="sr">Replace with</span><input type="text" id="replace-input" spellcheck="false" placeholder="Replace"></label>
        <button class="btn sm" type="button" data-act="replace-one">Replace</button>
        <button class="btn sm" type="button" data-act="replace-all">Replace all</button>
        <button class="ibtn sm find-close" type="button" data-act="search-close" aria-label="Close find" title="Close (Esc)"><svg class="icon" width="16" height="16" aria-hidden="true" focusable="false"><use href="#i-close"/></svg></button>
      </div>
      <div class="editor-wrap" id="cm-editor"></div>
      <div class="sbar">
        <span class="msg" id="status-line" data-state="ok" role="status"><svg class="icon" width="14" height="14" aria-hidden="true" focusable="false"><use id="status-icon" href="#i-status-ok"/></svg><span class="status-msg" id="status-msg">Loading…</span></span>
        <span class="hide-sm" id="last-saved"></span>
        <span class="r"><span class="hide-sm" id="doc-stats"></span><span id="cursor-pos">Ln 1, Col 1</span></span>
      </div>
    </div>

    <aside class="panel" id="panel-snippets" hidden aria-labelledby="sn-h">
      <div class="panel-hd">
        <h2 id="sn-h">Snippets and templates</h2>
        <button class="ibtn" type="button" data-close="snippets" aria-label="Close snippets"><svg class="icon" width="16" height="16" aria-hidden="true" focusable="false"><use href="#i-close"/></svg></button>
      </div>
      <div class="panel-bd" id="snippets-list"></div>
    </aside>

    <aside class="panel" id="panel-backups" hidden aria-labelledby="bk-h">
      <div class="panel-hd">
        <button class="ibtn" type="button" id="bk-back" data-act="close-preview" aria-label="Back to backups" hidden><svg class="icon" width="16" height="16" aria-hidden="true" focusable="false"><use href="#i-chevron-left"/></svg></button>
        <h2 id="bk-h">Backups</h2>
        <button class="ibtn" type="button" data-close="backups" aria-label="Close backups"><svg class="icon" width="16" height="16" aria-hidden="true" focusable="false"><use href="#i-close"/></svg></button>
      </div>
      <div class="panel-bd" id="backups-list"></div>
      <div class="bk-preview" id="backup-preview" hidden>
        <div class="bk-head"><b id="preview-name"></b><div class="muted" id="preview-meta"></div></div>
        <div class="pv-tabs" id="preview-tabs"></div>
        <div class="pv" id="preview-content" hidden></div>
        <div class="pv diff" id="diff-content"></div>
        <div class="panel-ft">
          <p>Rolling back writes this backup to the live Caddyfile and reloads Caddy. Your current file is backed up first.</p>
          <div class="acts">
            <button class="btn btn-primary" type="button" data-act="rollback-preview"><svg class="icon" width="16" height="16" aria-hidden="true" focusable="false"><use href="#i-restore"/></svg>Roll back and reload</button>
            <button class="btn" type="button" data-act="restore-preview">Load into editor</button>
            <button class="btn btn-quiet" type="button" data-act="close-preview">Cancel</button>
          </div>
        </div>
      </div>
    </aside>
  </section>
```

- [ ] **Step 5: Panels (`panels.js` rewrite, `caddyfile.js`, `main.js`)**

Replace `src/static/js/app/panels.js` with:

```js
// Side panels (Snippets, Backups): one open at a time, toggled from the header.
import { clearPreview, loadBackups } from './backups.js';
import { editorView, fetchJson, setDot, showError } from './core.js';
import { toast } from './ui/toast.js';

const panel = (name) => document.getElementById(`panel-${name}`);
const headerButton = (name) => document.getElementById(`panel-btn-${name}`);

export function closeAllPanels() {
  document.querySelectorAll('.panel').forEach(p => { p.hidden = true; });
  document.querySelectorAll('[id^="panel-btn-"]').forEach(b => b.setAttribute('aria-pressed', 'false'));
  clearPreview();
}

export function togglePanel(name) {
  const wasOpen = !panel(name).hidden;
  closeAllPanels();
  if (wasOpen) { headerButton(name)?.focus(); return; }
  panel(name).hidden = false;
  headerButton(name)?.setAttribute('aria-pressed', 'true');
  panel(name).querySelector('[data-close]')?.focus();
  if (name === 'backups') loadBackups();
  if (name === 'snippets') loadSnippets();
}

export function closePanel(name) {
  const wasOpen = !panel(name).hidden;
  closeAllPanels();
  if (wasOpen) headerButton(name)?.focus();
}

export async function loadSnippets() {
  const list = document.getElementById('snippets-list');
  let data;
  try { data = await fetchJson('/api/snippets'); }
  catch (e) { showError(list, 'Could not load snippets', e); return; }
  list.textContent = '';
  data.snippets.forEach((s) => {
    const card = document.createElement('button');
    card.type = 'button';
    card.className = 'snip';
    const name = document.createElement('b');
    name.textContent = s.name;
    const desc = document.createElement('span');
    desc.textContent = s.description;
    card.append(name, desc);
    card.addEventListener('click', () => insertSnippet(s));
    list.appendChild(card);
  });
}

function insertSnippet(s) {
  const pos = editorView.state.selection.main.head;
  const line = editorView.state.doc.lineAt(pos).number;
  editorView.dispatch({ changes: { from: pos, insert: s.code } });
  setDot('yellow');
  closePanel('snippets');
  toast(`Inserted "${s.name}" at line ${line}`, { kind: 'ok' });
}
```

In `caddyfile.js`, add `import { closeAllPanels } from './panels.js';` and `import { lintCurrent } from './validate.js';`. In `showView`, replace the `if (view !== 'editor') { … }` block with `if (view !== 'editor') closeAllPanels();`. In `loadCaddyfile`, after `setStatus('Loaded', 'ok');` add `lintCurrent();`.

In `main.js`: change the `backups.js` import to `import { closePreview, restoreFromPreview, rollbackFromPreview } from './backups.js';` and the `panels.js` import to `import { closeAllPanels, closePanel, togglePanel } from './panels.js';`. In the Escape listener, replace the two `querySelectorAll(...)` lines and `clearPreview();` with `closeAllPanels();`. In the click delegation, drop `[data-ptab]` from the selector and delete the `if (t.dataset.ptab) …` line.

- [ ] **Step 6: Backups list and preview (`backups.js`)**

Add `import { segmented } from './ui/seg.js';` and add `el` to the `core.js` import. Replace `loadBackups`, `previewBackup`, `showPreviewTab`, `clearPreview` and `closePreview` with the code below (`restoreFromPreview` and `rollbackFromPreview` stay as in Task 11):

```js
let previewSeg = null;

export async function loadBackups() {
  const list = document.getElementById('backups-list');
  clearPreview();
  let data;
  try { data = await fetchJson('/api/backups'); }
  catch (e) { showError(list, 'Could not load backups', e); return; }
  list.textContent = '';
  if (!data.backups.length) {
    list.append(el('p', 'panel-note', 'No backups yet. One is taken before every save and restore.'));
    return;
  }
  const now = Date.now();
  data.backups.forEach((b) => {
    const label = backupLabel(b, now);
    const row = el('div', 'bk');
    const open = el('button', 'open');
    open.type = 'button';
    open.append(el('b', '', label), el('span', 'muted', b.replace('Caddyfile.', '')));
    open.addEventListener('click', () => previewBackup(b));
    const del = el('button', 'btn sm btn-danger', 'Delete');
    del.type = 'button';
    del.setAttribute('aria-label', `Delete the backup from ${label}`);
    del.addEventListener('click', async (e) => {
      e.stopPropagation();
      const ok = await confirmDialog({
        title: `Delete the backup from ${label}?`,
        body: 'The file is removed from disk and cannot be restored. Your live Caddyfile is not affected.',
        confirmLabel: 'Delete backup',
        danger: true,
      });
      if (!ok) return;
      try {
        await fetchJson(`/api/backups/${encodeURIComponent(b)}`, { method: 'DELETE' });
        toast(`Deleted the backup from ${label}`, { kind: 'ok' });
        loadBackups();
      } catch (err) { toast(`Delete failed: ${err.message}`, { kind: 'error' }); }
    });
    row.append(open, del);
    list.append(row);
  });
  list.append(el('p', 'panel-note', `The ${data.backups.length} newest backups. One is taken before every save and restore.`));
}

async function previewBackup(name) {
  let data;
  try { data = await fetchJson(`/api/backups/${encodeURIComponent(name)}`); }
  catch (e) { toast(`Could not load backup: ${e.message}`, { kind: 'error' }); return; }
  previewBackupContent = data.content; currentPreviewName = name;
  document.getElementById('backups-list').hidden = true;
  document.getElementById('backup-preview').hidden = false;
  document.getElementById('bk-back').hidden = false;
  document.getElementById('bk-h').textContent = 'Backup';
  document.getElementById('preview-name').textContent = backupLabel(name);
  document.getElementById('preview-meta').textContent = `${name.replace('Caddyfile.', '')}, ${data.content.split('\n').length} lines`;
  document.getElementById('preview-content').textContent = data.content;
  renderDiff(getContent(), data.content);
  if (!previewSeg) {
    previewSeg = segmented({
      label: 'Preview mode', value: 'diff', onChange: showPreviewTab,
      options: [{ id: 'preview', label: 'Preview' }, { id: 'diff', label: 'Diff vs editor' }],
    });
    document.getElementById('preview-tabs').append(previewSeg.el);
  }
  showPreviewTab('diff');
  document.getElementById('bk-back').focus();
}

export function showPreviewTab(tab) {
  previewSeg?.set(tab);
  document.getElementById('preview-content').hidden = tab !== 'preview';
  document.getElementById('diff-content').hidden = tab !== 'diff';
}

// Drop the preview text and rendered diff so they aren't kept in the DOM after
// the panel closes. Safe to call when nothing is open.
export function clearPreview() {
  previewBackupContent = ''; currentPreviewName = '';
  document.getElementById('preview-content').textContent = '';
  document.getElementById('diff-content').textContent = '';
  document.getElementById('backup-preview').hidden = true;
  document.getElementById('backups-list').hidden = false;
  document.getElementById('bk-back').hidden = true;
  document.getElementById('bk-h').textContent = 'Backups';
}

export function closePreview() {
  clearPreview();
  document.querySelector('#backups-list .open')?.focus();
}
```

- [ ] **Step 7: Warnings strip, lint on load, save summary (`validate.js`)**

Add the imports `import { revealLine } from './core.js';` (merge it into the existing `core.js` import), `import { iconEl } from './icons.js';`, `import { affectedSites } from './caddyfile-sites.js';`, and add `parseWarning` to the `warnings.js` import. Replace `showWarnings` and `hideWarnings` with:

```js
export function showWarnings(warnings) {
  const box = document.getElementById('warnings');
  box.textContent = '';
  for (const w of warnings || []) {
    const { line, text } = parseWarning(w);
    const li = document.createElement('li');
    li.append(iconEl('warning', { size: 16 }));
    const span = document.createElement('span');
    if (line != null) {
      const link = document.createElement('button');
      link.type = 'button';
      link.className = 'linkbtn';
      link.textContent = `Line ${line}`;
      link.addEventListener('click', () => revealLine(line));
      span.append(link, document.createTextNode(' '));
    }
    span.append(document.createTextNode(text));
    li.append(span);
    box.append(li);
  }
  box.hidden = box.children.length === 0;
}

export function hideWarnings() {
  const box = document.getElementById('warnings');
  box.textContent = '';
  box.hidden = true;
}

/** Validate the editor content quietly (on load, after a save) to fill the strip. */
export async function lintCurrent() {
  let data;
  try { data = await _validateRequest(getContent()); } catch (e) { return; }
  if (data.valid) showWarnings(data.warnings); else hideWarnings();
}
```

In `_doSave`'s `data.ok` branch, replace `hideWarnings();` with `lintCurrent();`, so warnings that are still true, such as an unresolvable upstream, stay visible. Replace `openSaveModal` with:

```js
function openSaveModal(summary, live, next) {
  const box = document.getElementById('save-diff-summary');
  box.textContent = '';
  const add = (cls, text) => { const s = document.createElement('span'); s.className = cls; s.textContent = text; box.append(s); };
  add('a', `+${summary.added} added`);
  add('d', `−${summary.removed} removed`);
  const sites = affectedSites(summary, live, next);
  if (sites.length) add('muted', `${sites.length} ${sites.length === 1 ? 'site' : 'sites'} affected: ${sites.join(', ')}`);
  saveDialog().showModal();
  saveDialog().querySelector('[data-act="confirm-save"]').focus();
  return new Promise(resolve => { _saveResolver = resolve; });
}
```

In `search.js`, `_showCount` sets `label.className = …`. Replace both assignments with `label.classList.toggle('none', <same condition as before>)` (first branch: `!!_query()`; second: `false`), so the `fcount` class survives.

- [ ] **Step 8: Editor CSS**

Delete the old rules for `.warnings`, `/* Panels */`, `/* Snippets & backups cards */` (including `.backup-row*`), `/* Search */` and `/* Diff rows … */`. Keep `/* Find bar match highlighting */` (`.cm-find-*`). Under `/* === editor === */`, before the `.sbar` rules from Task 12, add **mockup lines 290–298 verbatim** (`.warns` through `.fcount`) and, after the `.sbar` rules, **mockup lines 318–340 verbatim** (`.panel` through `.diff .lnn`). Skip lines 299–313, which are the mockup's fake code view and Vim bar; CodeMirror draws the real ones. Apply `.ic` → `.icon` and `.warns a` → `.warns .linkbtn`. Append:

```css
.linkbtn{border:0;background:none;padding:0;color:var(--accent);font:inherit;cursor:pointer;text-decoration:underline;text-decoration-style:dotted;text-underline-offset:3px}
.warns .linkbtn{font-family:var(--mono);font-size:12.5px}
.search-bar:not(.open){display:none}
.findbar .find-close{margin-left:auto}
.match-count.none{color:var(--crit)}
.bk-preview{display:flex;flex-direction:column;flex:1;min-height:0}
.bk-head{padding:12px 16px 0}
.bk-head .muted{font-size:var(--t-xs)}
.panel-note{padding:12px 16px;font-size:var(--t-xs);color:var(--ink-3)}
.panel-bd .metrics-hint{padding:12px 16px}
.diff-del{background:var(--del-bg)}
.diff-ins{background:var(--add-bg)}
.diff-meta{color:var(--ink-3)}
```

- [ ] **Step 9: Run the tests and check in the browser**

Run: `for t in tests/*.test.mjs; do node "$t" || exit 1; done`
Expected: PASS.
Browser http://localhost:8888/editor:
- Indent one line of `dev/run/Caddyfile` with four spaces, then reload. The strip shows "Line N Not formatted…" without pressing anything, and clicking "Line N" puts the cursor on that line. Check formats the file and that warning goes away.
- Find opens the bar (the header button reads pressed), the counter shows "x of y", and Esc closes it.
- Snippets: cards are buttons, and inserting one shows a toast with the line number.
- Backups: rows read "Today, 14:24" plus the raw name. Preview / Diff is a segmented control. Back returns to the list.
- Save & Reload: the dialog shows "+N added −M removed" and "K sites affected: …".

- [ ] **Step 10: Commit**

```bash
git add src/templates/index.html src/static/js/app src/static/css/style.css tests/diff-summary.test.mjs
git commit -m "feat(editor): line-linked warnings strip, restyled find bar and panels, save summary"
```

---

### Task 16: Sign-in page styling

**Files:**
- Modify: `src/static/css/style.css` (login section)
- Test: covered by `SignInPageTest` (Task 7) and `tokens.test.mjs`. This task is CSS only, so its check is the browser pass below.

**Interfaces:**
- Consumes: the markup from Task 7 and the `#i-mark` / `#i-shield` symbols from Task 11.

- [ ] **Step 1: Add the CSS**

Add `/* === login === */` with **mockup lines 362–372 verbatim**. Change `.login{min-height:calc(100vh - 30px);…}` to `min-height:100vh`, and apply `.ic` → `.icon`. Append:

```css
.login-card p .mono{color:var(--ink)}
.cf .muted{font-size:var(--t-sm)}
.login .gbtn svg{flex:none}
```

- [ ] **Step 2: Check both variants in the browser**

Run the app locally on loopback in Google mode (this reaches nothing beyond the machine; `/welcome` renders without contacting Google):

```bash
mkdir -p /tmp/cc-login/backups && printf ':80 {\n\trespond 200\n}\n' > /tmp/cc-login/Caddyfile
AUTH_MODE=google GOOGLE_CLIENT_ID=x GOOGLE_CLIENT_SECRET=y \
SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
SERVER_URL=http://localhost:9099 SESSION_COOKIE_SECURE=false GEOIP_AUTO_UPDATE=false \
BACKUP_DIR=/tmp/cc-login/backups CADDYFILE_PATH=/tmp/cc-login/Caddyfile AUDIT_LOG=/tmp/cc-login/backups/audit.log \
uv run --frozen flask --app app run --host 127.0.0.1 --port 9099
```

Open http://localhost:9099/welcome at 1440 and 390 px in both themes. You should see the brand mark, "Sign in to Caddy Console", "Manage the Caddy server at localhost: …", a full-width primary "Sign in with Google", and the allowed-list hint. Stop it, then rerun with `AUTH_MODE=cloudflare UNSAFE_ALLOW_UNVERIFIED_CF_HEADER=true ALLOWED_EMAILS=dev@local` (drop the Google variables) and open http://localhost:9099/. The page shows the "Protected by Cloudflare Access" block and "Reload after signing in", with HTTP 403. Stop the server and `rm -rf /tmp/cc-login`.

- [ ] **Step 3: Commit**

```bash
git add src/static/css/style.css
git commit -m "feat(login): on-system sign-in page"
```

---

### Task 17: Responsive breakpoints (1024 px and 720 px)

**Files:**
- Modify: `src/static/css/style.css` (responsive section, at the very end)
- Test: `tests/tokens.test.mjs` (variables). Layout is checked in the browser.

- [ ] **Step 1: Add the media queries**

Append `/* === responsive === */` and **mockup lines 373–459 verbatim** (the `1100px`, `1024px` and `720px` blocks and `prefers-reduced-motion`), then make these edits to the copied text:
- `.ic` → `.icon` everywhere (for example `.tabs a .ic` → `.tabs a .icon`, `.acct-btn>.ic` → `.acct-btn>.icon`).
- `.panel{position:fixed;z-index:58;top:calc(var(--hdr) + 30px);…}` → `top:var(--hdr)`.
- `.editor{height:calc(100vh - var(--hdr) - 30px - 62px)}` → `height:calc(100vh - var(--hdr) - 62px)`.
- Delete `.mock span{display:none}`.
- `.etools #btn-check{display:none}` → `.etools [data-act="validate"]{display:none}`.
- `#find-close,#find-prev,#find-next,#find-count{order:1}` → `.findbar .find-close,.findbar [data-act="search-prev"],.findbar [data-act="search-next"],.findbar .fcount{order:1}`.
- `#find-close{margin-left:0!important}` → `.findbar .find-close{margin-left:0!important}`.

Then add inside the `720px` block:

```css
  .toasts{bottom:76px;left:12px;right:12px;transform:none}
  .ippop{left:0!important;right:0;top:auto!important;bottom:0;width:auto;max-height:78vh!important}
```

(The first places toasts above the bottom tab bar. The second overrides the popover's inline `top`/`left` so it becomes a bottom sheet.)

- [ ] **Step 2: Check in the browser**

At 1024 px: Explore facets are behind "Filters (n)" in a drawer with a scrim, and Esc and the close button both close it. The Snippets and Backups panels overlay the editor. The editor tool labels collapse to icons, each with a tooltip.
At 390 px: the tabs are a bottom bar, Sites and stream rows are stacked, and the account menu, IP popover and panels are bottom sheets. The find bar wraps. No horizontal scroll on any view (`document.documentElement.scrollWidth <= innerWidth` in the console).

- [ ] **Step 3: Commit**

```bash
git add src/static/css/style.css
git commit -m "feat(ui): responsive layout at 1024 and 720 px"
```

---

## Part 4: Verification

### Task 18: Bundles, full test run, impeccable, browser pass, screenshots

**Files:**
- Modify: `docs/screenshots/dashboard.png`, `explore.png`, `event-detail.png`, `editor.png` (regenerated)
- Possibly modify: any file a check below finds wrong (fix it in place, and note the fix in the commit body)

- [ ] **Step 1: Bundles are unchanged**

Run: `npm run build && git diff --exit-code -- src/static/js/`
Expected: exit 0. No bundle input changed; the app modules are served unbundled. A diff here means a dependency drifted, so investigate before going on.

- [ ] **Step 2: Every test**

Run: `uv run --frozen python -m unittest discover -s tests -t . && for t in tests/*.test.mjs; do node "$t" || exit 1; done`
Expected: all PASS.

- [ ] **Step 3: No native dialogs, no inline handlers, no unsafe-inline**

Run:
```bash
node tests/no-native-dialogs.test.mjs
grep -rnE "\son[a-z]+=\"" src/templates/ && echo "inline handler found" || echo "no inline handlers"
curl -sI -H 'Cf-Access-Authenticated-User-Email: dev@local' http://localhost:8888/ | grep -i content-security-policy
```
Expected: the test passes, "no inline handlers", and the CSP shows `script-src 'self' 'sha256-…'` with no `unsafe-inline` in `script-src`. (The dev front proxy injects the identity header itself; the header on curl is harmless.)

- [ ] **Step 4: impeccable detector**

Run, with the dev stack up:
```bash
IMP='/Users/mocepetr/.claude/plugins/cache/impeccable/impeccable/4.5.2/skills/impeccable/scripts/impeccable'
"$IMP" detect http://localhost:8888/
"$IMP" detect 'http://localhost:8888/explore?range=1h'
"$IMP" detect http://localhost:8888/editor
"$IMP" detect src/templates/welcome.html
"$IMP" detect src/static/css/style.css
```
Expected: no findings, or only findings that are deliberate and copied from the approved mockup. Fix real findings. List any that are kept, with the reason, in the commit body of Step 7.

- [ ] **Step 5: Browser pass (use a browser tool for screenshots)**

Seed traffic first: `python3 dev/seed-logs.py | docker compose -f docker-compose.dev.yaml exec -T caddy-target sh -c 'cat >> /var/log/caddy/access.log'`.

For each viewport **1440×900, 1024×768, 390×844** and each theme (**Dark**, **Light**, set from the account menu), check:

1. **Dashboard**:
   - The verdict is first and gives severity as icon plus words.
   - The config card reads "Changed … ago by …". "by" appears only after a save made through the console.
   - The figures sit unboxed, and their sub-lines appear only when they have data.
   - The notice has "How to fix" and "Dismiss", and Undo works.
   - Sites show health icon plus word, "high"/"slow" tags, and sparklines. At 390 px the rows are stacked.
   - Recent changes show verbs and relative times.
   - The footer counts events.
2. **Explore**:
   - Facets show "N values", visible exclude buttons, and the excluded state (strike, tag, pressed).
   - The query bar has a range chip after drag-to-zoom, the range select, and Live.
   - The histogram axis labels are not clipped and "now" is at the right edge. Keyboard-only: Tab to the chart, arrow keys move the readout.
   - The stats line reads correctly.
   - An expanded 504 row shows "Gateway timeout", "upstream timeout", the country name, the Ray ID with copy (when present), and raw JSON collapsed.
   - The IP popover is a bottom sheet at 390 px.
3. **Editor**:
   - The status bar shows only here.
   - Find, Snippets and Backups toggle with a pressed state.
   - The save-diff dialog shows the summary and the sites affected.
   - The backup preview offers Preview / Diff vs editor, and rollback uses a red confirm.
   - The Vim keymap shows its bar and the extra shortcuts.
   - Save & Reload reads "No changes" and is disabled when the editor is clean.
4. **Account menu**: Theme System / Dark / Light, Editor keys, shortcuts, Log out and the version. Keyboard: Esc closes it and returns focus.
5. **Sign-in page**: both variants, as in Task 16.
6. **Keyboard-only pass** over the whole app: every control is reachable, focus rings are visible, and no action needs hover.

Error states (trigger each in the dev stack; restore with `./dev/run.sh reset` when done):

| State | How to trigger | Expected |
|---|---|---|
| Invalid Caddyfile on save | In the Editor, add `\tthisisnotadirective` inside a site block, then Save & Reload | "Cannot save: the config is invalid" dialog with Caddy's message in monospace; nothing written |
| Save conflict | Edit in the Editor (do not save), then run `printf '\n# edited behind the editor\n' >> dev/run/Caddyfile`, then Save & Reload and confirm the diff | "The Caddyfile changed on disk" dialog. "Keep my edits" keeps them; "Reload the latest version" replaces them and shows a toast |
| Caddy admin API down | `docker compose -f docker-compose.dev.yaml stop caddy-target`, wait 15 s on the Dashboard | Verdict "Caddy is not answering the console". In the Editor, Save shows a warning toast about the failed reload. Then `docker compose -f docker-compose.dev.yaml start caddy-target` |
| Unhealthy upstream | Already true in the seed: `photos.example.com` dials `127.0.0.1:2283` with `health_uri` | Verdict "photos.example.com is down … has failed since HH:MM". The time stays the same after a page reload and after `docker compose -f docker-compose.dev.yaml restart caddy-console` (the state is in `dev/run/backups/upstream-health.json`) |
| Empty access log | `docker compose -f docker-compose.dev.yaml exec caddy-target sh -c ': > /var/log/caddy/access.log'` | Dashboard: "No requests in the last hour"; no "+n%" line; no notice. Explore: "No requests in this range …". Re-seed afterwards |
| Restore failure | `printf 'this is not a caddyfile {\n' > dev/run/backups/Caddyfile.20260101-000000`, then Backups → that row → Roll back and reload → confirm | "Restore failed" dialog: "The live Caddyfile was not changed" plus Caddy's message. Then delete that backup from the panel |
| Unresolvable upstream warning | In a site block add `\treverse_proxy nosuchhost.invalid:8080`, then Check | The strip shows "Line N Upstream nosuchhost.invalid:8080 could not be resolved from the console container"; the line link jumps; Save asks "Save with 1 warning?" |
| Unformatted-file warning | `sed -i '' 's/^\treverse_proxy 127.0.0.1:8096/    reverse_proxy 127.0.0.1:8096/' dev/run/Caddyfile` (GNU sed: drop the `''`), then reload /editor | The strip shows "Line N Not formatted — Check will fix whitespace on 1 line" without pressing anything. Save shows no warnings question. Check formats the file and clears the warning |

Fix anything that fails, re-run Step 2, and commit each fix separately (`fix(ui): …`).

- [ ] **Step 6: Regenerate the screenshots**

With seeded traffic, dark theme, 1440×900, capture:
- `docs/screenshots/dashboard.png`: `/`.
- `docs/screenshots/explore.png`: `/explore?range=1h`.
- `docs/screenshots/event-detail.png`: Explore with a 5xx row expanded and the IP popover open.
- `docs/screenshots/editor.png`: `/editor` with the find bar open and the Backups panel showing a preview.

The README references these four names, so keep them.

- [ ] **Step 7: Commit**

```bash
git add docs/screenshots
git commit -m "docs(screenshots): regenerate for Direction A"
```

---

## Self-review notes (for the executor)

- Spec coverage map: §1 tokens → Task 8, themes → Tasks 6 and 9, shared components → Tasks 11 and 12, breakpoints → Task 17, new modules → Tasks 9–11. §2 table: rows map 1:1 to Tasks 1, 2, 2, 3, 4, 5 and 7. §3 Header → 12, Dashboard → 13, Explore → 14, Editor → 15, Login → 7 and 16. §4 error handling → hidden-when-null in `dashboard-model.js` and `explore.js`, corrupt state file in Task 2, DNS timeouts in Task 5, blocked storage in Task 9. §5 testing → the tests in each task plus Task 18.
- Names used across tasks: `confirmDialog`/`alertDialog` (11), `toast` (11), `segmented` (12), `revealLine`/`revealSite` (13), `withoutFormat`/`parseWarning` (11), `summarizeOps` (11), `affectedSites` (15), `lintCurrent` (15), `closeAllPanels` (15), `applyEditorTheme` (9), `upstream_health.record` (2), `audit.last_change` (3), `validator.fmt_warning` / `upstream_resolve_warnings` (4, 5), `theme_boot.THEME_BOOT_JS` / `THEME_BOOT_HASH` (6).
- Decisions this plan takes where the spec is silent or the code disagrees (raise them in review if any is wrong):
  1. `previous_total` is computed only from events already in memory, as the spec says. The dashboard asks for 1 h, so on a fresh worker the cache holds only that hour and the "+n% vs previous hour" line stays hidden. It appears once some request on that worker (for example Explore at 6 h) has loaded a wider window. Showing it reliably would mean loading twice the window, which is one changed line in `/api/sites` and a deliberate spec change.
  2. `/api/upstreams` did not know health; that came only from `/api/traffic` (Prometheus). To record `unhealthy_since` it now also fetches `/metrics`, so each dashboard poll makes one more admin API call.
  3. Check applies `caddy fmt` immediately, so the "not formatted" warning would never be seen after Check. The editor therefore validates quietly on load and after each save (`lintCurrent`) to fill the strip, and Save does not ask about that one warning.
  4. Cloudflare mode had no sign-in page (plain-text 403; `/welcome` redirects). The Cloudflare variant is now the 403 body for page requests.
  5. The Ray ID exists only in the raw log line, so opening a row fetches that line (one request per expand) while keeping the JSON collapsed.
  6. Mockup details with no source data stay hidden rather than faked: backup "Before save by … / 58 lines", audit "58 lines, +2 −2". Facet "N values" shows `N+` when the backend reports events in values beyond its top list, because it returns no distinct count.
  7. The verdict gains three states the spec does not list, ordered by severity: admin API unreachable, config check failed, and high 5xx rate (≥10 % with at least 5 errors). Without them a broken Caddy would read "All 7 sites are serving".
  8. `configured_sites` counts distinct host matchers, so a block with two hostnames counts as two.
  9. The header uses the mockup's brand mark. `static/img/favicon.svg` and the touch icons are not changed.
  10. At ≤720 px the mockup hides Check; this plan keeps that. Save & Reload still validates first.
