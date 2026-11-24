# IP Bans Phase 3 (CrowdSec Plugin) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An operator who adds `docker-compose.crowdsec-plugin.yaml` on top of the CrowdSec overlay gets a pinned, scanned custom Caddy image that enforces CrowdSec decisions per site without a reload, behind a generated `protect_crowdsec` route that never lets a protected address reach the plugin, with the Caddy admin API provably unreachable from CrowdSec and cloudflared, while manual bans keep file mode and every baseline stack stays exactly as it is.

**Architecture:** CI builds `ghcr.io/viralone/caddy-crowdsec` and `ghcr.io/viralone/caddy-crowdsec-cloudflare` from committed `go.mod`/`go.sum` main packages (stock Caddy 2.11.9 plus `github.com/hslatman/caddy-crowdsec-bouncer/http`, and `caddy-dns/cloudflare` for the second) compiled with the pinned `caddy:2.11.9-builder` toolchain onto the pinned `caddy:2.11.9-alpine` base. The image's entrypoint is a small stdlib-only Go preflight that adapts the Caddyfile and refuses to start Caddy unless the admin API is bound to the fixed `caddy-admin` address with origins and the bouncer key is a placeholder that matches the configured secret mode. The console renders `BANS_DIR/crowdsec-plugin-protect.caddy` (the `(protect_crowdsec)` snippet with the complete protected set) through the Phase 1 journaled transaction, recording its hash in `BACKUP_DIR/plugin-policy.json`; detection walks live JSON for `http.handlers.crowdsec` per site, and the Security view and editor offer three scoped snippets only when the running build has the module, the admin bind is safe and the prerequisites are live.

**Tech Stack:** Python 3 / Flask / gunicorn, stdlib only, `unittest`; Preact + htm (committed `explore-vendor.js`), plain ES modules, node `assert` scripts; Go 1.27.4 from `caddy:2.11.9-builder` (preflight: standard library only); `github.com/hslatman/caddy-crowdsec-bouncer` v0.15.0, `github.com/caddy-dns/cloudflare` v0.2.4; Docker Compose; GitHub Actions (SHA-pinned), `anchore/sbom-action`, `anchore/scan-action`.

**Spec:** `docs/superpowers/specs/2026-11-23-ip-bans-design.md` (binding). This plan covers "Phase 3: optional caddy-crowdsec-bouncer plugin" (3.1-3.6), the Phase 3 rows of "Mode detection and health" (CrowdSec plugin enforced; a global app without a per-site handler is not enforcement), the Phase 3 rows of "Configuration" (`CROWDSEC_PLUGIN_BOUNCER_KEY`, `CROWDSEC_PLUGIN_BOUNCER_KEY_FILE`, `CADDY_ADMIN_ADDRESS`), "Testing" ("Run the optional plugin overlay" and plugin snippet adaptation in both secret modes), the "Phase 3 gate", and the plugin section of `docs/security.md`. Task 0 fixes four Phase 2 defects found in review. The Phase 1 and Phase 2 plans (`docs/superpowers/plans/2026-11-24-ip-bans-phase1.md`, `...-phase2.md`) describe the code this plan extends. Phase 4 is out of scope.

## Global Constraints

- English everywhere (UI copy, comments, docs, commit messages).
- No new runtime dependencies: `pyproject.toml` `dependencies` and `package.json` stay unchanged. `npm run build` must leave `git diff -- src/static/js/` empty. The Go preflight uses the standard library only (its `go.mod` has no `require`).
- No native `alert()`/`confirm()`/`prompt()` (`tests/no-native-dialogs.test.mjs`); confirmations use `src/static/js/app/ui/dialog.js`.
- Text from records, LAPI, Caddy or API responses is rendered only as text nodes (Preact text children or `textContent`). No `innerHTML`, `outerHTML`, `insertAdjacentHTML` or `dangerouslySetInnerHTML` in new or touched files.
- Commits use the already configured git identity. Never run `git config`. One commit per task with the message given in the task.
- Documentation, fixtures and tests use `example.com` hostnames and documentation addresses only (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) plus the private Docker subnets named below. Nothing personal.
- Baseline Compose files (`docker-compose.{prod,internal,tunnel,nas,dev}.yaml`) are not changed. Plugin mode lives only in `docker-compose.crowdsec-plugin.yaml` and its NAS companion `docker-compose.nas.crowdsec-plugin.yaml`; both are used together with the Phase 2 CrowdSec overlay. `dev/check-compose.sh` keeps failing if a baseline file mentions CrowdSec.
- CrowdSec port 8080 is never published. CrowdSec and cloudflared never join `caddy-admin`. Caddy joins `crowdsec-lapi` only in plugin mode.
- Fixed admin address in every plugin variant: Caddy is `172.30.250.2` on `caddy-admin` (subnet `172.30.250.0/29`, `internal: true`), the same address the tunnel stack already uses. Caddyfile bind: `admin 172.30.250.2:2019 { origins caddy:2019 172.30.250.2:2019 }`. `CADDY_ADMIN_ADDRESS=172.30.250.2:2019` is set on both Caddy and the console; the console's `CADDY_API_URL` becomes `http://172.30.250.2:2019`; the Caddy health check uses the same address.
- Bouncer identities: the console keeps `caddy_console` with `CROWDSEC_CONSOLE_BOUNCER_KEY`; the plugin is `caddy_plugin` with `CROWDSEC_PLUGIN_BOUNCER_KEY` (environment form) or the Docker secret `/run/secrets/crowdsec_plugin_bouncer_key` named by `CROWDSEC_PLUGIN_BOUNCER_KEY_FILE` (file form). The console never receives the plugin key, only the file path. The two keys must differ; the overlay check and the integration test assert it.
- The plugin key is never logged, never printed by the preflight, never placed in the Caddyfile literally (it would appear in Caddy's `/config/`), never returned by the console API. The Caddyfile carries only `{env.CROWDSEC_PLUGIN_BOUNCER_KEY}` or `{file.<path>}`, which the pinned plugin resolves at provision time with Caddy's global replacer (verified: `crowdsec/crowdsec.go` `repl.ReplaceKnown(c.APIKey, "")` on `caddy.NewReplacer()`, which includes `fileReplacementProvider`; Caddy trims one trailing `\n` and `\r`).
- Plugin Caddyfile, exactly: global `crowdsec { api_url http://crowdsec:8080 / api_key <placeholder> / ticker_interval 10s }` plus `order crowdsec first`. Stream mode stays on (no `disable_streaming`); `enable_hard_fails` stays off (the plugin default), so a LAPI outage keeps the last in-memory decisions.
- Pinned images (multi-arch index digests read with `docker buildx imagetools inspect`): builder `caddy:2.11.9-builder@sha256:cda07fe9d82728c7ac44d844306d435e98131423dc7b114f05a8a8ecfff94707` (Go 1.27.4, `GOTOOLCHAIN=local`), base `caddy:2.11.9-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0`, CrowdSec as in Phase 2.
- Plugin image tags: `2.11.9-crowdsec-0.15.0` and `sha-<short commit>`; pushed to GHCR only on `push` to `master` (the condition the existing `build-and-push` job uses), after every test job passed. Pull requests build, scan and test without any secret.
- GitHub Actions are pinned by commit SHA with the version in a comment, as in `.github/workflows/docker-publish.yml`.
- `BANS_ENABLED=false` disables plugin support in the console too: no plugin status, no plugin snippets, no protect file.
- Lock order is unchanged (Phase 2): `bans-sync.lock`, then `caddyfile_lock()`. The module probe and every admin API read happen outside `caddyfile_lock()` except the existing availability probe.
- Test commands (CI uses `unittest`, not pytest): `uv run --frozen python -m unittest discover -s tests -t .` and `for t in tests/*.test.mjs; do node "$t" || exit 1; done`. One module: `uv run --frozen python -m unittest tests.test_plugin_settings -v`. Go: `./dev/plugin-go.sh test` (Task 1).

## Review Focus

1. **The operator starts the plugin overlay but the Caddyfile still says `admin 0.0.0.0:2019`** (or has no `admin` line, which means `localhost:2019`). Caddy must not start listening at all while it is attached to `crowdsec-lapi`: the preflight exits non-zero with a message naming the required bind, and a later Save in the editor that puts the wildcard back is refused before `/load`. Pinned by `TestWildcardAndLoopbackAdminAreRefused` (Task 1) and `test_save_refuses_an_admin_bind_other_than_the_fixed_one` (Task 6).
2. **The bouncer key is typed literally into the global `crowdsec` block** (`api_key 3f9a...`). It would be visible to anyone who can read Caddy's `/config/`. The preflight refuses it, the validator warns, and Security reports "key written into the Caddyfile" without ever echoing the value. Pinned by `TestLiteralKeyIsRefusedWithoutEchoingIt` (Task 1) and `test_live_literal_key_is_reported_without_the_key` (Task 3).
3. **A manual ban from a new verified console address** adds that address to `management_addresses`. The protected route definition must change in the same journaled transaction as `bans-manual.caddy`, or the plugin could ban the operator's own address. Pinned by `test_manual_ban_regenerates_the_plugin_route_in_the_same_transaction` (Task 4).
4. **A site uses the bare `crowdsec` directive instead of `import protect_crowdsec`.** The plugin then runs for private, Docker and `BANS_NEVER` addresses. Security marks the site "Plugin runs without the protected ranges" (critical), the validator warns, and the manual-ban detection does not mistake the handler for an application pre-handler. Pinned by `test_bare_handler_is_plugin_unprotected` and `test_plugin_route_is_not_a_pre_handler_for_manual_bans` (Task 5) and `test_bare_crowdsec_directive_warns` (Task 6).
5. **The key secret file was written with `echo key > file`** (trailing newline), or is mounted at a different path than `CROWDSEC_PLUGIN_BOUNCER_KEY_FILE`. The newline case must work (Caddy trims it); the path mismatch must stop Caddy before launch with a message naming both paths and never the content. Pinned by `TestKeyFileMismatchIsRefused` (Task 1) and step 7 of `dev/crowdsec-plugin-it.sh` (Task 10), whose secret file ends in `\n` and which starts Caddy with a mismatched path and placeholder.

---

## Verified facts this plan relies on

Checked against source, not memory (clone of `hslatman/caddy-crowdsec-bouncer` at tag `v0.15.0`, commit `4a6ce1d3094dbfd270fecf2a91aaab81663d0cb4`, 2026-10-30; Caddy `v2.11.9`):

- Module path `github.com/hslatman/caddy-crowdsec-bouncer/http` registers `http.handlers.crowdsec` and the handler directive `crowdsec` (no default order: the Caddyfile needs `order crowdsec first`). Importing it also pulls in `http.handlers.appsec`; the `crowdsec` app and `admin.api.crowdsec` come from its `crowdsec` package. Expected non-standard modules: `admin.api.crowdsec`, `crowdsec`, `http.handlers.appsec`, `http.handlers.crowdsec` (plus `dns.providers.cloudflare` in the Cloudflare variant).
- v0.15.0's `go.mod` requires Caddy v2.11.7 and `go 1.26.1`; a main module requiring Caddy v2.11.9 selects v2.11.9 (minimal version selection), and the builder's Go 1.27.4 satisfies `go 1.26.1`.
- The handler takes the client address from `caddyhttp.GetVar(ctx, caddyhttp.ClientIPVarKey)` (`internal/httputils/http.go` `determineIPFromRequest`), which is Caddy's resolved `client_ip` after `trusted_proxies`, not `RemoteAddr` and not a raw `X-Forwarded-For`.
- Global options: `api_url`, `api_key`, `ticker_interval` (default `60s`), `disable_streaming` (streaming is the default), `enable_hard_fails` (default off), `lapi_timeout`, `metrics_interval` (default `0s`, off), `appsec_*`. The stream bouncer pulls `/v1/decisions/stream` with `community_pull` and `additional_pull` query flags.
- `caddy list-modules --json --skip-standard` prints a JSON array of `{module_name, module_type, version, package_url}`.
- `caddy-dns/cloudflare` latest tag is `v0.2.4`.
- CrowdSec centralized allowlists (`cscli allowlists create|add`, CrowdSec ≥ 1.6.8) drop new local alerts, block `cscli decisions add` and filter blocklist pulls, but do not remove existing decisions: they are defense in depth only, exactly as the spec says.

Design decisions that follow from these facts:

- **`go build` from committed `go.mod`/`go.sum` instead of `xcaddy build --with`.** xcaddy resolves the rest of the dependency graph at build time and has no lockfile, so two builds of the same `--with` line can differ and Dependabot cannot see the versions. Each variant is a three-line `main.go` (what xcaddy generates internally) whose `go.sum` pins every transitive module; Dependabot's `gomod` ecosystem tracks both directories and its `docker` ecosystem tracks the literal `FROM` lines. The pinned `caddy:2.11.9-builder` image is still the toolchain.
- **The fixed-admin and secret-mode checks run in the image's entrypoint**, before `caddy run`, because Docker attaches `crowdsec-lapi` before the process starts: a check after start would already be too late.
- **The protected route definition carries a `vars caddy_console_plugin_protect 1` marker**, like the file policies, so live JSON shows which sites imported it and the Phase 1 reload-need rule works unchanged.
- **The Phase 3 overlay registers the plugin bouncer** (`BOUNCER_KEY_caddy_plugin` on the `crowdsec` service) rather than the Phase 2 overlay, so file-sync-only deployments never need a plugin key.

## File Structure

**Image (new, `caddy-plugin/`):**
- `caddy-plugin/Dockerfile`: builder stage (preflight test and build, Caddy build, `list-modules` record) and final stage on the pinned base.
- `caddy-plugin/crowdsec/{go.mod,go.sum,main.go}` and `caddy-plugin/crowdsec-cloudflare/{go.mod,go.sum,main.go}`: the two Caddy builds.
- `caddy-plugin/preflight/{go.mod,main.go,check.go,check_test.go}`: the entrypoint preflight.
- `dev/plugin-go.sh`: runs `go` inside the pinned builder image (`tidy`, `test`); `dev/build-plugin-image.sh`: local build of one variant plus the module check; `dev/check-plugin-modules.py`: asserts the non-standard module set.

**Backend (new):** `src/bans/plugin.py` (settings, module probe, admin exposure, live app summary, snippet context, allowlist command), `src/bans/pluginpolicy.py` (`BACKUP_DIR/plugin-policy.json`).

**Backend (modified):** `src/bans/lapi.py`, `src/bans/sync.py`, `src/bans/syncstate.py` (Task 0); `src/config.py` (Phase 3 rows); `src/bans/render.py` (protected route definition); `src/bans/service.py` (plugin source in holds, candidates, re-apply, expiry, status, site rows); `src/bans/detect.py` (plugin detection, crowdsec handler is not a pre-handler); `src/bans/scan.py` (snippet-name imports, plugin warnings); `src/routes/editor.py` (plugin snippets and context, warnings, save guard); `src/snippets.json` (five plugin snippets).

**Frontend (new):** `src/static/js/app/security-plugin.js` (plugin section of the Security view).

**Frontend (modified):** `security-model.js`, `security.js`, `snippet-insert.js`, `panels.js`.

**Compose and checks (new):** `docker-compose.crowdsec-plugin.yaml`, `docker-compose.nas.crowdsec-plugin.yaml`, `dev/check-plugin-overlay.py`, `crowdsec/check-plugin-isolation.sh` (operator deployment check, shipped).

**Tests (new):** `tests/test_plugin_settings.py`, `tests/test_plugin_policy.py`, `tests/test_plugin_status.py`, `tests/test_plugin_snippets.py`, `tests/fixtures/plugin/{base,env,file}.Caddyfile`, `tests/fixtures/plugin/crowdsec-plugin-protect.caddy`, `tests/fixtures/bans/adapted-plugin-layouts.json` (generated), `tests/integration/make_plugin_fixtures.sh`, `tests/integration/fake_lapi.py`, `tests/integration/plugin_it.py`, `tests/integration/plugin/compose.yaml`, `tests/integration/plugin/compose.file-secret.yaml`, `dev/crowdsec-plugin-it.sh`, `dev/adapt-plugin-snippets.sh`.

**Tests (modified):** `tests/_bans.py` (FakeCaddy plugin module and admin; reset removes `plugin-policy.json`), `tests/test_crowdsec_lapi.py`, `tests/test_crowdsec_sync.py`, `tests/security-model.test.mjs`, `tests/snippet-insert.test.mjs`.

**Ops/docs:** `dev/check-compose.sh`, `dev/check-crowdsec-overlay.py` (`--plugin`), `.github/workflows/docker-publish.yml`, `.github/dependabot.yml`, `docs/security.md`, `docs/setup.md`, `docs/development.md`.

---

### Task 0: Phase 2 follow-ups

Four defects found in the Phase 2 review:

(a) `lapi._abort()` (`src/bans/lapi.py:251-268`, called from `fetch_stream` at `:299-304`) calls `resp.close()` on the caller thread after trying to shut the socket down through private attributes. When neither attribute path exists (another urllib3 version, a TLS socket wrapper), `close()` reaches `BufferedReader.close()`, which blocks on the lock the worker's in-progress `read()` holds, so the caller blocks past `READ_DEADLINE` and the sync leader hangs with it. Fix: `_abort` only shuts the socket down; the worker's `finally: resp.close()` (already at `:247-248`) closes the response once its read returns.

(b) A poll can take up to `READ_DEADLINE` (60 s) before `step()` writes the status file, while `service._crowdsec_status` calls the report stale after `STALE_POLLS × CROWDSEC_POLL_INTERVAL + BANS_SYNC_INTERVAL` seconds (25 s at the minimums 5 and 10). A slow LAPI therefore shows "out of date" instead of "unreachable". **Chosen fix: derive the deadline from the window.** The longest gap between two status writes is one poll wait plus one fetch, so the deadline is `min(60, 2 × poll + sync − 5)` seconds (15 s at the minimums, 45 s at the defaults), and `step()` also writes the report right after a successful merge, before the coalesced apply, so a slow Caddy reload never widens the gap either. A status write before every fetch alone would not be enough: the fetch itself would still outlast the window.

(c) A non-`RequestException` raised inside the worker (for example `requests.get` raising `ValueError` or `LocationParseError` on a malformed URL, or anything from a urllib3 internals change) leaves `box` without `"error"` or `"body"`, and `fetch_stream` raises `KeyError('body')`, which `Synchronizer.step()` does not catch. It must surface as `LapiUnavailable` naming only the exception type.

(d) Between a delta poll that adds a decision and the next coalesced apply (up to `BANS_SYNC_INTERVAL`), Security says "1 active decision synced" while the decision table is empty. `last_apply_at < last_success_at` is true after almost every poll (polls run every 10 s, applies at most every 30 s), so it cannot tell "applied" from "waiting". Instead the synchronizer records `pending_apply`: true when the accepted set changed since the last successful apply. The model then says "1 decision synced, applying…".

**Files:**
- Modify: `src/bans/lapi.py` (`_request`, `_abort`, `fetch_stream`, new `read_deadline`)
- Modify: `src/bans/sync.py` (`step`, `_merge`, `_maybe_apply`, `_write`)
- Modify: `src/bans/syncstate.py` (`FIELDS`)
- Modify: `src/static/js/app/security-model.js` (`crowdsecState`)
- Test: `tests/test_crowdsec_lapi.py`, `tests/test_crowdsec_sync.py`, `tests/security-model.test.mjs`

**Interfaces:**
- Produces: `lapi.read_deadline() -> float` (seconds; tests patch it instead of `lapi.READ_DEADLINE`, which becomes `READ_DEADLINE_MAX = 60`); `lapi.DEADLINE_MARGIN = 5`; status-file field `pending_apply: bool`; `Synchronizer.pending_apply`.

- [ ] **Step 1: Update the existing deadline tests to the new seam**

In `tests/test_crowdsec_lapi.py`, replace every `mock.patch.object(lapi, "READ_DEADLINE", X)` (three places: `test_slow_drip_body_hits_the_total_deadline`, `test_hung_request_is_bounded_and_never_piles_up_threads`, `RealSocketDeadlineTest.test_slow_drip_over_a_real_socket`) with `mock.patch.object(lapi, "read_deadline", lambda: X)`, keeping each `X`.

`test_slow_drip_body_hits_the_total_deadline` relied on `_abort` calling `close()`. Change its fake so the watchdog wakes it through a socket shutdown instead, and close stays the worker's job:

```python
    def test_slow_drip_body_hits_the_total_deadline(self):
        # One byte, then a read that blocks until the watchdog shuts the socket
        # down: no single blocking call may outlast the deadline.
        class Sock:
            def __init__(self, woken):
                self.woken = woken

            def shutdown(self, how):
                self.woken.set()

        class Drip(_crowdsec.FakeStreamResponse):
            def __init__(self):
                super().__init__()
                self.woken = threading.Event()
                self.raw = type("Raw", (), {})()
                self.raw._connection = type("Conn", (), {})()
                self.raw._connection.sock = Sock(self.woken)

            def iter_content(self, chunk_size=1):
                yield b" "
                if not self.woken.wait(10):
                    return
                raise requests.ConnectionError("shut down by the watchdog")

        resp = Drip()
        self.lapi.mode, self.lapi.response = "response", resp
        started = time.monotonic()
        with mock.patch.object(lapi, "read_deadline", lambda: 0.3), self.assertRaises(lapi.LapiUnavailable) as cm:
            lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=ORIGINS)
        self.assertLess(time.monotonic() - started, 2)
        self.assertIn("took too long", str(cm.exception))
        self.assertNotIn(_crowdsec.KEY, str(cm.exception))
        self.assertTrue(_worker_gone(), "the request thread must end once the socket is shut down")
        self.assertTrue(resp.closed, "the worker closes the response after its read returns")
```

- [ ] **Step 2: Write the failing LAPI tests**

Append to `FetchTest` in `tests/test_crowdsec_lapi.py`:

```python
    def test_deadline_returns_even_when_the_socket_cannot_be_found(self):
        # (a) No private attribute path leads to a socket, and close() blocks
        # like BufferedReader.close() does while another thread is in read().
        # The caller must still return at the deadline and never call close().
        release = threading.Event()
        self.addCleanup(release.set)
        closed_by = []

        class Stuck(_crowdsec.FakeStreamResponse):
            def iter_content(self, chunk_size=1):
                yield b" "
                release.wait(10)
                raise requests.ConnectionError("released")

            def close(self):
                closed_by.append(threading.current_thread().name)
                release.wait(10)
                super().close()

        self.lapi.mode, self.lapi.response = "response", Stuck()
        started = time.monotonic()
        with mock.patch.object(lapi, "read_deadline", lambda: 0.3):
            with self.assertRaisesRegex(lapi.LapiUnavailable, "took too long"):
                lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=ORIGINS)
        self.assertLess(time.monotonic() - started, 2)
        self.assertNotIn(threading.current_thread().name, closed_by)
        release.set()
        self.assertTrue(_worker_gone())
        self.assertEqual(closed_by, ["crowdsec-lapi-request"])

    def test_unexpected_exceptions_in_the_worker_are_unavailable(self):
        # (c) Not a RequestException: before the response, and while reading it.
        def boom(url, **kw):
            raise ValueError(f"bad url with {kw['headers']['X-Api-Key']}")
        with mock.patch.object(requests, "get", boom):
            with self.assertRaises(lapi.LapiUnavailable) as cm:
                lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=ORIGINS)
        self.assertEqual(str(cm.exception), "the request failed (ValueError)")

        class Odd(_crowdsec.FakeStreamResponse):
            def iter_content(self, chunk_size=1):
                raise RuntimeError("urllib3 internals changed " + _crowdsec.KEY)
                yield b""
        self.lapi.mode, self.lapi.response = "response", Odd()
        with self.assertRaises(lapi.LapiUnavailable) as cm:
            lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=ORIGINS)
        self.assertEqual(str(cm.exception), "reading the response failed (RuntimeError)")
        self.assertNotIn(_crowdsec.KEY, str(cm.exception))
        self.assertTrue(self.lapi.response.closed)


class DeadlineWindowTest(unittest.TestCase):
    def test_read_deadline_stays_inside_the_staleness_window(self):
        # (b) The longest gap between status writes is one poll wait plus one
        # fetch; it must stay below service's stale limit for every bound.
        from src.bans import service
        for poll in (5, 10, 60, 300):
            for sync in (10, 30, 600, 3600):
                with mock.patch.object(config, "CROWDSEC_POLL_INTERVAL", poll), \
                        mock.patch.object(config, "BANS_SYNC_INTERVAL", sync):
                    deadline = lapi.read_deadline()
                    limit = service.STALE_POLLS * poll + sync
                    self.assertLessEqual(deadline, lapi.READ_DEADLINE_MAX)
                    self.assertLessEqual(poll + deadline + lapi.DEADLINE_MARGIN, limit, (poll, sync))
                    self.assertGreaterEqual(deadline, 10, (poll, sync))
        with mock.patch.object(config, "CROWDSEC_POLL_INTERVAL", 5), mock.patch.object(config, "BANS_SYNC_INTERVAL", 10):
            self.assertEqual(lapi.read_deadline(), 15)
        with mock.patch.object(config, "CROWDSEC_POLL_INTERVAL", 10), mock.patch.object(config, "BANS_SYNC_INTERVAL", 30):
            self.assertEqual(lapi.read_deadline(), 45)
```

- [ ] **Step 3: Write the failing synchronizer tests**

`tests/test_crowdsec_sync.py` already has `SyncCase` (FakeCaddy, FakeLapi, CrowdSec enabled, a fake monotonic `Clock`, and `self.step(advance=0)`, which moves the clock and calls `self.sync.step()`). Add `import threading` and `import requests` to its imports, then append:

```python
class SlowLapiStatusTest(SyncCase):
    def test_a_hung_lapi_is_reported_unreachable_not_stale(self):
        # (b) The poll ends at the derived deadline and writes "unreachable";
        # the Security view reads a fresh report, not a stale one.
        release = threading.Event()
        self.addCleanup(release.set)
        real_get = requests.get

        def hang(url, **kw):
            if url.startswith(_crowdsec.URL):
                release.wait(10)
            return real_get(url, **kw)
        with mock.patch.object(requests, "get", hang), mock.patch.object(lapi, "read_deadline", lambda: 0.2):
            self.assertEqual(self.step(), "unreachable")
        doc = syncstate.read()
        self.assertEqual(doc["lapi_state"], "unreachable")
        self.assertFalse(service._crowdsec_status(store.utc_now())["stale"])

    def test_the_report_is_written_before_the_coalesced_apply(self):
        # (b) and (d): after a successful merge the report says the new
        # decision is pending, even while the apply that follows is slow.
        seen = []
        real_apply = service.apply_crowdsec

        def slow_apply(*a, **kw):
            seen.append(syncstate.read())
            return real_apply(*a, **kw)
        self.lapi.add("203.0.113.40")
        with mock.patch.object(service, "apply_crowdsec", slow_apply):
            self.step()
        self.assertEqual(seen[0]["decisions"], 1)
        self.assertIs(seen[0]["pending_apply"], True)
        self.assertIs(syncstate.read()["pending_apply"], False)

    def test_pending_apply_follows_changes_between_coalesced_applies(self):
        # (d) A delta between applies leaves pending_apply true until the next
        # apply; an unchanged repeated snapshot does not set it.
        self.step()                                        # snapshot + first apply
        self.assertIs(syncstate.read()["pending_apply"], False)
        self.lapi.add("203.0.113.41")
        self.step(config.CROWDSEC_POLL_INTERVAL)           # inside BANS_SYNC_INTERVAL: no apply
        doc = syncstate.read()
        self.assertEqual((doc["decisions"], doc["pending_apply"]), (1, True))
        self.step(config.BANS_SYNC_INTERVAL)
        self.assertIs(syncstate.read()["pending_apply"], False)
        self.sync.need_snapshot = True                     # the same decisions again
        self.step(config.CROWDSEC_POLL_INTERVAL)
        self.assertIs(syncstate.read()["pending_apply"], False)
```

- [ ] **Step 4: Write the failing model test**

Append to `tests/security-model.test.mjs` before its final `console.log` line:

```js
console.log('\n--- Phase 2 follow-ups ---');
check('synced decisions that are not applied yet read as applying, not active', () => {
  const pending = { ...CS_OK, sync: { ...CS_OK.sync, decisions: 1, pending_apply: true } };
  const s = M.crowdsecState(pending, NOW);
  assert.equal(s.title, '1 decision synced, applying…');
  assert.equal(s.tone, 'ok');
  assert.match(s.detail, /within BANS_SYNC_INTERVAL/);
  assert.equal(M.crowdsecState({ ...CS_OK, sync: { ...CS_OK.sync, pending_apply: false } }, NOW).title, '3 active decisions synced');
  // Older reports have no field: unchanged wording.
  assert.equal(M.crowdsecState(CS_OK, NOW).title, '3 active decisions synced');
  // An apply problem still wins over "applying".
  const cap = { ...pending, sync: { ...pending.sync, apply_state: 'capacity_exceeded', apply_message: 'too many' } };
  assert.equal(M.crowdsecState(cap, NOW).title, 'Over capacity: automatic apply paused');
});
```

- [ ] **Step 5: Run the tests to verify they fail**

Run: `uv run --frozen python -m unittest tests.test_crowdsec_lapi tests.test_crowdsec_sync -v`
Expected: FAIL (`lapi` has no attribute `read_deadline`; `KeyError: 'body'`; `pending_apply` missing).
Run: `node tests/security-model.test.mjs`
Expected: FAIL at "synced decisions that are not applied yet".

- [ ] **Step 6: Implement the LAPI fixes**

In `src/bans/lapi.py` replace the `READ_DEADLINE = 60` block and the three functions:

```python
TIMEOUT = (3.05, 15)
# TIMEOUT bounds each socket read, not the whole exchange: a peer that sends
# one byte every few seconds would otherwise hold the sync leader (and its
# flock) forever. A poll that takes longer than read_deadline() in total is an
# outage. The deadline stays inside the Security view's staleness window
# (service.STALE_POLLS x poll + sync): the longest gap between two status
# writes is one poll wait plus one fetch, so a slow LAPI reads "unreachable",
# never "out of date".
READ_DEADLINE_MAX = 60
DEADLINE_MARGIN = 5


def read_deadline() -> float:
    return float(min(READ_DEADLINE_MAX,
                     2 * config.CROWDSEC_POLL_INTERVAL + config.BANS_SYNC_INTERVAL - DEADLINE_MARGIN))
```

```python
def _read_bounded(resp, aborted) -> bytes:
    chunks, size = [], 0
    try:
        for chunk in resp.iter_content(65536):
            if aborted.is_set():
                break
            size += len(chunk)
            if size > MAX_BYTES:
                raise LapiMalformed("the response is larger than 32 MiB")
            chunks.append(chunk)
    except LapiMalformed:
        raise
    except Exception as e:                  # noqa: BLE001 - any read failure is an outage, named by type only
        raise LapiUnavailable(f"reading the response failed ({type(e).__name__})") from None
    return b"".join(chunks)


def _request(url, params, headers, box, aborted) -> None:
    """The blocking part of one poll, run on a worker thread so the caller's
    wait is bounded by read_deadline() whatever the peer does. Every outcome
    lands in box as "body" or "error"; messages name exception types only."""
    try:
        resp = http_client.get(url, params=params, headers=headers, timeout=TIMEOUT,
                               stream=True, allow_redirects=False)
    except Exception as e:                  # noqa: BLE001 - RequestException or anything else
        box["error"] = LapiUnavailable(type(e).__name__ if isinstance(e, http_client.RequestException)
                                       else f"the request failed ({type(e).__name__})")
        return
    box["resp"] = resp
    try:
        if aborted.is_set():
            return
        if resp.status_code in (401, 403):
            raise LapiAuthError(f"HTTP {resp.status_code}")
        if resp.status_code != 200:
            raise LapiUnavailable(f"HTTP {resp.status_code}")
        box["body"] = _read_bounded(resp, aborted)
    except (LapiAuthError, LapiUnavailable, LapiMalformed) as e:
        box["error"] = e
    except Exception as e:                  # noqa: BLE001
        box["error"] = LapiUnavailable(f"the request failed ({type(e).__name__})")
    finally:
        try:
            resp.close()                    # only ever here: the read holding the buffer lock has returned
        except Exception:                   # noqa: BLE001
            pass


def _abort(resp) -> None:
    """Wake a read that is blocked on the socket: shutdown() interrupts a recv
    in another thread. Never close() here: BufferedReader.close() takes the
    lock the blocked read holds, so it would block this (the caller's) thread
    past the deadline. The worker closes the response once its read returns;
    when no socket is found, the stray thread is still bounded by _inflight."""
    paths = (("raw", "_connection", "sock"), ("raw", "_fp", "fp", "raw", "_sock"))
    for path in paths:
        obj = resp
        for name in path:
            obj = getattr(obj, name, None)
        if obj is not None and hasattr(obj, "shutdown"):
            try:
                obj.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
```

In `fetch_stream`, take the deadline once and handle the missing body:

```python
    deadline = read_deadline()
    worker.join(deadline)
    if worker.is_alive():
        aborted.set()
        resp = box.get("resp")
        if resp is not None:
            _abort(resp)
        raise LapiUnavailable(f"the response took too long (over {deadline:g} s)")
    if "error" in box:
        raise box["error"]
    if "body" not in box:
        raise LapiUnavailable("the request ended without a response")
    return parse_stream(box["body"])
```

Update the docstring of `fetch_stream` ("Takes at most read_deadline() seconds").

- [ ] **Step 7: Implement `pending_apply` and the early status write**

In `src/bans/syncstate.py` append `"pending_apply"` to `FIELDS`.

In `src/bans/sync.py`:

```python
def _fingerprint(desired) -> dict:
    """What the Security view shows of the accepted set: id -> value. New
    fetch times on a repeated snapshot are not a change."""
    from . import addr
    return {did: addr.token(a.net) for did, a in desired.items()}
```

In `Synchronizer.__init__` add `self.pending_apply = False` and `self.applied = {}` (the fingerprint of the last successful apply). In `step()`, in the `else:` branch after `self._set("lapi", "ok")`:

```python
            self._set("lapi", "ok")
            self.pending_apply = _fingerprint(self.desired) != self.applied
            self._write()                 # before the apply: a slow reload never ages the report
            self._maybe_apply(now_m)
```

In `_maybe_apply`, on `result.ok`:

```python
        if result.ok:
            self.snapshot_audit = False
            self.applied = _fingerprint(self.desired)
            self.pending_apply = False
            self._set("apply", "ok")
```

In `_write`, add `"pending_apply": self.pending_apply` to `doc`.

- [ ] **Step 8: Implement the model wording**

In `src/static/js/app/security-model.js`, in `crowdsecState`, replace the `title` and `detail` lines:

```js
  const n = Number(s.decisions) || 0;
  const noun = n === 1 ? 'decision' : 'decisions';
  const applying = s.pending_apply === true && s.apply_state === 'ok';
  const synced = applying ? `${n} ${noun} synced, applying…` : `${n} active ${noun} synced`;
  const title = s.lapi_state !== 'ok' ? lapiTitle : (applyTitle || synced);
  const last = s.last_success_at ? `Last successful poll ${relativeTime(s.last_success_at, now)}.` : '';
  const wait = applying && s.lapi_state === 'ok'
    ? `New decisions are written to the CrowdSec file within BANS_SYNC_INTERVAL (${Number(s.sync_interval) || 30} s).` : '';
  const detail = [s.lapi_state !== 'ok' ? s.lapi_message : '', s.apply_state !== 'ok' ? s.apply_message : '', wait, last]
    .filter(Boolean).join(' ');
```

`apply_state` is `"ok"` after the first successful apply; before it, `pending` shows "Waiting for the first sync" as today.

- [ ] **Step 9: Run the tests to verify they pass**

Run: `uv run --frozen python -m unittest tests.test_crowdsec_lapi tests.test_crowdsec_sync tests.test_crowdsec_status -v`
Expected: PASS.
Run: `node tests/security-model.test.mjs`
Expected: PASS.
Run the full suites (Global Constraints). Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add src/bans/lapi.py src/bans/sync.py src/bans/syncstate.py src/static/js/app/security-model.js \
  tests/test_crowdsec_lapi.py tests/test_crowdsec_sync.py tests/security-model.test.mjs
git commit -m "fix(crowdsec): never close a response from the watchdog, keep the deadline inside the staleness window and show pending applies"
```

---
### Task 1: The plugin image's entrypoint preflight

Docker attaches `crowdsec-lapi` before Caddy's process starts, so the only place that can refuse an exposed admin API before anything listens is the image's entrypoint. This task writes it as a standard-library Go program with table tests; Task 2 builds it into the image.

**Files:**
- Create: `caddy-plugin/preflight/go.mod`, `caddy-plugin/preflight/check.go`, `caddy-plugin/preflight/main.go`
- Test: `caddy-plugin/preflight/check_test.go`
- Create: `dev/plugin-go.sh`

**Interfaces:**
- Produces: binary `/usr/bin/caddy-console-preflight` (Task 2). For `caddy run [--config P] [--adapter A] ...` it runs `caddy adapt`, then `Check`, then `exec`s Caddy; any other argv is `exec`'d unchanged (so `docker run IMAGE caddy adapt ...`, `caddy version` and `docker compose exec caddy sh` work). Refusal: message on stderr prefixed `caddy-console preflight: refusing to start Caddy:`, exit status 78. Environment read: `CADDY_ADMIN_ADDRESS`, `CADDY_ADMIN_SUBNET`, `CROWDSEC_PLUGIN_BOUNCER_KEY` (only whether it is empty), `CROWDSEC_PLUGIN_BOUNCER_KEY_FILE`.
- Go API (package `main`): `Check(env Env, config []byte, ifaces []netip.Prefix, stat func(string) (fs.FileInfo, error)) error`; `flagValue(args []string, name, def string) string`.

- [ ] **Step 1: Add the Go runner**

Create `dev/plugin-go.sh` (mode 0755):

```bash
#!/usr/bin/env bash
# Run Go from the pinned Caddy builder image, so no local Go install is needed.
#   ./dev/plugin-go.sh test                          vet and test the preflight
#   ./dev/plugin-go.sh tidy crowdsec                 refresh caddy-plugin/crowdsec/go.sum
#   ./dev/plugin-go.sh tidy crowdsec-cloudflare
set -euo pipefail
cd "$(dirname "$0")/.."
# Keep in step with the FROM line in caddy-plugin/Dockerfile (Dependabot updates that one).
BUILDER=caddy:2.11.9-builder@sha256:cda07fe9d82728c7ac44d844306d435e98131423dc7b114f05a8a8ecfff94707
RUN=(docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e GOPATH=/tmp/go -e GOCACHE=/tmp/gocache
     -e GOTOOLCHAIN=local -e CGO_ENABLED=0)
case "${1:-}" in
  test)
    "${RUN[@]}" -v "$PWD/caddy-plugin/preflight:/src:ro" -w /src "$BUILDER" \
      sh -c 'go vet ./... && go test -count=1 ./...'
    ;;
  tidy)
    variant="${2:?usage: dev/plugin-go.sh tidy <crowdsec|crowdsec-cloudflare>}"
    test -f "caddy-plugin/$variant/go.mod"
    "${RUN[@]}" -e GOFLAGS=-mod=mod -v "$PWD/caddy-plugin/$variant:/src" -w /src "$BUILDER" \
      sh -c 'go mod tidy && go mod verify'
    ;;
  *)
    echo "usage: dev/plugin-go.sh test | tidy <crowdsec|crowdsec-cloudflare>" >&2
    exit 2
    ;;
esac
```

- [ ] **Step 2: Write the failing tests**

Create `caddy-plugin/preflight/go.mod`:

```
module github.com/viralone/caddy-console/caddy-plugin/preflight

go 1.26
```

Create `caddy-plugin/preflight/check_test.go`:

```go
package main

import (
	"encoding/json"
	"io/fs"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const (
	adminAddr = "172.30.250.2:2019"
	subnet    = "172.30.250.0/29"
	keyFile   = "/run/secrets/crowdsec_plugin_bouncer_key"
	secret    = "3f9a1c0b7e6d5a4f3e2d1c0b9a8f7e6d"
)

type fakeInfo struct {
	size int64
	mode fs.FileMode
}

func (f fakeInfo) Name() string       { return "k" }
func (f fakeInfo) Size() int64        { return f.size }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return nil }

func statWith(files map[string]fakeInfo) func(string) (fs.FileInfo, error) {
	return func(p string) (fs.FileInfo, error) {
		if fi, ok := files[p]; ok {
			return fi, nil
		}
		return nil, fs.ErrNotExist
	}
}

var mounted = statWith(map[string]fakeInfo{keyFile: {size: 65}})

func ifaces(p ...string) []netip.Prefix {
	out := []netip.Prefix{}
	for _, s := range p {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

var docker = ifaces("172.30.250.2/29", "172.19.0.3/16", "127.0.0.1/8")

// cfg builds adapted JSON. admin nil means no admin key; apiKey "" means no crowdsec app.
func cfg(admin map[string]any, apiKey string) []byte {
	doc := map[string]any{"apps": map[string]any{}}
	if admin != nil {
		doc["admin"] = admin
	}
	if apiKey != "" {
		doc["apps"] = map[string]any{"crowdsec": map[string]any{"api_url": "http://crowdsec:8080", "api_key": apiKey}}
	}
	b, _ := json.Marshal(doc)
	return b
}

func fixed() map[string]any {
	return map[string]any{"listen": "tcp/" + adminAddr, "origins": []string{"caddy:2019", adminAddr}}
}

func envMode() Env  { return Env{AdminAddress: adminAddr, AdminSubnet: subnet, KeySet: true} }
func fileMode() Env { return Env{AdminAddress: adminAddr, AdminSubnet: subnet, KeyFile: keyFile} }

func mustRefuse(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a refusal containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("refusal %q does not contain %q", err.Error(), want)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("refusal echoes the key: %q", err.Error())
	}
}

func TestFixedBindStartsInBothKeyModes(t *testing.T) {
	if err := Check(envMode(), cfg(fixed(), "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}"), docker, mounted); err != nil {
		t.Fatal(err)
	}
	if err := Check(fileMode(), cfg(fixed(), "{file."+keyFile+"}"), docker, mounted); err != nil {
		t.Fatal(err)
	}
	listen := fixed()
	listen["listen"] = adminAddr // without the tcp/ prefix
	if err := Check(envMode(), cfg(listen, ""), docker, mounted); err != nil {
		t.Fatal(err)
	}
}

func TestWildcardAndLoopbackAdminAreRefused(t *testing.T) {
	cases := map[string]string{
		"tcp/0.0.0.0:2019": "wildcard", ":2019": "wildcard", "tcp/[::]:2019": "wildcard",
		"localhost:2019": "loopback", "tcp/127.0.0.1:2019": "loopback", "[::1]:2019": "loopback",
		"unix//run/caddy-admin.sock": "unix socket", "tcp/172.30.250.3:2019": "differs from CADDY_ADMIN_ADDRESS",
	}
	for listen, want := range cases {
		a := fixed()
		a["listen"] = listen
		mustRefuse(t, Check(envMode(), cfg(a, ""), docker, mounted), want)
	}
	mustRefuse(t, Check(envMode(), cfg(nil, ""), docker, mounted), "no admin line")
	mustRefuse(t, Check(envMode(), cfg(map[string]any{"disabled": true}, ""), docker, mounted), "admin off")
	err := Check(envMode(), cfg(nil, ""), docker, mounted)
	if !strings.Contains(err.Error(), "admin 172.30.250.2:2019 {") {
		t.Fatalf("the refusal must show the required bind: %v", err)
	}
}

func TestOriginsMustListTheFixedAddress(t *testing.T) {
	a := fixed()
	a["origins"] = []string{"caddy:2019"}
	mustRefuse(t, Check(envMode(), cfg(a, ""), docker, mounted), "origins")
	delete(a, "origins")
	mustRefuse(t, Check(envMode(), cfg(a, ""), docker, mounted), "origins")
}

func TestAdminAddressSettingsAreValidated(t *testing.T) {
	for _, bad := range []string{"", "0.0.0.0:2019", "127.0.0.1:2019", "caddy:2019", "172.30.250.2", "[fe80::1]:2019"} {
		e := envMode()
		e.AdminAddress = bad
		mustRefuse(t, Check(e, cfg(fixed(), ""), docker, mounted), "CADDY_ADMIN_ADDRESS")
	}
	e := envMode()
	e.AdminSubnet = "172.30.250.1/29"
	mustRefuse(t, Check(e, cfg(fixed(), ""), docker, mounted), "CADDY_ADMIN_SUBNET")
	e.AdminSubnet = "172.30.251.0/29"
	mustRefuse(t, Check(e, cfg(fixed(), ""), docker, mounted), "not inside CADDY_ADMIN_SUBNET")
}

func TestAddressMustBeOnTheAdminNetworkOnly(t *testing.T) {
	mustRefuse(t, Check(envMode(), cfg(fixed(), ""), ifaces("172.19.0.3/16"), mounted), "has no address 172.30.250.2")
	mustRefuse(t, Check(envMode(), cfg(fixed(), ""), ifaces("172.30.250.2/24"), mounted), "a network other than")
	shared := ifaces("172.30.250.2/29", "172.30.250.4/29")
	mustRefuse(t, Check(envMode(), cfg(fixed(), ""), shared, mounted), "another interface")
}

func TestLiteralKeyIsRefusedWithoutEchoingIt(t *testing.T) {
	mustRefuse(t, Check(envMode(), cfg(fixed(), secret), docker, mounted), "written into the Caddyfile")
}

func TestKeyFileMismatchIsRefused(t *testing.T) {
	mustRefuse(t, Check(fileMode(), cfg(fixed(), "{file./run/secrets/other}"), docker, mounted),
		"{file./run/secrets/other}")
	mustRefuse(t, Check(fileMode(), cfg(fixed(), "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}"), docker, mounted),
		"{file."+keyFile+"}")
	missing := statWith(map[string]fakeInfo{"/run/secrets/other": {size: 65}})
	mustRefuse(t, Check(fileMode(), cfg(fixed(), "{file."+keyFile+"}"), docker, missing), "is not mounted")
	mustRefuse(t, Check(fileMode(), cfg(fixed(), ""), docker, missing), "is not mounted") // checked before the app exists
	empty := statWith(map[string]fakeInfo{keyFile: {size: 0}})
	mustRefuse(t, Check(fileMode(), cfg(fixed(), ""), docker, empty), "is empty")
	dir := statWith(map[string]fakeInfo{keyFile: {mode: fs.ModeDir}})
	mustRefuse(t, Check(fileMode(), cfg(fixed(), ""), docker, dir), "not a regular file")
	for _, bad := range []string{"run/secrets/k", "/run/secrets/../k", "/run/./k", "/run/secrets/k ", "/run/secrets/{k}"} {
		e := fileMode()
		e.KeyFile = bad
		mustRefuse(t, Check(e, cfg(fixed(), ""), docker, mounted), "absolute path")
	}
	both := fileMode()
	both.KeySet = true
	mustRefuse(t, Check(both, cfg(fixed(), ""), docker, mounted), "not both")
}

func TestEnvModeNeedsTheKeyAndThePlaceholder(t *testing.T) {
	e := envMode()
	e.KeySet = false
	mustRefuse(t, Check(e, cfg(fixed(), "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}"), docker, mounted), "CROWDSEC_PLUGIN_BOUNCER_KEY is empty")
	if err := Check(e, cfg(fixed(), ""), docker, mounted); err != nil {
		t.Fatalf("no crowdsec app yet: only the admin checks apply: %v", err)
	}
	mustRefuse(t, Check(envMode(), cfg(fixed(), "{env.OTHER}"), docker, mounted), "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}")
}

func TestUnreadableConfigIsRefused(t *testing.T) {
	mustRefuse(t, Check(envMode(), []byte("not json"), docker, mounted), "adapted Caddyfile")
}

func TestStatErrorsOtherThanMissingAreReported(t *testing.T) {
	denied := func(string) (fs.FileInfo, error) { return nil, fs.ErrPermission }
	mustRefuse(t, Check(fileMode(), cfg(fixed(), ""), docker, denied), "cannot be checked")
}

func TestFlagValue(t *testing.T) {
	args := []string{"caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter=caddyfile"}
	if got := flagValue(args, "--config", "x"); got != "/etc/caddy/Caddyfile" {
		t.Fatal(got)
	}
	if got := flagValue(args, "--adapter", "x"); got != "caddyfile" {
		t.Fatal(got)
	}
	if got := flagValue(args, "--watch", "none"); got != "none" {
		t.Fatal(got)
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `./dev/plugin-go.sh test`
Expected: FAIL to compile (`undefined: Check`, `undefined: Env`, `undefined: flagValue`).

- [ ] **Step 4: Write the check**

Create `caddy-plugin/preflight/check.go`:

```go
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

const envPlaceholder = "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}"

// Same rule as src/bans/plugin.py parse_key_file(): absolute, plain segments only.
var keyPath = regexp.MustCompile(`^/(?:[A-Za-z0-9_][A-Za-z0-9._-]*/)*[A-Za-z0-9_][A-Za-z0-9._-]*$`)

// Env is what the preflight reads from the container environment. KeySet
// says whether CROWDSEC_PLUGIN_BOUNCER_KEY is non-empty; the value is never read.
type Env struct {
	AdminAddress string // CADDY_ADMIN_ADDRESS, for example 172.30.250.2:2019
	AdminSubnet  string // CADDY_ADMIN_SUBNET, for example 172.30.250.0/29
	KeySet       bool
	KeyFile      string // CROWDSEC_PLUGIN_BOUNCER_KEY_FILE
}

type adaptedConfig struct {
	Admin *struct {
		Disabled bool     `json:"disabled"`
		Listen   string   `json:"listen"`
		Origins  []string `json:"origins"`
	} `json:"admin"`
	Apps struct {
		CrowdSec *struct {
			APIKey string `json:"api_key"`
		} `json:"crowdsec"`
	} `json:"apps"`
}

func required(admin netip.AddrPort) string {
	return fmt.Sprintf("put this in the global options:\n\tadmin %s {\n\t\torigins caddy:2019 %s\n\t}", admin, admin)
}

func fixedAddress(raw string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(raw)
	if err == nil {
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	a := ap.Addr()
	if err != nil || ap.Port() == 0 || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() ||
		a.IsLinkLocalUnicast() || a.Zone() != "" {
		return netip.AddrPort{}, errors.New("CADDY_ADMIN_ADDRESS must be Caddy's fixed caddy-admin address and port, " +
			"for example 172.30.250.2:2019 (not a wildcard, loopback or host name)")
	}
	return ap, nil
}

// Check returns nil when Caddy may start. config is `caddy adapt` output;
// ifaces lists the container's addresses with their networks; stat reports
// on the key file without opening it. Messages never contain the key.
func Check(env Env, config []byte, ifaces []netip.Prefix, stat func(string) (fs.FileInfo, error)) error {
	admin, err := fixedAddress(env.AdminAddress)
	if err != nil {
		return err
	}
	subnet, err := netip.ParsePrefix(env.AdminSubnet)
	if err != nil || subnet != subnet.Masked() {
		return errors.New("CADDY_ADMIN_SUBNET must be the caddy-admin network, for example 172.30.250.0/29")
	}
	if !subnet.Contains(admin.Addr()) {
		return fmt.Errorf("CADDY_ADMIN_ADDRESS %s is not inside CADDY_ADMIN_SUBNET %s", admin, subnet)
	}
	var cfg adaptedConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return fmt.Errorf("cannot read the adapted Caddyfile (%v)", err)
	}
	if err := checkAdmin(cfg, admin); err != nil {
		return err
	}
	if err := checkInterface(admin.Addr(), subnet, ifaces); err != nil {
		return err
	}
	return checkKey(env, cfg, stat)
}

func checkAdmin(cfg adaptedConfig, admin netip.AddrPort) error {
	if cfg.Admin == nil || (cfg.Admin.Listen == "" && !cfg.Admin.Disabled) {
		return fmt.Errorf("the Caddyfile has no admin line, so Caddy would listen on localhost:2019; %s", required(admin))
	}
	if cfg.Admin.Disabled {
		return fmt.Errorf("the Caddyfile turns the admin API off (admin off), but the console needs it; %s", required(admin))
	}
	listen := strings.TrimPrefix(cfg.Admin.Listen, "tcp/")
	if strings.HasPrefix(listen, "unix/") {
		return fmt.Errorf("the admin API is a unix socket, which the console cannot reach; %s", required(admin))
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("the admin listen address %q is not host:port; %s", cfg.Admin.Listen, required(admin))
	}
	if host == "localhost" {
		return fmt.Errorf("the admin API listens on loopback only (%s), so the console cannot reach it; %s", listen, required(admin))
	}
	if host == "" {
		return fmt.Errorf("the admin API listens on a wildcard address (%s), which CrowdSec could reach; %s", listen, required(admin))
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("the admin listen host %q is not an IP address; %s", host, required(admin))
	}
	a = a.Unmap()
	switch {
	case a.IsUnspecified():
		return fmt.Errorf("the admin API listens on a wildcard address (%s), which CrowdSec could reach; %s", listen, required(admin))
	case a.IsLoopback():
		return fmt.Errorf("the admin API listens on loopback only (%s), so the console cannot reach it; %s", listen, required(admin))
	}
	if netip.AddrPortFrom(a, admin.Port()) != admin || port != fmt.Sprint(admin.Port()) {
		return fmt.Errorf("the admin listen address %s differs from CADDY_ADMIN_ADDRESS %s; %s", listen, admin, required(admin))
	}
	if !slices.Contains(cfg.Admin.Origins, admin.String()) {
		return fmt.Errorf("the admin origins must list %s, or the console and recovery commands are refused; %s", admin, required(admin))
	}
	return nil
}

func checkInterface(admin netip.Addr, subnet netip.Prefix, ifaces []netip.Prefix) error {
	var own *netip.Prefix
	for i, p := range ifaces {
		if p.Addr().Unmap() == admin {
			own = &ifaces[i]
		}
	}
	if own == nil {
		return fmt.Errorf("the container has no address %s; give Caddy ipv4_address %s on caddy-admin", admin, admin)
	}
	if own.Masked() != subnet {
		return fmt.Errorf("%s is on a network other than CADDY_ADMIN_SUBNET %s (%s)", admin, subnet, own.Masked())
	}
	for _, p := range ifaces {
		if p.Addr().Unmap() != admin && p.Masked().Contains(admin) {
			return fmt.Errorf("%s is also reachable through another interface (%s); caddy-admin must not be shared", admin, p)
		}
	}
	return nil
}

func validKeyPath(p string) bool {
	if len(p) > 255 || !keyPath.MatchString(p) {
		return false
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

func checkKey(env Env, cfg adaptedConfig, stat func(string) (fs.FileInfo, error)) error {
	want := envPlaceholder
	if env.KeyFile != "" {
		if env.KeySet {
			return errors.New("set CROWDSEC_PLUGIN_BOUNCER_KEY or CROWDSEC_PLUGIN_BOUNCER_KEY_FILE, not both")
		}
		if !validKeyPath(env.KeyFile) {
			return errors.New("CROWDSEC_PLUGIN_BOUNCER_KEY_FILE must be an absolute path such as " +
				"/run/secrets/crowdsec_plugin_bouncer_key (letters, digits, '.', '_', '-' and '/')")
		}
		info, err := stat(env.KeyFile)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("the key file %s is not mounted in the Caddy container; mount the secret at exactly "+
				"the path in CROWDSEC_PLUGIN_BOUNCER_KEY_FILE", env.KeyFile)
		case err != nil:
			// A stat error names the path and the errno text only; it never reads the file.
			return fmt.Errorf("the key file %s cannot be checked (%v)", env.KeyFile, err)
		case !info.Mode().IsRegular():
			return fmt.Errorf("the key file %s is not a regular file", env.KeyFile)
		case info.Size() == 0:
			return fmt.Errorf("the key file %s is empty", env.KeyFile)
		case info.Size() > 4096:
			return fmt.Errorf("the key file %s is larger than 4 KiB", env.KeyFile)
		}
		want = "{file." + env.KeyFile + "}"
	}
	if cfg.Apps.CrowdSec == nil {
		return nil // the global crowdsec app is not configured yet
	}
	got := cfg.Apps.CrowdSec.APIKey
	if got == want {
		if env.KeyFile == "" && !env.KeySet {
			return errors.New("CROWDSEC_PLUGIN_BOUNCER_KEY is empty; set it, or use CROWDSEC_PLUGIN_BOUNCER_KEY_FILE")
		}
		return nil
	}
	if strings.HasPrefix(got, "{env.") || strings.HasPrefix(got, "{file.") {
		return fmt.Errorf("the crowdsec api_key is %s, but this container expects %s", got, want)
	}
	return fmt.Errorf("the crowdsec api_key is written into the Caddyfile, where anyone who can read Caddy's "+
		"config sees it; use api_key %s", want)
}
```

- [ ] **Step 5: Write the entrypoint**

Create `caddy-plugin/preflight/main.go`:

```go
// caddy-console-preflight is the entrypoint of the Caddy Console plugin images
// (docs/security.md#crowdsec-plugin). For `caddy run ...` it adapts the
// Caddyfile and refuses to start Caddy unless the admin API is bound to the
// fixed caddy-admin address with origins and the CrowdSec bouncer key is a
// placeholder matching the configured secret mode. Every other command
// (caddy adapt, caddy version, sh) is exec'd unchanged.
package main

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func flagValue(args []string, name, def string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
		if v, ok := strings.CutPrefix(a, name+"="); ok {
			return v
		}
	}
	return def
}

func localPrefixes() []netip.Prefix {
	out := []netip.Prefix{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		ip = ip.Unmap()
		if ip.Is4() && ones > 32 {
			ones -= 96
		}
		out = append(out, netip.PrefixFrom(ip, ones))
	}
	return out
}

func preflight(args []string) error {
	cmd := exec.Command("/usr/bin/caddy", "adapt",
		"--config", flagValue(args, "--config", "/etc/caddy/Caddyfile"),
		"--adapter", flagValue(args, "--adapter", "caddyfile"))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 2000 {
			msg = msg[:2000]
		}
		return fmt.Errorf("caddy adapt failed (%v): %s", err, msg)
	}
	env := Env{
		AdminAddress: os.Getenv("CADDY_ADMIN_ADDRESS"),
		AdminSubnet:  os.Getenv("CADDY_ADMIN_SUBNET"),
		KeySet:       os.Getenv("CROWDSEC_PLUGIN_BOUNCER_KEY") != "",
		KeyFile:      os.Getenv("CROWDSEC_PLUGIN_BOUNCER_KEY_FILE"),
	}
	return Check(env, out, localPrefixes(), os.Stat)
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: caddy-console-preflight caddy run [flags] | <command> [args]")
		os.Exit(2)
	}
	if len(args) >= 2 && args[0] == "caddy" && args[1] == "run" {
		if err := preflight(args); err != nil {
			fmt.Fprintf(os.Stderr, "caddy-console preflight: refusing to start Caddy: %v\n", err)
			os.Exit(78)
		}
		fmt.Fprintln(os.Stderr, "caddy-console preflight: admin bind and bouncer key checks passed")
	}
	path, err := exec.LookPath(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "caddy-console preflight: %v\n", err)
		os.Exit(127)
	}
	if err := syscall.Exec(path, args, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "caddy-console preflight: exec %s: %v\n", path, err)
		os.Exit(126)
	}
}
```

`caddy adapt` stderr carries Caddyfile warnings, never the key: an `{env.*}`/`{file.*}` placeholder is not resolved by `adapt`, and the adapted JSON on stdout is never printed.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `./dev/plugin-go.sh test`
Expected: `ok  github.com/viralone/caddy-console/caddy-plugin/preflight` and no `go vet` findings.

- [ ] **Step 7: Commit**

```bash
git add caddy-plugin/preflight dev/plugin-go.sh
git commit -m "feat(crowdsec-plugin): entrypoint preflight that refuses an exposed admin API or a mismatched bouncer key"
```

---

### Task 2: Reproducible plugin images and their module record

**Files:**
- Create: `caddy-plugin/Dockerfile`, `caddy-plugin/crowdsec/{go.mod,main.go,go.sum}`, `caddy-plugin/crowdsec-cloudflare/{go.mod,main.go,go.sum}`
- Create: `dev/build-plugin-image.sh`, `dev/check-plugin-modules.py`
- Modify: `.github/dependabot.yml`

**Interfaces:**
- Consumes: `caddy-plugin/preflight` (Task 1).
- Produces: local images `caddy-crowdsec:local` and `caddy-crowdsec-cloudflare:local` (`./dev/build-plugin-image.sh <variant>`), each with `/usr/share/caddy-console/modules.json` (the build's `list-modules --json --skip-standard`). Later tasks run `IMAGE=caddy-crowdsec:local`. `dev/check-plugin-modules.py <variant> < modules.json` exits non-zero unless the non-standard module set is exactly the expected one at the pinned versions.

- [ ] **Step 1: Write the failing module check**

Create `dev/check-plugin-modules.py`:

```python
"""Assert a plugin image carries exactly the expected third-party modules.

  docker run --rm IMAGE caddy list-modules --json --skip-standard | python3 dev/check-plugin-modules.py crowdsec
"""
import json
import re
import sys

BOUNCER = "github.com/hslatman/caddy-crowdsec-bouncer"
CLOUDFLARE = "github.com/caddy-dns/cloudflare"
EXPECTED = {
    "crowdsec": {"admin.api.crowdsec": BOUNCER, "crowdsec": BOUNCER,
                 "http.handlers.appsec": BOUNCER, "http.handlers.crowdsec": BOUNCER},
}
EXPECTED["crowdsec-cloudflare"] = {**EXPECTED["crowdsec"], "dns.providers.cloudflare": CLOUDFLARE}


def required_versions(variant):
    """Versions from the committed go.mod, so this check and the build agree."""
    with open(f"caddy-plugin/{variant}/go.mod", encoding="utf-8") as f:
        text = f.read()
    return {m: v for m, v in re.findall(r"^\s*(github\.com/\S+)\s+(v\S+)", text, re.M)}


def main(variant):
    if variant not in EXPECTED:
        sys.exit(f"unknown variant {variant!r}")
    mods = json.load(sys.stdin)
    found = {m["module_name"]: m for m in mods if m.get("module_type") in ("non-standard", "unknown")}
    problems = []
    if set(found) != set(EXPECTED[variant]):
        problems.append(f"non-standard modules are {sorted(found)}, expected {sorted(EXPECTED[variant])}")
    versions = required_versions(variant)
    for name, module in EXPECTED[variant].items():
        m = found.get(name) or {}
        if not str(m.get("package_url", "")).startswith(module):
            problems.append(f"{name} comes from {m.get('package_url')!r}, expected {module}")
        elif m.get("version") != versions.get(module):
            problems.append(f"{name} is {m.get('version')!r}, go.mod pins {versions.get(module)!r}")
    if problems:
        sys.exit("\n".join(problems))
    print(f"{variant}: modules ok ({', '.join(sorted(found))})")


main(*sys.argv[1:2])
```

Create `dev/build-plugin-image.sh` (mode 0755):

```bash
#!/usr/bin/env bash
# Build one plugin image locally and check its modules (docs/development.md).
#   ./dev/build-plugin-image.sh crowdsec              -> caddy-crowdsec:local
#   ./dev/build-plugin-image.sh crowdsec-cloudflare   -> caddy-crowdsec-cloudflare:local
set -euo pipefail
cd "$(dirname "$0")/.."
variant="${1:?usage: dev/build-plugin-image.sh <crowdsec|crowdsec-cloudflare>}"
image="caddy-$variant:local"
export BUILDX_BUILDER="${BUILDX_BUILDER:-default}"
docker build -f caddy-plugin/Dockerfile --build-arg VARIANT="$variant" -t "$image" caddy-plugin
docker run --rm "$image" caddy list-modules --json --skip-standard | python3 dev/check-plugin-modules.py "$variant"
# The module record baked into the image is the one this build produced.
docker run --rm "$image" cat /usr/share/caddy-console/modules.json | python3 dev/check-plugin-modules.py "$variant"
version="$(docker run --rm "$image" caddy version)"
case "$version" in v2.11.9*) ;; *) echo "unexpected Caddy version: $version" >&2; exit 1 ;; esac
echo "$image: Caddy $version"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `./dev/build-plugin-image.sh crowdsec`
Expected: FAIL (`caddy-plugin/Dockerfile` does not exist).

- [ ] **Step 3: Write the two builds**

Create `caddy-plugin/crowdsec/main.go`:

```go
// Caddy 2.11.9 with the CrowdSec HTTP bouncer, for docker-compose.crowdsec-plugin.yaml.
// Equivalent to `xcaddy build --with github.com/hslatman/caddy-crowdsec-bouncer/http`,
// with every dependency pinned by go.sum.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/hslatman/caddy-crowdsec-bouncer/http"
)

func main() {
	caddycmd.Main()
}
```

Create `caddy-plugin/crowdsec/go.mod`:

```
module github.com/viralone/caddy-console/caddy-plugin/crowdsec

go 1.26.1

require (
	github.com/caddyserver/caddy/v2 v2.11.9
	github.com/hslatman/caddy-crowdsec-bouncer v0.15.0
)
```

Create `caddy-plugin/crowdsec-cloudflare/main.go` with the same content plus one import and its own comment:

```go
// Caddy 2.11.9 with the CrowdSec HTTP bouncer and the Cloudflare DNS provider
// (DNS-01), for the NAS plugin overlay. Cloudflare as a proxy or Tunnel does
// not need this variant.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddy-dns/cloudflare"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/hslatman/caddy-crowdsec-bouncer/http"
)

func main() {
	caddycmd.Main()
}
```

Create `caddy-plugin/crowdsec-cloudflare/go.mod`:

```
module github.com/viralone/caddy-console/caddy-plugin/crowdsec-cloudflare

go 1.26.1

require (
	github.com/caddy-dns/cloudflare v0.2.4
	github.com/caddyserver/caddy/v2 v2.11.9
	github.com/hslatman/caddy-crowdsec-bouncer v0.15.0
)
```

Then generate the lock files (network access to the Go module proxy is needed once):

Run: `./dev/plugin-go.sh tidy crowdsec && ./dev/plugin-go.sh tidy crowdsec-cloudflare`
Expected: `go.sum` created in both directories, `go.mod` gains an indirect `require` block, `all modules verified`. Check that `go.mod` still requires exactly `github.com/caddyserver/caddy/v2 v2.11.9` and `github.com/hslatman/caddy-crowdsec-bouncer v0.15.0` directly (tidy must not raise them). If tidy added a `toolchain` line, remove it (the builder runs with `GOTOOLCHAIN=local`).

- [ ] **Step 4: Write the Dockerfile**

Create `caddy-plugin/Dockerfile`:

```dockerfile
# syntax=docker/dockerfile:1
# Optional Caddy images for CrowdSec plugin mode (docs/security.md#crowdsec-plugin).
# Build context is this directory; VARIANT is crowdsec or crowdsec-cloudflare:
#   docker build -f caddy-plugin/Dockerfile --build-arg VARIANT=crowdsec -t caddy-crowdsec:local caddy-plugin
# Both FROM lines are literal tag@digest pins so Dependabot (docker) can update them;
# dev/plugin-go.sh uses the same builder pin.
FROM caddy:2.11.9-builder@sha256:cda07fe9d82728c7ac44d844306d435e98131423dc7b114f05a8a8ecfff94707 AS build
ARG VARIANT=crowdsec
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /src/preflight
COPY preflight/ ./
RUN go vet ./... && go test -count=1 ./... \
 && go build -trimpath -ldflags='-s -w' -o /out/caddy-console-preflight .
WORKDIR /src/caddy
COPY ${VARIANT}/ ./
# go.sum pins the whole graph; -mod=readonly fails the build if go.mod/go.sum are stale.
RUN go mod verify \
 && go build -trimpath -ldflags='-s -w' -o /out/caddy . \
 && /out/caddy list-modules --json --skip-standard > /out/modules.json

FROM caddy:2.11.9-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0
ARG VARIANT=crowdsec
COPY --from=build /out/caddy /usr/bin/caddy
COPY --from=build /out/caddy-console-preflight /usr/bin/caddy-console-preflight
COPY --from=build /out/modules.json /usr/share/caddy-console/modules.json
LABEL org.opencontainers.image.title="caddy-${VARIANT}" \
      org.opencontainers.image.description="Caddy 2.11.9 with the CrowdSec HTTP bouncer v0.15.0 for Caddy Console plugin mode" \
      org.opencontainers.image.licenses="Apache-2.0"
# Caddy runs as root in the official image and the Compose files grant only
# NET_BIND_SERVICE, so no file capability is needed on the replaced binary.
ENTRYPOINT ["/usr/bin/caddy-console-preflight"]
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
```

- [ ] **Step 5: Track the Go modules and the image pins with Dependabot**

Append to `.github/dependabot.yml` under `updates:`:

```yaml
  # Plugin images (caddy-plugin/): the Caddy builds' go.mod/go.sum. A plugin
  # bump must pass the plugin integration suite (client IP in direct, proxied
  # and tunnel fixtures) before it is merged (spec 3.2).
  - package-ecosystem: "gomod"
    directories:
      - "/caddy-plugin/crowdsec"
      - "/caddy-plugin/crowdsec-cloudflare"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 3
    cooldown:
      default-days: 7
    groups:
      caddy-plugin-modules:
        patterns:
          - "*"

  - package-ecosystem: "docker"
    directory: "/caddy-plugin"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 3
    cooldown:
      default-days: 3
```

When Dependabot bumps the plugin, the image tag version in `.github/workflows/docker-publish.yml` (Task 11, `PLUGIN_VERSION`) must be bumped in the same PR; Task 11's CI step fails if they disagree.

- [ ] **Step 6: Build and check both variants**

Run: `./dev/build-plugin-image.sh crowdsec && ./dev/build-plugin-image.sh crowdsec-cloudflare`
Expected: `crowdsec: modules ok (admin.api.crowdsec, crowdsec, http.handlers.appsec, http.handlers.crowdsec)` twice, the Cloudflare variant also lists `dns.providers.cloudflare`, and `Caddy v2.11.9 ...`.

Run: `docker run --rm caddy-crowdsec:local caddy run`
Expected: exit status 78 and `caddy-console preflight: refusing to start Caddy: CADDY_ADMIN_ADDRESS must be ...` (no environment given), proving the entrypoint is wired.

- [ ] **Step 7: Commit**

```bash
git add caddy-plugin/Dockerfile caddy-plugin/crowdsec caddy-plugin/crowdsec-cloudflare \
  dev/build-plugin-image.sh dev/check-plugin-modules.py .github/dependabot.yml
git commit -m "feat(crowdsec-plugin): pinned Caddy builds with the CrowdSec bouncer and a recorded module list"
```

---
### Task 3: Console settings, module probe and admin exposure check

**Files:**
- Create: `src/bans/plugin.py`
- Modify: `src/config.py` (Phase 3 rows), `src/bans/service.py` (`init_config`)
- Modify: `tests/_bans.py` (FakeCaddy knows the plugin module; `reset()` removes `plugin-policy.json`)
- Test: `tests/test_plugin_settings.py`

**Interfaces:**
- Produces in `src/bans/plugin.py`:
  - `ConfigError(ValueError)`; `parse_key_file(raw) -> str` (`""` or a validated absolute path); `parse_admin_address(raw) -> AdminAddress` with `AdminAddress(host: str, port: int, fixed: bool)` and `str()` → `host:port` (`[v6]:port`).
  - `key_file() -> str`, `key_mode() -> "env" | "file"`, `api_key_placeholder() -> str` (`{env.CROWDSEC_PLUGIN_BOUNCER_KEY}` or `{file.<path>}`), `admin_address() -> AdminAddress`.
  - `API_URL = "http://crowdsec:8080"`, `TICKER_INTERVAL = "10s"`, `DEFAULT_KEY_FILE = "/run/secrets/crowdsec_plugin_bouncer_key"`, `ENV_PLACEHOLDER`.
  - `module_available(force=False) -> bool | None` (cached `/adapt` probe; never under `caddyfile_lock()`), `cached_module() -> bool | None` (no probe), `reset_cache()`.
  - `AdminProblem(code: str, message: str)`; `admin_problem(live) -> AdminProblem | None`. Codes: `admin_not_fixed`, `admin_missing`, `admin_off`, `admin_unix`, `admin_wildcard`, `admin_loopback`, `admin_mismatch`, `admin_origins`, `admin_shared`.
  - `live_app(live) -> dict | None`: `{"api_url", "ticker_interval", "streaming", "hard_fails", "key_form": "expected"|"placeholder"|"literal"|"missing", "key_placeholder"}`; never the key.
- Produces in `tests/_bans.py`: `FakeCaddy.plugin` (bool, default `False`): `/adapt` of text with a `crowdsec {` block answers 400 `unrecognized global option: crowdsec` unless it is `True`.

- [ ] **Step 1: Teach FakeCaddy about the module and the new state file**

In `tests/_bans.py`:

```python
_CROWDSEC_BLOCK = re.compile(r"(?m)^\s*crowdsec\s*\{")
```

In `FakeCaddy.__init__` add `self.plugin = False`. In `_post`, inside the `/adapt` branch before the 200 return:

```python
            if _CROWDSEC_BLOCK.search(text) and not self.plugin:
                return FakeResponse(400, {"error": "adapting config using caddyfile: unrecognized global option: crowdsec"})
```

In `reset()`, also remove the plugin state file (it does not start with `bans`):

```python
        if name.startswith("bans") or name.startswith(".bans") or name == "plugin-policy.json":
```

- [ ] **Step 2: Write the failing tests**

Create `tests/test_plugin_settings.py`:

```python
"""Plugin-mode settings, the module probe and the admin exposure check (spec 3.1, 3.3).

Run with:  uv run --frozen python -m unittest tests.test_plugin_settings -v
"""
import glob
import ipaddress
import json
import os
import re
import unittest
from unittest import mock

import tests._env  # noqa: F401
from tests import _bans, _crowdsec

from src import config
from src.bans import plugin, protected, service

SECRET = "3f9a1c0b7e6d5a4f3e2d1c0b9a8f7e6d"
FIXED = "172.30.250.2:2019"


def live(listen="tcp/" + FIXED, origins=("caddy:2019", FIXED), app=None, **admin):
    doc = {"admin": {"listen": listen, "origins": list(origins), **admin}, "apps": {}}
    if listen is None:
        doc.pop("admin")
    if app is not None:
        doc["apps"]["crowdsec"] = app
    return doc


class SettingsTest(unittest.TestCase):
    def test_key_file_paths(self):
        self.assertEqual(plugin.parse_key_file(""), "")
        self.assertEqual(plugin.parse_key_file("  /run/secrets/crowdsec_plugin_bouncer_key "),
                         "/run/secrets/crowdsec_plugin_bouncer_key")
        for bad in ("run/secrets/k", "/run/secrets/../k", "/run/./k", "/run/secrets/k b", "/run/{k}",
                    "/" + "a" * 300, "/run/secrets/", "/run//k"):
            with self.assertRaises(plugin.ConfigError, msg=bad) as cm:
                plugin.parse_key_file(bad)
            self.assertIn("CROWDSEC_PLUGIN_BOUNCER_KEY_FILE", str(cm.exception))

    def test_admin_addresses(self):
        cases = {"0.0.0.0:2019": ("0.0.0.0", False), ":2019": ("", False), "localhost:2019": ("localhost", False),
                 "127.0.0.1:2019": ("127.0.0.1", False), "172.30.250.2:2019": ("172.30.250.2", True),
                 "[2001:db8::2]:2019": ("2001:db8::2", True), "[::]:2019": ("::", False),
                 "caddy:2019": ("caddy", False)}
        for raw, (host, fixed) in cases.items():
            a = plugin.parse_admin_address(raw)
            self.assertEqual((a.host, a.port, a.fixed), (host, 2019, fixed), raw)
        self.assertEqual(str(plugin.parse_admin_address("[2001:db8::2]:2019")), "[2001:db8::2]:2019")
        self.assertEqual(str(plugin.parse_admin_address("")), "0.0.0.0:2019")
        for bad in ("172.30.250.2", "172.30.250.2:0", "172.30.250.2:70000", "http://x:2019", "999.1.1.1:2019", "a b:1"):
            with self.assertRaises(plugin.ConfigError, msg=bad):
                plugin.parse_admin_address(bad)

    def test_invalid_settings_refuse_startup(self):
        for name, value in (("CROWDSEC_PLUGIN_BOUNCER_KEY_FILE", "relative/path"), ("CADDY_ADMIN_ADDRESS", "nope")):
            with mock.patch.object(config, name, value), self.assertRaisesRegex(RuntimeError, name):
                service.init_config()

    def test_placeholder_follows_the_key_mode(self):
        with mock.patch.object(config, "CROWDSEC_PLUGIN_BOUNCER_KEY_FILE", ""):
            self.assertEqual((plugin.key_mode(), plugin.api_key_placeholder()),
                             ("env", "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}"))
        with mock.patch.object(config, "CROWDSEC_PLUGIN_BOUNCER_KEY_FILE", "/run/secrets/k"):
            self.assertEqual((plugin.key_mode(), plugin.api_key_placeholder()), ("file", "{file./run/secrets/k}"))

    def test_console_never_reads_the_plugin_key(self):
        root = os.path.join(os.path.dirname(__file__), "..", "src")
        reads = re.compile(r"""environ(?:\.get)?\s*[\[(]\s*["']CROWDSEC_PLUGIN_BOUNCER_KEY["']|getenv\(\s*["']CROWDSEC_PLUGIN_BOUNCER_KEY["']""")
        for path in glob.glob(os.path.join(root, "**", "*.py"), recursive=True):
            with open(path, encoding="utf-8") as f:
                self.assertIsNone(reads.search(f.read()), path)
        self.assertFalse(hasattr(config, "CROWDSEC_PLUGIN_BOUNCER_KEY"))


class ModuleProbeTest(unittest.TestCase):
    def setUp(self):
        plugin.reset_cache()
        self.addCleanup(plugin.reset_cache)
        self.caddy = _bans.FakeCaddy().install(self)
        self.lapi = _crowdsec.FakeLapi().install(self)

    def test_probe_tells_the_build(self):
        self.assertIs(plugin.module_available(), False)
        self.caddy.plugin = True
        self.assertIs(plugin.module_available(), False, "cached")
        self.assertIs(plugin.module_available(force=True), True)
        self.assertIs(plugin.cached_module(), True)
        self.assertEqual(self.lapi.calls, [], "the probe only adapts; it never contacts LAPI")
        probes = [t for k, t in self.caddy.calls if k == "adapt"]
        self.assertTrue(all("caddy-console-module-probe" in t for t in probes))
        self.assertFalse(any(k == "load" for k, _ in self.caddy.calls))

    def test_unreachable_or_unrelated_errors_are_unknown(self):
        self.caddy.down = True
        self.assertIsNone(plugin.module_available(force=True))
        self.caddy.down = False
        self.caddy.adapt_status = 500
        self.assertIsNone(plugin.module_available(force=True))

    def test_cached_module_never_probes(self):
        self.assertIsNone(plugin.cached_module())
        self.assertEqual(self.caddy.calls, [])


class AdminProblemTest(unittest.TestCase):
    def setUp(self):
        for name, value in (("CADDY_ADMIN_ADDRESS", FIXED), ("CROWDSEC_URL", _crowdsec.URL)):
            p = mock.patch.object(config, name, value)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(protected, "read_docker_networks",
                              lambda: [ipaddress.ip_network("172.30.250.0/29"), ipaddress.ip_network("172.31.0.0/24")])
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(plugin, "_lapi_addresses", lambda: [ipaddress.ip_address("172.31.0.5")])
        p.start()
        self.addCleanup(p.stop)

    def code(self, doc):
        problem = plugin.admin_problem(doc)
        return problem.code if problem else None

    def test_the_fixed_bind_is_fine(self):
        self.assertIsNone(plugin.admin_problem(live()))
        self.assertIsNone(plugin.admin_problem(live(listen=FIXED)))

    def test_each_exposure_is_named(self):
        self.assertEqual(self.code(live(listen=None)), "admin_missing")
        self.assertEqual(self.code(live(listen="")), "admin_missing")
        self.assertEqual(self.code(live(disabled=True)), "admin_off")
        self.assertEqual(self.code(live(listen="unix//run/a.sock")), "admin_unix")
        for listen in ("tcp/0.0.0.0:2019", ":2019", "tcp/[::]:2019"):
            self.assertEqual(self.code(live(listen=listen)), "admin_wildcard", listen)
        for listen in ("localhost:2019", "tcp/127.0.0.1:2019", "[::1]:2019"):
            self.assertEqual(self.code(live(listen=listen)), "admin_loopback", listen)
        self.assertEqual(self.code(live(listen="tcp/172.30.250.3:2019")), "admin_mismatch")
        self.assertEqual(self.code(live(origins=("caddy:2019",))), "admin_origins")

    def test_an_interface_shared_with_crowdsec_is_refused(self):
        with mock.patch.object(plugin, "_lapi_addresses", lambda: [ipaddress.ip_address("172.30.250.5")]):
            self.assertEqual(self.code(live()), "admin_shared")

    def test_the_console_must_use_the_fixed_address(self):
        with mock.patch.object(config, "CADDY_ADMIN_ADDRESS", "0.0.0.0:2019"):
            problem = plugin.admin_problem(live())
        self.assertEqual(problem.code, "admin_not_fixed")
        self.assertIn("docker-compose.crowdsec-plugin.yaml", problem.message)

    def test_messages_show_the_required_bind(self):
        problem = plugin.admin_problem(live(listen="tcp/0.0.0.0:2019"))
        self.assertIn("admin 172.30.250.2:2019 { origins caddy:2019 172.30.250.2:2019 }", problem.message)


class LiveAppTest(unittest.TestCase):
    def test_no_app(self):
        self.assertIsNone(plugin.live_app(live()))

    def test_expected_placeholder(self):
        with mock.patch.object(config, "CROWDSEC_PLUGIN_BOUNCER_KEY_FILE", ""):
            app = plugin.live_app(live(app={"api_url": "http://crowdsec:8080", "api_key": "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}",
                                            "ticker_interval": "10s", "enable_streaming": True}))
        self.assertEqual(app, {"api_url": "http://crowdsec:8080", "ticker_interval": "10s", "streaming": True,
                               "hard_fails": False, "key_form": "expected", "key_placeholder": None})

    def test_other_placeholder_is_named(self):
        with mock.patch.object(config, "CROWDSEC_PLUGIN_BOUNCER_KEY_FILE", "/run/secrets/k"):
            app = plugin.live_app(live(app={"api_key": "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}"}))
        self.assertEqual((app["key_form"], app["key_placeholder"]), ("placeholder", "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}"))
        self.assertEqual(app["ticker_interval"], "60s")

    def test_live_literal_key_is_reported_without_the_key(self):
        app = plugin.live_app(live(app={"api_key": SECRET, "disable_streaming": False}))
        self.assertEqual(app["key_form"], "literal")
        self.assertNotIn(SECRET, json.dumps(app))
        self.assertEqual(plugin.live_app(live(app={}))["key_form"], "missing")
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `uv run --frozen python -m unittest tests.test_plugin_settings -v`
Expected: FAIL with `ImportError: cannot import name 'plugin'`.

- [ ] **Step 4: Add the configuration rows**

In `src/config.py`, after the Phase 2 CrowdSec block:

```python
# Phase 3, CrowdSec plugin mode (docs/security.md#crowdsec-plugin). The plugin's
# own key (CROWDSEC_PLUGIN_BOUNCER_KEY) belongs to the Caddy container and is
# never read here: the console only needs the secret's path, if one is used, to
# offer the matching {file.<path>} placeholder. CADDY_ADMIN_ADDRESS is the admin
# bind health checks and recovery use; the plugin overlay sets the fixed
# caddy-admin address. Both are validated by src/bans/plugin.py at startup.
CROWDSEC_PLUGIN_BOUNCER_KEY_FILE = os.environ.get("CROWDSEC_PLUGIN_BOUNCER_KEY_FILE", "").strip()
CADDY_ADMIN_ADDRESS = os.environ.get("CADDY_ADMIN_ADDRESS", "").strip() or "0.0.0.0:2019"
```

In `src/bans/service.py` `init_config()`, after the CrowdSec checks:

```python
    try:
        plugin.parse_key_file(config.CROWDSEC_PLUGIN_BOUNCER_KEY_FILE)
        plugin.parse_admin_address(config.CADDY_ADMIN_ADDRESS)
    except plugin.ConfigError as e:
        raise RuntimeError(str(e)) from e
```

and add `plugin` to the `from . import ...` line.

- [ ] **Step 5: Write `src/bans/plugin.py`**

```python
"""CrowdSec plugin mode from the console's side (spec 3.1-3.6).

The console never holds the plugin's bouncer key. It knows only whether the
key comes from the environment or a file, and that file's path, so it can offer
the matching placeholder. Everything else is read from Caddy: whether the
running build has the module (an /adapt probe, which provisions nothing and so
contacts no LAPI), where the admin API listens and whether the global crowdsec
app is loaded (GET /config/).
"""
import ipaddress
import re
import socket
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from .. import config
from . import caddy as caddy_admin
from . import protected

DEFAULT_KEY_FILE = "/run/secrets/crowdsec_plugin_bouncer_key"
ENV_PLACEHOLDER = "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}"
API_URL = "http://crowdsec:8080"
TICKER_INTERVAL = "10s"
# Same rule as caddy-plugin/preflight/check.go keyPath.
_KEY_PATH = re.compile(r"^/(?:[A-Za-z0-9_][A-Za-z0-9._-]*/)*[A-Za-z0-9_][A-Za-z0-9._-]*\Z")
_ADMIN = re.compile(r"^(?:\[([0-9A-Fa-f:.]+)\]|([0-9.]+)|([A-Za-z0-9.-]*)):([0-9]{1,5})\Z")
_UNRECOGNIZED = re.compile(r"unrecognized global option:?\s*crowdsec", re.I)
PROBE_TEXT = ("{\n\tcrowdsec {\n\t\tapi_url http://crowdsec.invalid:8080\n"
              "\t\tapi_key caddy-console-module-probe\n\t}\n}\n")
MODULE_TTL = 300.0
MODULE_UNKNOWN_TTL = 30.0
LAPI_TTL = 60.0

_lock = threading.Lock()
_cache = {}


class ConfigError(ValueError):
    pass


def parse_key_file(raw) -> str:
    text = (raw or "").strip()
    if not text:
        return ""
    if len(text) > 255 or not _KEY_PATH.match(text) or any(s in (".", "..") for s in text[1:].split("/")):
        raise ConfigError("CROWDSEC_PLUGIN_BOUNCER_KEY_FILE must be an absolute path such as "
                          f"{DEFAULT_KEY_FILE} (letters, digits, '.', '_', '-' and '/')")
    return text


@dataclass(frozen=True)
class AdminAddress:
    host: str
    port: int
    fixed: bool

    def __str__(self) -> str:
        return f"[{self.host}]:{self.port}" if ":" in self.host else f"{self.host}:{self.port}"


def parse_admin_address(raw) -> AdminAddress:
    text = (raw or "").strip() or "0.0.0.0:2019"
    m = _ADMIN.match(text)
    if not m or not 0 < int(m.group(4)) < 65536:
        raise ConfigError("CADDY_ADMIN_ADDRESS must be host:port, for example 172.30.250.2:2019")
    port = int(m.group(4))
    if m.group(3) is not None:
        return AdminAddress(m.group(3), port, False)          # a name, or "" for ":2019"
    try:
        ip = ipaddress.ip_address(m.group(1) or m.group(2))
    except ValueError:
        raise ConfigError("CADDY_ADMIN_ADDRESS must be host:port, for example 172.30.250.2:2019") from None
    fixed = not (ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local)
    return AdminAddress(str(ip), port, fixed)


def admin_address() -> AdminAddress:
    return parse_admin_address(config.CADDY_ADMIN_ADDRESS)


def key_file() -> str:
    return parse_key_file(config.CROWDSEC_PLUGIN_BOUNCER_KEY_FILE)


def key_mode() -> str:
    return "file" if key_file() else "env"


def api_key_placeholder() -> str:
    path = key_file()
    return f"{{file.{path}}}" if path else ENV_PLACEHOLDER


# --- module probe -------------------------------------------------------------------

def reset_cache() -> None:
    with _lock:
        _cache.clear()


def cached_module():
    """The last probe result without probing: for code under caddyfile_lock()."""
    with _lock:
        hit = _cache.get("module")
    return hit[0] if hit else None


def module_available(force=False):
    """True/False: does the running Caddy build have the crowdsec module? None
    when that cannot be told (Caddy unreachable or an unrelated adapt error).
    Never call this while holding caddyfile_lock(): it talks to Caddy."""
    now = time.monotonic()
    with _lock:
        hit = _cache.get("module")
        if hit and not force and now - hit[1] < (MODULE_TTL if hit[0] is not None else MODULE_UNKNOWN_TTL):
            return hit[0]
    try:
        result = caddy_admin.adapt(PROBE_TEXT)
        value = True if result.ok else (False if _UNRECOGNIZED.search(result.message or "") else None)
    except caddy_admin.CaddyUnavailable:
        value = None
    with _lock:
        _cache["module"] = (value, time.monotonic())
    return value


# --- admin exposure (spec 3.1) ----------------------------------------------------------

@dataclass(frozen=True)
class AdminProblem:
    code: str
    message: str


def _lapi_addresses() -> list:
    """CrowdSec's addresses as the console resolves CROWDSEC_URL, cached briefly."""
    host = urlsplit(config.CROWDSEC_URL or "").hostname
    if not host:
        return []
    with _lock:
        hit = _cache.get("lapi")
        if hit and hit[0] == host and time.monotonic() - hit[2] < LAPI_TTL:
            return hit[1]
    try:
        found = sorted({ipaddress.ip_address(i[4][0]) for i in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)},
                       key=str)
    except (OSError, ValueError):
        found = []
    with _lock:
        _cache["lapi"] = (host, found, time.monotonic())
    return found


def _listen(live):
    admin = (live or {}).get("admin")
    if not isinstance(admin, dict):
        return "", []
    if admin.get("disabled"):
        return "off", []
    origins = admin.get("origins") if isinstance(admin.get("origins"), list) else []
    return str(admin.get("listen") or "").removeprefix("tcp/"), [str(o) for o in origins]


def admin_problem(live):
    """None when Caddy's running admin bind is the fixed caddy-admin address,
    lists it in origins and shares no network with CrowdSec; otherwise what is
    wrong and the bind to use. Plugin activation is refused while this is set."""
    want = admin_address()
    if not want.fixed:
        return AdminProblem("admin_not_fixed",
                            f"The console's CADDY_ADMIN_ADDRESS is {want}, not Caddy's fixed caddy-admin address. "
                            "Start it with docker-compose.crowdsec-plugin.yaml, which sets 172.30.250.2:2019.")
    hint = f"Use admin {want} {{ origins caddy:2019 {want} }} in the global options, then Save & Reload."
    listen, origins = _listen(live)
    if listen == "":
        return AdminProblem("admin_missing", "Caddy's running config has no admin listener, so it listens on "
                            f"localhost:2019 only. {hint}")
    if listen == "off":
        return AdminProblem("admin_off", f"Caddy's admin API is turned off. {hint}")
    if listen.startswith("unix/"):
        return AdminProblem("admin_unix", f"Caddy's admin API is a unix socket. {hint}")
    host, _, port = listen.rpartition(":")
    host = host.strip("[]")
    if host == "":
        return AdminProblem("admin_wildcard", f"Caddy's admin API listens on every interface ({listen}), "
                            f"so CrowdSec could reach it. {hint}")
    if host == "localhost":
        return AdminProblem("admin_loopback", f"Caddy's admin API listens on loopback only ({listen}). {hint}")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return AdminProblem("admin_mismatch", f"Caddy's admin API listens on {listen}, not {want}. {hint}")
    if ip.is_unspecified:
        return AdminProblem("admin_wildcard", f"Caddy's admin API listens on every interface ({listen}), "
                            f"so CrowdSec could reach it. {hint}")
    if ip.is_loopback:
        return AdminProblem("admin_loopback", f"Caddy's admin API listens on loopback only ({listen}). {hint}")
    if str(ip) != want.host or port != str(want.port):
        return AdminProblem("admin_mismatch", f"Caddy's admin API listens on {listen}, not {want}. {hint}")
    if str(want) not in origins:
        return AdminProblem("admin_origins", f"Caddy's admin origins do not list {want}. {hint}")
    for net in protected.read_docker_networks():
        if ip in net and any(a in net for a in _lapi_addresses()):
            return AdminProblem("admin_shared", f"Caddy's admin address {want} is on a network CrowdSec also "
                                f"joins ({net}). caddy-admin must be shared only with the console.")
    return None


def live_app(live):
    """The running global crowdsec app, without its key: only whether the key
    is the expected placeholder, another placeholder, missing, or written in."""
    app = ((live or {}).get("apps") or {}).get("crowdsec")
    if not isinstance(app, dict):
        return None
    key = app.get("api_key")
    expected = api_key_placeholder()
    if not key:
        form = "missing"
    elif key == expected:
        form = "expected"
    elif isinstance(key, str) and key.startswith(("{env.", "{file.")) and key.endswith("}") and len(key) <= 300:
        form = "placeholder"
    else:
        form = "literal"
    return {"api_url": str(app.get("api_url") or "")[:200],
            "ticker_interval": str(app.get("ticker_interval") or "60s")[:20],
            "streaming": app.get("enable_streaming") is not False,
            "hard_fails": app.get("enable_hard_fails") is True,
            "key_form": form, "key_placeholder": key if form == "placeholder" else None}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `uv run --frozen python -m unittest tests.test_plugin_settings -v`
Expected: PASS. Then the full Python suite. Expected: PASS (FakeCaddy only rejects text with a `crowdsec {` block, which no earlier test sends).

- [ ] **Step 7: Commit**

```bash
git add src/config.py src/bans/plugin.py src/bans/service.py tests/_bans.py tests/test_plugin_settings.py
git commit -m "feat(crowdsec-plugin): plugin settings, module probe and admin exposure check"
```

---
### Task 4: The protected route definition and its transaction

`BANS_DIR/crowdsec-plugin-protect.caddy` holds the reusable `(protect_crowdsec)` snippet whose `not client_ip` line is the complete protected set (spec 3.4). It is a policy file owned by its own state file `BACKUP_DIR/plugin-policy.json`, so it joins the Phase 1 journaled transaction: every change that alters a dependency (manual mutation with a new verified address, management expiry, CrowdSec sync, Re-apply) rewrites it in the same journal as the other files. A fresh plugin install with no other change gets it from the expiry tick, alone.

**Files:**
- Create: `src/bans/pluginpolicy.py`
- Modify: `src/bans/render.py` (`PluginRoute`, `PLUGIN`, `render_plugin_route`)
- Modify: `src/bans/service.py` (`_plugin_active`, `_plugin_changes`, `_holds`, `_candidates`, `reapply`, `expire_tick`, `_recovery_info_locked`, `availability`)
- Modify: `src/bans/plugin.py` (`allowlist_commands`)
- Test: `tests/test_plugin_policy.py`

**Interfaces:**
- Consumes: `plugin.cached_module()`, `plugin.module_available()` (Task 3).
- Produces:
  - `render.PLUGIN` (`PluginRoute`): `.filename = "crowdsec-plugin-protect.caddy"`, `.marker = "caddy_console_plugin_protect"`, `.matcher = "caddy_console_crowdsec_candidate"`, `.snippet = "protect_crowdsec"`, `.path`, `.glob`, `.import_line` (`import <BANS_DIR>/crowdsec-plugin-protect*.caddy`), `.site_import` (`import protect_crowdsec`).
  - `render.render_plugin_route(exclusion_tokens) -> bytes`.
  - `pluginpolicy.PATH`, `pluginpolicy.VERSION = 1`, `pluginpolicy.SCHEMA = 1`, `recorded_hash() -> str | None`, `exists() -> bool`, `dumps(policy_hash) -> bytes`.
  - `service._plugin_active() -> bool`; hold name `"plugin"` in `_holds()`; Re-apply accepts `{"source": "plugin"}`; `service.plugin_route_current(state) -> bool`.
  - `plugin.allowlist_commands(protected) -> str` (copy-only `cscli` lines).
  - Audit action `plugin_route_rendered` (detail: protected-range count and short hash).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_plugin_policy.py`:

```python
"""The protected plugin route and plugin-policy.json (spec 3.4).

Run with:  uv run --frozen python -m unittest tests.test_plugin_policy -v
"""
import json
import os
import unittest
from unittest import mock

import tests._env as env
from tests import _bans, _crowdsec

from src import audit, config
from src.bans import fsio, plugin, pluginpolicy, protected, render, service, store, txn

D = env.BANS_DIR
PLUGIN_SITES = (
    "{{\n\tadmin 172.30.250.2:2019 {{\n\t\torigins caddy:2019 172.30.250.2:2019\n\t}}\n}}\n"
    "import {d}/crowdsec-plugin-protect*.caddy\n\n"
    "example.com {{\n\timport {d}/bans-manual*.caddy\n\timport protect_crowdsec\n\trespond 200\n}}\n").format(d=D)
BASE_TOKENS = "private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10"


class PluginCase(unittest.TestCase):
    def setUp(self):
        _bans.reset(PLUGIN_SITES)
        _bans.fresh_audit(self)
        service.reset_caches()
        plugin.reset_cache()
        self.addCleanup(service.reset_caches)
        self.addCleanup(plugin.reset_cache)
        docker = mock.patch.object(protected, "read_docker_networks", lambda: [])
        docker.start()
        self.addCleanup(docker.stop)
        self.caddy = _bans.FakeCaddy().install(self)
        self.caddy.plugin = True
        self.lapi = _crowdsec.FakeLapi().install(self)
        _crowdsec.enable(self)
        self.assertIs(plugin.module_available(force=True), True)

    def route(self):
        return (fsio.read_bytes(render.PLUGIN.path) or b"").decode()


class RenderTest(unittest.TestCase):
    def test_route_shape(self):
        data = render.render_plugin_route(["private_ranges", "100.64.0.0/10", "203.0.113.50"]).decode()
        self.assertEqual(data, (
            "# Managed by Caddy Console. Do not edit; changes are overwritten.\n"
            "(protect_crowdsec) {\n"
            "\tvars caddy_console_plugin_protect 1\n"
            "\t@caddy_console_crowdsec_candidate {\n"
            "\t\tnot client_ip private_ranges 100.64.0.0/10 203.0.113.50\n"
            "\t}\n"
            "\tcrowdsec @caddy_console_crowdsec_candidate\n"
            "}\n"))
        self.assertEqual(render.PLUGIN.import_line, f"import {D}/crowdsec-plugin-protect*.caddy")
        self.assertEqual(render.PLUGIN.site_import, "import protect_crowdsec")

    def test_state_file_embeds_the_hash(self):
        doc = json.loads(pluginpolicy.dumps("sha256:" + "a" * 64))
        self.assertEqual(doc, {"version": 1, "schema": 1,
                               "last_rendered_hashes": {"crowdsec-plugin-protect.caddy": "sha256:" + "a" * 64}})


class TransactionTest(PluginCase):
    def test_fresh_install_gets_the_route_from_the_expiry_tick(self):
        self.assertEqual(service.expire_tick(), "applied")
        self.assertIn(f"not client_ip {BASE_TOKENS}\n", self.route())
        self.assertEqual(pluginpolicy.recorded_hash(), fsio.sha256_tag(fsio.read_bytes(render.PLUGIN.path)))
        self.assertFalse(os.path.exists(store.STATE_PATH), "a plugin-only render writes no ban state")
        self.assertFalse(os.path.exists(render.SOURCES["manual"].path))
        self.assertEqual(oct(os.stat(render.PLUGIN.path).st_mode & 0o777), "0o644")
        self.assertEqual(oct(os.stat(pluginpolicy.PATH).st_mode & 0o777), "0o600")
        self.assertIn("load", [k for k, _ in self.caddy.calls], "the Caddyfile imports the definition: reload")
        self.assertIn("plugin_route_rendered", [e["action"] for e in audit.iter_entries()])
        self.assertEqual(service.expire_tick(), "idle")

    def test_manual_ban_regenerates_the_plugin_route_in_the_same_transaction(self):
        service.expire_tick()
        seen = []
        real = txn.apply_locked

        def spy(changes, **kw):
            seen.append(sorted(os.path.basename(c.path) for c in changes))
            return real(changes, **kw)
        with mock.patch.object(txn, "apply_locked", spy):
            body, status = service.add_ban({"value": "198.51.100.7", "duration": "24h", "reason": ""},
                                           "a@example.com", "203.0.113.50")
        self.assertEqual(status, 201, body)
        self.assertEqual(len(seen), 1, "one journal for the ban and the route")
        self.assertLessEqual({"bans-manual.caddy", "bans.json", "crowdsec-plugin-protect.caddy", "plugin-policy.json"},
                             set(seen[0]))
        self.assertIn(" 203.0.113.50\n", self.route(), "the new verified console address is protected")
        self.assertEqual(pluginpolicy.recorded_hash(), fsio.sha256_tag(fsio.read_bytes(render.PLUGIN.path)))

    def test_bans_never_change_is_picked_up_by_the_tick(self):
        service.expire_tick()
        with mock.patch.object(config, "BANS_NEVER", "192.0.2.10"):
            service.reset_caches()
            self.assertEqual(service.expire_tick(), "applied")
        self.assertIn(" 192.0.2.10\n", self.route())

    def test_out_of_band_edit_holds_the_route_until_reapply(self):
        service.expire_tick()
        with open(render.PLUGIN.path, "a", encoding="ascii") as f:
            f.write("# edited\n")
        state = store.load()
        self.assertEqual(service._holds(state), {"plugin": "differs"})
        self.assertEqual(service.expire_tick(), "idle")
        self.assertTrue(self.route().endswith("# edited\n"))
        info = service.recovery_info()
        self.assertEqual((info["kind"], info["files"], info["held_sources"]),
                         ("policy_hold", ["crowdsec-plugin-protect.caddy"], ["plugin"]))
        body, status = service.reapply({"source": "plugin"}, "a@example.com", None)
        self.assertEqual(status, 200, body)
        self.assertFalse(self.route().endswith("# edited\n"))
        self.assertEqual(service._holds(store.load()), {})

    def test_a_corrupt_plugin_policy_holds_instead_of_regenerating(self):
        service.expire_tick()
        with open(pluginpolicy.PATH, "w", encoding="utf-8") as f:
            f.write("{not json")
        self.assertIsNone(pluginpolicy.recorded_hash())
        self.assertEqual(service._holds(store.load()), {"plugin": "differs"})

    def test_deleted_route_file_is_held_as_missing(self):
        service.expire_tick()
        os.remove(render.PLUGIN.path)
        self.assertEqual(service._holds(store.load()), {"plugin": "missing"})

    def test_crowdsec_sync_keeps_the_route_current(self):
        service.expire_tick()
        result = service.apply_crowdsec([_crowdsec.accepted("203.0.113.9")])
        self.assertTrue(result.ok, result.message)
        self.assertEqual(pluginpolicy.recorded_hash(), fsio.sha256_tag(fsio.read_bytes(render.PLUGIN.path)))

    def test_reapply_plugin_is_refused_when_not_in_use(self):
        self.caddy.plugin = False
        plugin.module_available(force=True)
        body, status = service.reapply({"source": "plugin"}, "a@example.com", None)
        self.assertEqual((status, body["code"]), (400, "source_not_enabled"))


class InactiveTest(unittest.TestCase):
    def test_stock_caddy_never_gets_the_route(self):
        _bans.reset()
        service.reset_caches()
        plugin.reset_cache()
        self.addCleanup(plugin.reset_cache)
        caddy = _bans.FakeCaddy().install(self)
        _crowdsec.FakeLapi().install(self)
        _crowdsec.enable(self)
        docker = mock.patch.object(protected, "read_docker_networks", lambda: [])
        docker.start()
        self.addCleanup(docker.stop)
        self.assertEqual(service.expire_tick(), "idle")
        self.assertFalse(os.path.exists(render.PLUGIN.path))
        self.assertFalse(os.path.exists(pluginpolicy.PATH))
        self.assertFalse(service._plugin_active())
        self.assertFalse(any(k == "load" for k, _ in caddy.calls))


class AllowlistTest(unittest.TestCase):
    def test_commands_use_the_static_protected_set_only(self):
        prot = protected.build(never=[protected.addr.canonical("192.0.2.10")],
                               management=[protected.addr.canonical("203.0.113.50")],
                               docker=["172.30.250.0/29"])
        text = plugin.allowlist_commands(prot)
        lines = text.splitlines()
        self.assertEqual(lines[0], "cscli allowlists delete caddy_console_protected || true")
        self.assertEqual(lines[1], "cscli allowlists create caddy_console_protected -d 'Caddy Console protected ranges'")
        self.assertTrue(lines[2].startswith("cscli allowlists add caddy_console_protected 127.0.0.0/8 ::1 10.0.0.0/8"))
        self.assertIn(" 192.0.2.10", lines[2])
        self.assertIn(" 172.30.250.0/29", lines[2])
        self.assertNotIn("203.0.113.50", text, "verified console addresses change at runtime: not in the static list")
        self.assertNotIn("private_ranges", text)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run --frozen python -m unittest tests.test_plugin_policy -v`
Expected: FAIL with `ImportError: cannot import name 'pluginpolicy'`.

- [ ] **Step 3: Render the route**

Append to `src/bans/render.py`:

```python
@dataclass(frozen=True)
class PluginRoute:
    """The reusable protected route for plugin mode (spec 3.4). Not a ban
    source: it holds no records, only the protected set, and its state lives
    in BACKUP_DIR/plugin-policy.json (src/bans/pluginpolicy.py)."""
    filename: str = "crowdsec-plugin-protect.caddy"
    marker: str = "caddy_console_plugin_protect"
    matcher: str = "caddy_console_crowdsec_candidate"
    snippet: str = "protect_crowdsec"

    @property
    def glob(self) -> str:
        return self.filename[: -len(".caddy")] + "*.caddy"

    @property
    def path(self) -> str:
        return os.path.join(config.BANS_DIR, self.filename)

    @property
    def import_line(self) -> str:
        return f"import {os.path.join(config.BANS_DIR, self.glob)}"

    @property
    def site_import(self) -> str:
        return f"import {self.snippet}"


PLUGIN = PluginRoute()


def render_plugin_route(exclusion_tokens) -> bytes:
    """The vars marker lets live JSON show which sites imported the snippet
    (matcher names do not survive adaptation); the matcher keeps every
    protected client away from the plugin, whatever LAPI decided."""
    return "".join([
        HEADER,
        f"({PLUGIN.snippet}) {{\n",
        f"\tvars {PLUGIN.marker} 1\n",
        f"\t@{PLUGIN.matcher} {{\n",
        "\t\tnot client_ip " + " ".join(exclusion_tokens) + "\n",
        "\t}\n",
        f"\tcrowdsec @{PLUGIN.matcher}\n",
        "}\n",
    ]).encode("ascii")
```

- [ ] **Step 4: Write the state file module**

Create `src/bans/pluginpolicy.py`:

```python
"""BACKUP_DIR/plugin-policy.json: schema version and last rendered hash of
BANS_DIR/crowdsec-plugin-protect.caddy (spec 1.1, 3.4).

A transaction state file in the Phase 1 sense: it owns the route file and
embeds its candidate hash (txn._check_embedded_hashes). An unreadable file
records nothing, so an existing route file is held until Re-apply rather
than silently regenerated.
"""
import json
import os

from ..config import BACKUP_DIR
from .render import PLUGIN

PATH = os.path.join(BACKUP_DIR, "plugin-policy.json")
VERSION = 1
SCHEMA = 1                       # the layout render.render_plugin_route() writes
MAX_BYTES = 64 * 1024


def exists() -> bool:
    return os.path.exists(PATH)


def recorded_hash():
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
    if not isinstance(doc, dict) or doc.get("version") != VERSION or doc.get("schema") != SCHEMA:
        return None
    hashes = doc.get("last_rendered_hashes")
    value = hashes.get(PLUGIN.filename) if isinstance(hashes, dict) else None
    return value if isinstance(value, str) else None


def dumps(policy_hash: str) -> bytes:
    doc = {"version": VERSION, "schema": SCHEMA, "last_rendered_hashes": {PLUGIN.filename: policy_hash}}
    return (json.dumps(doc, sort_keys=True, indent=1) + "\n").encode("utf-8")
```

- [ ] **Step 5: Wire it into the service**

In `src/bans/service.py` add `plugin, pluginpolicy` to the `from . import ...` line, then:

```python
def _plugin_active() -> bool:
    """Render the protected route once the running Caddy has the module (with
    CrowdSec configured), or once it left something behind (the file or its
    recorded hash), so a Re-apply still manages it after the plugin is gone.
    Only the cached probe result is used: this runs under caddyfile_lock()."""
    if not config.BANS_ENABLED:
        return False
    return ((lapi.enabled() and plugin.cached_module() is True)
            or os.path.exists(render.PLUGIN.path) or pluginpolicy.exists())


def _plugin_changes(prot) -> list:
    data = render.render_plugin_route(prot.exclusion_tokens())
    return [txn.Change(render.PLUGIN.path, "policy", data, marker=render.PLUGIN.marker),
            txn.Change(pluginpolicy.PATH, "state", pluginpolicy.dumps(fsio.sha256_tag(data)),
                       owns=(render.PLUGIN.filename,))]


def plugin_route_current(state) -> bool:
    """The route file on disk equals what the current protected set renders."""
    want = render.render_plugin_route(protected_for(state).exclusion_tokens())
    return fsio.read_bytes(render.PLUGIN.path) == want


def _policy_filename(name) -> str:
    return render.PLUGIN.filename if name == "plugin" else render.SOURCES[name].filename
```

`availability()`: refresh the module probe before anything takes the lock (it is cached; with CrowdSec off it never probes):

```python
def availability(force=False, background=False) -> Availability:
    ...
    if lapi.enabled():
        plugin.module_available()            # outside caddyfile_lock(); cached
    now = time.monotonic()
    ...
```

(put the two new lines first in the function body, after the docstring).

`_holds(state)`: after the loop over sources:

```python
    if _plugin_active():
        recorded = pluginpolicy.recorded_hash()
        actual = fsio.sha256_tag(fsio.read_bytes(render.PLUGIN.path))
        if recorded != actual and not (recorded is None and actual is None):
            out["plugin"] = "missing" if actual is None else "differs"
    return out
```

`_candidates(...)`: before the `bans.json` state change is appended:

```python
    if _plugin_active() and "plugin" not in holds:
        changes += _plugin_changes(prot)
```

`reapply(...)`:

```python
    if source not in render.SOURCES and source != "plugin":
        return _error("invalid_source", "Unknown policy source.", 400)

    def mutate(state, now, version):
        active = _plugin_active() if source == "plugin" else source in render.active_sources(state)
        if not active:
            raise BanError("source_not_enabled", f"The {source} source is not in use.", 400)
        return Mutation({"source": source}, 200, [("bans_reapply", source)])
```

`_recovery_info_locked()`: in the `policy_hold` branch use `"files": [_policy_filename(n) for n in sorted(holds)]`.

`expire_tick(...)`: replace the `if not removed and not aged: return "idle"` line and what follows with:

```python
        if not removed and not aged:
            if "plugin" in holds or not _plugin_active() or plugin_route_current(state):
                return "idle"
            # Only the plugin route is out of date (first start, BANS_NEVER or
            # Docker networks changed): render it alone, writing no ban state.
            changes = _plugin_changes(protected_for(state))
            outcome = txn.apply_locked(changes, actor="system", source="plugin",
                                       audit_events=[("plugin_route_rendered", _route_detail(changes[0].data))])
            return "applied" if outcome.ok else outcome.code
        try:
            changes = _candidates(state, protected_for(state), holds, now)
        ...
```

and add the helper:

```python
def _route_detail(data: bytes) -> str:
    line = next((l for l in data.decode("ascii").splitlines() if l.strip().startswith("not client_ip ")), "")
    return f"{len(line.split()) - 2} protected ranges, {fsio.sha256_tag(data)[7:19]}"
```

When the route changes as part of another transaction, no extra event is added: that transaction's own audit events and txn's `bans_policy_applied` already record it. `plugin_route_rendered` is written only by the tick's route-only render.

- [ ] **Step 6: Generate the allowlist commands**

Append to `src/bans/plugin.py`:

```python
ALLOWLIST = "caddy_console_protected"


def allowlist_commands(prot) -> str:
    """Copy-only commands for a CrowdSec LAPI allowlist with the static
    protected set (core ranges, BANS_NEVER, Docker networks). Defense in depth
    only (spec 3.4): allowlists stop new decisions but keep existing ones, and
    verified console addresses change at runtime, so they are left out."""
    from . import addr
    values = [addr.token(n) for cat, n in prot.entries if cat not in ("operator", "profile")]
    seen = list(dict.fromkeys(values))
    return "\n".join([
        f"cscli allowlists delete {ALLOWLIST} || true",
        f"cscli allowlists create {ALLOWLIST} -d 'Caddy Console protected ranges'",
        f"cscli allowlists add {ALLOWLIST} " + " ".join(seen),
    ]) + "\n"
```

(`protected.CORE` lists loopback first, so the `add` line starts `127.0.0.0/8 ::1 10.0.0.0/8`.)

- [ ] **Step 7: Run the tests to verify they pass**

Run: `uv run --frozen python -m unittest tests.test_plugin_policy -v`
Expected: PASS.

Then the full Python suite. If an existing Phase 1/2 test asserts an exact list of FakeCaddy calls while CrowdSec is enabled, the new probe adds one `adapt` whose text contains `caddy-console-module-probe`: filter those out in that test's helper (do not change the probe).
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/bans/render.py src/bans/pluginpolicy.py src/bans/service.py src/bans/plugin.py tests/test_plugin_policy.py
git commit -m "feat(crowdsec-plugin): protected route definition rendered through the shared ban transaction"
```

---
### Task 5: Plugin detection per site and the plugin part of the Security API

The Security view must say, per site, whether CrowdSec decisions reach it through the file, the plugin, both or neither (spec 3.5), proven from the live JSON: `http.handlers.crowdsec` in the site's effective order, inside a route whose `not client_ip` matcher is the current protected set. A global `crowdsec` app with no per-site handler is not enforcement. The plugin handler also only blocks, so it must not turn the manual or CrowdSec file policy into "pre-handler present".

**Files:**
- Create: `tests/integration/make_plugin_fixtures.sh`, `tests/fixtures/bans/adapted-plugin-layouts.json` (generated, committed)
- Modify: `src/bans/detect.py` (`classify`, `PRIVATE_RANGES`, `expand_tokens`, `plugin_site_statuses`)
- Modify: `src/bans/scan.py` (`block_import_state(..., snippet=None)`)
- Modify: `src/bans/service.py` (`_site_rows`, `_plugin_status`, `status`)
- Test: `tests/test_plugin_status.py`

**Interfaces:**
- Consumes: `render.PLUGIN`, `service._plugin_active()`, `service.plugin_route_current()` (Task 4); `plugin.cached_module()`, `plugin.admin_problem()`, `plugin.live_app()`, `plugin.allowlist_commands()` (Tasks 3-4).
- Produces:
  - `detect.plugin_site_statuses(config, *, expected_exclusions=None) -> list[SiteStatus]`, same order as `detect.site_statuses`. Statuses: `enforced`, `enforced_pre_handler`, `unknown` (including an out-of-date protected set), `plugin_unprotected`, `not_imported`.
  - `detect.expand_tokens(tokens) -> list[str]` (`private_ranges` → Caddy's CIDRs).
  - `scan.block_import_state(text, block, path, after=(), snippet=None)`: with `snippet`, an import counts when its token equals that snippet name.
  - Site rows gain `policies["plugin"]` (same shape as other policies) whenever the plugin is active or the live config has a crowdsec handler.
  - `GET /api/security` gains `"plugin"`: `{"enabled": false}` or `{"enabled": true, "module": bool|null, "refused": bool, "admin": {"code","message"}|null, "app": <live_app>|null, "key_mode", "key_file", "placeholder", "ticker_interval", "definition": {"file", "import_line", "site_import", "present", "hash", "current", "hold", "hold_reason", "imported"}, "allowlist", "check_command"}`.

- [ ] **Step 1: Generate the adapted fixtures with the built plugin binary**

Create `tests/integration/make_plugin_fixtures.sh` (mode 0755):

```bash
#!/usr/bin/env bash
# Adapt representative plugin layouts with the plugin image and print the JSON
# (only `caddy adapt`; nothing runs):
#   ./dev/build-plugin-image.sh crowdsec
#   tests/integration/make_plugin_fixtures.sh caddy-crowdsec:local > tests/fixtures/bans/adapted-plugin-layouts.json
set -euo pipefail
cd "$(dirname "$0")/../.."
IMAGE="${1:?usage: make_plugin_fixtures.sh IMAGE}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
H='# Managed by Caddy Console. Do not edit; changes are overwritten.'
route() {   # $1: dir, $2: exclusion tokens
  mkdir -p "$tmp/fx/$1"
  printf '%s\n(protect_crowdsec) {\n\tvars caddy_console_plugin_protect 1\n\t@caddy_console_crowdsec_candidate {\n\t\tnot client_ip %s\n\t}\n\tcrowdsec @caddy_console_crowdsec_candidate\n}\n' "$H" "$2" \
    > "$tmp/fx/$1/crowdsec-plugin-protect.caddy"
}
route current "private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10"
route old "private_ranges 100.64.0.0/10 169.254.0.0/16"
printf '%s\nvars caddy_console_manual_policy 1\n@caddy_console_manual_banned {\n\tclient_ip 198.51.100.0/24 203.0.113.7\n\tnot client_ip private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10\n}\nhandle @caddy_console_manual_banned {\n\trespond 403\n}\n' "$H" \
  > "$tmp/fx/current/bans-manual.caddy"
printf '%s\nvars caddy_console_crowdsec_policy 1\n@caddy_console_crowdsec_banned {\n\tclient_ip 192.0.2.0/24 203.0.113.9\n\tnot client_ip private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10\n}\nhandle @caddy_console_crowdsec_banned {\n\trespond 403\n}\n' "$H" \
  > "$tmp/fx/current/bans-crowdsec.caddy"
G='{
	admin 0.0.0.0:2019
	crowdsec {
		api_url http://crowdsec:8080
		api_key {env.CROWDSEC_PLUGIN_BOUNCER_KEY}
		ticker_interval 10s
	}
	order crowdsec first
}
'
M='import /etc/caddy/fx/current/bans-manual*.caddy'
C='import /etc/caddy/fx/current/bans-crowdsec*.caddy'
layout() {  # $1: name, $2: route dir, $3: site body
  printf '%simport /etc/caddy/fx/%s/crowdsec-plugin-protect*.caddy\n\na.example.com {\n%s}\n' "$G" "$2" "$3" > "$tmp/$1.Caddyfile"
}
layout plugin_only current $'\timport protect_crowdsec\n\treverse_proxy 127.0.0.1:9\n'
layout manual_and_plugin current $'\t'"$M"$'\n\timport protect_crowdsec\n\treverse_proxy 127.0.0.1:9\n'
layout manual_crowdsec_and_plugin current $'\t'"$M"$'\n\t'"$C"$'\n\timport protect_crowdsec\n\treverse_proxy 127.0.0.1:9\n'
layout manual_and_crowdsec_file current $'\t'"$M"$'\n\t'"$C"$'\n\treverse_proxy 127.0.0.1:9\n'
layout bare_handler current $'\t'"$M"$'\n\tcrowdsec\n\treverse_proxy 127.0.0.1:9\n'
layout app_without_handler current $'\t'"$M"$'\n\treverse_proxy 127.0.0.1:9\n'
layout plugin_redir current $'\timport protect_crowdsec\n\tredir /old /new\n\treverse_proxy 127.0.0.1:9\n'
layout plugin_strict_route current $'\troute {\n\t\timport protect_crowdsec\n\t\t'"$M"$'\n\t\treverse_proxy 127.0.0.1:9\n\t}\n'
layout plugin_outdated old $'\timport protect_crowdsec\n\treverse_proxy 127.0.0.1:9\n'
out="$tmp/out"
mkdir "$out"
for f in "$tmp"/*.Caddyfile; do
  name="$(basename "$f" .Caddyfile)"
  docker run --rm -v "$tmp:/etc/caddy:ro" "$IMAGE" caddy adapt --config "/etc/caddy/$name.Caddyfile" \
    --adapter caddyfile > "$out/$name.json"
done
python3 - "$out" <<'PY'
import json, os, sys
d = sys.argv[1]
print(json.dumps({n[:-5]: json.load(open(os.path.join(d, n))) for n in sorted(os.listdir(d))}, indent=1, sort_keys=True))
PY
```

Run: `./dev/build-plugin-image.sh crowdsec && tests/integration/make_plugin_fixtures.sh caddy-crowdsec:local > tests/fixtures/bans/adapted-plugin-layouts.json`
Expected: a JSON object with the nine layout names. Open `plugin_only` and confirm the site subroute's first route is `{"match":[{"not":[{"client_ip":{"ranges":[...]}}]}],"handle":[{"handler":"crowdsec"}]}` with `private_ranges` expanded to `192.168.0.0/16 172.16.0.0/12 10.0.0.0/8 127.0.0.1/8 fd00::/8 ::1` and that a `vars` handler with `caddy_console_plugin_protect` follows. If the layout differs, the tests below are still the contract; adjust only `detect.py`.

- [ ] **Step 2: Write the failing tests**

Create `tests/test_plugin_status.py`:

```python
"""Per-site plugin detection and the plugin part of GET /api/security (spec 3.5,
"Mode detection and health").

Run with:  uv run --frozen python -m unittest tests.test_plugin_status -v
"""
import copy
import json
import os
import unittest
from unittest import mock

import tests._env as env
from tests import _bans, _crowdsec

from src import config
from src.bans import addr, detect, fsio, plugin, protected, render, scan, service, store

HERE = os.path.dirname(__file__)
with open(os.path.join(HERE, "fixtures", "bans", "adapted-plugin-layouts.json"), encoding="utf-8") as f:
    FX = json.load(f)
CURRENT = detect.expand_tokens(["private_ranges", "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10"])
MANUAL = render.SOURCES["manual"]
SECRET = "3f9a1c0b7e6d5a4f3e2d1c0b9a8f7e6d"
FIXED = "172.30.250.2:2019"


def plugin_status(name, expected=CURRENT):
    return detect.plugin_site_statuses(FX[name], expected_exclusions=expected)[0]


class DetectTest(unittest.TestCase):
    def test_expand_tokens(self):
        self.assertEqual(detect.expand_tokens(["private_ranges", "203.0.113.5"]),
                         ["192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8", "127.0.0.1/8", "fd00::/8", "::1",
                          "203.0.113.5"])

    def test_protected_route_is_enforced(self):
        for name in ("plugin_only", "manual_and_plugin", "plugin_redir", "plugin_strict_route"):
            s = plugin_status(name)
            self.assertEqual((s.status, s.pre_handlers), ("enforced", []), name)
        self.assertEqual(plugin_status("plugin_only", expected=None).status, "enforced")

    def test_bare_handler_is_plugin_unprotected(self):
        s = plugin_status("bare_handler")
        self.assertEqual(s.status, "plugin_unprotected")
        self.assertIn("import protect_crowdsec", s.detail)

    def test_a_global_app_without_a_site_handler_is_not_enforcement(self):
        self.assertIn("crowdsec", FX["app_without_handler"]["apps"])
        self.assertEqual(plugin_status("app_without_handler").status, "not_imported")
        self.assertEqual(plugin_status("manual_and_crowdsec_file").status, "not_imported")

    def test_an_outdated_protected_set_is_unknown(self):
        s = plugin_status("plugin_outdated")
        self.assertEqual(s.status, "unknown")
        self.assertIn("Re-apply", s.detail)

    def test_plugin_route_is_not_a_pre_handler_for_manual_bans(self):
        for name in ("manual_and_plugin", "manual_crowdsec_and_plugin", "bare_handler", "plugin_strict_route"):
            s = detect.site_statuses(FX[name], MANUAL, True,
                                     expected_ranges=["198.51.100.0/24", "203.0.113.7"])[0]
            self.assertEqual((s.status, s.pre_handlers), ("enforced", []), name)

    def test_rows_align_with_the_file_detection(self):
        for name, cfg in FX.items():
            self.assertEqual([s.label for s in detect.plugin_site_statuses(cfg)],
                             [s.label for s in detect.site_statuses(cfg, MANUAL, False)], name)


class ImportStateTest(unittest.TestCase):
    def test_snippet_import_position(self):
        d = env.BANS_DIR
        text = (f"a.example.com {{\n\timport {d}/bans-manual*.caddy\n\timport {d}/bans-crowdsec*.caddy\n"
                "\timport protect_crowdsec\n\trespond 200\n}\n")
        block = scan.site_blocks(text)[0]
        after = (render.SOURCES["manual"].path, render.SOURCES["crowdsec"].path)
        st = scan.block_import_state(text, block, None, after=after, snippet="protect_crowdsec")
        self.assertEqual((st["present"], st["line"], st["first_child"], st["layout"]), (True, 4, True, "site"))
        late = text.replace("\timport protect_crowdsec\n\trespond 200\n", "\trespond 200\n\timport protect_crowdsec\n")
        st = scan.block_import_state(late, scan.site_blocks(late)[0], None, after=after, snippet="protect_crowdsec")
        self.assertEqual((st["present"], st["first_child"]), (True, False))
        none = scan.block_import_state("a.example.com {\n\trespond 200\n}\n", scan.site_blocks("a.example.com {\n\trespond 200\n}\n")[0],
                                       None, snippet="protect_crowdsec")
        self.assertFalse(none["present"])


class StatusCase(unittest.TestCase):
    SITE = ("{{\n\tadmin 172.30.250.2:2019 {{\n\t\torigins caddy:2019 172.30.250.2:2019\n\t}}\n}}\n"
            "import {d}/crowdsec-plugin-protect*.caddy\n\n"
            "a.example.com {{\n\timport {d}/bans-manual*.caddy\n\timport protect_crowdsec\n"
            "\treverse_proxy 127.0.0.1:9\n}}\n")

    def setUp(self):
        _bans.reset(self.SITE.format(d=env.BANS_DIR))
        service.reset_caches()
        plugin.reset_cache()
        self.addCleanup(service.reset_caches)
        self.addCleanup(plugin.reset_cache)
        for name, value in (("CADDY_ADMIN_ADDRESS", FIXED),):
            p = mock.patch.object(config, name, value)
            p.start()
            self.addCleanup(p.stop)
        docker = mock.patch.object(protected, "read_docker_networks", lambda: [])
        docker.start()
        self.addCleanup(docker.stop)
        self.caddy = _bans.FakeCaddy().install(self)
        self.caddy.plugin = True
        _crowdsec.FakeLapi().install(self)
        _crowdsec.enable(self)
        p = mock.patch.object(plugin, "_lapi_addresses", lambda: [])
        p.start()
        self.addCleanup(p.stop)
        now = store.utc_now()
        state = store.State()
        for v in ("198.51.100.0/24", "203.0.113.7"):
            state.records.append(store.new_manual_record(addr.canonical(v), "24h", "", "a@example.com", now))
        fsio.atomic_write(store.STATE_PATH, store.dumps(state), 0o600)
        plugin.module_available(force=True)
        self.assertEqual(service.expire_tick(), "applied")   # writes the route for the current protected set
        # Only now install the real adapted layout: FakeCaddy's /load replaced live above.
        live = copy.deepcopy(FX["manual_and_plugin"])
        live["admin"] = {"listen": "tcp/" + FIXED, "origins": ["caddy:2019", FIXED]}
        self.caddy.live = live

    def status(self):
        return service.status("203.0.113.200")


class StatusTest(StatusCase):
    def test_rows_report_the_plugin_path_per_site(self):
        row = next(r for r in self.status()["sites"] if r["label"] == "a.example.com")
        p = row["policies"]["plugin"]
        self.assertEqual(p["status"], "enforced")
        self.assertEqual((p["import"]["present"], p["import"]["first_child"]), (True, True))
        self.assertNotIn("plugin", self.status()["sources"], "plugin is not a ban source")

    def test_plugin_block(self):
        s = self.status()["plugin"]
        self.assertEqual((s["enabled"], s["module"], s["refused"], s["admin"]), (True, True, False, None))
        self.assertEqual((s["key_mode"], s["placeholder"], s["ticker_interval"]),
                         ("env", "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}", "10s"))
        d = s["definition"]
        self.assertEqual((d["present"], d["current"], d["hold"], d["imported"]), (True, True, False, True))
        self.assertEqual(d["import_line"], render.PLUGIN.import_line)
        self.assertEqual(len(d["hash"]), 12)
        self.assertIn("cscli allowlists add caddy_console_protected", s["allowlist"])
        self.assertIn("crowdsec/check-plugin-isolation.sh", s["check_command"])

    def test_a_wildcard_admin_refuses_activation(self):
        self.caddy.live["admin"] = {"listen": "tcp/0.0.0.0:2019"}
        s = self.status()["plugin"]
        self.assertEqual((s["refused"], s["admin"]["code"]), (True, "admin_wildcard"))

    def test_an_outdated_running_route_is_unknown(self):
        with mock.patch.object(config, "BANS_NEVER", "192.0.2.10"):
            service.reset_caches()
            row = next(r for r in self.status()["sites"] if r["label"] == "a.example.com")
        self.assertEqual(row["policies"]["plugin"]["status"], "unknown")

    def test_the_key_never_appears_in_status(self):
        self.caddy.live["apps"]["crowdsec"]["api_key"] = SECRET
        body = json.dumps(self.status())
        self.assertNotIn(SECRET, body)
        self.assertIn('"key_form": "literal"', body)

    def test_unreachable_caddy_marks_the_plugin_unknown_too(self):
        self.caddy.down = True
        row = next(r for r in self.status()["sites"] if r["label"] == "a.example.com")
        self.assertEqual(row["policies"]["plugin"]["status"], "caddy_unreachable")
        self.assertIsNone(self.status()["plugin"]["admin"])


class StockStatusTest(unittest.TestCase):
    def test_stock_caddy_has_no_plugin_block_or_rows(self):
        _bans.reset()
        service.reset_caches()
        plugin.reset_cache()
        self.addCleanup(plugin.reset_cache)
        _bans.FakeCaddy().install(self)
        docker = mock.patch.object(protected, "read_docker_networks", lambda: [])
        docker.start()
        self.addCleanup(docker.stop)
        s = service.status(None)
        self.assertEqual(s["plugin"], {"enabled": False})
        self.assertTrue(all("plugin" not in r["policies"] for r in s["sites"]))
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `uv run --frozen python -m unittest tests.test_plugin_status -v`
Expected: FAIL (`detect` has no `expand_tokens` / `plugin_site_statuses`; `block_import_state` has no `snippet`).

- [ ] **Step 4: Implement the detection**

In `src/bans/detect.py`:

```python
# Caddy's `private_ranges` shortcut as it appears in adapted JSON
# (caddyhttp.PrivateRangesCIDR in Caddy 2.11.9).
PRIVATE_RANGES = ("192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8", "127.0.0.1/8", "fd00::/8", "::1")


def expand_tokens(tokens) -> list:
    out = []
    for t in tokens:
        out.extend(PRIVATE_RANGES if t == "private_ranges" else (t,))
    return out
```

In `classify(h)`, before the final return:

```python
    if name == "crowdsec":
        # The plugin only blocks banned clients (spec 3.5): never an application
        # pre-handler for a file policy, wherever `order crowdsec first` puts it.
        return "benign", None
```

Append:

```python
PLUGIN_UNPROTECTED = ("The crowdsec handler runs here without import protect_crowdsec, so private, Docker and "
                      "BANS_NEVER addresses reach the plugin. Replace the crowdsec line with import protect_crowdsec.")
PLUGIN_OUTDATED = ("The running protected route is older than the current protected set. Use Re-apply for the "
                   "plugin route in Security.")


def _protect_ranges(route):
    """The union of `not client_ip` ranges in the route's matchers, or None."""
    found = None
    for m in route.get("match") or []:
        if not isinstance(m, dict):
            continue
        for n in m.get("not") or []:
            nets = _client_ip_ranges(n)
            if nets:
                found = (found or set()) | nets
    return found


def _plugin_status(route, label, hosts, server, expected=None) -> SiteStatus:
    events = []
    _events(route, events, id(route))
    s = SiteStatus(label, hosts, server, "not_imported")
    at = next((i for i, (k, v, _, _) in enumerate(events) if k == "handler" and v.get("handler") == "crowdsec"), None)
    if at is None:
        return s
    handler = events[at][1]
    owner_at = max(i for i, (k, v, _, _) in enumerate(events[:at])
                   if k == "route" and any(h is handler for h in v.get("handle") or []))
    owner = events[owner_at][1]
    ranges = _protect_ranges(owner)
    if ranges is None or not _nets(REQUIRED_PROTECTED) <= ranges:
        s.status, s.detail = "plugin_unprotected", PLUGIN_UNPROTECTED
        return s
    if expected is not None and ranges != expected:
        s.status, s.detail = "unknown", PLUGIN_OUTDATED
        return s
    pre, unknown = [], []
    for kind, h, _, shielded in events[:owner_at]:
        if kind != "handler" or shielded:
            continue
        verdict, name = classify(h)
        bucket = pre if verdict == "pre" else unknown if verdict == "unknown" else None
        if bucket is not None and name not in bucket:
            bucket.append(name)
    if unknown:
        s.status, s.pre_handlers = "unknown", pre + unknown
        s.detail = "Handlers run before the plugin check that could answer the request first: " + ", ".join(unknown) + "."
    elif pre:
        s.status, s.pre_handlers = "enforced_pre_handler", pre
    else:
        s.status = "enforced"
    return s


def plugin_site_statuses(config, *, expected_exclusions=None) -> list:
    """Per site, is the crowdsec handler in effective order behind the
    protected matcher? Same iteration as site_statuses, so rows align.
    `expected_exclusions`: the current protected tokens (expand_tokens form);
    a running route with another set is reported as out of date."""
    expected = None if expected_exclusions is None else _nets(expected_exclusions)
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
            out.append(_plugin_status(route, hosts[0] if hosts else (listen or name), hosts, name, expected))
    return out
```

`_events` records each route before its handlers, so the owning route of the crowdsec handler is always earlier in `events`.

- [ ] **Step 5: Implement snippet-name imports**

In `src/bans/scan.py`, change `block_import_state`:

```python
def _is_snippet_import(line, snippet) -> bool:
    m = _IMPORT.match(line)
    return bool(m and m.group(1) == snippet)


def block_import_state(text, block, path, after=(), snippet=None) -> dict:
    """`after`: other managed policy paths that may come before this import
    (the CrowdSec import goes directly after the manual one). `snippet`: match
    `import <snippet>` (a Caddyfile snippet such as protect_crowdsec) instead
    of a file glob covering `path`."""
    mine = (lambda line: _is_snippet_import(line, snippet)) if snippet else (lambda line: _is_policy_import(line, path))
```

and use `mine(line)` everywhere the function body called `_is_policy_import(line, path)` (the `matches` list and `leads`).

- [ ] **Step 6: Implement the service side**

In `src/bans/service.py`:

```python
def _plugin_rows_wanted(live) -> bool:
    if _plugin_active():
        return True
    return live is not None and any(s.status != "not_imported" for s in detect.plugin_site_statuses(live))
```

In `_site_rows`, after `detected` is filled for the file sources:

```python
    show_plugin = _plugin_rows_wanted(live)
    names = list(sources) + (["plugin"] if show_plugin else [])
    if live is not None and show_plugin:
        expected = None
        if "plugin" not in holds:
            expected = detect.expand_tokens(protected_for(state or store.State()).exclusion_tokens())
        detected["plugin"] = detect.plugin_site_statuses(live, expected_exclusions=expected)
```

and make `policy()` handle the plugin:

```python
    plugin_after = tuple(render.SOURCES[n].path for n in render.SOURCES)

    def policy(name, status, block, mgmt, found=None):
        imp = None
        if block is not None:
            imp = (scan.block_import_state(text, block, None, after=plugin_after, snippet=render.PLUGIN.snippet)
                   if name == "plugin" else
                   scan.block_import_state(text, block, sources[name].path, after=after.get(name, ())))
        ...
```

In the fallback loop use `for name in names` instead of `for name in sources`.

Add:

```python
ISOLATION_CHECK = ("crowdsec/check-plugin-isolation.sh -- -f docker-compose.prod.yaml -f docker-compose.crowdsec.yaml "
                   "-f docker-compose.crowdsec-plugin.yaml")


def _plugin_status(live, state, holds, text) -> dict:
    module = plugin.cached_module() if lapi.enabled() else None
    app = plugin.live_app(live) if live is not None else None
    if not (_plugin_active() or module or app):
        return {"enabled": False}
    problem = plugin.admin_problem(live) if live is not None else None
    data = fsio.read_bytes(render.PLUGIN.path)
    static = protected.build(never=never_networks(), docker=protected.read_docker_networks())
    return {
        "enabled": True, "module": module, "refused": problem is not None,
        "admin": None if problem is None else {"code": problem.code, "message": problem.message},
        "app": app, "key_mode": plugin.key_mode(), "key_file": plugin.key_file() or None,
        "placeholder": plugin.api_key_placeholder(),
        "ticker_interval": app["ticker_interval"] if app else plugin.TICKER_INTERVAL,
        "definition": {
            "file": render.PLUGIN.path, "import_line": render.PLUGIN.import_line,
            "site_import": render.PLUGIN.site_import, "present": data is not None,
            "hash": fsio.sha256_tag(data)[7:19] if data is not None else None,
            "current": data is not None and state is not None and plugin_route_current(state),
            "hold": "plugin" in holds, "hold_reason": holds.get("plugin"),
            "imported": scan.mentions_import(text, render.PLUGIN.path),
        },
        "allowlist": plugin.allowlist_commands(static),
        "check_command": ISOLATION_CHECK,
    }
```

In `status()`, read the Caddyfile once (`text = _read_caddyfile()`), pass it to `_site_rows(live, text, ...)`, and add `"plugin": _plugin_status(live, state, holds, text)` to the returned dict. `holds` there is `_holds(state) if state else {}`, which now includes `"plugin"`. `_plugin_status` never calls `module_available()` (status already ran `availability()`, which refreshed it).

Rows: a management site's plugin policy goes through `_management_status` like the others, so a console site that imports `protect_crowdsec` is reported as a lockout risk.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `uv run --frozen python -m unittest tests.test_plugin_status tests.test_crowdsec_status tests.test_bans_detect -v`
Expected: PASS. Then the full Python suite. Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/bans/detect.py src/bans/scan.py src/bans/service.py tests/test_plugin_status.py \
  tests/integration/make_plugin_fixtures.sh tests/fixtures/bans/adapted-plugin-layouts.json
git commit -m "feat(crowdsec-plugin): per-site plugin enforcement from live JSON and plugin health in the Security API"
```

---
### Task 6: Plugin snippets, validator warnings and the admin save guard

Three insertable snippets at three scopes plus one copy-only command block (spec 3.6). The global app has an environment and a file-secret variant; the API serves only the one matching `CROWDSEC_PLUGIN_BOUNCER_KEY_FILE`, so the UI can never insert both. The exact code of every shipped plugin snippet is pinned by committed fixture Caddyfiles that CI adapts with the built binary (Task 11). While the console runs with the fixed admin address, Save and Restore refuse a Caddyfile whose admin bind would expose port 2019 (Review Focus 1).

**Files:**
- Modify: `src/snippets.json` (five entries)
- Modify: `src/routes/editor.py` (`get_snippets`, `validate`, `save`, `restore_backup`)
- Modify: `src/bans/plugin.py` (`admin_guard`), `src/bans/service.py` (`plugin_snippet_context`), `src/bans/scan.py` (`plugin_warnings`)
- Modify: `tests/_bans.py` (FakeCaddy adapts the `admin` line)
- Create: `tests/fixtures/plugin/base.Caddyfile`, `tests/fixtures/plugin/env.Caddyfile`, `tests/fixtures/plugin/file.Caddyfile`, `tests/fixtures/plugin/crowdsec-plugin-protect.caddy`
- Test: `tests/test_plugin_snippets.py`

**Interfaces:**
- Consumes: Tasks 3-5.
- Produces:
  - Snippet ids: `crowdsec-plugin-global-env`, `crowdsec-plugin-global-file` (`"insert": "global-options"`, `"scope": "global"`, `"key_mode"`), `crowdsec-plugin-definition` (`"insert": "top-level"`), `crowdsec-plugin-site` (`"insert": "site-first"`), `crowdsec-plugin-allowlist` (`"insert": "copy-only"`, `"scope": "host"`). All have `"phase": "plugin"` and `"prerequisites": ["BANS_ENABLED", "CROWDSEC_URL", "CROWDSEC_PLUGIN"]`.
  - `GET /api/snippets` `context.plugin`: `{"module": bool|null, "blocked": str, "key_mode", "app_live": bool, "app_on_disk": bool, "definition_target": "<BANS_DIR>/crowdsec-plugin-protect.caddy", "definition_import": bool, "definition_current": bool, "definition_hash": str|null, "snippet": "protect_crowdsec"}`, or `null` when plugin snippets are not offered.
  - `plugin.admin_guard(content) -> str | None` (message when Save must be refused).
  - `scan.plugin_warnings(text, definition_path, management=frozenset(), *, snippet="protect_crowdsec", placeholder=None, crowdsec_path=None) -> list[str]`.
  - Save/Restore refusal: HTTP 409 `{"ok": false, "code": "admin_exposed", "message": "Not saved: ..."}`, audit `save_refused`.

- [ ] **Step 1: Write the fixtures**

`tests/fixtures/plugin/base.Caddyfile` (tabs for indentation):

```caddyfile
{
	admin 172.30.250.2:2019 {
		origins caddy:2019 172.30.250.2:2019
	}
}

plugin.example.com {
	import /etc/caddy/console/bans-manual*.caddy
	respond "ok" 200
}

file.example.com {
	import /etc/caddy/console/bans-manual*.caddy
	import /etc/caddy/console/bans-crowdsec*.caddy
	respond "ok" 200
}
```

`tests/fixtures/plugin/env.Caddyfile`: `base.Caddyfile` with the three plugin snippets inserted exactly where Task 7's planners put them:

```caddyfile
{
	admin 172.30.250.2:2019 {
		origins caddy:2019 172.30.250.2:2019
	}
	crowdsec {
		api_url http://crowdsec:8080
		api_key {env.CROWDSEC_PLUGIN_BOUNCER_KEY}
		ticker_interval 10s
	}
	order crowdsec first
}

import /etc/caddy/console/crowdsec-plugin-protect*.caddy

plugin.example.com {
	import /etc/caddy/console/bans-manual*.caddy
	import protect_crowdsec
	respond "ok" 200
}

file.example.com {
	import /etc/caddy/console/bans-manual*.caddy
	import /etc/caddy/console/bans-crowdsec*.caddy
	respond "ok" 200
}
```

`tests/fixtures/plugin/file.Caddyfile`: identical to `env.Caddyfile` except the key line, `api_key {file./run/secrets/crowdsec_plugin_bouncer_key}`.

`tests/fixtures/plugin/crowdsec-plugin-protect.caddy`: the bytes of `render.render_plugin_route(protected.RENDER_BASE)` (the test below asserts this; generate it with `uv run --frozen python -c 'import tests._env; from src.bans import render, protected; import sys; sys.stdout.buffer.write(render.render_plugin_route(protected.RENDER_BASE))' > tests/fixtures/plugin/crowdsec-plugin-protect.caddy`).

- [ ] **Step 2: Add the snippets**

Append to the array in `src/snippets.json` (after `crowdsec-log-fields`):

```json
  {
    "id": "crowdsec-plugin-global-env",
    "name": "CrowdSec plugin: global app",
    "description": "Loads the CrowdSec bouncer and runs its handler first. Goes inside the global options block. The key comes from CROWDSEC_PLUGIN_BOUNCER_KEY in the Caddy container; decisions are polled every 10 s, near-real-time without a reload.",
    "phase": "plugin",
    "scope": "global",
    "insert": "global-options",
    "key_mode": "env",
    "supported_modes": ["direct", "cloudflare-proxied", "cloudflare-tunnel"],
    "prerequisites": ["BANS_ENABLED", "CROWDSEC_URL", "CROWDSEC_PLUGIN"],
    "code": "crowdsec {\n\tapi_url http://crowdsec:8080\n\tapi_key {env.CROWDSEC_PLUGIN_BOUNCER_KEY}\n\tticker_interval 10s\n}\norder crowdsec first\n"
  },
  {
    "id": "crowdsec-plugin-global-file",
    "name": "CrowdSec plugin: global app",
    "description": "Loads the CrowdSec bouncer and runs its handler first. Goes inside the global options block. The key is read from the mounted secret file named by CROWDSEC_PLUGIN_BOUNCER_KEY_FILE; decisions are polled every 10 s, near-real-time without a reload.",
    "phase": "plugin",
    "scope": "global",
    "insert": "global-options",
    "key_mode": "file",
    "supported_modes": ["direct", "cloudflare-proxied", "cloudflare-tunnel"],
    "prerequisites": ["BANS_ENABLED", "CROWDSEC_URL", "CROWDSEC_PLUGIN"],
    "code": "crowdsec {\n\tapi_url http://crowdsec:8080\n\tapi_key {file./run/secrets/crowdsec_plugin_bouncer_key}\n\tticker_interval 10s\n}\norder crowdsec first\n"
  },
  {
    "id": "crowdsec-plugin-definition",
    "name": "CrowdSec plugin: load protected route definition",
    "description": "Loads the generated protect_crowdsec snippet, which keeps protected addresses away from the plugin. Goes at top level, outside every site and the global options.",
    "phase": "plugin",
    "scope": "top-level",
    "insert": "top-level",
    "supported_modes": ["direct", "cloudflare-proxied", "cloudflare-tunnel"],
    "prerequisites": ["BANS_ENABLED", "CROWDSEC_URL", "CROWDSEC_PLUGIN"],
    "code": "import /etc/caddy/console/crowdsec-plugin-protect*.caddy\n"
  },
  {
    "id": "crowdsec-plugin-site",
    "name": "CrowdSec plugin: protect this site",
    "description": "Answer 403 to addresses CrowdSec banned, through the plugin. Goes first in a site block, or after the ban imports. Needs the global app and the definition loaded in Caddy first.",
    "phase": "plugin",
    "scope": "site",
    "insert": "site-first",
    "supported_modes": ["direct", "cloudflare-proxied", "cloudflare-tunnel"],
    "prerequisites": ["BANS_ENABLED", "CROWDSEC_URL", "CROWDSEC_PLUGIN"],
    "code": "import protect_crowdsec\n"
  },
  {
    "id": "crowdsec-plugin-allowlist",
    "name": "CrowdSec plugin: LAPI allowlist",
    "description": "cscli commands that put the static protected ranges into a CrowdSec allowlist, as defense in depth. Run them inside the crowdsec container. Copy only.",
    "phase": "plugin",
    "scope": "host",
    "insert": "copy-only",
    "supported_modes": ["direct", "cloudflare-proxied", "cloudflare-tunnel"],
    "prerequisites": ["BANS_ENABLED", "CROWDSEC_URL", "CROWDSEC_PLUGIN"],
    "code": "cscli allowlists delete caddy_console_protected || true\ncscli allowlists create caddy_console_protected -d 'Caddy Console protected ranges'\ncscli allowlists add caddy_console_protected 127.0.0.0/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 fe80::/10 100.64.0.0/10 fc00::/7 0.0.0.0/8 224.0.0.0/4 240.0.0.0/4 :: ff00::/8\n"
  }
```

The `crowdsec-plugin-allowlist` code is exactly `plugin.allowlist_commands(protected.build())` (the core set; single addresses such as `::1` are written without a prefix length, as `addr.token` does). The test `test_allowlist_snippet_is_the_core_set` pins it; the API replaces it with the deployment's own static set (with `BANS_NEVER` and Docker networks) when it serves it.

- [ ] **Step 3: Teach FakeCaddy the admin line**

In `tests/_bans.py`:

```python
_ADMIN_RE = re.compile(r"(?m)^\s*admin\s+(\S+)(?:\s*\{\s*\n\s*origins\s+([^\n]+)\n)?")
```

In `FakeCaddy.adapt_text(text)`, build the result dict as today, then:

```python
        m = _ADMIN_RE.search(text)
        if m and m.group(1) != "{":
            result["admin"] = {"listen": m.group(1)} if m.group(1) != "off" else {"disabled": True}
            if m.group(2):
                result["admin"]["origins"] = m.group(2).split()
        return result
```

(Name the dict `result` instead of returning the literal directly.)

- [ ] **Step 4: Write the failing tests**

Create `tests/test_plugin_snippets.py`:

```python
"""Plugin snippets, their context, validator warnings and the admin save guard (spec 3.1, 3.6).

Run with:  uv run --frozen python -m unittest tests.test_plugin_snippets -v
"""
import json
import os
import unittest
from unittest import mock

import tests._env as env
from tests import _bans, _crowdsec

from src import config
from src.bans import plugin, protected, render, scan, service

HERE = os.path.dirname(__file__)
FIX = os.path.join(HERE, "fixtures", "plugin")
FIXED = "172.30.250.2:2019"
IDS = ("crowdsec-plugin-global-env", "crowdsec-plugin-global-file", "crowdsec-plugin-definition",
       "crowdsec-plugin-site", "crowdsec-plugin-allowlist")


def fixture(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as f:
        return f.read()


def shipped():
    with open(os.path.join(HERE, "..", "src", "snippets.json"), encoding="utf-8") as f:
        return {s["id"]: s for s in json.load(f) if "id" in s}


class ShippedTest(unittest.TestCase):
    def test_every_plugin_snippet_line_is_in_the_adapted_fixtures(self):
        s = shipped()
        for sid, name in (("crowdsec-plugin-global-env", "env.Caddyfile"), ("crowdsec-plugin-global-file", "file.Caddyfile")):
            text = fixture(name)
            for code_id in (sid, "crowdsec-plugin-definition", "crowdsec-plugin-site"):
                for line in s[code_id]["code"].splitlines():
                    self.assertIn(line, text, (name, code_id, line))
        self.assertNotIn("{file.", fixture("env.Caddyfile"))
        self.assertNotIn("{env.", fixture("file.Caddyfile"))

    def test_route_fixture_is_the_rendered_definition(self):
        with open(os.path.join(FIX, "crowdsec-plugin-protect.caddy"), "rb") as f:
            self.assertEqual(f.read(), render.render_plugin_route(protected.RENDER_BASE))

    def test_allowlist_snippet_is_the_core_set(self):
        self.assertEqual(shipped()["crowdsec-plugin-allowlist"]["code"], plugin.allowlist_commands(protected.build()))

    def test_plugin_snippets_declare_scope_and_prerequisites(self):
        s = shipped()
        self.assertEqual([s[i]["insert"] for i in IDS],
                         ["global-options", "global-options", "top-level", "site-first", "copy-only"])
        for i in IDS:
            self.assertEqual(s[i]["prerequisites"], ["BANS_ENABLED", "CROWDSEC_URL", "CROWDSEC_PLUGIN"])
            self.assertEqual(s[i]["phase"], "plugin")


class SnippetApiTest(_bans.ApiCase):
    def setUp(self):
        super().setUp()
        plugin.reset_cache()
        self.addCleanup(plugin.reset_cache)
        _crowdsec.enable(self)
        for name, value in (("CADDY_ADMIN_ADDRESS", FIXED), ("CROWDSEC_PLUGIN_BOUNCER_KEY_FILE", "")):
            p = mock.patch.object(config, name, value)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(plugin, "_lapi_addresses", lambda: [])
        p.start()
        self.addCleanup(p.stop)
        self.caddy.live = {"admin": {"listen": "tcp/" + FIXED, "origins": ["caddy:2019", FIXED]}, "apps": {}}

    def snippets(self):
        r = self.get("/api/snippets")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        return {s.get("id"): s for s in body["snippets"]}, body["context"]

    def test_stock_caddy_offers_no_plugin_snippet(self):
        found, ctx = self.snippets()
        self.assertFalse(set(IDS) & set(found))
        self.assertIsNone(ctx["plugin"])

    def test_env_mode_offers_only_the_env_global(self):
        self.caddy.plugin = True
        found, ctx = self.snippets()
        self.assertEqual(sorted(set(IDS) & set(found)), sorted(set(IDS) - {"crowdsec-plugin-global-file"}))
        self.assertEqual(found["crowdsec-plugin-definition"]["code"], f"import {env.BANS_DIR}/crowdsec-plugin-protect*.caddy\n")
        p = ctx["plugin"]
        self.assertEqual((p["module"], p["blocked"], p["key_mode"], p["app_live"], p["snippet"]),
                         (True, "", "env", False, "protect_crowdsec"))
        self.assertEqual(p["definition_target"], f"{env.BANS_DIR}/crowdsec-plugin-protect.caddy")

    def test_file_mode_uses_the_configured_path(self):
        self.caddy.plugin = True
        with mock.patch.object(config, "CROWDSEC_PLUGIN_BOUNCER_KEY_FILE", "/run/secrets/my_key"):
            found, ctx = self.snippets()
        self.assertNotIn("crowdsec-plugin-global-env", found)
        self.assertIn("api_key {file./run/secrets/my_key}\n", found["crowdsec-plugin-global-file"]["code"])
        self.assertEqual(ctx["plugin"]["key_mode"], "file")

    def test_an_exposed_admin_blocks_plugin_insertion(self):
        self.caddy.plugin = True
        self.caddy.live["admin"] = {"listen": "tcp/0.0.0.0:2019"}
        _, ctx = self.snippets()
        self.assertIn("every interface", ctx["plugin"]["blocked"])

    def test_context_tracks_the_live_app_and_the_definition(self):
        self.caddy.plugin = True
        _bans.write_caddyfile(fixture("env.Caddyfile").replace("/etc/caddy/console", env.BANS_DIR))
        self.caddy.live["apps"]["crowdsec"] = {"api_key": "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}"}
        _, ctx = self.snippets()
        p = ctx["plugin"]
        self.assertEqual((p["app_live"], p["app_on_disk"], p["definition_import"], p["definition_current"]),
                         (True, True, True, False))
        service.expire_tick()
        _, ctx = self.snippets()
        self.assertTrue(ctx["plugin"]["definition_current"])
        self.assertEqual(len(ctx["plugin"]["definition_hash"]), 12)

    def test_served_allowlist_uses_the_deployment_set(self):
        self.caddy.plugin = True
        with mock.patch.object(config, "BANS_NEVER", "192.0.2.10"):
            service.reset_caches()
            found, _ = self.snippets()
        self.assertIn(" 192.0.2.10", found["crowdsec-plugin-allowlist"]["code"])


class SaveGuardTest(_bans.ApiCase):
    GOOD = "{\n\tadmin 172.30.250.2:2019 {\n\t\torigins caddy:2019 172.30.250.2:2019\n\t}\n}\nexample.com {\n\trespond 200\n}\n"

    def setUp(self):
        super().setUp()
        p = mock.patch.object(plugin, "_lapi_addresses", lambda: [])
        p.start()
        self.addCleanup(p.stop)

    def save(self, content):
        return self.post("/api/save", {"content": content})

    def test_save_refuses_an_admin_bind_other_than_the_fixed_one(self):
        with mock.patch.object(config, "CADDY_ADMIN_ADDRESS", FIXED):
            self.assertEqual(self.save(self.GOOD).status_code, 200)
            for bad in (self.GOOD.replace("admin 172.30.250.2:2019 {\n\t\torigins caddy:2019 172.30.250.2:2019\n\t}",
                                          "admin 0.0.0.0:2019"),
                        "example.com {\n\trespond 200\n}\n",
                        self.GOOD.replace("origins caddy:2019 172.30.250.2:2019", "origins caddy:2019")):
                r = self.save(bad)
                self.assertEqual(r.status_code, 409, bad)
                self.assertEqual(r.get_json()["code"], "admin_exposed")
                self.assertTrue(r.get_json()["message"].startswith("Not saved: "))
        self.assertFalse(any(k == "load" and "0.0.0.0" in t for k, t in self.caddy.calls))

    def test_the_guard_is_off_without_a_fixed_admin_address(self):
        self.assertEqual(self.save("{\n\tadmin 0.0.0.0:2019\n}\nexample.com {\n\trespond 200\n}\n").status_code, 200)


class WarningTest(unittest.TestCase):
    D = env.BANS_DIR

    def warn(self, text, management=frozenset(), placeholder="{env.CROWDSEC_PLUGIN_BOUNCER_KEY}"):
        return scan.plugin_warnings(text, render.PLUGIN.path, management, placeholder=placeholder,
                                    crowdsec_path=render.SOURCES["crowdsec"].path)

    def test_the_fixture_is_clean(self):
        self.assertEqual(self.warn(fixture("env.Caddyfile").replace("/etc/caddy/console", self.D)), [])

    def test_bare_crowdsec_directive_warns(self):
        text = f"import {self.D}/crowdsec-plugin-protect*.caddy\na.example.com {{\n\tcrowdsec\n\trespond 200\n}}\n"
        self.assertEqual(len([w for w in self.warn(text) if w.startswith("Line 3:") and "import protect_crowdsec" in w]), 1)

    def test_site_import_needs_the_top_level_definition(self):
        w = self.warn("a.example.com {\n\timport protect_crowdsec\n}\n")
        self.assertTrue(any(x.startswith("Line 2:") and "top level" in x for x in w), w)
        inside = f"a.example.com {{\n\timport {self.D}/crowdsec-plugin-protect*.caddy\n\timport protect_crowdsec\n}}\n"
        self.assertTrue(any(x.startswith("Line 2:") and "outside every site" in x for x in self.warn(inside)))

    def test_redundant_file_and_plugin_paths_warn(self):
        text = (f"import {self.D}/crowdsec-plugin-protect*.caddy\na.example.com {{\n"
                f"\timport {self.D}/bans-crowdsec*.caddy\n\timport protect_crowdsec\n}}\n")
        self.assertTrue(any("twice" in x for x in self.warn(text)))

    def test_console_site_import_is_a_lockout_risk(self):
        text = f"import {self.D}/crowdsec-plugin-protect*.caddy\nconsole.example.com {{\n\timport protect_crowdsec\n}}\n"
        self.assertTrue(any("lock you out" in x for x in self.warn(text, {"console.example.com"})))

    def test_literal_or_mismatched_key_warns_without_echoing(self):
        g = "{\n\tcrowdsec {\n\t\tapi_url http://crowdsec:8080\n\t\tapi_key %s\n\t}\n\torder crowdsec first\n}\n"
        w = self.warn(g % "3f9a1c0b7e6d5a4f3e2d1c0b9a8f7e6d")
        self.assertTrue(any(x.startswith("Line 4:") and "written into the Caddyfile" in x for x in w), w)
        self.assertFalse(any("3f9a1c0b7e6d" in x for x in w))
        w = self.warn(g % "{file./run/secrets/k}")
        self.assertTrue(any("{env.CROWDSEC_PLUGIN_BOUNCER_KEY}" in x for x in w), w)

    def test_global_app_without_order_warns(self):
        w = self.warn("{\n\tcrowdsec {\n\t\tapi_key {env.CROWDSEC_PLUGIN_BOUNCER_KEY}\n\t}\n}\n")
        self.assertTrue(any("order crowdsec first" in x for x in w), w)


class ValidateApiTest(_bans.ApiCase):
    def test_validate_reports_plugin_warnings(self):
        text = f"import {env.BANS_DIR}/crowdsec-plugin-protect*.caddy\na.example.com {{\n\tcrowdsec\n}}\n"
        body = self.post("/api/validate", {"content": text}).get_json()
        self.assertTrue(any("import protect_crowdsec" in w for w in body["warnings"]), body)
```

- [ ] **Step 5: Run the tests to verify they fail**

Run: `uv run --frozen python -m unittest tests.test_plugin_snippets -v`
Expected: FAIL (missing snippets, `context.plugin` absent, `scan.plugin_warnings` undefined, save not refused).

- [ ] **Step 6: Implement the warnings**

Append to `src/bans/scan.py`:

```python
_CROWDSEC_LINE = re.compile(r"^crowdsec(\s|$)")
_API_KEY = re.compile(r"^api_key\s+(\S+)")


def _depth_lines(text):
    """(line number, stripped line, depth before the line) for every non-empty line."""
    out, depth = [], 0
    for i, raw in enumerate(str(text).split("\n"), 1):
        line = _strip(raw)
        if not line:
            continue
        out.append((i, line, depth))
        bare = _PLACEHOLDER.sub("", line)
        depth = max(0, depth + bare.count("{") - bare.count("}"))
    return out


def _global_block(lines):
    """The global options block: the first top-level line, when it is a bare "{"."""
    if not lines or lines[0][1] != "{" or lines[0][2] != 0:
        return []
    inner = []
    for ln, line, depth in lines[1:]:
        if depth == 0:
            break
        inner.append((ln, line, depth))
    return inner


def plugin_warnings(text, definition_path, management=frozenset(), *, snippet="protect_crowdsec",
                    placeholder=None, crowdsec_path=None) -> list:
    out = []
    lines = _depth_lines(text)
    glob_line = f"import {os.path.join(os.path.dirname(definition_path), os.path.basename(definition_path)[:-len('.caddy')] + '*.caddy')}"
    top = [(ln, line) for ln, line, d in lines if d == 0]
    definition_top = any(_is_policy_import(line, definition_path) for _, line in top)
    g = _global_block(lines)
    app_at = next((ln for ln, line, d in g if d == 1 and line.startswith("crowdsec") and line.endswith("{")), None)
    if app_at is not None:
        if not any(d == 1 and re.match(r"^order\s+crowdsec\s", line) for _, line, d in g):
            out.append(f"Line {app_at}: add `order crowdsec first` to the global options, or Caddy cannot place the "
                       "crowdsec handler.")
        for ln, line, d in g:
            m = _API_KEY.match(line)
            if d != 2 or not m:
                continue
            value = m.group(1)
            if not value.startswith(("{env.", "{file.")):
                out.append(f"Line {ln}: the bouncer key is written into the Caddyfile, where anyone who can read "
                           f"Caddy's config sees it; use api_key {placeholder or '{env.CROWDSEC_PLUGIN_BOUNCER_KEY}'}.")
            elif placeholder and value != placeholder:
                out.append(f"Line {ln}: api_key is {value}, but this deployment's Caddy expects {placeholder} "
                           "(set by CROWDSEC_PLUGIN_BOUNCER_KEY_FILE).")
    for block in site_blocks(text):
        inner = [(ln, line) for ln, line, d in lines if block.start < ln < block.end and d >= 1]
        uses = [ln for ln, line in inner if _is_snippet_import(line, snippet)]
        for ln, line in inner:
            if _is_policy_import(line, definition_path):
                out.append(f"Line {ln}: the protected route definition is a top-level import; move it outside every "
                           "site block, below the global options.")
            elif _CROWDSEC_LINE.match(line) and not line.endswith("{"):
                out.append(f"Line {ln}: the crowdsec handler without import {snippet} also runs for private, Docker "
                           f"and BANS_NEVER addresses; use import {snippet} instead.")
        if not uses:
            continue
        if not definition_top:
            out.append(f"Line {uses[0]}: import {snippet} needs the protected route definition at top level "
                       f"first: {glob_line}")
        if set(block.hosts) & set(management):
            out.append(f"Line {uses[0]}: this is the console's own site; the CrowdSec plugin here could lock you "
                       "out of the console.")
        if len(uses) > 1:
            out.append(f"Line {uses[0]}: this site imports {snippet} {len(uses)} times; keep one import.")
        if crowdsec_path and any(_is_policy_import(line, crowdsec_path) for _, line in inner):
            out.append(f"Line {uses[0]}: this site enforces CrowdSec decisions twice, through bans-crowdsec.caddy "
                       "and the plugin; plugin sites do not need the CrowdSec file import.")
    return out
```

- [ ] **Step 7: Implement the save guard and the snippet context**

Append to `src/bans/plugin.py`:

```python
def admin_guard(content: str):
    """While the console runs with a fixed CADDY_ADMIN_ADDRESS (the plugin
    overlay), refuse to save a Caddyfile whose admin bind would expose port
    2019 or lose the console. None means "save may go on"; an unreachable
    Caddy or an adapt error is left to the save path, which fails anyway."""
    if not config.BANS_ENABLED or not admin_address().fixed:
        return None
    try:
        result = caddy_admin.adapt(content)
    except caddy_admin.CaddyUnavailable:
        return None
    if not result.ok:
        return None
    problem = admin_problem(result.config)
    return problem.message if problem else None
```

Append to `src/bans/service.py`:

```python
def plugin_snippet_context(text):
    """What the editor needs to place the plugin snippets (spec 3.6), or None
    when they are not offered (CrowdSec off, or a build without the module)."""
    if not lapi.enabled():
        return None
    module = plugin.module_available()
    if module is False:
        return None
    try:
        live = caddy_admin.live_config()
    except caddy_admin.CaddyUnavailable:
        live = None
    problem = plugin.admin_problem(live) if live is not None else None
    try:
        state = store.load()
    except store.StateCorrupt:
        state = None
    data = fsio.read_bytes(render.PLUGIN.path)
    return {
        "module": module, "blocked": problem.message if problem else "",
        "key_mode": plugin.key_mode(),
        "app_live": plugin.live_app(live) is not None,
        "app_on_disk": bool(re.search(r"(?m)^\s*crowdsec\s*\{", text or "")),
        "definition_target": render.PLUGIN.path,
        "definition_import": scan.mentions_import(text, render.PLUGIN.path),
        "definition_current": data is not None and state is not None and plugin_route_current(state),
        "definition_hash": fsio.sha256_tag(data)[7:19] if data is not None else None,
        "snippet": render.PLUGIN.snippet,
    }
```

(add `import re` to `service.py` if it is not imported yet).

In `src/routes/editor.py`:

- Import `from ..bans import plugin as bans_plugin` next to the other `..bans` imports.
- `validate()`: inside `if config.BANS_ENABLED:` append

  ```python
        if "crowdsec" in content.lower():
            warnings += bans_scan.plugin_warnings(
                content, bans_render.PLUGIN.path, mgmt, placeholder=bans_plugin.api_key_placeholder(),
                crowdsec_path=bans_render.SOURCES["crowdsec"].path)
  ```

- `save()` and `restore_backup()`: right after the `caddy_validate` check succeeds:

  ```python
    exposed = bans_plugin.admin_guard(content)
    if exposed:
        log_action("save_refused", user, "admin bind would expose the Caddy admin API")
        return jsonify({"ok": False, "code": "admin_exposed", "message": f"Not saved: {exposed}"}), 409
  ```

  (in `restore_backup` use the same block; its audit detail is `f"{safe_name}: admin bind"`).
- `get_snippets()`: read `text` before filtering (move the Caddyfile read up), then replace the CrowdSec filter with:

  ```python
    crowdsec = bool(bans_lapi.url())
    from ..bans import service as bans_service           # service imports this module; keep it lazy
    plugin_ctx = bans_service.plugin_snippet_context(text) if crowdsec else None
    mode = bans_plugin.key_mode()

    def offered(s):
        pre = s.get("prerequisites", [])
        if "CROWDSEC_URL" in pre and not crowdsec:
            return False
        if "CROWDSEC_PLUGIN" in pre and plugin_ctx is None:
            return False
        return s.get("key_mode") in (None, mode)
    snippets = [s for s in snippets if offered(s)]
    for s in snippets:
        if s.get("id") == "crowdsec-plugin-global-file":
            s["code"] = s["code"].replace(bans_plugin.DEFAULT_KEY_FILE, bans_plugin.key_file())
        elif s.get("id") == "crowdsec-plugin-allowlist":
            s["code"] = bans_plugin.allowlist_commands(
                bans_protected.build(never=bans_service.never_networks(), docker=bans_protected.read_docker_networks()))
  ```

  and add `"plugin": plugin_ctx` to the returned `context` (with `from ..bans import protected as bans_protected` at the top). The existing loop that rewrites `/etc/caddy/console/` to `BANS_DIR` covers the definition snippet because it has a `phase`.

- [ ] **Step 8: Run the tests to verify they pass**

Run: `uv run --frozen python -m unittest tests.test_plugin_snippets -v`
Expected: PASS. Then the full Python suite (existing snippet tests filter by prerequisites; none uses `CROWDSEC_PLUGIN`). Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add src/snippets.json src/routes/editor.py src/bans/plugin.py src/bans/service.py src/bans/scan.py \
  tests/_bans.py tests/fixtures/plugin tests/test_plugin_snippets.py
git commit -m "feat(crowdsec-plugin): scoped plugin snippets, validator warnings and a save guard for the fixed admin bind"
```

---
### Task 7: Scoped insertion in the editor

The three plugin snippets belong to three scopes; the UI never inserts different scopes at one cursor position (spec 3.6). The global app goes inside the global options block (created at the top when there is none), the definition goes at top level directly below it, and the site import goes first in the site or after its ban imports. Each is offered only when its prerequisites hold: the running build has the module, the admin bind is safe, and for the site import, the global app is live in Caddy and the definition file is imported and current.

**Files:**
- Modify: `src/static/js/app/snippet-insert.js`
- Modify: `src/static/js/app/panels.js`
- Test: `tests/snippet-insert.test.mjs`

**Interfaces:**
- Consumes: `GET /api/snippets` `context.plugin` and the snippet ids/`insert` modes (Task 6); fixtures `tests/fixtures/plugin/{base,env,file}.Caddyfile`.
- Produces in `snippet-insert.js`:
  - `PLUGIN_SNIPPET = 'protect_crowdsec'`, `PLUGIN_IMPORT_AFTER = ['manual', 'crowdsec']`.
  - `globalOptionsBlock(text) -> {start, end} | null` (1-based lines of `{` and its closing `}`).
  - `planGlobalOptionInsertion(text, code) -> {ok, line, text} | {ok: false, reason: 'duplicate-global', line}`.
  - `planTopLevelInsertion(text, code, {target}) -> {ok, line, text, atEnd?} | {ok: false, reason: 'duplicate', line}`.
  - `planSiteInsertion(..., {snippetName})`: with `snippetName`, an `import <snippetName>` line is the duplicate.
  - `pluginGate(snippet, pluginCtx) -> null | 'plugin-unavailable' | 'plugin-module-missing' | 'plugin-blocked' | 'plugin-definition-stale' | 'plugin-app-missing' | 'plugin-definition-missing'`.
- Produces in `panels.js`: `insertBanImportAtLine(line, 'plugin')` inserts `crowdsec-plugin-site` (used by the Security view, Task 8).

- [ ] **Step 1: Write the failing tests**

In `tests/snippet-insert.test.mjs`, extend the import destructuring with `PLUGIN_IMPORT_AFTER, PLUGIN_SNIPPET, globalOptionsBlock, planGlobalOptionInsertion, planTopLevelInsertion, pluginGate`. Change the existing check `'scopes: ban imports insert first in a site, everything else is copy only'` to skip plugin snippets (`snippets.filter(x => x.scope && x.phase !== 'plugin')`). Then append before the final `console.log`:

```js
console.log('\n--- CrowdSec plugin scopes ---');
const FIX = path.join(ROOT, 'tests', 'fixtures', 'plugin');
const fixture = (n) => fs.readFileSync(path.join(FIX, n), 'utf8');
const byId = Object.fromEntries(snippets.filter(s => s.id).map(s => [s.id, s]));
const DIR = '/etc/caddy/console';
const DEF_T = `${DIR}/crowdsec-plugin-protect.caddy`;
const SITE_OPTS = { snippetName: PLUGIN_SNIPPET, managementHosts: ['console.example.com'],
  after: PLUGIN_IMPORT_AFTER.map(a => `${DIR}/${SOURCE_FILES[a]}`) };
const insertAll = (text, globalId) => {
  let t = applyPlan(text, planGlobalOptionInsertion(text, byId[globalId].code));
  t = applyPlan(t, planTopLevelInsertion(t, byId['crowdsec-plugin-definition'].code, { target: DEF_T }));
  const site = t.split('\n').indexOf('plugin.example.com {') + 1;
  return applyPlan(t, planSiteInsertion(t, site, byId['crowdsec-plugin-site'].code, SITE_OPTS));
};
check('the shipped plugin snippets produce exactly the adapted fixtures, in both secret modes', () => {
  assert.equal(insertAll(fixture('base.Caddyfile'), 'crowdsec-plugin-global-env'), fixture('env.Caddyfile'));
  assert.equal(insertAll(fixture('base.Caddyfile'), 'crowdsec-plugin-global-file'), fixture('file.Caddyfile'));
});
check('the global options block is found, and created when missing', () => {
  assert.deepEqual(globalOptionsBlock(fixture('base.Caddyfile')), { start: 1, end: 5 });
  assert.equal(globalOptionsBlock('a.example.com {\n}\n'), null);
  assert.equal(globalOptionsBlock('# c\n\n{\n\tdebug\n}\n').start, 3);
  const p = planGlobalOptionInsertion('a.example.com {\n\trespond 200\n}\n', 'order crowdsec first\n');
  assert.deepEqual([p.ok, p.line, p.text], [true, 1, '{\n\torder crowdsec first\n}\n\n']);
});
check('the global app is never inserted twice', () => {
  const env = fixture('env.Caddyfile');
  const p = planGlobalOptionInsertion(env, byId['crowdsec-plugin-global-file'].code);
  assert.deepEqual([p.ok, p.reason, p.line], [false, 'duplicate-global', 5]);
});
check('the definition goes below the global options, once, at top level only', () => {
  const env = fixture('env.Caddyfile');
  assert.equal(planTopLevelInsertion(env, byId['crowdsec-plugin-definition'].code, { target: DEF_T }).reason, 'duplicate');
  const bare = 'a.example.com {\n\trespond 200\n}\n';
  const p = planTopLevelInsertion(bare, byId['crowdsec-plugin-definition'].code, { target: DEF_T });
  assert.deepEqual([p.line, p.text], [1, `import ${DIR}/crowdsec-plugin-protect*.caddy\n\n`]);
  const end = planTopLevelInsertion('{\n\tdebug\n}', byId['crowdsec-plugin-definition'].code, { target: DEF_T });
  assert.deepEqual([end.line, end.atEnd, end.text], [4, true, `\n\nimport ${DIR}/crowdsec-plugin-protect*.caddy`]);
  // An import of the definition inside a site is not a top-level duplicate.
  const inSite = `a.example.com {\n\timport ${DIR}/crowdsec-plugin-protect*.caddy\n}\n`;
  assert.equal(planTopLevelInsertion(inSite, byId['crowdsec-plugin-definition'].code, { target: DEF_T }).ok, true);
});
check('the site import follows the ban imports, is matched by name, and never goes into the console site', () => {
  const env = fixture('env.Caddyfile');
  const site = env.split('\n').indexOf('plugin.example.com {') + 1;
  assert.equal(planSiteInsertion(env, site, 'import protect_crowdsec\n', SITE_OPTS).reason, 'duplicate');
  const file = env.split('\n').indexOf('file.example.com {') + 1;
  const p = planSiteInsertion(env, file, 'import protect_crowdsec\n', SITE_OPTS);
  assert.deepEqual([p.ok, p.line], [true, file + 3], 'after the manual and CrowdSec file imports');
  assert.equal(planSiteInsertion(CF, 29, 'import protect_crowdsec\n', SITE_OPTS).reason, 'management-site');
  // Without snippetName the name is never a duplicate of a file glob (old behaviour kept).
  assert.equal(importMatches('protect_crowdsec', DEF_T), false);
});
check('plugin snippets are offered only when their prerequisites hold', () => {
  const ok = { module: true, blocked: '', app_live: true, definition_import: true, definition_current: true };
  const site = byId['crowdsec-plugin-site'];
  const def = byId['crowdsec-plugin-definition'];
  const glob = byId['crowdsec-plugin-global-env'];
  assert.equal(pluginGate(site, ok), null);
  assert.equal(pluginGate(site, null), 'plugin-unavailable');
  assert.equal(pluginGate(glob, { ...ok, module: false }), 'plugin-module-missing');
  assert.equal(pluginGate(glob, { ...ok, module: null }), null, 'unknown build: Check will tell');
  assert.equal(pluginGate(glob, { ...ok, blocked: 'Caddy admin listens on every interface' }), 'plugin-blocked');
  assert.equal(pluginGate(def, { ...ok, definition_current: false }), 'plugin-definition-stale');
  assert.equal(pluginGate(site, { ...ok, app_live: false }), 'plugin-app-missing');
  assert.equal(pluginGate(site, { ...ok, definition_import: false }), 'plugin-definition-missing');
  assert.equal(pluginGate(site, { ...ok, definition_current: false }), 'plugin-definition-missing');
  assert.equal(pluginGate(glob, { ...ok, app_live: false, definition_import: false }), null);
});
check('plugin snippet scopes', () => {
  assert.deepEqual(['crowdsec-plugin-global-env', 'crowdsec-plugin-global-file', 'crowdsec-plugin-definition',
    'crowdsec-plugin-site', 'crowdsec-plugin-allowlist'].map(id => [byId[id].scope, byId[id].insert]),
  [['global', 'global-options'], ['global', 'global-options'], ['top-level', 'top-level'], ['site', 'site-first'], ['host', 'copy-only']]);
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `node tests/snippet-insert.test.mjs`
Expected: FAIL (`planGlobalOptionInsertion` is not exported).

- [ ] **Step 3: Implement the planners**

In `src/static/js/app/snippet-insert.js`, change the duplicate check inside `planSiteInsertion` and its options:

```js
export function planSiteInsertion(text, cursorLine, code, { target, managementHosts = [], after = [], snippetName = null } = {}) {
  ...
  for (let n = block.start + 1; n <= block.end - 1; n++) {
    const m = stripComment(lines[n - 1]).match(/^import\s+(\S+)/);
    if (m && (snippetName ? m[1] === snippetName : importMatches(m[1], target))) return { ok: false, reason: 'duplicate', block, line: n };
  }
```

and append:

```js
/** The CrowdSec plugin's site import (spec 3.6): `import protect_crowdsec`, after any ban imports. */
export const PLUGIN_SNIPPET = 'protect_crowdsec';
export const PLUGIN_IMPORT_AFTER = ['manual', 'crowdsec'];

const count = (s, ch) => s.split(ch).length - 1;

/** Non-empty lines with the brace depth before each (placeholders are not blocks). */
function depthLines(text) {
  const out = [];
  let depth = 0;
  String(text).split('\n').forEach((raw, i) => {
    const line = stripComment(raw);
    if (!line) return;
    out.push({ n: i + 1, line, depth });
    const bare = line.replace(/\{[^{}\s]*\}/g, '');
    depth = Math.max(0, depth + count(bare, '{') - count(bare, '}'));
  });
  return out;
}

/** The global options block: the first top-level line when it is a bare `{`. */
export function globalOptionsBlock(text) {
  const lines = depthLines(text);
  if (!lines.length || lines[0].line !== '{') return null;
  // The block ends on the last line before the next top-level line (or at the end of the file).
  for (let i = 1; i < lines.length; i++) if (lines[i].depth === 0) return { start: lines[0].n, end: lines[i - 1].n };
  return { start: lines[0].n, end: lines[lines.length - 1].n };
}

/** Insert lines inside the global options, before its closing brace; create the block if there is none. */
export function planGlobalOptionInsertion(text, code) {
  const body = String(code).replace(/\n$/, '').split('\n');
  const g = globalOptionsBlock(text);
  if (!g) return { ok: true, line: 1, text: '{\n' + body.map(l => '\t' + l).join('\n') + '\n}\n\n' };
  const inner = depthLines(text).filter(l => l.n > g.start && l.n < g.end);
  const dup = inner.find(l => l.depth === 1 && /^crowdsec(\s|\{|$)/.test(l.line));
  if (dup) return { ok: false, reason: 'duplicate-global', line: dup.n };
  const lines = String(text).split('\n');
  const first = inner.find(l => l.depth === 1);
  const indent = (first && lines[first.n - 1].match(/^\s*/)[0]) || '\t';
  return { ok: true, line: g.end, text: body.map(l => indent + l).join('\n') + '\n' };
}

/** A top-level import, directly below the global options (or first in the file); never twice at top level. */
export function planTopLevelInsertion(text, code, { target } = {}) {
  const dup = depthLines(text).find((l) => {
    const m = l.depth === 0 && l.line.match(/^import\s+(\S+)/);
    return m && importMatches(m[1], target);
  });
  if (dup) return { ok: false, reason: 'duplicate', line: dup.n };
  const body = String(code).trim();
  const g = globalOptionsBlock(text);
  if (!g) return { ok: true, line: 1, text: body + '\n\n' };
  const lines = String(text).split('\n');
  if (g.end >= lines.length) return { ok: true, line: g.end + 1, text: '\n\n' + body, atEnd: true };
  return { ok: true, line: g.end + 1, text: '\n' + body + '\n' };
}

/** Why a plugin snippet cannot be inserted now, or null (spec 3.6 prerequisites). */
export function pluginGate(snippet, ctx) {
  if (!ctx) return 'plugin-unavailable';
  if (ctx.module === false) return 'plugin-module-missing';
  if (ctx.blocked) return 'plugin-blocked';
  if (snippet.insert === 'top-level' && !ctx.definition_current) return 'plugin-definition-stale';
  if (snippet.id === 'crowdsec-plugin-site') {
    if (!ctx.app_live) return 'plugin-app-missing';
    if (!ctx.definition_import || !ctx.definition_current) return 'plugin-definition-missing';
  }
  return null;
}
```

- [ ] **Step 4: Wire it into the snippets panel**

In `src/static/js/app/panels.js`, import the new names and add:

```js
const SOURCE_SNIPPETS = { manual: 'manual-bans-site', crowdsec: 'crowdsec-bans-site', plugin: 'crowdsec-plugin-site' };

const PLUGIN_REFUSED = {
  'plugin-unavailable': () => 'Plugin mode is not available: CrowdSec is not configured or the running Caddy has no crowdsec module.',
  'plugin-module-missing': () => 'The running Caddy build has no crowdsec module. Start the plugin image (docker-compose.crowdsec-plugin.yaml) first.',
  'plugin-blocked': (p) => `Plugin mode is refused: ${p.blocked}`,
  'plugin-definition-stale': () => 'The protected route file is missing or out of date. Re-apply the plugin route in Security first.',
  'plugin-app-missing': () => 'Caddy has not loaded the CrowdSec plugin app yet. Insert the global app, Save & Reload, then protect sites.',
  'plugin-definition-missing': () => 'Load the protected route definition (top level) and Save & Reload before protecting a site.',
};
REFUSED['duplicate-global'] = 'The global options already configure crowdsec.';
```

For a refused plugin site import, use the message `'This site already imports protect_crowdsec.'` when `plan.reason === 'duplicate'` (in `insertSiteFirst`: `const msg = isPlugin && plan.reason === 'duplicate' ? 'This site already imports protect_crowdsec.' : REFUSED[plan.reason];`), and in `insertScoped` map `duplicate` to `'The protected route definition is already imported at top level.'`.

In `insertSiteFirst(s, cursorLine)`, after the `ctx` check:

```js
  const isPlugin = s.phase === 'plugin';
  if (isPlugin) {
    const gate = pluginGate(s, ctx.plugin);
    if (gate) {
      toast(PLUGIN_REFUSED[gate](ctx.plugin || {}), { kind: 'warn', action: { label: 'Copy', run: () => copySnippet(s) } });
      return false;
    }
  }
  const dir = ctx.bans_dir || '/etc/caddy/console';
  const source = Object.keys(SOURCE_SNIPPETS).find(k => SOURCE_SNIPPETS[k] === s.id) || 'manual';
  const opts = isPlugin
    ? { snippetName: PLUGIN_SNIPPET, managementHosts: ctx.management_hosts || [],
        after: PLUGIN_IMPORT_AFTER.map(a => `${dir}/${SOURCE_FILES[a]}`) }
    : { target: `${dir}/${SOURCE_FILES[source]}`, managementHosts: ctx.management_hosts || [],
        after: (IMPORT_AFTER[source] || []).map(a => `${dir}/${SOURCE_FILES[a]}`) };
  const plan = planSiteInsertion(editorView.state.doc.toString(), cursorLine, s.code, opts);
```

Add the scoped inserter and route the new modes in `insertSnippet`:

```js
function insertScoped(s) {
  const ctx = snippetData?.context;
  if (!ctx) {
    toast('Snippet settings are not loaded yet, so the snippet was not inserted.',
      { kind: 'warn', action: { label: 'Copy', run: () => copySnippet(s) } });
    return false;
  }
  const gate = pluginGate(s, ctx.plugin);
  if (gate) {
    toast(PLUGIN_REFUSED[gate](ctx.plugin || {}), { kind: 'warn', action: { label: 'Copy', run: () => copySnippet(s) } });
    return false;
  }
  const text = editorView.state.doc.toString();
  const plan = s.insert === 'global-options'
    ? planGlobalOptionInsertion(text, s.code)
    : planTopLevelInsertion(text, s.code, { target: ctx.plugin.definition_target });
  if (!plan.ok) {
    toast(REFUSED[plan.reason] || 'This snippet is already in the Caddyfile.', { kind: 'warn' });
    return false;
  }
  const doc = editorView.state.doc;
  const from = plan.atEnd ? doc.length : doc.line(plan.line).from;
  editorView.dispatch({ changes: { from, insert: plan.text } });
  setDot('yellow');
  closePanel('snippets');
  const hash = s.insert === 'top-level' && ctx.plugin.definition_hash ? ` (protected ranges ${ctx.plugin.definition_hash})` : '';
  const unknown = ctx.plugin.module === null ? ' Caddy did not answer, so Check will tell whether this build has the crowdsec module.' : '';
  toast(`Inserted "${s.name}" at line ${plan.line}${hash}. Review it, then Save & Reload.${unknown}`, { kind: unknown ? 'warn' : 'ok' });
  return true;
}

function insertSnippet(s) {
  if (s.insert === 'copy-only') { copySnippet(s); return; }
  if (s.insert === 'global-options' || s.insert === 'top-level') { insertScoped(s); return; }
  ...
}
```

In `insertBanImportAtLine`, when `source === 'plugin'` and the snippet is missing, toast `PLUGIN_REFUSED['plugin-unavailable']()` instead of the CrowdSec message.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `node tests/snippet-insert.test.mjs && node tests/no-native-dialogs.test.mjs`
Expected: PASS. Then all node suites. Expected: PASS. Run `npm run build` and confirm `git diff -- src/static/js/` shows only the two source files you edited (no bundle change).

- [ ] **Step 6: Commit**

```bash
git add src/static/js/app/snippet-insert.js src/static/js/app/panels.js tests/snippet-insert.test.mjs
git commit -m "feat(crowdsec-plugin): insert the global, top-level and site snippets at their own scopes"
```

---
### Task 8: Security view: plugin health and the CrowdSec path per site

**Files:**
- Create: `src/static/js/app/security-plugin.js`
- Modify: `src/static/js/app/security-model.js` (`SOURCE_LABELS`, `SITE`, `pluginState`, `crowdsecPath`, `pluginSiteActions`, `baseState`)
- Modify: `src/static/js/app/security.js` (plugin section, per-site CrowdSec path, plugin pseudo-source in Sites)
- Test: `tests/security-model.test.mjs`

**Interfaces:**
- Consumes: `GET /api/security` `plugin` block and `sites[].policies.plugin` (Task 5); `POST /api/security/reapply {"source": "plugin"}` (Task 4); `app:insert-ban-import` with `source: 'plugin'` (Task 7).
- Produces in `security-model.js`: `pluginState(plugin) -> {tone, title, detail} | null`; `crowdsecPath(site) -> {text, tone} | null`; `pluginSiteActions(policy, site, plugin) -> string[]`; `SOURCE_LABELS.plugin = 'CrowdSec plugin'`; site status `plugin_unprotected`.

- [ ] **Step 1: Write the failing model tests**

Append to `tests/security-model.test.mjs` before its final `console.log`:

```js
console.log('\n--- CrowdSec plugin ---');
const PLUG = {
  enabled: true, module: true, refused: false, admin: null, key_mode: 'env', key_file: null,
  placeholder: '{env.CROWDSEC_PLUGIN_BOUNCER_KEY}', ticker_interval: '10s',
  app: { api_url: 'http://crowdsec:8080', ticker_interval: '10s', streaming: true, hard_fails: false, key_form: 'expected', key_placeholder: null },
  definition: { file: '/etc/caddy/console/crowdsec-plugin-protect.caddy', import_line: 'import /etc/caddy/console/crowdsec-plugin-protect*.caddy',
    site_import: 'import protect_crowdsec', present: true, hash: '0123456789ab', current: true, hold: false, hold_reason: null, imported: true },
  allowlist: 'cscli allowlists add caddy_console_protected 127.0.0.0/8\n', check_command: 'crowdsec/check-plugin-isolation.sh -- ...',
};
check('plugin health wording, worst problem first', () => {
  assert.equal(M.pluginState({ enabled: false }), null);
  assert.deepEqual([M.pluginState(PLUG).tone, M.pluginState(PLUG).title], ['ok', 'Near-real-time without reload, polling every 10s']);
  const refused = M.pluginState({ ...PLUG, refused: true, admin: { code: 'admin_wildcard', message: 'listens on every interface' } });
  assert.deepEqual([refused.tone, refused.title, refused.detail], ['crit', 'Plugin mode refused: the admin API would be exposed', 'listens on every interface']);
  assert.equal(M.pluginState({ ...PLUG, module: false }).title, 'The running Caddy has no crowdsec module');
  assert.equal(M.pluginState({ ...PLUG, app: { ...PLUG.app, key_form: 'literal' } }).tone, 'crit');
  assert.doesNotMatch(M.pluginState({ ...PLUG, app: { ...PLUG.app, key_form: 'literal' } }).detail, /[0-9a-f]{16}/);
  assert.match(M.pluginState({ ...PLUG, app: { ...PLUG.app, key_form: 'placeholder', key_placeholder: '{file./run/secrets/x}' } }).detail, /\{file\.\/run\/secrets\/x\}.*\{env\.CROWDSEC_PLUGIN_BOUNCER_KEY\}/);
  assert.equal(M.pluginState({ ...PLUG, app: null }).title, 'Plugin app not loaded');
  assert.equal(M.pluginState({ ...PLUG, definition: { ...PLUG.definition, current: false } }).title, 'Protected route definition is out of date');
  assert.equal(M.pluginState({ ...PLUG, definition: { ...PLUG.definition, hold: true, hold_reason: 'differs' } }).title, 'Protected route differs from state');
  assert.equal(M.pluginState({ ...PLUG, app: { ...PLUG.app, streaming: false } }).tone, 'warn');
});
const pol = (crowdsec, plugin) => ({ policies: { manual: { status: 'enforced' }, crowdsec: { status: crowdsec }, plugin: { status: plugin } } });
check('each site says which path CrowdSec decisions take', () => {
  assert.deepEqual(M.crowdsecPath(pol('enforced', 'not_imported')), { text: 'CrowdSec decisions: file sync', tone: 'ok' });
  assert.deepEqual(M.crowdsecPath(pol('imported_empty', 'enforced')), { text: 'CrowdSec decisions: file sync and plugin (redundant, both enforce)', tone: 'warn' });
  assert.deepEqual(M.crowdsecPath(pol('not_imported', 'enforced')), { text: 'CrowdSec decisions: plugin', tone: 'ok' });
  assert.deepEqual(M.crowdsecPath(pol('not_imported', 'not_imported')), { text: 'CrowdSec decisions: not enforced', tone: 'none' });
  assert.deepEqual(M.crowdsecPath(pol('not_imported', 'plugin_unprotected')), { text: 'CrowdSec decisions: plugin without the protected ranges', tone: 'crit' });
  assert.equal(M.crowdsecPath({ policies: { manual: {} } }), null, 'no plugin rows: nothing to say');
});
check('a bare crowdsec handler is critical and offers no insert', () => {
  const s = M.siteStatus({ status: 'plugin_unprotected', detail: 'x' });
  assert.deepEqual([s.label, s.tone], ['Plugin runs without the protected ranges', 'crit']);
  assert.match(s.detail, /import protect_crowdsec/);
});
check('the plugin site import is offered only when the plugin is ready', () => {
  const site = { source: 'main' };
  const p = { status: 'not_imported', import: { present: false } };
  assert.deepEqual(M.pluginSiteActions(p, site, PLUG), ['insert', 'copy']);
  assert.deepEqual(M.pluginSiteActions(p, { source: 'external' }, PLUG), ['copy']);
  assert.deepEqual(M.pluginSiteActions(p, site, { ...PLUG, app: null }), []);
  assert.deepEqual(M.pluginSiteActions(p, site, { ...PLUG, refused: true }), []);
  assert.deepEqual(M.pluginSiteActions(p, site, { ...PLUG, definition: { ...PLUG.definition, imported: false } }), []);
  assert.deepEqual(M.pluginSiteActions({ ...p, status: 'enforced' }, site, PLUG), []);
});
check('a refused or held plugin shows in the overall verdict', () => {
  const base = { available: true, degraded: null, caddy: { reachable: true }, sources: { manual: {} }, sites: [{ policies: { manual: { status: 'enforced' } } }] };
  assert.equal(M.overallState({ ...base, plugin: PLUG }).tone, 'ok');
  const refused = M.overallState({ ...base, plugin: { ...PLUG, refused: true, admin: { code: 'admin_wildcard', message: 'm' } } });
  assert.deepEqual([refused.tone, refused.title], ['crit', 'Plugin mode refused: the admin API would be exposed']);
  const held = M.overallState({ ...base, plugin: { ...PLUG, definition: { ...PLUG.definition, hold: true } } });
  assert.equal(held.title, 'Policy differs from state');
  assert.match(held.body, /CrowdSec plugin route/);
});
check('SOURCE_LABELS name the plugin', () => assert.equal(M.SOURCE_LABELS.plugin, 'CrowdSec plugin'));
```

Also extend the existing "no Security file writes HTML" scan in this test file to include `security-plugin.js` (it lists the Security files by name; add the new one to that list).

- [ ] **Step 2: Run it to verify it fails**

Run: `node tests/security-model.test.mjs`
Expected: FAIL (`M.pluginState is not a function`).

- [ ] **Step 3: Implement the model**

In `src/static/js/app/security-model.js`:

```js
export const SOURCE_LABELS = { manual: 'Manual', crowdsec: 'CrowdSec', plugin: 'CrowdSec plugin' };
```

Add to `SITE`: `plugin_unprotected: ['Plugin runs without the protected ranges', 'crit'],` and to the `detail` map in `siteStatus`:
`plugin_unprotected: 'The crowdsec handler runs here without import protect_crowdsec, so private, Docker and BANS_NEVER addresses reach the plugin. Replace the crowdsec line with import protect_crowdsec, then Save & Reload.',`

Append:

```js
const ENFORCES = ['enforced', 'enforced_pre_handler', 'imported_empty'];

export function pluginState(p) {
  if (!p?.enabled) return null;
  if (p.refused) return { tone: 'crit', title: 'Plugin mode refused: the admin API would be exposed', detail: p.admin?.message || '' };
  if (p.module === false) return { tone: 'warn', title: 'The running Caddy has no crowdsec module', detail: 'Start the plugin image with docker-compose.crowdsec-plugin.yaml; stored files stay as they are.' };
  const d = p.definition || {};
  if (d.hold) return { tone: 'warn', title: 'Protected route differs from state', detail: 'crowdsec-plugin-protect.caddy was changed outside the console. Re-apply the plugin route.' };
  if (!d.present || !d.current) return { tone: 'warn', title: 'Protected route definition is out of date', detail: 'Re-apply the plugin route so the protected ranges match the current settings.' };
  if (!p.app) return { tone: 'none', title: 'Plugin app not loaded', detail: 'Insert "CrowdSec plugin: global app" and "load protected route definition" in the editor, then Save & Reload.' };
  if (p.app.key_form === 'literal') return { tone: 'crit', title: 'Bouncer key written into the Caddyfile', detail: `Anyone who can read Caddy's config sees it. Use api_key ${p.placeholder} and rotate the key.` };
  if (p.app.key_form === 'missing') return { tone: 'crit', title: 'The crowdsec app has no bouncer key', detail: `Use api_key ${p.placeholder}.` };
  if (p.app.key_form === 'placeholder') return { tone: 'warn', title: 'Bouncer key placeholder does not match this deployment', detail: `Caddy uses ${p.app.key_placeholder}; this deployment expects ${p.placeholder}.` };
  if (!p.app.streaming) return { tone: 'warn', title: 'Live mode: every request asks CrowdSec', detail: 'Remove disable_streaming from the crowdsec global options.' };
  return { tone: 'ok', title: `Near-real-time without reload, polling every ${p.app.ticker_interval || p.ticker_interval}`, detail: '' };
}

export function crowdsecPath(site) {
  const pol = site?.policies || {};
  if (!pol.plugin) return null;
  if (pol.plugin.status === 'plugin_unprotected') return { text: 'CrowdSec decisions: plugin without the protected ranges', tone: 'crit' };
  const file = ENFORCES.includes(pol.crowdsec?.status);
  const plug = ENFORCES.includes(pol.plugin.status);
  if (file && plug) return { text: 'CrowdSec decisions: file sync and plugin (redundant, both enforce)', tone: 'warn' };
  if (plug) return { text: 'CrowdSec decisions: plugin', tone: 'ok' };
  if (file) return { text: 'CrowdSec decisions: file sync', tone: 'ok' };
  return { text: 'CrowdSec decisions: not enforced', tone: 'none' };
}

export function pluginSiteActions(policy, site, plugin) {
  const base = siteActions({ ...policy, source: site.source });
  const ready = plugin?.enabled && !plugin.refused && plugin.module !== false && plugin.app
    && plugin.definition?.imported && plugin.definition?.current;
  if (!ready) return [];
  return base;
}
```

In `baseState`, extend the held list and add the refusal check right after it:

```js
  const held = Object.entries(status.sources || {}).filter(([, s]) => s?.hold).map(([n]) => SOURCE_LABELS[n] || n);
  if (status.plugin?.definition?.hold) held.push('CrowdSec plugin route');
  if (held.length) { ... unchanged ... }
  const ps = pluginState(status.plugin);
  if (ps && status.plugin.refused) return { tone: 'crit', title: ps.title, body: ps.detail };
```

and, after the CrowdSec sync check, `if (ps && ps.tone === 'crit') return { tone: 'warn', title: 'CrowdSec plugin needs attention', body: ps.title };`.

- [ ] **Step 4: Implement the view**

Create `src/static/js/app/security-plugin.js`:

```js
// CrowdSec plugin part of the Security view (spec 3.6): health, admin bind,
// key mode, polling interval, the protected route definition and copy-only
// commands. Wording lives in security-model.js; every string from the API is
// a text child. `onCopy(text, what)` is the view's clipboard helper.
import { h, htm } from '../explore-vendor.js';
import { Icon } from './icons.js';
import { pluginState } from './security-model.js';

const html = htm.bind(h);
const SEV = { crit: 'critical', warn: 'warn', ok: 'ok', none: 'ok' };

export function PluginSection({ plugin, onCopy, onReapply }) {
  const st = pluginState(plugin);
  if (!st) return null;
  const d = plugin.definition || {};
  const key = plugin.key_mode === 'file' ? `File secret ${plugin.key_file} (${plugin.placeholder})` : `Environment (${plugin.placeholder})`;
  return html`
    <section aria-labelledby="sec-plugin-h">
      <div class="h-sec"><h2 id="sec-plugin-h">CrowdSec plugin</h2>
        <p>Caddy asks CrowdSec directly. Protected addresses never reach the plugin; manual bans still use the ban file.</p></div>
      <p class=${'sec-cs-state sev-' + SEV[st.tone]} role=${st.tone === 'crit' ? 'alert' : 'status'}>
        <strong>${st.title}</strong>${st.detail && html` <span class="muted small">${st.detail}</span>`}</p>
      <dl class="sec-protected">
        <div><dt>Module</dt><dd>${plugin.module === true ? 'Present in the running Caddy' : plugin.module === false ? 'Missing' : 'Unknown (Caddy did not answer)'}</dd></div>
        <div><dt>Admin API</dt><dd>${plugin.refused ? plugin.admin?.message || 'Exposed' : 'Fixed caddy-admin address only'}</dd></div>
        <div><dt>Bouncer key</dt><dd class="mono">${key}</dd></div>
        <div><dt>Polling</dt><dd>Every ${plugin.ticker_interval}, near-real-time without reload</dd></div>
        <div><dt>Protected route</dt><dd class="mono">${d.import_line}${d.hash ? ` (protected ranges ${d.hash}${d.current ? '' : ', out of date'})` : ' (not generated yet)'}</dd></div>
      </dl>
      <div class="acts">
        <button class="btn" type="button" onClick=${onReapply}>Re-apply plugin route</button>
        <button class="btn btn-quiet" type="button" title=${plugin.allowlist} onClick=${() => onCopy(plugin.allowlist, 'cscli allowlist commands')}><${Icon} name="copy" size=${14} />Copy LAPI allowlist commands</button>
        <button class="btn btn-quiet" type="button" title=${plugin.check_command} onClick=${() => onCopy(plugin.check_command, 'Isolation check command')}><${Icon} name="copy" size=${14} />Copy isolation check</button>
      </div>
      <p class="muted small">Run the isolation check on the host after every start: Caddy port 2019 must refuse connections from the CrowdSec and cloudflared containers.</p>
    </section>`;
}
```

In `src/static/js/app/security.js`:

- Import `PluginSection` and `crowdsecPath, pluginSiteActions` from the model.
- In `App`, build the Sites sources and render the section after the CrowdSec one:

  ```js
  const plug = status.plugin?.enabled ? status.plugin : null;
  const siteSources = plug ? { ...active, plugin: { import_line: plug.definition.site_import } } : active;
  const reapplyPlugin = async () => {
    const r = await call('/api/security/reapply', 'POST', { source: 'plugin' });
    toast(r.ok ? 'Plugin route re-applied.' : errorMessage(r.body, r.status), { kind: r.ok ? 'ok' : 'error' });
    load();
  };
  ...
  ${plug && html`<${PluginSection} plugin=${plug} onCopy=${copy} onReapply=${reapplyPlugin} />`}
  ...
  <${Sites} sites=${status.sites} sources=${siteSources} plugin=${plug} />
  ```

- In `Sites({ sites, sources, plugin })`, compute actions with `name === 'plugin' ? pluginSiteActions(p, s, plugin) : siteActions({ ...p, source: s.source })`, and under the site label render the path line when present:

  ```js
        ${(() => { const cp = crowdsecPath(s); return cp && html`<span class=${'sec-path tone-' + cp.tone}>${cp.text}</span>`; })()}
  ```

The import-line list above Sites keeps listing only real sources (`active`); the plugin row's "Copy import" copies `import protect_crowdsec`. No new CSS class is required (`tone-*` already exists for `.sec-policy`); add a one-line `.sec-path { display: block; font-size: var(--fs-sm); }` next to `.sec-policy` in the Security stylesheet only if it does not render on its own line.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `node tests/security-model.test.mjs && node tests/no-native-dialogs.test.mjs`
Expected: PASS. All node suites: PASS. `npm run build` leaves `git diff -- src/static/js/` limited to the edited sources.

Then check the view by hand: `./dev/run.sh up`, open `http://localhost:8888/security`. Stock dev Caddy: no plugin section, site rows unchanged. (The plugin section is exercised end to end in Task 10.)

- [ ] **Step 6: Commit**

```bash
git add src/static/js/app/security-plugin.js src/static/js/app/security-model.js src/static/js/app/security.js tests/security-model.test.mjs
git commit -m "feat(crowdsec-plugin): Security view plugin health and the CrowdSec path of each site"
```

---
### Task 9: The plugin Compose overlays, their static checks and the deployment isolation check

**Files:**
- Create: `docker-compose.crowdsec-plugin.yaml`, `docker-compose.nas.crowdsec-plugin.yaml`
- Create: `dev/check-plugin-overlay.py`, `crowdsec/check-plugin-isolation.sh`
- Modify: `dev/check-crowdsec-overlay.py` (`--plugin`), `dev/check-compose.sh` (Phase 3 gate)

**Interfaces:**
- Produces:
  - `docker-compose.crowdsec-plugin.yaml` (services `caddy`, `caddy-console`, `crowdsec`) and `docker-compose.nas.crowdsec-plugin.yaml` (`caddy`, `caddy-editor`, `crowdsec`). Both need `CADDY_PLUGIN_IMAGE` (immutable reference) and `CROWDSEC_PLUGIN_BOUNCER_KEY`, and are used after the Phase 2 overlay: `docker compose -f <base> -f docker-compose.crowdsec.yaml -f docker-compose.crowdsec-plugin.yaml up -d` (NAS: the two `.nas` files).
  - `dev/check-plugin-overlay.py CADDY CONSOLE VARIANT < config.json` (exit non-zero with one line per problem).
  - `crowdsec/check-plugin-isolation.sh [--caddy NAME] [--console NAME] [--data-port N] -- <compose -f args>`: exit 0 only when every CrowdSec and cloudflared container is refused on Caddy port 2019 at every Caddy address (including `172.30.250.2`), reaches the data-plane port on each network it shares with Caddy, and the plugin and console keys differ.

- [ ] **Step 1: Write the failing static check**

Create `dev/check-plugin-overlay.py`:

```python
"""Check the CrowdSec plugin overlay on `docker compose config --format json` (stdin).

  docker compose -f BASE -f CROWDSEC -f PLUGIN config --format json | python3 dev/check-plugin-overlay.py CADDY CONSOLE VARIANT

VARIANT is crowdsec or crowdsec-cloudflare (the image the stack must use).
"""
import json
import re
import sys

ADMIN_IP, ADMIN_ADDR, SUBNET = "172.30.250.2", "172.30.250.2:2019", "172.30.250.0/29"
IMAGE = r"^ghcr\.io/viralone/caddy-{variant}(?::[\w.-]+)?(?:@sha256:[0-9a-f]{{64}}|:sha-[0-9a-f]{{7,40}})$"


def nets(service):
    return set(service.get("networks") or {})


def ports(service):
    out = set()
    for p in service.get("ports") or []:
        out |= {str(p.get("target")), str(p.get("published"))}
    return out


def main(caddy, console, variant):
    cfg = json.load(sys.stdin)
    services, networks, problems = cfg["services"], cfg.get("networks") or {}, []
    cd, co, cs = services[caddy], services[console], services.get("crowdsec") or {}
    if not re.match(IMAGE.format(variant=re.escape(variant)), cd.get("image", "")):
        problems.append(f"Caddy image must be ghcr.io/viralone/caddy-{variant} by digest or sha- tag: {cd.get('image')}")
    if not {"caddy-admin", "crowdsec-lapi"} <= nets(cd):
        problems.append(f"Caddy networks are {sorted(nets(cd))}; it needs caddy-admin and crowdsec-lapi")
    if ((cd.get("networks") or {}).get("caddy-admin") or {}).get("ipv4_address") != ADMIN_IP:
        problems.append(f"Caddy has no fixed ipv4_address {ADMIN_IP} on caddy-admin")
    admin = networks.get("caddy-admin") or {}
    if not admin.get("internal"):
        problems.append("caddy-admin is not internal")
    subnets = [c.get("subnet") for c in ((admin.get("ipam") or {}).get("config") or [])]
    if subnets != [SUBNET]:
        problems.append(f"caddy-admin subnet is {subnets}, expected [{SUBNET}]")
    env, cenv, senv = cd.get("environment") or {}, co.get("environment") or {}, cs.get("environment") or {}
    for k, v in (("CADDY_ADMIN_ADDRESS", ADMIN_ADDR), ("CADDY_ADMIN_SUBNET", SUBNET)):
        if env.get(k) != v:
            problems.append(f"Caddy {k} must be {v}")
    if not env.get("CROWDSEC_PLUGIN_BOUNCER_KEY") and not env.get("CROWDSEC_PLUGIN_BOUNCER_KEY_FILE"):
        problems.append("Caddy has neither CROWDSEC_PLUGIN_BOUNCER_KEY nor CROWDSEC_PLUGIN_BOUNCER_KEY_FILE")
    if f"http://{ADMIN_ADDR}/" not in " ".join(map(str, (cd.get("healthcheck") or {}).get("test") or [])):
        problems.append("the Caddy health check does not use the fixed admin address")
    if cenv.get("CADDY_API_URL") != f"http://{ADMIN_ADDR}" or cenv.get("CADDY_ADMIN_ADDRESS") != ADMIN_ADDR:
        problems.append("the console must use CADDY_API_URL and CADDY_ADMIN_ADDRESS at the fixed admin address")
    if "CROWDSEC_PLUGIN_BOUNCER_KEY" in cenv:
        problems.append("the console must not receive the plugin's bouncer key")
    plug, cons = senv.get("BOUNCER_KEY_caddy_plugin"), senv.get("BOUNCER_KEY_caddy_console")
    if env.get("CROWDSEC_PLUGIN_BOUNCER_KEY") and plug != env.get("CROWDSEC_PLUGIN_BOUNCER_KEY"):
        problems.append("crowdsec BOUNCER_KEY_caddy_plugin and Caddy's CROWDSEC_PLUGIN_BOUNCER_KEY differ")
    if plug and plug == cons:
        problems.append("the plugin and the console share one bouncer key; they must differ")
    for name, svc in services.items():
        if name not in (caddy, console) and "caddy-admin" in nets(svc):
            problems.append(f"{name} joins caddy-admin")
        if name not in (caddy, console, "crowdsec") and "crowdsec-lapi" in nets(svc):
            problems.append(f"{name} joins crowdsec-lapi")
        if ports(svc) & {"2019", "8080"}:
            problems.append(f"{name} publishes port 2019 or 8080")
    if cs.get("ports"):
        problems.append("crowdsec publishes ports")
    if problems:
        sys.exit("\n".join(problems))


main(*sys.argv[1:4])
```

Change `dev/check-crowdsec-overlay.py` so plugin mode may put Caddy on `crowdsec-lapi`:

```python
def main(caddy, console, plugin=False):
    ...
    for name, svc in services.items():
        if name not in ("crowdsec", console) + ((caddy,) if plugin else ()) and "crowdsec-lapi" in nets(svc):
            problems.append(f"{name} joins crowdsec-lapi")
    if not plugin and "crowdsec-lapi" in nets(services[caddy]):
        problems.append("Caddy joins crowdsec-lapi")
    ...


main(sys.argv[1], sys.argv[2], "--plugin" in sys.argv[3:])
```

Append the Phase 3 gate to `dev/check-compose.sh`:

```bash
# Phase 3 gate: the plugin overlay keeps CrowdSec and cloudflared off caddy-admin,
# pins the fixed admin address and uses a key of its own. It is checked on top
# of the CrowdSec overlay, as it is used.
export CROWDSEC_PLUGIN_BOUNCER_KEY=dummy-plugin-key
export CADDY_PLUGIN_IMAGE=ghcr.io/viralone/caddy-crowdsec:sha-0000000
for combo in "docker-compose.prod.yaml docker-compose.crowdsec.yaml docker-compose.crowdsec-plugin.yaml caddy caddy-console crowdsec" \
             "docker-compose.internal.yaml docker-compose.crowdsec.yaml docker-compose.crowdsec-plugin.yaml caddy caddy-console crowdsec" \
             "docker-compose.tunnel.yaml docker-compose.crowdsec.yaml docker-compose.crowdsec-plugin.yaml caddy caddy-console crowdsec" \
             "docker-compose.nas.yaml docker-compose.nas.crowdsec.yaml docker-compose.nas.crowdsec-plugin.yaml caddy caddy-editor crowdsec-cloudflare"; do
  read -r base cs plug caddy console variant <<<"$combo"
  image="ghcr.io/viralone/caddy-$variant:sha-0000000"
  out=$(CADDY_PLUGIN_IMAGE="$image" docker compose -f "$base" -f "$cs" -f "$plug" config --format json)
  python3 dev/check-crowdsec-overlay.py "$caddy" "$console" --plugin <<<"$out" \
    || { echo "$base + $plug: CrowdSec overlay check failed" >&2; exit 1; }
  python3 dev/check-plugin-overlay.py "$caddy" "$console" "$variant" <<<"$out" \
    || { echo "$base + $plug: plugin overlay check failed" >&2; exit 1; }
  # The same key for both bouncers must be caught.
  if CADDY_PLUGIN_IMAGE="$image" CROWDSEC_PLUGIN_BOUNCER_KEY="$CROWDSEC_CONSOLE_BOUNCER_KEY" \
      docker compose -f "$base" -f "$cs" -f "$plug" config --format json \
      | python3 dev/check-plugin-overlay.py "$caddy" "$console" "$variant" 2>/dev/null; then
    echo "$base + $plug: a shared bouncer key was not detected" >&2; exit 1
  fi
  echo "$base + $plug: ok"
done
# The baseline files still render without any plugin variable.
unset CROWDSEC_PLUGIN_BOUNCER_KEY CADDY_PLUGIN_IMAGE
```

- [ ] **Step 2: Run it to verify it fails**

Run: `./dev/check-compose.sh`
Expected: the Phase 1 and 2 lines print `ok`, then FAIL because `docker-compose.crowdsec-plugin.yaml` does not exist.

- [ ] **Step 3: Write the overlays**

Create `docker-compose.crowdsec-plugin.yaml`:

```yaml
# Optional CrowdSec plugin add-on (docs/security.md#crowdsec-plugin). Needs the
# CrowdSec overlay first:
#
#   docker compose -f docker-compose.prod.yaml -f docker-compose.crowdsec.yaml \
#     -f docker-compose.crowdsec-plugin.yaml up -d
#   crowdsec/check-plugin-isolation.sh -- -f docker-compose.prod.yaml \
#     -f docker-compose.crowdsec.yaml -f docker-compose.crowdsec-plugin.yaml
#
# Works with the prod, internal and tunnel stacks; the NAS stack uses
# docker-compose.nas.crowdsec-plugin.yaml. It replaces only the Caddy image,
# puts Caddy on crowdsec-lapi so the plugin can poll LAPI, and pins Caddy to
# 172.30.250.2 on caddy-admin. Before the first start, the Caddyfile must bind
# the admin API there and nowhere else:
#
#   {
#       admin 172.30.250.2:2019 {
#           origins caddy:2019 172.30.250.2:2019
#       }
#   }
#
# The image's entrypoint refuses to start Caddy otherwise. No port is
# published; CrowdSec and cloudflared never join caddy-admin. A stack whose
# caddy-admin network already exists without this subnet must be taken down
# once (docker compose ... down, without -v) so Compose can recreate it.
services:
  caddy:
    # An immutable reference: ghcr.io/viralone/caddy-crowdsec@sha256:<digest>
    # or ghcr.io/viralone/caddy-crowdsec:sha-<commit>.
    image: ${CADDY_PLUGIN_IMAGE:?Set CADDY_PLUGIN_IMAGE to ghcr.io/viralone/caddy-crowdsec@sha256:<digest> or :sha-<commit>}
    environment:
      CADDY_ADMIN_ADDRESS: 172.30.250.2:2019
      CADDY_ADMIN_SUBNET: 172.30.250.0/29
      # A key of its own, never the console's: LAPI stream cursors belong to a
      # bouncer identity. Registered below as the bouncer "caddy_plugin".
      CROWDSEC_PLUGIN_BOUNCER_KEY: ${CROWDSEC_PLUGIN_BOUNCER_KEY:?Set CROWDSEC_PLUGIN_BOUNCER_KEY (python -c "import secrets; print(secrets.token_hex(32))"), different from CROWDSEC_CONSOLE_BOUNCER_KEY}
      CROWDSEC_PLUGIN_BOUNCER_KEY_FILE: ""
    networks:
      caddy-admin:
        ipv4_address: 172.30.250.2
      crowdsec-lapi: {}
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://172.30.250.2:2019/config/"]

  caddy-console:
    environment:
      CADDY_API_URL: http://172.30.250.2:2019
      CADDY_ADMIN_ADDRESS: 172.30.250.2:2019
      # Environment-key mode. For a file secret see docs/security.md.
      CROWDSEC_PLUGIN_BOUNCER_KEY_FILE: ""

  crowdsec:
    environment:
      BOUNCER_KEY_caddy_plugin: ${CROWDSEC_PLUGIN_BOUNCER_KEY:?Set CROWDSEC_PLUGIN_BOUNCER_KEY}

networks:
  # Caddy <-> console only. The fixed address lets the Caddyfile bind the
  # admin API to this network alone.
  caddy-admin:
    internal: true
    ipam:
      config:
        - subnet: 172.30.250.0/29
  crowdsec-lapi:
    internal: true
```

Create `docker-compose.nas.crowdsec-plugin.yaml` with the same comments adapted to the NAS file names, `caddy` using `${CADDY_PLUGIN_IMAGE:?Set CADDY_PLUGIN_IMAGE to ghcr.io/viralone/caddy-crowdsec-cloudflare@sha256:<digest> or :sha-<commit>}` (the NAS stack needs DNS-01; its `CLOUDFLARE_API_TOKEN` stays from the base file), the same `caddy` environment, networks and health check, the console block under `caddy-editor` instead of `caddy-console`, the same `crowdsec` block, and the same top-level `networks`.

- [ ] **Step 4: Write the deployment isolation check**

Create `crowdsec/check-plugin-isolation.sh` (mode 0755):

```bash
#!/usr/bin/env bash
# Deployment check for CrowdSec plugin mode (docs/security.md#crowdsec-plugin, spec 3.1).
# Run it on the Docker host after every start; plugin mode is not started
# successfully until it passes. It needs no published port: each probe runs in
# the network namespace of the CrowdSec or cloudflared container itself.
#
#   crowdsec/check-plugin-isolation.sh [--caddy caddy] [--console caddy-console] [--data-port 80] \
#     -- -f docker-compose.prod.yaml -f docker-compose.crowdsec.yaml -f docker-compose.crowdsec-plugin.yaml
set -euo pipefail
CADDY=caddy CONSOLE=caddy-console DATA_PORT=80 ADMIN_IP=172.30.250.2
while [ $# -gt 0 ]; do
  case "$1" in
    --caddy) CADDY="$2"; shift 2 ;;
    --console) CONSOLE="$2"; shift 2 ;;
    --data-port) DATA_PORT="$2"; shift 2 ;;
    --) shift; break ;;
    *) echo "usage: $0 [--caddy NAME] [--console NAME] [--data-port N] -- <docker compose -f ...>" >&2; exit 2 ;;
  esac
done
[ $# -gt 0 ] || { echo "pass the Compose files after --" >&2; exit 2; }
COMPOSE=(docker compose "$@")
fail() { echo "plugin isolation: FAILED: $*" >&2; exit 1; }

caddy_id="$("${COMPOSE[@]}" ps -q "$CADDY")"; [ -n "$caddy_id" ] || fail "$CADDY is not running"
console_id="$("${COMPOSE[@]}" ps -q "$CONSOLE")"; [ -n "$console_id" ] || fail "$CONSOLE is not running"
probe_image="$(docker inspect -f '{{.Config.Image}}' "$console_id")"

# Exit 0 when a TCP connection to $2:$3 succeeds from inside container $1.
reach() {
  docker run --rm --network "container:$1" --entrypoint /app/.venv/bin/python "$probe_image" -c '
import socket, sys
try:
    socket.create_connection((sys.argv[1], int(sys.argv[2])), 3).close()
except OSError:
    sys.exit(1)' "$2" "$3"
}
networks_of() { docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}} {{end}}' "$1"; }

caddy_nets="$(networks_of "$caddy_id")"
peers="$("${COMPOSE[@]}" ps --format '{{.Service}}' | grep -E '^(crowdsec|cloudflared)' || true)"
[ -n "$peers" ] || fail "no crowdsec or cloudflared container is running"
for peer in $peers; do
  peer_id="$("${COMPOSE[@]}" ps -q "$peer")"
  peer_nets="$(networks_of "$peer_id")"
  targets="$ADMIN_IP"
  for entry in $caddy_nets; do targets="$targets ${entry#*=}"; done
  for ip in $targets; do
    [ -n "$ip" ] || continue
    if reach "$peer_id" "$ip" 2019; then fail "$peer reached the Caddy admin API at $ip:2019"; fi
  done
  shared=""
  for entry in $caddy_nets; do
    case " $peer_nets " in *" ${entry%%=*}="*) shared="$shared ${entry#*=}" ;; esac
  done
  if [ -n "$shared" ]; then
    answered=""
    for ip in $shared; do if reach "$peer_id" "$ip" "$DATA_PORT"; then answered="$ip"; break; fi; done
    [ -n "$answered" ] || fail "$peer cannot reach Caddy's data plane on port $DATA_PORT ($shared)"
    echo "$peer: 2019 refused on $(echo "$targets" | wc -w | tr -d ' ') addresses; data plane answers at $answered:$DATA_PORT"
  else
    echo "$peer: 2019 refused on $(echo "$targets" | wc -w | tr -d ' ') addresses; shares no network with Caddy"
  fi
done

# The two bouncers must not share a key (compares the rendered environment; file secrets are not read).
"${COMPOSE[@]}" config --format json | python3 -c '
import json, sys
env = (json.load(sys.stdin)["services"].get("crowdsec") or {}).get("environment") or {}
p, c = env.get("BOUNCER_KEY_caddy_plugin"), env.get("BOUNCER_KEY_caddy_console")
sys.exit("the plugin and the console share one bouncer key" if p and p == c else 0)' || fail "shared bouncer key"
echo "plugin isolation: ok"
```

- [ ] **Step 5: Run the checks to verify they pass**

Run: `./dev/check-compose.sh`
Expected: every Phase 1, 2 and 3 line ends with `ok`.

Run: `docker compose -f docker-compose.prod.yaml config >/dev/null` with none of the plugin variables set (as `check-compose.sh` does for the baseline). Expected: renders; no `CADDY_PLUGIN_IMAGE` is needed. (`crowdsec/check-plugin-isolation.sh` runs against real containers in Task 10.)

- [ ] **Step 6: Commit**

```bash
git add docker-compose.crowdsec-plugin.yaml docker-compose.nas.crowdsec-plugin.yaml dev/check-plugin-overlay.py \
  dev/check-crowdsec-overlay.py dev/check-compose.sh crowdsec/check-plugin-isolation.sh
git commit -m "feat(crowdsec-plugin): optional plugin overlays with a fixed admin bind, static checks and an isolation check"
```

---
### Task 10: Plugin integration suite

Everything in the spec's "Run the optional plugin overlay" list, against the image built in Task 2, a fake LAPI that speaks the decision-stream protocol, the real console image, and client containers whose addresses make the direct, proxied-DNS and Tunnel fixtures real TCP peers: a direct client at `198.51.100.10`, a "Cloudflare edge" at `192.0.2.10` that Caddy trusts on `:8001`, and a cloudflared stand-in at `172.30.252.3` that Caddy trusts on `:8002`. The suite follows the operator's own order: start Caddy with the global app and the definition import, let the console render the definition, then protect the sites through the console's Save.

**Files:**
- Create: `tests/integration/plugin/compose.yaml`, `tests/integration/plugin/compose.file-secret.yaml`
- Create: `tests/integration/fake_lapi.py`, `tests/integration/plugin_it.py`, `tests/integration/plugin_client.py`
- Create: `dev/crowdsec-plugin-it.sh`

**Interfaces:**
- Consumes: `caddy-crowdsec:local` (Task 2; `PLUGIN_IMAGE` overrides), the shipped snippets (Task 6), `crowdsec/check-plugin-isolation.sh` (Task 9), every console API from Tasks 3-8.
- Produces: `./dev/crowdsec-plugin-it.sh` (exit 0 = Phase 3 gate passed locally; Task 11 runs it in CI). Compose project `caddy-console-plugin-it`; host directories under `dev/run/plugin-it*` (git-ignored, removed on exit).

- [ ] **Step 1: Write the fake LAPI**

Create `tests/integration/fake_lapi.py`:

```python
"""A fake CrowdSec LAPI for the plugin integration suite (never discovered).

Speaks the bouncer side of LAPI v1: GET /v1/decisions/stream (startup=true
returns the active set, later polls the changes since that bouncer's last
poll), GET /v1/decisions (live mode: always null) and POST /v1/usage-metrics.
Each bouncer is told apart by its key: FAKE_LAPI_KEYS="console:<key>,plugin:<key>",
and the two keys must differ. The suite drives it through /it/* with the
FAKE_LAPI_CONTROL token. Runs only on the internal crowdsec-lapi network.

  python -m tests.integration.fake_lapi
"""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

KEYS = {}
for item in os.environ.get("FAKE_LAPI_KEYS", "").split(","):
    name, _, key = item.partition(":")
    if name and key:
        KEYS[key] = name
if len(KEYS) != 2 or set(KEYS.values()) != {"console", "plugin"}:
    sys.exit("fake_lapi: FAKE_LAPI_KEYS needs two different keys named console and plugin")
CONTROL = os.environ["FAKE_LAPI_CONTROL"]
lock = threading.Lock()
state = {"seq": 0, "events": [], "active": {}, "cursors": {}, "calls": [], "next_id": 1000}


def decision(value, origin, scenario, scope):
    state["next_id"] += 1
    return {"id": state["next_id"], "origin": origin, "scenario": scenario, "scope": scope, "type": "ban",
            "value": value, "duration": "3h59m58s"}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(min(n, 1 << 20)) if n else b""
        try:
            return json.loads(raw or b"{}")
        except ValueError:
            return {}

    def _bouncer(self, path, query):
        name = KEYS.get(self.headers.get("X-Api-Key", ""))
        with lock:
            state["calls"].append({"name": name, "ua": self.headers.get("User-Agent", "")[:100], "path": path,
                                   "startup": (query.get("startup") or [""])[0]})
            del state["calls"][:-500]
        return name

    def do_GET(self):
        u = urlsplit(self.path)
        q = parse_qs(u.query)
        if u.path == "/it/calls":
            if self.headers.get("X-Control") != CONTROL:
                return self._send(403, {"message": "control token"})
            with lock:
                return self._send(200, state["calls"])
        name = self._bouncer(u.path, q)
        if name is None:
            return self._send(403, {"message": "access forbidden"})
        if u.path == "/v1/decisions/stream":
            startup = (q.get("startup") or ["false"])[0] == "true"
            with lock:
                since = 0 if startup else state["cursors"].get(name, 0)
                if startup:
                    new, deleted = list(state["active"].values()), []
                else:
                    new = [d for s, kind, d in state["events"] if s > since and kind == "new"]
                    deleted = [{**d, "duration": "-1s"} for s, kind, d in state["events"] if s > since and kind == "deleted"]
                state["cursors"][name] = state["seq"]
            return self._send(200, {"new": new or None, "deleted": deleted or None})
        if u.path == "/v1/decisions":
            return self._send(200, None)
        return self._send(404, {"message": "not found"})

    def do_POST(self):
        u = urlsplit(self.path)
        if u.path.startswith("/it/"):
            if self.headers.get("X-Control") != CONTROL:
                return self._send(403, {"message": "control token"})
            body = self._body()
            with lock:
                state["seq"] += 1
                if u.path == "/it/add":
                    d = decision(body["value"], body.get("origin", "lists:it"), body.get("scenario", "it/plugin"),
                                 body.get("scope", "Ip"))
                    state["active"][d["id"]] = d
                    state["events"].append((state["seq"], "new", d))
                    return self._send(200, d)
                if u.path == "/it/delete":
                    d = state["active"].pop(int(body["id"]), None)
                    if d:
                        state["events"].append((state["seq"], "deleted", d))
                    return self._send(200, {"deleted": bool(d)})
            return self._send(404, {"message": "not found"})
        name = self._bouncer(u.path, {})
        if name is None:
            return self._send(403, {"message": "access forbidden"})
        self._body()
        return self._send(201, {})

    def log_message(self, fmt, *args):
        sys.stderr.write("fake_lapi: " + (fmt % args) + "\n")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
```

If the pinned plugin calls an endpoint the fake does not know, its log shows `"GET /path ..." 404`; add that endpoint here with LAPI v1.8.2's response shape rather than weakening an assertion.

- [ ] **Step 2: Write the client helper**

Create `tests/integration/plugin_client.py`:

```python
"""One HTTP request from a client container, retried until the expected status.

  python -m tests.integration.plugin_client URL HOST EXPECT [--within S] [--header 'Name: value' ...]
"""
import argparse
import sys
import time

import requests


def main():
    p = argparse.ArgumentParser()
    p.add_argument("url")
    p.add_argument("host")
    p.add_argument("expect", type=int)
    p.add_argument("--within", type=float, default=0)
    p.add_argument("--header", action="append", default=[])
    a = p.parse_args()
    headers = {"Host": a.host, **dict(h.split(": ", 1) for h in a.header)}
    end = time.monotonic() + a.within
    while True:
        try:
            code = requests.get(a.url, headers=headers, timeout=5, allow_redirects=False).status_code
        except requests.RequestException as e:
            code = f"error {type(e).__name__}"
        if code == a.expect:
            print(f"{a.host} {a.url} {' '.join(a.header)} -> {code}")
            return
        if time.monotonic() >= end:
            sys.exit(f"plugin_client: {a.host} {a.url} {a.header} answered {code}, expected {a.expect}")
        time.sleep(1)


main()
```

- [ ] **Step 3: Write the suite's console-side steps**

Create `tests/integration/plugin_it.py`:

```python
"""CrowdSec plugin mode end to end (spec "Run the optional plugin overlay").

Runs inside the console container of tests/integration/plugin/compose.yaml, one
step per call; dev/crowdsec-plugin-it.sh drives the steps that need the host or
another container. It uses the console only through its HTTP API and files,
and the Caddyfiles it writes use the shipped snippet code verbatim, so every
successful start is also the "documented snippets adapt and run" check.

  python -m tests.integration.plugin_it <command> [args]
"""
import json
import os
import re
import sys
import time

import requests

CADDYFILE = "/etc/caddy/Caddyfile"
BANS_DIR = "/etc/caddy/console"
ROUTE = f"{BANS_DIR}/crowdsec-plugin-protect.caddy"
CONSOLE = "http://127.0.0.1:9090"
LAPI = "http://crowdsec:8080"
CONTROL = {"X-Control": os.environ.get("FAKE_LAPI_CONTROL", "")}
AUTH = {"Cf-Access-Authenticated-User-Email": "it@example.com"}
FIXED = "172.30.250.2:2019"
ADMIN = {
    "fixed": f"\tadmin {FIXED} {{\n\t\torigins caddy:2019 {FIXED}\n\t}}\n",
    "wildcard": "\tadmin 0.0.0.0:2019\n",
    "loopback": "\tadmin localhost:2019\n",
    "missing": "",
}
SERVERS = ("\tservers :8001 {\n\t\ttrusted_proxies static 192.0.2.0/24\n\t\tclient_ip_headers Cf-Connecting-Ip\n\t}\n"
           "\tservers :8002 {\n\t\ttrusted_proxies static 172.30.252.3/32\n\t\tclient_ip_headers Cf-Connecting-Ip\n\t}\n")


def fail(message):
    sys.exit(f"plugin_it: {message}")


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


def shipped():
    with open("/app/src/snippets.json", encoding="utf-8") as f:
        return {s["id"]: s["code"].replace("/etc/caddy/console/", BANS_DIR + "/") for s in json.load(f) if "id" in s}


def indent(code, prefix):
    return "".join(prefix + line + "\n" for line in code.splitlines())


def caddyfile(mode, admin="fixed", stage="full", key_path=None):
    s = shipped()
    glob = s[f"crowdsec-plugin-global-{mode}"]
    if key_path:
        glob = glob.replace("/run/secrets/crowdsec_plugin_bouncer_key", key_path)
    site = indent(s["crowdsec-plugin-site"], "\t") if stage == "full" else ""
    hosts = lambda h: f"http://{h}, http://{h}:8001, http://{h}:8002"
    return ("{\n" + ADMIN[admin] + SERVERS + indent(glob, "\t") + "}\n\n" + s["crowdsec-plugin-definition"] + "\n"
            + hosts("plugin.it.example.com") + " {\n\timport " + BANS_DIR + "/bans-manual*.caddy\n" + site
            + "\trespond \"plugin ok\" 200\n}\n\n"
            + hosts("file.it.example.com") + " {\n\timport " + BANS_DIR + "/bans-manual*.caddy\n\timport "
            + BANS_DIR + "/bans-crowdsec*.caddy\n\trespond \"file ok\" 200\n}\n")


def session():
    s = requests.Session()
    s.headers.update(AUTH)
    page = s.get(CONSOLE + "/", timeout=10).text
    s.headers["X-CSRF-Token"] = re.search(r'name="csrf-token" content="([^"]+)"', page).group(1)
    return s


def security():
    r = session().get(CONSOLE + "/api/security", timeout=20)
    r.raise_for_status()
    return r.json()


def row(status, host):
    return next(x for x in status["sites"] if host in x["hosts"])


def cmd_write_caddyfile(mode, admin="fixed", stage="full", key_path=None):
    with open(CADDYFILE, "w", encoding="utf-8") as f:
        f.write(caddyfile(mode, admin, stage, key_path))


def cmd_wait_definition():
    wait(lambda: security()["plugin"]["module"] is True, 60, "the console to see the crowdsec module")
    wait(lambda: security()["plugin"]["definition"]["current"], 90, "the protected route definition")
    with open(ROUTE, encoding="utf-8") as f:
        text = f.read()
    if "\t\tnot client_ip private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10 " not in text \
            or " 203.0.113.99" not in text:
        fail(f"the route lacks the protected set or BANS_NEVER:\n{text}")
    p = security()["plugin"]
    if p["refused"] or p["admin"] is not None:
        fail(f"plugin mode refused: {p['admin']}")
    print(f"definition current ({p['definition']['hash']}); admin bind accepted")


def cmd_save(mode):
    s = session()
    version = s.get(CONSOLE + "/api/caddyfile", timeout=10).json().get("version")
    bad = caddyfile(mode, admin="wildcard")
    r = s.post(CONSOLE + "/api/save", json={"content": bad, "version": version}, timeout=30)
    if r.status_code != 409 or r.json().get("code") != "admin_exposed":
        fail(f"a wildcard admin save was not refused: {r.status_code} {r.text[:300]}")
    r = s.post(CONSOLE + "/api/save", json={"content": caddyfile(mode), "version": version}, timeout=60)
    if r.status_code != 200 or not r.json().get("ok"):
        fail(f"saving the protected sites failed: {r.status_code} {r.text[:500]}")
    print("wildcard save refused; protected sites saved and loaded")


def cmd_check_paths():
    def ready():
        st = security()
        p, f = row(st, "plugin.it.example.com")["policies"], row(st, "file.it.example.com")["policies"]
        return (p["plugin"]["status"] == "enforced" and p["crowdsec"]["status"] == "not_imported"
                and f["plugin"]["status"] == "not_imported" and f["crowdsec"]["status"] in ("enforced", "imported_empty"))
    wait(ready, 60, "plugin site on the plugin path and file site on the file path")
    print("per-site CrowdSec paths: plugin site -> plugin, file site -> file sync")


def cmd_lapi_add(value, origin="lists:it"):
    r = requests.post(LAPI + "/it/add", json={"value": value, "origin": origin}, headers=CONTROL, timeout=5)
    r.raise_for_status()
    print(r.json()["id"])


def cmd_check_keys():
    calls = requests.get(LAPI + "/it/calls", headers=CONTROL, timeout=5).json()
    stream = [c for c in calls if c["path"] == "/v1/decisions/stream"]
    plugin = {c["ua"].split("/")[0] for c in stream if c["name"] == "plugin"}
    console = {c["ua"].split("/")[0] for c in stream if c["name"] == "console"}
    if not plugin or not console or "caddy-console" in plugin or console != {"caddy-console"}:
        fail(f"bouncer identities are mixed up: plugin UAs {plugin}, console UAs {console}")
    if any(c["name"] is None for c in calls):
        fail("a request used an unknown key")
    print(f"plugin polls with its own key ({sorted(plugin)}); the console with its own")


def cmd_manual_ban(value):
    r = session().post(CONSOLE + "/api/bans", json={"value": value, "duration": "4h", "reason": "plugin it"}, timeout=60)
    if r.status_code != 201 or r.json().get("enforcement") != "enforced":
        fail(f"manual ban failed: {r.status_code} {r.text[:300]}")
    with open(f"{BANS_DIR}/bans-manual.caddy", encoding="utf-8") as f:
        if value not in f.read():
            fail("the manual ban is not in bans-manual.caddy")
    with open(ROUTE, encoding="utf-8") as f:
        if value in f.read():
            fail("a manual ban leaked into the plugin route")
    print(f"manual ban {value} rendered to bans-manual.caddy only")


def cmd_wait_file_record(value):
    def stored():
        with open("/backups/bans.json", encoding="utf-8") as f:
            return any(r["source"] == "crowdsec" and r["value"] == value for r in json.load(f)["records"])
    wait(stored, 45, f"the console's file sync to store {value}")


def cmd_check_ignored(value):
    with open("/backups/bans.json", encoding="utf-8") as f:
        if any(r["value"] == value for r in json.load(f)["records"]):
            fail(f"{value} (lists:it origin) was synced into the file; only the plugin should enforce it")


COMMANDS = {name[4:].replace("_", "-"): fn for name, fn in globals().items() if name.startswith("cmd_")}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        fail(f"usage: plugin_it {{{'|'.join(sorted(COMMANDS))}}} [args]")
    COMMANDS[sys.argv[1]](*sys.argv[2:])
```

`GET /api/caddyfile` is the editor's existing read of the Caddyfile and its version.

- [ ] **Step 4: Write the Compose project**

Create `tests/integration/plugin/compose.yaml`:

```yaml
# Plugin-mode integration project, driven by dev/crowdsec-plugin-it.sh. NOT for
# deployment. Same isolation as docker-compose.crowdsec-plugin.yaml, plus
# client containers whose addresses are the direct, proxied and tunnel peers.
name: caddy-console-plugin-it

x-console-image: &console-image
  image: caddy-console:plugin-it
  read_only: true
  cap_drop: [ALL]
  security_opt: ["no-new-privileges:true"]
  tmpfs: ["/tmp:size=64m,mode=1777"]
  volumes:
    - ../../../tests:/app/tests:ro

services:
  caddy:
    image: ${PLUGIN_IMAGE:-caddy-crowdsec:local}
    read_only: true
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]
    security_opt: ["no-new-privileges:true"]
    tmpfs: ["/tmp:size=64m,mode=1777"]
    environment:
      CADDY_ADMIN_ADDRESS: 172.30.250.2:2019
      CADDY_ADMIN_SUBNET: 172.30.250.0/29
      CROWDSEC_PLUGIN_BOUNCER_KEY: ${IT_PLUGIN_KEY:?}
      CROWDSEC_PLUGIN_BOUNCER_KEY_FILE: ""
    volumes:
      - ../../../dev/run/plugin-it:/etc/caddy:ro
      - caddy-data:/data
      - caddy-config:/config
    networks:
      caddy-admin: {ipv4_address: 172.30.250.2}
      crowdsec-lapi: {}
      edge-direct: {ipv4_address: 198.51.100.2}
      edge-proxied: {ipv4_address: 192.0.2.2}
      caddy-edge: {ipv4_address: 172.30.252.2}
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://172.30.250.2:2019/config/"]
      interval: 5s
      timeout: 5s
      retries: 20

  console:
    <<: *console-image
    build: ../../..
    user: "${CADDY_CONSOLE_UID:-1000}:${CADDY_CONSOLE_GID:-1000}"
    tmpfs: ["/tmp:size=128m,mode=1777"]
    environment:
      AUTH_MODE: cloudflare
      UNSAFE_ALLOW_UNVERIFIED_CF_HEADER: "true"
      ALLOWED_EMAILS: it@example.com
      SECRET_KEY: plugin-it-only-not-a-real-secret-0123456789
      SESSION_COOKIE_SECURE: "false"
      GEOIP_AUTO_UPDATE: "false"
      SERVER_URL: http://console.it.example.com
      CADDYFILE_PATH: /etc/caddy/Caddyfile
      BACKUP_DIR: /backups
      AUDIT_LOG: /backups/audit.log
      CADDY_API_URL: http://172.30.250.2:2019
      CADDY_ADMIN_ADDRESS: 172.30.250.2:2019
      CROWDSEC_PLUGIN_BOUNCER_KEY_FILE: ""
      BANS_ENABLED: "true"
      BANS_NEVER: 203.0.113.99
      CROWDSEC_URL: http://crowdsec:8080
      CROWDSEC_CONSOLE_BOUNCER_KEY: ${IT_CONSOLE_KEY:?}
      CROWDSEC_ORIGINS: crowdsec,cscli
      CROWDSEC_POLL_INTERVAL: "5"
      BANS_SYNC_INTERVAL: "10"
      FAKE_LAPI_CONTROL: ${IT_CONTROL:?}
    volumes:
      - ../../../dev/run/plugin-it:/etc/caddy
      - ../../../dev/run/plugin-it-backups:/backups
      - ../../../tests:/app/tests:ro
    networks:
      caddy-admin: {ipv4_address: 172.30.250.3}
      crowdsec-lapi: {}
    healthcheck:
      test: ["CMD", "/app/.venv/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:9090/health', timeout=3)"]
      interval: 5s
      timeout: 5s
      retries: 20

  crowdsec:
    <<: *console-image
    command: ["/app/.venv/bin/python", "-m", "tests.integration.fake_lapi"]
    environment:
      FAKE_LAPI_KEYS: console:${IT_CONSOLE_KEY:?},plugin:${IT_PLUGIN_KEY:?}
      FAKE_LAPI_CONTROL: ${IT_CONTROL:?}
    networks: [crowdsec-lapi]

  client-direct:
    <<: *console-image
    command: ["sleep", "infinity"]
    networks:
      edge-direct: {ipv4_address: 198.51.100.10}

  edge-proxy:
    <<: *console-image
    command: ["sleep", "infinity"]
    networks:
      edge-proxied: {ipv4_address: 192.0.2.10}

  cloudflared:
    <<: *console-image
    command: ["sleep", "infinity"]
    networks:
      caddy-edge: {ipv4_address: 172.30.252.3}

networks:
  caddy-admin:
    internal: true
    ipam: {config: [{subnet: 172.30.250.0/29}]}
  crowdsec-lapi:
    internal: true
  edge-direct:
    internal: true
    ipam: {config: [{subnet: 198.51.100.0/24}]}
  edge-proxied:
    internal: true
    ipam: {config: [{subnet: 192.0.2.0/24}]}
  caddy-edge:
    internal: true
    ipam: {config: [{subnet: 172.30.252.0/29}]}

volumes:
  caddy-data:
  caddy-config:
```

Create `tests/integration/plugin/compose.file-secret.yaml`:

```yaml
# File-secret mode on top of compose.yaml. IT_KEY_FILE lets the suite point the
# variable at a path other than the mount, which the preflight must refuse.
services:
  caddy:
    environment:
      CROWDSEC_PLUGIN_BOUNCER_KEY: ""
      CROWDSEC_PLUGIN_BOUNCER_KEY_FILE: ${IT_KEY_FILE:-/run/secrets/crowdsec_plugin_bouncer_key}
    secrets: [crowdsec_plugin_bouncer_key]
  console:
    environment:
      CROWDSEC_PLUGIN_BOUNCER_KEY_FILE: /run/secrets/crowdsec_plugin_bouncer_key

secrets:
  crowdsec_plugin_bouncer_key:
    file: ../../../dev/run/plugin-it-secret/crowdsec_plugin_bouncer_key
```

- [ ] **Step 5: Write the driver**

Create `dev/crowdsec-plugin-it.sh` (mode 0755):

```bash
#!/usr/bin/env bash
# CrowdSec plugin mode end to end (spec "Run the optional plugin overlay", Phase 3 gate).
# Needs Docker. Builds caddy-crowdsec:local unless PLUGIN_IMAGE names an image.
# Throwaway keys, so CI needs no secret. Removes its project and files on exit.
set -euo pipefail
cd "$(dirname "$0")/.."
export CADDY_CONSOLE_UID="$(id -u)" CADDY_CONSOLE_GID="$(id -g)" BUILDX_BUILDER="${BUILDX_BUILDER:-default}"
rand() { python3 -c 'import secrets; print(secrets.token_hex(24))'; }
export IT_CONSOLE_KEY="$(rand)" IT_PLUGIN_KEY="$(rand)" IT_CONTROL="$(rand)"
export PLUGIN_IMAGE="${PLUGIN_IMAGE:-caddy-crowdsec:local}"
F=tests/integration/plugin
P=(docker compose -f "$F/compose.yaml")
PF=(docker compose -f "$F/compose.yaml" -f "$F/compose.file-secret.yaml")
it() { "${P[@]}" exec -T console /app/.venv/bin/python -m tests.integration.plugin_it "$@"; }
req() { local svc="$1"; shift; "${P[@]}" exec -T "$svc" /app/.venv/bin/python -m tests.integration.plugin_client "$@"; }
lapi_add() { it lapi-add "$@" | tail -n 1; }
refused() {  # $@: compose command prefix; Caddy must exit before launch with $MSG
  local out
  if out="$("$@" run --rm --no-deps caddy 2>&1)"; then echo "Caddy started but should have been refused" >&2; return 1; fi
  grep -q "refusing to start Caddy" <<<"$out" && grep -q "$MSG" <<<"$out" || { echo "$out" >&2; return 1; }
  echo "refused before launch: $MSG"
}
cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then "${P[@]}" logs --tail 200 >&2 || true; fi
  "${P[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf dev/run/plugin-it dev/run/plugin-it-backups dev/run/plugin-it-secret
  if [ "$status" -ne 0 ]; then echo "plugin integration: FAILED (exit $status)" >&2; fi
  exit "$status"
}
trap cleanup EXIT

docker image inspect "$PLUGIN_IMAGE" >/dev/null 2>&1 || ./dev/build-plugin-image.sh crowdsec
docker run --rm "$PLUGIN_IMAGE" caddy list-modules --json --skip-standard | python3 dev/check-plugin-modules.py crowdsec
mkdir -p dev/run/plugin-it/console dev/run/plugin-it-backups dev/run/plugin-it-secret
# Written like `echo key > file`: Caddy trims the trailing newline (Review Focus 5).
printf '%s\n' "$IT_PLUGIN_KEY" > dev/run/plugin-it-secret/crowdsec_plugin_bouncer_key
"${P[@]}" build console
"${P[@]}" up -d --wait --wait-timeout 120 crowdsec console client-direct edge-proxy cloudflared

# 1. The admin bind is checked before Caddy listens.
for admin in wildcard loopback missing; do
  it write-caddyfile env "$admin" bootstrap
  case "$admin" in wildcard) MSG="wildcard address" ;; loopback) MSG="loopback only" ;; missing) MSG="no admin line" ;; esac
  refused "${P[@]}"
done

# 2. Environment-key mode, in the operator's order.
it write-caddyfile env fixed bootstrap
"${P[@]}" up -d --wait --wait-timeout 120 caddy
it wait-definition
it save env
it check-paths
crowdsec/check-plugin-isolation.sh --caddy caddy --console console -- -f "$F/compose.yaml"

# 3. The plugin uses Caddy's resolved client IP, never RemoteAddr or a forged header, without a reload.
t0="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
lapi_add 198.51.100.10 >/dev/null      # the direct client itself
lapi_add 203.0.113.80 >/dev/null       # a visitor behind the trusted edge
lapi_add 203.0.113.81 >/dev/null       # a visitor behind the tunnel
lapi_add 192.0.2.10 >/dev/null         # the edge peer's own address: must not block its visitors
lapi_add 10.1.2.3 >/dev/null           # protected (private): never reaches the plugin
lapi_add 203.0.113.99 >/dev/null       # protected (BANS_NEVER)
lapi_add 203.0.113.86 >/dev/null       # enforced, added with the protected ones
D=http://198.51.100.2/ E=http://192.0.2.2:8001/ T=http://172.30.252.2:8002/
req edge-proxy "$E" plugin.it.example.com 403 --within 30 --header 'Cf-Connecting-Ip: 203.0.113.80'
req edge-proxy "$E" plugin.it.example.com 403 --within 30 --header 'Cf-Connecting-Ip: 203.0.113.86'
req client-direct "$D" plugin.it.example.com 403 --within 30
req client-direct "$D" file.it.example.com 200                                   # file site: no plugin there
req cloudflared "$T" plugin.it.example.com 403 --within 30 --header 'Cf-Connecting-Ip: 203.0.113.81'
req edge-proxy "$E" plugin.it.example.com 200 --header 'Cf-Connecting-Ip: 203.0.113.82'   # peer banned, visitor not
req edge-proxy "$E" plugin.it.example.com 200 --header 'Cf-Connecting-Ip: 10.1.2.3'
req edge-proxy "$E" plugin.it.example.com 200 --header 'Cf-Connecting-Ip: 203.0.113.99'
it check-ignored 203.0.113.80                                                     # lists:it origin: not file-synced
if "${P[@]}" logs --since "$t0" caddy | grep -q '"uri":"/load"'; then echo "Caddy was reloaded during plugin enforcement" >&2; exit 1; fi
echo "plugin enforcement without reload: ok"
# A forged header from a peer the listener does not trust is ignored: port 80 trusts no proxy, so the
# resolved address is the (protected) tunnel peer itself, not the banned 203.0.113.80 it claims.
req cloudflared http://172.30.252.2/ plugin.it.example.com 200 --header 'Cf-Connecting-Ip: 203.0.113.80'
it check-keys

# 4. Manual bans keep file mode; mixed sites keep their CrowdSec path.
it manual-ban 203.0.113.84
req edge-proxy "$E" plugin.it.example.com 403 --header 'Cf-Connecting-Ip: 203.0.113.84'
req edge-proxy "$E" file.it.example.com 403 --header 'Cf-Connecting-Ip: 203.0.113.84'
lapi_add 203.0.113.87 cscli >/dev/null
it wait-file-record 203.0.113.87
req edge-proxy "$E" file.it.example.com 403 --within 30 --header 'Cf-Connecting-Ip: 203.0.113.87'
req edge-proxy "$E" plugin.it.example.com 403 --within 30 --header 'Cf-Connecting-Ip: 203.0.113.87'
it check-paths

# 5. LAPI outage: decisions in memory stay enforced; a Caddy start with LAPI down still serves.
lapi_add 203.0.113.88 >/dev/null
req edge-proxy "$E" plugin.it.example.com 403 --within 30 --header 'Cf-Connecting-Ip: 203.0.113.88'
"${P[@]}" stop crowdsec
sleep 25
req edge-proxy "$E" plugin.it.example.com 403 --header 'Cf-Connecting-Ip: 203.0.113.88'
"${P[@]}" restart caddy
"${P[@]}" up -d --wait --wait-timeout 180 caddy
req edge-proxy "$E" plugin.it.example.com 200 --within 30 --header 'Cf-Connecting-Ip: 203.0.113.85'
"${P[@]}" up -d --wait crowdsec      # the fake restarts empty: add the decision again
lapi_add 203.0.113.88 >/dev/null
req edge-proxy "$E" plugin.it.example.com 403 --within 60 --header 'Cf-Connecting-Ip: 203.0.113.88'
echo "outage and recovery: ok"

# 6. Host recovery through the fixed admin address.
it manual-ban 203.0.113.85
req edge-proxy "$E" plugin.it.example.com 403 --header 'Cf-Connecting-Ip: 203.0.113.85'
"${P[@]}" stop console
: > dev/run/plugin-it/console/bans-manual.caddy
"${P[@]}" exec -T -e CADDY_ADMIN_ADDRESS=172.30.250.2:2019 caddy sh -c \
  'caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --address "${CADDY_ADMIN_ADDRESS:-0.0.0.0:2019}"'
req edge-proxy "$E" plugin.it.example.com 200 --header 'Cf-Connecting-Ip: 203.0.113.85'
"${P[@]}" start console
echo "host recovery via 172.30.250.2:2019: ok"

# 7. File-secret mode: enforced with the mounted key; mismatched paths stop Caddy before launch.
it write-caddyfile file fixed full
"${PF[@]}" up -d --wait --wait-timeout 120 --force-recreate caddy console
lapi_add 203.0.113.91 >/dev/null
req edge-proxy "$E" plugin.it.example.com 403 --within 30 --header 'Cf-Connecting-Ip: 203.0.113.91'
echo "file-secret mode: ok"
# The one-off containers below take Caddy's fixed address, so the service must be stopped first.
"${PF[@]}" stop caddy
( export MSG="is not mounted" IT_KEY_FILE=/run/secrets/other; refused "${PF[@]}" )
it write-caddyfile file fixed full /run/secrets/other
( export MSG="but this container expects"; refused "${PF[@]}" )
it write-caddyfile env fixed full
( export MSG="but this container expects"; refused "${PF[@]}" )
echo "plugin integration: all passed"
```

Notes for the implementer: `refused` uses `docker compose run --rm --no-deps caddy`, which starts a one-off Caddy container with the same networks and environment, so the preflight is tested exactly as deployed; it uses Caddy's fixed address, so the `caddy` service is stopped whenever `refused` runs (step 1 runs before it starts; step 7 stops it). In step 3 the direct client's own address is banned, which proves the direct fixture; "peer banned, visitor not" proves `RemoteAddr` is not used behind a trusted edge, and the port-80 request from the tunnel peer proves an untrusted `Cf-Connecting-Ip` is ignored. Step 5's middle request uses `203.0.113.85`, which nothing bans at that point.

- [ ] **Step 6: Run the suite**

Run: `./dev/crowdsec-plugin-it.sh`
Expected: ends with `plugin integration: all passed`. Every step prints one `ok`/`->` line. If the plugin's startup pull blocks `docker compose up --wait` while the fake LAPI is stopped (step 5), raise only that step's `--wait-timeout`; never enable `enable_hard_fails`.

- [ ] **Step 7: Commit**

```bash
git add tests/integration/plugin tests/integration/fake_lapi.py tests/integration/plugin_it.py \
  tests/integration/plugin_client.py dev/crowdsec-plugin-it.sh
git commit -m "test(crowdsec-plugin): plugin overlay integration with real client peers, both secret modes and recovery"
```

---
### Task 11: CI: build, record, scan, adapt, integrate, and publish on the default branch

Pull requests build both plugin images, record `caddy list-modules`, generate SBOMs, scan for vulnerabilities, adapt every shipped plugin snippet with the built binaries in both secret modes and run the plugin integration suite, all without secrets. Only a `push` to `master` publishes, after every test job passed, exactly as the existing `build-and-push` job does.

**Files:**
- Create: `dev/adapt-plugin-snippets.sh`
- Modify: `.github/workflows/docker-publish.yml`

**Interfaces:**
- Consumes: `caddy-plugin/Dockerfile` (Task 2), `tests/fixtures/plugin/*` (Task 6), `dev/check-plugin-modules.py` (Task 2), `dev/crowdsec-plugin-it.sh` (Task 10).
- Produces: workflow env `PLUGIN_VERSION: "0.15.0"`; job `test-plugin`; job `publish-plugin` (matrix `crowdsec`, `crowdsec-cloudflare`) pushing `ghcr.io/<owner>/caddy-<variant>:2.11.9-crowdsec-0.15.0` and `:sha-<short>` with SBOM and provenance attestations; artifacts `plugin-modules-<variant>` (module list JSON) and `plugin-sbom-<variant>` (SPDX JSON).

- [ ] **Step 1: Write the snippet adaptation check**

Create `dev/adapt-plugin-snippets.sh` (mode 0755):

```bash
#!/usr/bin/env bash
# Adapt the exact code of every shipped plugin snippet with a built plugin image,
# in both secret modes (spec 3.6 and "Testing"). tests/test_plugin_snippets.py and
# tests/snippet-insert.test.mjs pin the fixtures to src/snippets.json.
#   ./dev/adapt-plugin-snippets.sh caddy-crowdsec:local
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE="${1:?usage: dev/adapt-plugin-snippets.sh IMAGE}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/console"
cp tests/fixtures/plugin/crowdsec-plugin-protect.caddy "$tmp/console/"
for mode in env file; do
  cp "tests/fixtures/plugin/$mode.Caddyfile" "$tmp/Caddyfile"
  docker run --rm -v "$tmp:/etc/caddy:ro" "$IMAGE" caddy adapt --config /etc/caddy/Caddyfile --adapter caddyfile \
    > "$tmp/$mode.json"
  python3 - "$tmp/$mode.json" "$mode" <<'PY'
import json, sys
cfg, mode = json.load(open(sys.argv[1])), sys.argv[2]
want = {"env": "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}", "file": "{file./run/secrets/crowdsec_plugin_bouncer_key}"}[mode]
app = cfg.get("apps", {}).get("crowdsec") or {}
assert app.get("api_key") == want, f"api_key is {app.get('api_key')!r}"
assert app.get("ticker_interval") == "10s" and app.get("api_url") == "http://crowdsec:8080", app

def has(node, pred):
    if isinstance(node, dict):
        return pred(node) or any(has(v, pred) for v in node.values())
    if isinstance(node, list):
        return any(has(v, pred) for v in node)
    return False

sites = {}
for srv in cfg["apps"]["http"]["servers"].values():
    for route in srv["routes"]:
        hosts = [h for m in route.get("match", []) for h in m.get("host", [])]
        for h in hosts:
            sites[h] = route
plugin = lambda n: n.get("handler") == "crowdsec"
guarded = lambda n: plugin_in(n) and any("not" in m for m in n.get("match", []))
plugin_in = lambda n: any(isinstance(h, dict) and h.get("handler") == "crowdsec" for h in n.get("handle", []) or [])
assert has(sites["plugin.example.com"], guarded), "plugin.example.com has no protected crowdsec route"
assert has(sites["plugin.example.com"], lambda n: n.get("caddy_console_plugin_protect") in (1, "1")), "no plugin marker"
assert not has(sites["file.example.com"], plugin), "file.example.com runs the plugin"
print(f"{mode}: every shipped plugin snippet adapts; plugin site protected, file site file-only")
PY
done
```

Run: `./dev/adapt-plugin-snippets.sh caddy-crowdsec:local && ./dev/adapt-plugin-snippets.sh caddy-crowdsec-cloudflare:local`
Expected: two `every shipped plugin snippet adapts` lines per image.

- [ ] **Step 2: Add the test job**

In `.github/workflows/docker-publish.yml`, add to the top-level `env:`:

```yaml
  # caddy-crowdsec-bouncer version in the plugin image tags; must equal caddy-plugin/*/go.mod.
  PLUGIN_VERSION: "0.15.0"
```

Add after `test-integration`:

```yaml
  test-plugin:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        variant: [crowdsec, crowdsec-cloudflare]
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Plugin version in the tags matches go.mod
        run: |
          grep -Eq "^\s*github.com/hslatman/caddy-crowdsec-bouncer v${PLUGIN_VERSION}$" "caddy-plugin/${{ matrix.variant }}/go.mod" || {
            echo "::error::PLUGIN_VERSION ${PLUGIN_VERSION} is not the version in caddy-plugin/${{ matrix.variant }}/go.mod"
            exit 1
          }

      - uses: docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069 # v4.4.1

      - name: Build the plugin image
        uses: docker/build-push-action@c3c9e263c25d99ce0380d002d59b67737d91b0dc # v7.4.0
        with:
          context: caddy-plugin
          file: caddy-plugin/Dockerfile
          build-args: VARIANT=${{ matrix.variant }}
          load: true
          push: false
          tags: caddy-${{ matrix.variant }}:ci
          cache-from: type=gha,scope=plugin-${{ matrix.variant }}
          cache-to: ${{ github.event_name == 'push' && format('type=gha,mode=max,scope=plugin-{0}', matrix.variant) || '' }}

      - name: Record and check the modules
        run: |
          docker run --rm caddy-${{ matrix.variant }}:ci caddy list-modules --json --skip-standard > modules.json
          python3 dev/check-plugin-modules.py ${{ matrix.variant }} < modules.json
          docker run --rm caddy-${{ matrix.variant }}:ci caddy version

      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: plugin-modules-${{ matrix.variant }}
          path: modules.json

      - name: Adapt every shipped plugin snippet with the built binary
        run: ./dev/adapt-plugin-snippets.sh caddy-${{ matrix.variant }}:ci

      - name: SBOM
        uses: anchore/sbom-action@dfcb83b97731532d72be422cbc51ee64adb6fd56 # v0.24.4
        with:
          image: caddy-${{ matrix.variant }}:ci
          format: spdx-json
          output-file: sbom-${{ matrix.variant }}.spdx.json
          artifact-name: plugin-sbom-${{ matrix.variant }}

      - name: Vulnerability scan
        uses: anchore/scan-action@11983a512817154c80a9db660c1a184be7513ed6 # v7.4.3
        with:
          image: caddy-${{ matrix.variant }}:ci
          fail-build: true
          severity-cutoff: critical
          only-fixed: true
          output-format: table

      - name: Plugin overlay integration
        if: matrix.variant == 'crowdsec'
        env:
          PLUGIN_IMAGE: caddy-crowdsec:ci
        run: ./dev/crowdsec-plugin-it.sh
```

The scan fails the build on a fixable critical finding; a fixable high finding shows in the table and is handled by bumping the base image or a module (Dependabot opens those PRs). Read the two Anchore actions' `action.yml` at the pinned commits and confirm the input names (`image`, `format`, `output-file`, `artifact-name`, `fail-build`, `severity-cutoff`, `only-fixed`, `output-format`) before committing; rename an input if the pinned release calls it differently.

Make `build-and-push` wait for it: `needs: [test-python, test-js, test-integration, test-plugin]`.

`dev/check-compose.sh` (already run in `test-integration`) covers the plugin overlays from Task 9.

- [ ] **Step 3: Add the publish job**

Append:

```yaml
  publish-plugin:
    if: github.event_name == 'push'
    needs: [test-python, test-js, test-integration, test-plugin]
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    strategy:
      matrix:
        variant: [crowdsec, crowdsec-cloudflare]
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Image name
        run: echo "PLUGIN_IMAGE=${REGISTRY}/${GITHUB_REPOSITORY_OWNER,,}/caddy-${{ matrix.variant }}" >> "$GITHUB_ENV"

      - uses: docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069 # v4.4.1

      - uses: docker/login-action@8aa5831fb8d48d8f76594c7ddde61ae58019f550 # v4.8.0
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@dc802804100637a589fabce1cb79ff13a1411302 # v6.2.0
        with:
          images: ${{ env.PLUGIN_IMAGE }}
          tags: |
            type=raw,value=2.11.9-crowdsec-${{ env.PLUGIN_VERSION }}
            type=sha

      - name: Build and push
        uses: docker/build-push-action@c3c9e263c25d99ce0380d002d59b67737d91b0dc # v7.4.0
        with:
          context: caddy-plugin
          file: caddy-plugin/Dockerfile
          build-args: VARIANT=${{ matrix.variant }}
          push: true
          sbom: true
          provenance: mode=max
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha,scope=plugin-${{ matrix.variant }}
          cache-to: type=gha,mode=max,scope=plugin-${{ matrix.variant }}
```

`latest` is deliberately not published: deployments use the digest or `sha-*` tag (spec 3.2).

- [ ] **Step 4: Check the workflow**

Run: `docker run --rm -v "$PWD:/w:ro" -w /w rhysd/actionlint:latest -color` (a one-off lint of the workflow files; nothing is installed in the repository)
Expected: no findings. Then check by eye: every `uses:` is a 40-character SHA with a version comment; `publish-plugin` is the only new job with `packages: write`; no job reads a secret except the two publish jobs' `GITHUB_TOKEN`.

Confirm the jobs' commands locally:
Run: `./dev/check-compose.sh && ./dev/adapt-plugin-snippets.sh caddy-crowdsec:local && PLUGIN_IMAGE=caddy-crowdsec:local ./dev/crowdsec-plugin-it.sh`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add dev/adapt-plugin-snippets.sh .github/workflows/docker-publish.yml
git commit -m "ci(crowdsec-plugin): build, record modules, SBOM, scan, adapt snippets and integrate; publish on master only"
```

---

### Task 12: Plugin documentation

**Files:**
- Modify: `docs/security.md` (new "CrowdSec plugin" section, host recovery table, configuration table)
- Modify: `docs/setup.md` (one link), `docs/development.md` (plugin tooling)

**Interfaces:**
- Consumes: everything above. Anchors other code already links to: `docs/security.md#crowdsec-plugin` (overlay comments, preflight, Security view copy text), `#host-recovery`.

- [ ] **Step 1: Write the section**

Add `## CrowdSec plugin` to `docs/security.md` after the CrowdSec file-sync section, with these subsections and facts (English, `example.com` and documentation addresses only):

1. **What it is.** A custom Caddy image enforces CrowdSec decisions per site without a reload. Latency is the polling interval (`ticker_interval 10s`): near-real-time, not instantaneous. Manual bans still use `bans-manual.caddy`; CrowdSec file sync keeps working for sites that import `bans-crowdsec*.caddy`.
2. **Images.** `ghcr.io/viralone/caddy-crowdsec` (stock Caddy 2.11.9 plus the CrowdSec HTTP module, which also brings the AppSec handler module, unused here) and `ghcr.io/viralone/caddy-crowdsec-cloudflare` (also `caddy-dns/cloudflare` for DNS-01; the NAS stack uses it; Cloudflare as a proxy or Tunnel does not need it). Tags `2.11.9-crowdsec-0.15.0` and `sha-<commit>`; deploy by digest (`docker buildx imagetools inspect ghcr.io/viralone/caddy-crowdsec:2.11.9-crowdsec-0.15.0`) or `sha-*`. Each image records its modules at `/usr/share/caddy-console/modules.json`; CI publishes an SBOM and scans every build.
3. **Before the first start: bind the admin API.** The required Caddyfile block (`admin 172.30.250.2:2019 { origins caddy:2019 172.30.250.2:2019 }`), why (Caddy joins `crowdsec-lapi`; a wildcard bind would let CrowdSec reach port 2019), and that the image refuses to start otherwise, with an example of the refusal line. Note for prod/internal/NAS: the overlay gives `caddy-admin` the subnet `172.30.250.0/29`; run `docker compose -f <base> down` once (no `-v`) so Compose recreates the network.
4. **Start it**, in this order (the console needs the running module before it renders the definition, and a site import needs the definition):
   ```bash
   export CROWDSEC_PLUGIN_BOUNCER_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
   export CADDY_PLUGIN_IMAGE=ghcr.io/viralone/caddy-crowdsec@sha256:<digest>
   docker compose -f docker-compose.prod.yaml -f docker-compose.crowdsec.yaml \
     -f docker-compose.crowdsec-plugin.yaml up -d
   crowdsec/check-plugin-isolation.sh -- -f docker-compose.prod.yaml \
     -f docker-compose.crowdsec.yaml -f docker-compose.crowdsec-plugin.yaml
   ```
   then in the editor: **CrowdSec plugin: global app**, **CrowdSec plugin: load protected route definition**, Save & Reload; wait until Security shows the definition as current; then **CrowdSec plugin: protect this site** per site (or **Add import in editor** in Security), Save & Reload. Give the internal and tunnel commands and the NAS command (`docker-compose.nas.yaml -f docker-compose.nas.crowdsec.yaml -f docker-compose.nas.crowdsec-plugin.yaml`, console service `caddy-editor`, `--console caddy-editor` for the check).
5. **The isolation check.** What `crowdsec/check-plugin-isolation.sh` proves (port 2019 refused from every CrowdSec and cloudflared container at every Caddy address and at `172.30.250.2`; the data-plane port answers where they share a network; the two bouncer keys differ), that it needs no published port, and that plugin mode is not started successfully until it passes. Run it after every `up`.
6. **Two keys.** The plugin is the bouncer `caddy_plugin` with `CROWDSEC_PLUGIN_BOUNCER_KEY`; the console keeps `caddy_console`. They must differ (LAPI stream cursors belong to a bouncer). Rotation: as for the console key, with `cscli bouncers delete caddy_plugin` and `--force-recreate crowdsec caddy`. Never write the key into the Caddyfile: Caddy's `/config/` would show it; the image refuses to start with a literal key.
7. **Key in a file secret.** Same copy-the-overlay approach as the console's file secret (the shipped overlay requires the environment key): in the copy, replace Caddy's `CROWDSEC_PLUGIN_BOUNCER_KEY` with `CROWDSEC_PLUGIN_BOUNCER_KEY_FILE: /run/secrets/crowdsec_plugin_bouncer_key`, mount the secret at exactly that path on Caddy, give the console the same `CROWDSEC_PLUGIN_BOUNCER_KEY_FILE` (path only), register it on CrowdSec as the secret target `bouncer_key_caddy_plugin` and drop `BOUNCER_KEY_caddy_plugin`. Show the YAML. The editor then offers the `{file./run/secrets/crowdsec_plugin_bouncer_key}` form only. A trailing newline in the file is fine. A path that differs from the mount stops Caddy before launch with both paths named.
8. **Protected addresses.** `crowdsec-plugin-protect.caddy` and the `(protect_crowdsec)` snippet (show the generated shape), regenerated with every change of `BANS_NEVER`, Docker networks or verified console addresses through the same journaled transaction as the ban files, recorded in `BACKUP_DIR/plugin-policy.json`. Never use the bare `crowdsec` directive. The **CrowdSec plugin: LAPI allowlist** commands (copy from Security) as defense in depth: allowlists stop new decisions but do not remove existing ones.
9. **Which sites use which path.** The spec 3.5 table (manual + CrowdSec file → file/file sync; manual + `protect_crowdsec` → file/plugin; manual only → file/none), and what Security shows for each, including the "redundant, both enforce" warning and "Plugin runs without the protected ranges".
10. **Outages and limits.** A LAPI outage keeps the decisions Caddy already has (`enable_hard_fails` stays off); a Caddy restart during an outage starts with none until LAPI answers; plugin mode has no `BANS_MAX` matcher budget, so CAPI or list origins are reasonable here (the plugin pulls every origin; `CROWDSEC_ORIGINS` limits only the console's file sync and display).

Update **Host recovery**: add a row "Any stack with the plugin overlay | ... | `172.30.250.2:2019`; the overlay sets `CADDY_ADMIN_ADDRESS` in the Caddy container, so `--address "${CADDY_ADMIN_ADDRESS:-0.0.0.0:2019}"` already uses it" and add `-f docker-compose.crowdsec.yaml -f docker-compose.crowdsec-plugin.yaml` to the commands for such stacks.

Update **Configuration** with the three Phase 3 rows:

| `CROWDSEC_PLUGIN_BOUNCER_KEY` | empty | Caddy container only: the plugin's own bouncer key. Never given to the console. |
| `CROWDSEC_PLUGIN_BOUNCER_KEY_FILE` | empty | Absolute path of a mounted secret with the plugin key, used instead of the environment key; the console gets the path only, to offer `{file.<path>}`. |
| `CADDY_ADMIN_ADDRESS` | `0.0.0.0:2019` | Admin address for health checks, recovery and the console's save guard; the plugin overlays set `172.30.250.2:2019`. |

- [ ] **Step 2: Link and tooling docs**

`docs/setup.md`: one sentence in the optional add-ons paragraph next to the CrowdSec link: "For enforcement without reloads, see [CrowdSec plugin](security.md#crowdsec-plugin)." The baseline quick start stays free of CrowdSec.

`docs/development.md`: a "Plugin images" subsection: `./dev/plugin-go.sh test` (preflight tests), `./dev/plugin-go.sh tidy <variant>` after a version bump, `./dev/build-plugin-image.sh <variant>`, `tests/integration/make_plugin_fixtures.sh` (regenerate `adapted-plugin-layouts.json` after a plugin or Caddy bump), `./dev/adapt-plugin-snippets.sh <image>`, `./dev/crowdsec-plugin-it.sh`; and the bump rule: a plugin version change updates both `go.mod` files, `PLUGIN_VERSION` in the workflow and the tag examples in `docs/security.md`, and must pass the plugin integration suite (client IP in the direct, proxied and tunnel fixtures) before merge.

- [ ] **Step 3: Check the docs**

Run: `grep -nE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' docs/security.md | grep -vE '(192\.0\.2|198\.51\.100|203\.0\.113|172\.30\.25[0-2]|127\.0\.0\.1|0\.0\.0\.0|10\.0\.0\.0|172\.16\.0\.0|192\.168\.0\.0|100\.64\.0\.0|169\.254\.0\.0)'`
Expected: no output (documentation and fixed Docker addresses only).
Run: `grep -n 'crowdsec-plugin' docs/security.md | head` and follow each command once against the dev notes; every file and script it names exists.

- [ ] **Step 4: Commit**

```bash
git add docs/security.md docs/setup.md docs/development.md
git commit -m "docs(crowdsec-plugin): plugin overlay, images, separate keys, isolation check and polling latency"
```

---

## Phase 3 gate (spec "Delivery gates")

- Plugin images are reproducible, pinned and scanned: Task 2 (`go.sum`, pinned `FROM` digests, `-mod=readonly`), Task 11 (`list-modules` record, SBOM, scan).
- Caddy Admin API is unreachable from every non-console network peer: Task 1 (preflight), Task 6 (save guard), Task 9 (static checks and `crowdsec/check-plugin-isolation.sh`), Task 10 (the check against running containers, refusals before launch).
- Protected-range plugin tests pass: Task 4 (route in every transaction), Task 5 (unprotected and outdated detection), Task 10 (private and `BANS_NEVER` decisions never block).
- `bans-crowdsec.caddy` is imported only by file-sync sites; plugin sites use the protected plugin route; mixed deployments pass: Task 5 (per-site paths), Task 6 (redundancy warning), Task 10 (`check-paths` and the mixed decision).
