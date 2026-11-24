# Development

## The no-auth dev stack

The quickest way to run the whole thing locally. A front Caddy injects the
identity header that Cloudflare Access would normally set, so there is no OAuth to
configure — and therefore **everything is bound to 127.0.0.1 only**.

```bash
./dev/run.sh up      # build and start, prints the URL
./dev/run.sh down    # stop and remove volumes
./dev/run.sh logs    # follow logs
./dev/run.sh reset   # restore dev/run/Caddyfile from the seed
```

Then open <http://localhost:8888>. It starts three containers:

| Container | Role |
|---|---|
| `caddy-front` | Stands in for Cloudflare Access; the only thing you browse to |
| `caddy-console` | The app, with `--reload` and `./src` bind-mounted |
| `caddy-target` | The Caddy whose config you are editing, on :8081 |

`dev/run/Caddyfile` is the file the console reads and writes, copied from
`dev/Caddyfile.seed` on first run — so saving in the UI never dirties the seed.

Python edits reload automatically. CSS, template and JS edits need a browser
refresh; **Jinja caches templates outside debug mode**, so a change to
`index.html` needs `docker compose -f docker-compose.dev.yaml restart caddy-console`.

## Seeding log data

An empty log makes the dashboard and explorer look broken. `dev/seed-logs.py`
writes two hours of believable traffic across seven sites, including an error
burst on one of them:

```bash
python3 dev/seed-logs.py | docker compose -f docker-compose.dev.yaml \
    exec -T caddy-target sh -c 'cat >> /var/log/caddy/access.log'
```

Entries come out oldest-first, which matters: the explorer bisects the file by
timestamp and assumes it is append-ordered.

## Tests

```bash
python3 -m unittest discover -s tests -t .   # backend
node tests/diff.test.mjs                     # diff algorithm
node tests/router.test.mjs                   # URL <-> state
node tests/explore-query.test.mjs            # query parsing
node tests/jsonview.test.mjs                 # raw-line formatting
node tests/ip-info.test.mjs                  # IP popover formatting
node tests/editor-prefs.test.mjs             # editor keymap preference
```

No Caddy binary and no network needed: the admin API is faked and `caddy fmt` /
`caddy validate` are patched out. GeoIP tests build tiny `.mmdb` fixtures with
`tests/_mmdb.py` and fake the DB-IP download.

The IP-ban integration suite needs Docker and runs against the stock Caddy in
the dev stack (CI runs it too):

```bash
./dev/bans-it.sh   # brings the stack up, runs tests/integration/bans_caddy_it.py
                   # inside the console container, then checks host recovery
```

It loads its own Caddyfile from `dev/run/itest/` and restores the dev one when
it finishes.

The CrowdSec overlay has its own suite:

```bash
./dev/crowdsec-it.sh   # dev stack + docker-compose.crowdsec.yaml, runs tests/integration/crowdsec_it.py
```

It needs network access to the CrowdSec Hub and generates its own bouncer key.

### Plugin images

The optional CrowdSec plugin images (`caddy-plugin/`, see
[CrowdSec plugin](security.md#crowdsec-plugin)) have their own tools. All of
them need Docker; the Go commands run inside the pinned `caddy:2.11.9-builder`
image, so no local Go is needed. Set `GOPROXY` (for example `GOPROXY=direct`)
if `proxy.golang.org` is not reachable from your network; CI uses the default.

```bash
./dev/plugin-go.sh test                       # entrypoint preflight tests (go vet, go test)
./dev/plugin-go.sh tidy crowdsec              # refresh go.mod/go.sum of a variant after a version bump
./dev/build-plugin-image.sh crowdsec          # -> caddy-crowdsec:local, then checks its modules
./dev/build-plugin-image.sh crowdsec-cloudflare
tests/integration/make_plugin_fixtures.sh     # regenerate tests/fixtures/bans/adapted-plugin-layouts.json
./dev/adapt-plugin-snippets.sh caddy-crowdsec:local   # adapt every shipped plugin snippet, both key modes
./dev/crowdsec-plugin-it.sh                   # plugin overlay end to end (builds caddy-crowdsec:local if missing)
```

`./dev/crowdsec-plugin-it.sh` runs its own Compose project
(`caddy-console-plugin-it`) with a fake LAPI, the console image and client
containers at documentation addresses (direct, proxied and tunnel peers). It
uses throwaway keys and removes its containers and `dev/run/plugin-it*` on
exit. `PLUGIN_IMAGE=<image>` tests another build.

Run `make_plugin_fixtures.sh` after a plugin or Caddy bump. A plugin version
change updates both `caddy-plugin/*/go.mod` files, `PLUGIN_VERSION` in
`.github/workflows/docker-publish.yml` and the tag examples in
`docs/security.md`. It must pass the plugin integration suite before merge,
because that suite proves the plugin uses Caddy's resolved client IP in the
direct, proxied and tunnel fixtures.

## Front-end build

App code is plain ES modules loaded straight by the browser — **no build step**,
which is why editing a file and refreshing works. Only two vendored bundles are
built, and only when their dependency changes:

```bash
npm install
npm run build          # both bundles
npm run build:editor   # CodeMirror
npm run build:vendor   # Preact + htm, used by the dashboard and explorer
```

Both outputs are committed, so a clone needs no npm at all.

## Where things live

| Path | What it is |
|---|---|
| `src/routes/` | Flask blueprints: `editor.py` (config, auth-adjacent), `ops.py` (metrics, explore) |
| `src/eventindex.py` | Columnar in-memory index of log events, and the query engine |
| `src/logfiles.py` | Finding data in time: file discovery, bisection, `.gz` archives |
| `src/static/js/app/` | ES modules, one per view or concern |
| `dev/` | Local stack helpers and seed data |
