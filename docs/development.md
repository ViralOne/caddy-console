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
| `caddy-editor` | The app, with `--reload` and `./src` bind-mounted |
| `caddy-target` | The Caddy whose config you are editing, on :8081 |

`dev/run/Caddyfile` is the file the editor reads and writes, copied from
`dev/Caddyfile.seed` on first run — so saving in the UI never dirties the seed.

Python edits reload automatically. CSS, template and JS edits need a browser
refresh; **Jinja caches templates outside debug mode**, so a change to
`index.html` needs `docker compose -f docker-compose.dev.yaml restart caddy-editor`.

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
```

No Caddy binary and no network needed: the admin API is faked and `caddy fmt` /
`caddy validate` are patched out.

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
