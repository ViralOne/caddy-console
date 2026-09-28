# Log Explorer: faceted search over the Caddy access log

Status: proposed
Date: 2026-09-28
Supersedes: 2026-09-28-metrics-redesign-design.md (stages 4-5; stages 1-2 stand)

## Why

Three views currently present the same log data three ways:

- **Logs tab** — a raw tail with no filtering. To find one site's errors you read
  JSON by eye.
- **Metrics › By Site** — per-host counts, which is a host facet with counts
  rendered as cards.
- **Failure drill-down** — `(status, path)` counts for one host, which is
  `status:5xx` plus a path facet.

One faceted explorer covers all three, and does the thing none of them can: ask
an arbitrary question ("5xx on this host, last hour, path containing /api") and
see the matching events, their distribution over time, and what else those events
have in common.

It also retires the contradiction documented in the superseded spec, because the
per-site figures stop living next to Prometheus server counters.

## Layout

```
┌ Editor │ Explore │ Metrics ────────────────────────────────────────────────┐
│  status:5xx host:watch.example.com                     [ last 24h ▾ ] [⏸] │
├──────────────────┬────────────────────────────────────────────────────────┤
│ FACETS           │ ▁▂▃▅▇█▆▄▃▂▁▂▃▅▇█▆▄▃▂▁   451 events                     │
│                  ├────────────────────────────────────────────────────────┤
│ Host             │ 11:04:22  502  watch.example.com  GET /api/v1/sync 0.9s│
│ ☑ watch     451  │ 11:04:19  502  watch.example.com  GET /api/v1/sync 1.2s│
│ ☐ bulk-a  5,600  │ 11:03:58  404  watch.example.com  GET /favicon.ico 0.0s│
│ Status           │ 11:03:41  502  watch.example.com  GET /api/v1/info  30s│
│ ☐ 2xx     9,534  │                                                        │
│ ☑ 5xx       505  │                                                        │
│ Method           │                                                        │
│ ☐ GET    10,001  │                                                        │
└──────────────────┴────────────────────────────────────────────────────────┘
```

- **Query bar** — `key:value` terms plus free text. Same-key terms OR together,
  different keys AND, `-` negates. Free text is a case-insensitive substring
  match on host and uri.
- **Facets** — Host, Status class, Status code, Method, Path prefix. Counts
  reflect the *other* active filters, so a count always states what clicking it
  would yield. Clicking toggles; toggling writes the equivalent term into the
  query bar, so the bar stays the single source of truth.
- **Histogram** — events per bucket, stacked by status class. Doubles as the
  range control: drag to narrow.
- **Stream** — newest first, one row per event, click to expand the full entry.
- **Follow** — when on, new matching events prepend, respecting active filters.
  Off by default whenever a range other than "now" is selected.

## Architecture: an in-memory event index

This replaces both the scalar counters shipped in `1700c2a` and the per-minute
bucket model proposed in the superseded spec.

Facet counts and histograms must be computed *per query*, since they reflect the
active filters. Pre-aggregated buckets cannot answer that, and re-parsing the
window per keystroke is far too slow (JSON-decoding 100 MB is ~600 ms). So parse
once, query many times:

`EventIndex` folds the log window into **columnar arrays**, extending the
existing incremental scan (same anchor, same offset resume, same rebuild rules):

| column | type | note |
|---|---|---|
| `ts` | `array('d')` | |
| `status` | `array('h')` | |
| `duration_ms` | `array('f')` | |
| `size` | `array('q')` | |
| `host_id`, `method_id`, `uri_id` | `array('i')` | interned via `{str: int}` |

Roughly 30 bytes per event, so 200k events is about 6 MB — cheap enough to hold
the whole window and query it repeatedly. Columnar rather than a list of tuples
because Python object overhead would make the same data ~140 bytes per event.

`MAX_EVENTS` (default 200k, configurable) caps retention. When the window holds
more, the oldest are dropped and the response says so, so a count is never
silently short.

A query is then a single pass of integer comparisons over the arrays —
tens of milliseconds for 200k events — producing a match index list, from which
facets, histogram, summary stats and the page of entries are all derived.

**Exact percentiles come free.** Because a query has the matching durations in
hand, p95 is computed directly. The superseded spec's 12-bin latency histogram
and its `p95~` estimate are both dropped.

## API

`GET /api/explore`

| param | meaning |
|---|---|
| `window_mb` | how much log to read (existing, 1-100) |
| `range` | `1h` / `6h` / `24h` / `7d`, or `from`/`to` epoch seconds |
| `q` | query string |
| `limit` | entries per page (default 200, max 1000) |
| `before_ts` | page older than this timestamp |

```
{
  "entries": [{"ts":…, "host":…, "method":…, "uri":…, "status":502,
               "duration_ms":912.3, "size":0, "client_ip":"…"}],
  "total": 451,
  "stats": {"requests":451, "error_rate":100.0,
            "avg_latency_ms":…, "p95_latency_ms":…, "bytes_out":…},
  "facets": {
    "host":   [{"value":"watch.example.com","count":451}, …],
    "status_class": […], "status": […], "method": […], "path": […]
  },
  "histogram": {"bucket_seconds":60,
                "buckets":[{"t":…,"2xx":0,"3xx":0,"4xx":8,"5xx":12}]},
  "range": {"from":…,"to":…,"truncated":false,"earliest_ts":…},
  "window": {"mb":10,"covered_bytes":…,"file_size":…},
  "indexed": 10119, "dropped": 0, "skipped": 0
}
```

Facet value lists are capped (top 50 by count, with an `other` remainder) for the
same reason the failure breakdown is capped today: a scanner walking random paths
must not be able to inflate a response.

`/api/logstats` and `/api/logs` are removed once Explore lands. `/api/logs/ping`
stays; it is used to generate a test entry.

## Metrics tab after this

Keeps only what the log cannot answer, each section labelled with its source and
time basis:

1. **Upstream health** — from Caddy's admin API.
2. **Server counters** — Prometheus, explicitly "since Caddy started".
3. **Editor activity** — saves, backups, logins.

The Overview KPI row is dropped: its traffic figures move to Explore, its editor
figures are already in Editor Activity. That resolves findings 1, 3, 4 and 7 of
the superseded spec by deletion rather than redesign.

## Frontend framework: Preact + htm, vendored

Explore carries far more derived state than anything else here — query, parsed
filters, range, drag-select, follow, facet and row expansion, paging, in-flight
request cancellation — all feeding one render. Hand-syncing the DOM stops paying
at that point; the existing `toggleFailures` already resyncs by hand with
`querySelectorAll(…).forEach(n => n.remove())`.

**Decision: Preact + htm, vendored via the existing esbuild devDependency,
committed like `editor.bundle.js`. Explore only; the editor, panels and backups
stay vanilla.** No build step for app code, so `docker-compose.dev.yaml`'s
bind-mount-and-refresh workflow keeps working.

SolidJS was considered and is the better framework *if* a build step is on the
table — fine-grained reactivity suits a stream that prepends rows every few
seconds better than a VDOM diff. It was rejected because we are staying
buildless, and Solid's buildless path (`solid-js/html`) is a poor trade by its
own README: it "cannot leverage expression analysis, necessitating manual
wrapping of expressions", so every reactive site needs a hand-written thunk
(`title=${() => selectedClass()}`) and forgetting one silently freezes the value
with no error. On a view whose entire job is live counts, that failure mode is
unacceptable. It also "requires a larger, non-treeshakeable runtime" and is
"slightly less efficient than JSX" — Solid's costs without its benefits. `htm`
has no equivalent trap, since Preact re-renders and re-evaluates expressions.

If the build-step constraint is ever lifted, revisit this: Solid + JSX becomes
the stronger option, and a proper Node stage would also let us stop committing
`editor.bundle.js` by hand.

## Frontend

Native ES modules (landed in `1700c2a`). New modules:

- `explore.js` — state (query, range, follow), fetch, orchestration
- `explore-query.js` — parse/serialise the query string; pure, unit-testable
- `explore-facets.js` — facet panel rendering
- `explore-stream.js` — event rows and row expansion
- `histogram.js` — inline SVG, hand-rolled, no dependency

Design tokens (stage 2 of the superseded spec) land first and are used
throughout; no new inline `style.cssText`.

Rendering rules for the histogram follow the charting guidance already applied:
status colours are the reserved status tokens, a legend is always present, the
stream below *is* the table view, 2px marks, recessive axes, and no dual axis.

Debounce the query bar at 250ms so typing doesn't issue a request per keystroke.

## Testing

Python:

- indexing: interning, column alignment, `MAX_EVENTS` drop with `dropped` count
- query parsing: same-key OR, cross-key AND, negation, free text, bad input
- filtering: each facet key, combinations, empty result
- facets: counts reflect other active filters but not the facet's own
- histogram: bucket assignment, width from range, totals match `total`
- stats: exact p95 against a known distribution
- paging: `before_ts` returns strictly older events, no duplicates
- `range` wider than the window sets `truncated` with `earliest_ts`

JavaScript (now practical, post-modules): `explore-query.js` round-trips a query
through parse and serialise; histogram path generation for known input.

## Order of work

1. **Design tokens** — palette, type scale, space scale; restyle existing markup.
2. **Event index + `/api/explore`** — backend only, tested standalone.
3. **Explore tab** — query bar, facets, stream, histogram, follow.
4. **Retire** — remove the Logs tab, By Site, drill-down, `/api/logstats`,
   `/api/logs`, and slim the Metrics tab.

Stage 4 deletes code shipped in `1700c2a` and earlier today. That is intended:
the facet panel and the query bar do those jobs better, and keeping both would
reproduce the three-views-of-one-dataset problem this spec exists to remove.

## Risks

- **Memory.** A 100 MB window of slim entries is roughly 350k events, above the
  200k default cap. Either the cap drops events (reported) or it is raised at a
  known cost of ~30 bytes per event. Worth measuring on the real log before
  choosing the default.
- **Query cost grows with the index.** 200k events per query is fine; if the cap
  is raised a lot, filtering needs revisiting (bitmap indexes per facet value).
- **Scope.** This deletes three working features in stage 4. If stage 3 stalls,
  stop before stage 4 rather than leaving the app with neither.
