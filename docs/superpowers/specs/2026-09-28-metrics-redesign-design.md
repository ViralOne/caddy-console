# Metrics page redesign: time-bucketed log stats, ES modules, design tokens

Status: partly superseded by 2026-09-28-log-explorer-design.md
Date: 2026-09-28

> The design-token work below still stands. The per-minute bucket model, the
> per-site table and the sparklines do not: a faceted explorer needs the matching
> events per query rather than pre-aggregated counters, which also makes p95
> exact instead of estimated. See the log-explorer spec.

## Why

The Metrics tab grew by accretion and now has one correctness problem and a set
of design problems. Measured against the current code:

1. **Two adjacent sections contradict each other.** `Per-Site Traffic` reports
   per-server Prometheus counters accumulated since Caddy started; `By Site`
   reports per-host figures from a byte-bounded log scan. On the dev stack they
   read `srv0 · 291 requests · 89% errors` and `bulk-a · 5,600 requests`
   respectively. Both are right; nothing on screen says why they differ by 20x.
2. **Two unrelated palettes.** Chrome is navy (`#1a1a2e`, `#16213e`, `#0f3460`),
   content is GitHub slate (`#0d1117`, `#161b22`, `#21262d`). 41 distinct hex
   values in 162 lines of CSS, 19 more hardcoded across 5 JS files, no tokens.
3. **Colour carries two meanings.** Decorative in the KPI row (In Flight purple,
   Bandwidth In orange, Backups grey — assigned per card with no rule); semantic
   elsewhere (red = 5xx, amber = slow). Neither reads reliably as a result.
4. **The KPI row mixes categories.** Traffic health sits at equal weight beside
   editor bookkeeping (Total Saves, Backups), which `Editor Activity` repeats.
5. **No time dimension.** Every figure is a scalar. `Error Rate 89.0%` — since
   when? The log carries `ts` on every entry and nothing uses it.
6. **Layout wastes the window.** At 1440px each site is a full-width card
   holding four short pills; ~60% is empty. Eight sites is a long scroll for
   data that fits one table.
7. **Redundancy.** A site card states `2xx 5,560 · 5xx 40`, then
   `REQUESTS 5,600`, then `0.71% 5xx` — one fact three ways.
8. **Nine font sizes** (9,10,11,12,13,14,15,16,22px) with no scale; 9-10px
   uppercase labels are below comfortable reading size.
9. **Accessibility.** Health is colour-only; `title=` is the only tooltip
   mechanism, invisible to keyboard and touch; `#546e7a` on `#0d1117` is under
   4.5:1.

## Non-goals

- No framework. See "Frontend stack" below.
- No change to the Flask backend beyond `logstats.py` and the `/api/logstats`
  route. Auth, editor, backups, validation, audit are untouched.
- No new runtime dependencies, no build step, no Docker image change.
- No persistence layer. An earlier sketch of this work proposed a background
  tailer writing per-minute buckets to SQLite. That was unnecessary: log entries
  carry `ts`, and the existing scan already visits every line, so the time
  dimension costs nothing extra and survives restarts by being recomputed.

## Aggregation: from scalars to buckets

`logstats.py` currently accumulates scalar counters per host from an anchor byte
offset. That can only answer "everything since the anchor", so it cannot serve a
1h-vs-24h selector. Replace it: the fold writes **per-minute buckets** per host,
and every summary figure is derived by summing buckets over the selected range.
One source of truth instead of two.

Per host, per bucket:

| field | purpose |
|---|---|
| `requests` | count |
| `classes` | `{2xx,3xx,4xx,5xx,other}` counts |
| `bytes_out` | sum |
| `duration_sum`, `duration_count` | mean latency |
| `latency_bins` | 12 log-spaced bins, for percentile estimation |
| `slowest`, `slowest_uri` | worst single request in the bucket |

`slowest` is kept per bucket rather than per host so it becomes range-scoped like
everything else. A lone 30s timeout on one path is worth surfacing and neither
the percentile nor the failure breakdown shows it.

Failure grouping by `(status, path)` stays as it is today — per host, not per
bucket. It answers "what is broken", which does not need a time axis, and
bucketing it would multiply its cardinality by the bucket count.

### Adaptive bucket width

Fixed 1-minute buckets over a 7-day span would be 10,080 buckets x 12 sites x
~16 fields ≈ 15 MB. Instead, at rebuild read the first and last entry's `ts` —
one line at each end of the scanned range, cheap — and pick a width so buckets
per host stay under ~1500:

| span | width |
|---|---|
| <= 24h | 1 min |
| <= 7d | 5 min |
| > 7d | 1 hour |

That lands around 2 MB for 12 sites. The chosen width is reported in the
response so the UI can label the axis honestly.

### Percentiles

Percentiles do not sum, so today's "most recent 2048 durations" reservoir cannot
answer a range query. Each bucket instead carries a 12-bin log-spaced latency
histogram; summing histograms across a range and interpolating gives p95 to
within a bin. This makes p95 an **estimate**, so the UI labels the column `p95~`
and the API field is `p95_latency_ms_est`. Being explicit beats being wrong.

### Window vs range

Two controls with different jobs, currently conflated:

- **Byte window** (existing, 10/25/50/100 MB) — how much log to read. A
  mechanical limit on work.
- **Time range** (new: 1h / 6h / 24h / 7d) — which buckets to sum for display.

The range is bounded by what the window actually contains. When the requested
range reaches further back than the scanned window, the response sets
`range_truncated` with the earliest timestamp available, and the UI says so
rather than presenting a short period as a long one.

## API

`GET /api/logstats?window_mb=N&range=24h&host=foo`

```
{
  "exists": true, "path": "...",
  "window_mb": 10, "window_bytes": ..., "covered_bytes": ..., "file_size": ...,
  "range": "24h", "range_truncated": false, "earliest_ts": 1790500000.0,
  "bucket_seconds": 60, "entries": 10119, "skipped": 0,
  "sites": {
    "<host>": {
      "requests": 5600, "classes": {"2xx": 5560, "5xx": 40},
      "errors": 40, "error_rate": 0.71,
      "avg_latency_ms": 50.0, "p95_latency_ms_est": 50.0,
      "bytes_out": 1300000,
      "slowest": {"uri": "/api/v2/sync", "ms": 30000.0},
      "series": [{"t": 1790500000, "requests": 12, "errors": 0}, ...]
    }
  },
  "totals": { ...same shape, all hosts summed, with series... },
  "detail": { ... }   // only when ?host= is given; unchanged from today
}
```

`series` is downsampled to at most 120 points for the sparkline. Summary figures
are computed from full-resolution buckets, not from the downsampled series, so
the numbers never disagree with themselves.

This replaces today's response shape. The 27 existing `logstats` tests are
rewritten against the bucket model; `status` becomes `classes`,
`p95_latency_ms` becomes `p95_latency_ms_est`, and `slowest` becomes
range-scoped rather than window-scoped.

## Frontend stack: native ES modules, no framework

The image has no Node stage (`Dockerfile:1-24`); `editor.bundle.js` is built by
hand and committed. A framework forces either a Node build stage into an image
that needs none, or a committed app bundle that gets forgotten — a trap the repo
already documents in `docker-compose.dev.yaml:46`, itself stale since the build
only covers CodeMirror.

Native `<script type="module">` needs no build. It gives module boundaries, real
`import`/`export`, no global namespace, no hand-maintained script order in
`index.html:132-142`, and tests that import a function instead of eval'ing source
against a stubbed `document` the way `tests/diff.test.mjs` must today. For a
single-user app on a LAN the extra requests do not matter. `editor.bundle.js`
stays as a vendor bundle.

Migration is mechanical and file-at-a-time: add `export` to what each file
exposes, `import` what it uses, replace the eleven `<script>` tags with one
`<script type="module" src="/static/js/app/main.js">`. Files this change does not
otherwise touch are converted but not restructured.

## Design tokens

One palette as CSS custom properties on `:root`, replacing the 41 CSS hex values
and the 19 in JS. The content palette (GitHub slate) wins; chrome is re-tinted to
match, since most surface area is already slate.

- **Surfaces**: `--bg`, `--surface`, `--surface-raised`, `--border`
- **Ink**: `--ink`, `--ink-secondary`, `--ink-muted` (all >= 4.5:1 on `--surface`)
- **Accent**: `--accent` for interactive affordances only
- **Status** (reserved, never decorative): `--status-good`, `--status-warn`,
  `--status-serious`, `--status-critical`
- **Type scale**: 11 / 12 / 14 / 16 / 20 / 28px, replacing nine ad-hoc sizes
- **Space scale**: 4 / 8 / 12 / 16 / 24px

The decorative KPI colouring goes away: tiles use ink tokens, and colour appears
only where it encodes state. `style.cssText` in JS is replaced by classes. Final
token values get run through the dataviz palette validator against the dark
surface before shipping, and any contrast WARN obligates a visible label.

## Layout and charts

**Structure**, top to bottom:

1. **Traffic** — range + window selectors, a small KPI row (requests, error
   rate, p95~, bandwidth out), and a stacked status-over-time chart.
2. **Sites** — one table row per site: `SITE · REQ · ERR% · TREND · p95~`,
   sortable, click to expand the existing failure breakdown. Replaces the cards.
3. **Upstreams** — as today, restyled.
4. **Server counters** — the Prometheus per-server figures, in their own section
   labelled "since Caddy started", away from the range-scoped table above. This
   is the fix for finding 1.
5. **Editor activity** — saves, backups, logins. Separated from traffic.

**Charts** are hand-rolled inline SVG, ~40 lines each, no dependency.

- *Status over time*: stacked area, one band per status class, using the reserved
  status tokens. Status colour rules apply, so bands carry a legend and a table
  view rather than relying on colour alone.
- *Per-site trend*: sparkline, requests per bucket, 2px line, no axes, no
  legend — a single series in a labelled row needs neither.
- Never a dual axis. Latency and request count are separate marks, never two
  y-scales on one plot.
- Crosshair + tooltip on the stacked chart; the sparkline is decorative support
  for a row whose numbers are already present, so it needs no hover layer.
- A table view exists for every chart, which for this page is the primary view.

## Testing

Python, extending `tests/test_logstats.py`:

- bucketing assigns entries to the right minute; boundary timestamps land once
- width selection picks 1m / 5m / 1h from the span
- range summation matches a hand-computed total over a known fixture
- a range wider than the window sets `range_truncated` with `earliest_ts`
- histogram p95 lands within one bin of the true p95 for a known distribution
- downsampling never exceeds 120 points and preserves the total request count
- failure grouping keeps its existing behaviour (cap, query-string stripping)

JavaScript, newly practical once modules land: unit tests for the range
summation helpers, sparkline path generation, and the sort comparators, imported
directly rather than eval'd.

## Order of work

Each stage leaves the app working and is reviewable on its own.

1. **ES modules** — mechanical conversion, no behaviour change. Verifies by the
   app still working and `diff.test.mjs` simplifying.
2. **Design tokens** — palette, type and space scales; restyle existing markup
   with no structural change.
3. **Bucket aggregation** — `logstats.py` refactor plus the new response shape,
   tests rewritten. No UI change yet beyond reading the new field names.
4. **Layout restructure** — table replaces cards, sections reorganised, the
   Prometheus/log separation lands.
5. **Charts** — stacked status chart and sparklines.

## Risks

- **Stage 3 changes the response shape**, so stages 3 and 4 must land together
  or the panel breaks in between. They can share a branch.
- **p95 becomes an estimate.** Mitigated by naming it so, not by hiding it.
- **Adaptive bucket width means the x-axis resolution changes** as the log grows.
  The response reports `bucket_seconds` so the chart can label it.
- **ES modules change load behaviour** — modules are deferred and run after
  parse, so anything relying on synchronous global availability during parse
  breaks. The conversion must check `events.js`, which wires listeners.
