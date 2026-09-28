# Architecture notes

Why a few non-obvious things are the way they are. Written down because the
reasoning is not visible from the code alone.

## Log data is read, never copied

There is no database. Everything the dashboard and explorer show is derived from
Caddy's access log on demand, which means nothing to keep in sync, nothing to
migrate, and no second copy of your traffic to protect.

Two properties of the log make that affordable:

**It is append-ordered.** A byte offset for any timestamp is found by binary
search — about twenty small reads rather than parsing the file. That is why the
default 30-minute view is instant even on a 100 MB log. Timestamps are not
*strictly* monotonic (concurrent writes interleave by microseconds), so the search
brackets conservatively and backs off 64 KB before reading; a stray inversion
costs a few extra lines, never a missing entry.

**Rolled files are named after when they rolled.** Caddy writes
`access-2026-01-30T22-15-42.123-size.log.gz`, so which archives overlap a
requested range is decided from filenames alone, without decompressing any of
them. An archive is only opened when a range actually reaches into it. A filename
whose timestamp cannot be parsed is treated as unbounded and read when needed —
better to open one file needlessly than to hide history.

## Events are stored in columns

The index keeps parallel `array` columns (timestamps, status, duration, size, plus
interned ids for host/method/uri/client) rather than a list of objects. Measured on
a 100 MB log: 38 bytes per event retained, against roughly 140 for a tuple of the
same fields.

This exists because facet counts and the histogram must be computed **per query** —
they reflect the active filters, so pre-aggregated counters cannot answer them, and
re-parsing the range on every keystroke is far too slow. Parse once, query many
times. Query cost at 277k events: 70–280 ms, with unfiltered the slow case because
facet counting dominates.

`CADDY_EXPLORE_MAX_EVENTS` caps what is held. When a range exceeds it the oldest
events are dropped and the UI says so, rather than quietly under-reporting.

## Facets exclude their own filter

With `host:a` active, the host facet still shows the other hosts with truthful
counts, so they remain clickable. That costs one extra scan per constrained key —
usually none or one, not one per facet. The related rule: a facet's count always
equals what clicking it returns, which is why `path:` is an exact path match rather
than a substring (free text covers substring search).

## The URL is the state

Explore keeps its whole state in the query string, so a pasted link reproduces the
sender's view. A drag-selected range is written as **absolute** epoch timestamps
and drops the relative `range`, because a relative range would drift and the same
link would show a different window tomorrow. State changes use `replaceState`
rather than `pushState`, so typing does not fill history with one entry per
keystroke.

## Preact + htm for two views only

The dashboard and explorer use Preact with `htm`; the editor, panels and backups
stay vanilla DOM.

Explore carries a lot of derived state — query, filters, range, drag-select,
follow, facet and row expansion, paging, request cancellation — all feeding one
render, and hand-syncing that much DOM stops paying. `htm` uses tagged templates
instead of JSX, so **app code still needs no build step**, which keeps the
bind-mount-and-refresh dev workflow intact. Only the vendor bundle is built, and
only when the dependency changes.

SolidJS was considered and would be the better choice *if* a build step were on the
table — fine-grained reactivity suits a stream that prepends rows. It was rejected
because its buildless path (`solid-js/html`) "cannot leverage expression analysis,
necessitating manual wrapping of expressions", so every reactive site needs a
hand-written thunk and a missed one silently freezes the value. On a view built
around live counts that failure mode is unacceptable. If the build-step constraint
is ever lifted, revisit this.

## Design tokens

Every colour, size and space comes from `src/static/css/tokens.css`. The four
status colours are reserved: they encode state and are never used to tell
components apart. That rule is why buttons are accent-coloured rather than green,
and why metric values are plain ink unless the number itself means something is
wrong.
