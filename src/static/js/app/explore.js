// Explore: faceted search over the access log.
//
// The only Preact view in the app. It earns the framework because one render is
// derived from a lot of state — query, range, follow, paging, expanded rows —
// and hand-syncing that much DOM is where the vanilla approach stops paying.
//
// The query string is the single source of truth: clicking a facet rewrites the
// query rather than keeping parallel state, so the search box always explains
// what is on screen.
import { h, htm, render, useCallback, useEffect, useRef, useState } from '../explore-vendor.js';
import { cycleTerm, setTermState, termState } from './explore-query.js';
import { CLASSES, Histogram } from './histogram.js';
import { Icon } from './icons.js';
import { JsonView } from './jsonview.js';
import { exploreStateFromSearch, exploreStateToSearch, replaceSearch } from './router.js';

const html = htm.bind(h);

// Time is the only control now. The log is append-ordered, so the server
// bisects to the start of a range instead of reading a fixed number of
// megabytes, and reaches into rolled archives when a range predates the live file.
const RANGES = [
  { key: '30m', label: 'last 30 min' },
  { key: '1h', label: 'last 1h' },
  { key: '6h', label: 'last 6h' },
  { key: '24h', label: 'last 24h' },
  { key: '7d', label: 'last 7d' },
  { key: '30d', label: 'last 30 days' },
];
const FACET_GROUPS = [
  { key: 'host', title: 'Host' },
  { key: 'status_class', title: 'Status', queryKey: 'status' },
  { key: 'status', title: 'Status code', queryKey: 'status' },
  { key: 'method', title: 'Method' },
  { key: 'path', title: 'Path' },
];
const DEBOUNCE_MS = 250;
const FOLLOW_MS = 4000;

// A facet row has three states, cycled by clicking it: not filtered, only this
// value, everything but this value. Each has its own shape, so the difference
// never rests on colour alone. Drawn as icons rather than the ☐/☑/☒ characters
// they replaced: those three render at wildly different weights and widths
// depending on the platform's emoji font, so a column of them never lined up.
const FACET_STATE = {
  off: { icon: 'box', cls: '', hint: 'click to show only this' },
  include: { icon: 'box-check', cls: ' on', hint: 'only this — click to exclude it instead' },
  exclude: { icon: 'box-x', cls: ' excluded', hint: 'excluded — click to clear' },
};

const pad = (n) => String(n).padStart(2, '0');
function clockTime(ts) {
  const d = new Date(ts * 1000);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
function formatMs(ms) {
  if (ms >= 1000) return (ms / 1000).toFixed(ms >= 10000 ? 0 : 1) + 's';
  return ms.toFixed(ms < 10 ? 1 : 0) + 'ms';
}
function formatBytesShort(n) {
  if (!n) return '0';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(n) / Math.log(1024));
  return (n / Math.pow(1024, i)).toFixed(i ? 1 : 0) + ' ' + units[i];
}
// Which query key each field maps to. Fields absent from this map are
// copy-only: offering "Filter by" for a field the backend cannot filter would
// be a menu item that silently does nothing.
const FIELD_KEYS = { host: 'host', method: 'method', path: 'path', status: 'status' };

function pathOf(uri) {
  return (uri || '').split('?', 1)[0];
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (e) {
    // Blocked outside a secure context, or permission refused.
    return false;
  }
}

function fieldsOf(e) {
  return [
    { label: 'time', display: new Date(e.ts * 1000).toISOString(), value: String(e.ts), zoom: e.ts },
    { label: 'host', display: e.host, value: e.host },
    { label: 'method', display: e.method, value: e.method },
    { label: 'path', display: e.uri, value: pathOf(e.uri) },
    { label: 'status', display: String(e.status), value: String(e.status) },
    { label: 'duration', display: formatMs(e.duration_ms), value: String(e.duration_ms) },
    { label: 'size', display: formatBytesShort(e.size), value: String(e.size) },
    { label: 'client', display: e.client_ip || '(none)', value: e.client_ip || '' },
  ];
}

function statusTone(status) {
  if (status >= 500) return 'critical';
  if (status >= 400) return 'warn';
  if (status >= 300) return 'accent';
  return 'good';
}
function latencyTone(ms) {
  return ms > 1000 ? 'critical' : ms > 300 ? 'warn' : 'good';
}

function App() {
  // The URL is the source of truth for everything shareable, so a pasted link
  // reproduces the sender's view exactly — filters, range and timestamps.
  const initial = exploreStateFromSearch();
  const [query, setQuery] = useState(initial.q);
  const [draft, setDraft] = useState(initial.q);   // what's in the input right now
  const [range, setRange] = useState(initial.range);
  const [custom, setCustom] = useState(initial.custom);  // {from, to}, pinned absolute
  const [follow, setFollow] = useState(initial.live);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(null);
  const [older, setOlder] = useState([]);          // pages fetched behind the first
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [exhausted, setExhausted] = useState(false);
  const [raw, setRaw] = useState({});              // offset -> original log line
  const [fieldMenu, setFieldMenu] = useState(null);  // "<rowKey>|<field label>"
  const [note, setNote] = useState('');            // transient confirmation
  const inflight = useRef(null);

  // Any click that is not on a field menu closes it.
  useEffect(() => {
    if (!fieldMenu) return;
    const close = (ev) => { if (!ev.target.closest('.field-menu, .field-trigger, .field-value-click')) setFieldMenu(null); };
    const esc = (ev) => { if (ev.key === 'Escape') setFieldMenu(null); };
    document.addEventListener('click', close);
    document.addEventListener('keydown', esc);
    return () => { document.removeEventListener('click', close); document.removeEventListener('keydown', esc); };
  }, [fieldMenu]);

  const flash = (msg) => { setNote(msg); setTimeout(() => setNote(''), 1800); };

  // Re-read the URL on demand. mountExplore() calls this when the view is shown
  // again, which covers dashboard drill-down links and Back/Forward, since the
  // component is never unmounted.
  useEffect(() => {
    applyUrlState = () => {
      const next = exploreStateFromSearch();
      setDraft(next.q);
      setQuery(next.q);
      setRange(next.range);
      setCustom(next.custom);
      setFollow(next.live);
    };
    return () => { applyUrlState = null; };
  }, []);

  // replaceState, not pushState: a history entry per keystroke would make Back
  // feel broken.
  useEffect(() => {
    replaceSearch(exploreStateToSearch({ q: query, range, custom, live: follow }));
  }, [query, range, custom, follow]);

  // Debounce the input: one request when typing settles, not one per keystroke.
  useEffect(() => {
    const t = setTimeout(() => setQuery(draft), DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [draft]);

  const load = useCallback(async () => {
    const params = new URLSearchParams({ limit: '200' });
    if (query) params.set('q', query);
    if (custom) { params.set('from', String(custom.from)); params.set('to', String(custom.to)); }
    else params.set('range', range);

    // A slow response for an old query must not overwrite a newer one.
    const token = {};
    inflight.current = token;
    try {
      const res = await fetch('/api/explore?' + params);
      if (res.status === 401) return;          // fetch wrapper redirects
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

  useEffect(() => {
    setLoading(true);
    setOlder([]);
    setExhausted(false);
    load();
  }, [load]);

  // Follow mode re-runs the same query on a timer. Disabled whenever a custom
  // range is pinned, since "live" and "a fixed window in the past" conflict.
  useEffect(() => {
    if (!follow || custom) return;
    // Paged history cannot survive a refreshing head: the newest window shifts
    // and would overlap what was already appended, rendering events twice.
    setOlder([]);
    setExhausted(false);
    const t = setInterval(load, FOLLOW_MS);
    return () => clearInterval(t);
  }, [follow, custom, load]);

  // Paging walks backwards from the oldest event on screen. The server takes a
  // timestamp rather than an offset, so pages cannot drift or duplicate when new
  // events arrive at the head while reading.
  const loadOlder = async () => {
    const shown = [...(data?.entries || []), ...older];
    if (!shown.length || loadingOlder || follow) return;
    setLoadingOlder(true);
    try {
      const params = new URLSearchParams({
        limit: '200',
        before_ts: String(shown[shown.length - 1].ts),
        before_offset: String(shown[shown.length - 1].offset),
      });
      if (query) params.set('q', query);
      // Page against the absolute bounds the first request resolved, not the
      // relative range. Re-sending range=1h would re-resolve now-3600 for every
      // page, so the window would slide while paging and the tail would vanish —
      // "222 of 228" followed by "no more events".
      const from = custom ? custom.from : data?.range?.from;
      const to = custom ? custom.to : data?.range?.to;
      if (from != null && to != null) {
        params.set('from', String(Math.floor(from)));
        params.set('to', String(Math.ceil(to)));
      } else {
        params.set('range', range);
      }
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

  const showRaw = async (fileId, offset) => {
    if (raw[offset] !== undefined) { setRaw(prev => ({ ...prev, [offset]: undefined })); return; }
    // Updater form, not a spread of the captured `raw`: two rows fetched at once
    // would otherwise have the second response discard the first.
    try {
      const res = await fetch(`/api/explore/raw?file=${fileId}&offset=${offset}`);
      const body = await res.json();
      if (body.line) {
        setRaw(prev => ({ ...prev, [offset]: body.line }));
      } else {
        // Failures are shown but not cached, so clicking again actually retries
        // instead of re-displaying a stale error — it can succeed on a retry
        // after the index reloads.
        flash(body.error || 'Could not read that line');
      }
    } catch (e) {
      flash(e.message);
    }
  };

  const fieldAction = async (action, field) => {
    const key = FIELD_KEYS[field.label];
    const term = key ? `${key}:${/[\s"]/.test(field.value) ? '"' + field.value + '"' : field.value}` : '';
    setFieldMenu(null);
    if (action === 'copy-value') {
      flash(await copyText(field.value) ? 'Value copied' : 'Copy blocked by the browser');
    } else if (action === 'copy-term') {
      flash(await copyText(term) ? 'Copied ' + term : 'Copy blocked by the browser');
    } else if (action === 'filter' || action === 'exclude') {
      // Through setTermState rather than appended: picking "Exclude" for a value
      // already filtered in has to flip it, not leave `host:a -host:a` behind.
      setDraft(setTermState(draft, key, field.value,
                            action === 'filter' ? 'include' : 'exclude'));
    } else if (action === 'replace') {
      setDraft(term);
    } else if (action === 'zoom') {
      // ±5 minutes around the event, which is usually the useful neighbourhood.
      setCustom({ from: Math.floor(field.zoom) - 300, to: Math.ceil(field.zoom) + 300 });
      setFollow(false);
    }
  };

  const cycleFacet = (key, value) => {
    const qk = FACET_GROUPS.find(g => g.key === key)?.queryKey || key;
    setDraft(cycleTerm(draft, qk, value));
  };
  const pickRange = (key) => { setCustom(null); setRange(key); };
  const onDragRange = (from, to) => { setCustom({ from, to }); setFollow(false); };

  const stats = data?.stats;
  const rangeLabel = custom
    ? `${clockTime(custom.from)} – ${clockTime(custom.to)}`
    : (RANGES.find(r => r.key === range) || {}).label;

  return html`
    <div class="explore">
      <div class="explore-bar">
        <input class="explore-input" type="text" spellcheck="false"
               placeholder="host:app.example.com status:5xx -path:/health  —  or any text"
               value=${draft} onInput=${e => setDraft(e.target.value)} />
        ${draft && html`<button class="btn btn-secondary btn-sm" onClick=${() => setDraft('')}>Clear</button>`}
        ${custom
          ? html`<span class="range-pin" title="Zoomed into a selected range">
                   <${Icon} name="clock" />
                   ${rangeLabel}
                   <button onClick=${() => setCustom(null)}
                           aria-label="Clear the selected range"
                           title="Back to ${(RANGES.find(r => r.key === range) || {}).label}">
                     <${Icon} name="close" size=${14} />
                   </button>
                 </span>`
          : html`<select class="select-inline" value=${range}
                         onChange=${e => pickRange(e.target.value)}>
                   ${RANGES.map(r => html`<option value=${r.key}>${r.label}</option>`)}
                 </select>`}
        ${note && html`<span class="explore-note">${note}</span>`}
        <button class=${'btn btn-sm ' + (follow ? 'btn-primary' : 'btn-secondary')}
                disabled=${!!custom}
                title=${custom ? 'Pinned to a selected range — pick a preset range to follow again' : 'Stream new matching events'}
                onClick=${() => setFollow(f => !f)}>
          <${Icon} name="live" class=${follow ? 'icon-pulse' : ''} />Live
        </button>
      </div>

      ${error && html`<div class="metrics-hint error explore-error">${error}</div>`}

      <div class="explore-body">
        <aside class="explore-facets">
          ${!data ? html`<div class="metrics-hint">Loading…</div>` : FACET_GROUPS.map(group => {
            const values = (data.facets || {})[group.key] || [];
            if (!values.length) return null;
            const other = (data.facet_other || {})[group.key] || 0;
            const qk = group.queryKey || group.key;
            return html`
              <div class="facet-group" key=${group.key}>
                <div class="facet-title">${group.title}</div>
                ${values.slice(0, 8).map(v => {
                  // Values the query language cannot express: an absent field, or
                  // a status this app never recorded a real code for.
                  const unfilterable = v.value === '' || (group.key === 'status' && v.value === '0');
                  if (unfilterable) {
                    return html`
                      <div class="facet-row facet-row-static" key=${v.value || '(none)'}
                           title="Entries with no value for this field — not filterable">
                        <span class="facet-check facet-check-none" aria-hidden="true">–</span>
                        <span class="facet-value">(none)</span>
                        <span class="facet-count">${v.count.toLocaleString()}</span>
                      </div>`;
                  }
                  const state = FACET_STATE[termState(draft, qk, v.value)];
                  return html`
                    <button class=${'facet-row' + state.cls} key=${v.value}
                            onClick=${() => cycleFacet(group.key, v.value)}
                            title=${`${v.value} — ${state.hint}`}
                            aria-label=${`${group.title} ${v.value}, ${state.hint}`}>
                      <${Icon} name=${state.icon} class="facet-check" />
                      <span class="facet-value">${v.value}</span>
                      <span class="facet-count">${v.count.toLocaleString()}</span>
                    </button>`;
                })}
                ${values.length > 8 && html`<div class="facet-more">+${values.length - 8} more</div>`}
                ${other > 0 && html`<div class="facet-more">${other.toLocaleString()} in other values</div>`}
              </div>`;
          })}
        </aside>

        <section class="explore-main">
          <${Histogram} histogram=${data?.histogram} total=${data?.total}
                        from=${data?.range?.from} to=${data?.range?.to}
                        loading=${loading} onRange=${onDragRange} />

          ${stats && stats.requests > 0 && html`
            <div class="explore-stats">
              <span>${stats.requests.toLocaleString()} events</span>
              <span class=${'tone-' + (stats.error_rate > 5 ? 'critical' : 'good')}>${stats.error_rate}% 5xx</span>
              <span class=${'tone-' + latencyTone(stats.avg_latency_ms)}>avg ${formatMs(stats.avg_latency_ms)}</span>
              <span class=${'tone-' + latencyTone(stats.p95_latency_ms)}>p95 ${formatMs(stats.p95_latency_ms)}</span>
              <span>${formatBytesShort(stats.bytes_out)} out</span>
              <span class="spacer"></span>
              <span class="explore-meta">${rangeLabel} · ${data.history?.rolls_read ? `${data.history.rolls_read} archive${data.history.rolls_read > 1 ? 's' : ''} read` : 'live log only'}</span>
            </div>`}

          ${data && !data.exists && html`
            <div class="metrics-hint">No access log at ${data.path}. Add a log directive to your sites — see the README for the snippet.</div>`}

          ${data?.range?.truncated && html`
            <div class="metrics-hint">This range reaches further back than the events held in memory. Earliest indexed: ${clockTime(data.range.earliest_ts)}. Narrow the range, or raise CADDY_EXPLORE_MAX_EVENTS.</div>`}

          ${data?.skipped > 0 && data?.indexed === 0 && html`
            <div class="metrics-hint error">${data.skipped.toLocaleString()} log lines were read but none could be indexed — every entry needs a "ts" field and a request host. Check the log format against the README snippet.</div>`}

          ${data?.dropped > 0 && html`
            <div class="metrics-hint">${data.dropped.toLocaleString()} oldest events dropped to stay within the in-memory cap, so counts cover less than the bytes read.</div>`}

          <div class="stream">
            ${data?.entries?.length === 0 && !loading && html`
              <div class="metrics-hint">No events match. ${draft ? 'Try removing a filter.' : ''}</div>`}
            ${[...(data?.entries || []), ...older].map(e => {
              const key = e.ts + '|' + e.host + '|' + e.uri + '|' + e.status;
              const open = expanded === key;
              return html`
                <div class=${'stream-row' + (open ? ' open' : '')} key=${key}
                     onClick=${() => setExpanded(open ? null : key)}>
                  <span class="stream-time">${clockTime(e.ts)}</span>
                  <span class=${'stream-status tone-' + statusTone(e.status)}>${e.status}</span>
                  <span class="stream-host">${e.host}</span>
                  <span class="stream-method">${e.method}</span>
                  <span class="stream-uri" title=${e.uri}>${e.uri}</span>
                  <span class=${'stream-dur tone-' + latencyTone(e.duration_ms)}>${formatMs(e.duration_ms)}</span>
                  ${open && html`
                    <div class="stream-detail" onClick=${ev => ev.stopPropagation()}>
                      ${fieldsOf(e).map(f => {
                        const id = key + '|' + f.label;
                        const filterable = !!FIELD_KEYS[f.label];
                        const toggle = () => {
                          // Don't hijack a drag-select: if the user has highlighted
                          // text, they are copying by hand, not asking for a menu.
                          if (String(window.getSelection() || '')) return;
                          setFieldMenu(fieldMenu === id ? null : id);
                        };
                        return html`
                          <div class="field-row" key=${f.label}>
                            <button class="field-trigger" title=${'Actions for ' + f.label}
                                    aria-haspopup="true" aria-expanded=${String(fieldMenu === id)}
                                    onClick=${toggle}><${Icon} name="more" size=${14} /></button>
                            <span class="field-label">${f.label}</span>
                            <span class="field-value field-value-click" role="button" tabindex="0"
                                  aria-haspopup="true" aria-expanded=${String(fieldMenu === id)}
                                  title=${'Actions for ' + f.label}
                                  onClick=${toggle}
                                  onKeyDown=${ev => {
                                    if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); toggle(); }
                                  }}>${f.display}</span>
                            ${fieldMenu === id && html`
                              <div class="field-menu" role="menu">
                                <button role="menuitem" onClick=${() => fieldAction('copy-value', f)}>Copy value</button>
                                ${filterable && html`
                                  <button role="menuitem" onClick=${() => fieldAction('copy-term', f)}>Copy ${FIELD_KEYS[f.label]}:${f.value}</button>`}
                                ${filterable && html`
                                  <div class="field-menu-group">
                                    <button role="menuitem" onClick=${() => fieldAction('filter', f)}>Filter by <b>${FIELD_KEYS[f.label]}:${f.value}</b></button>
                                    <button role="menuitem" onClick=${() => fieldAction('exclude', f)}>Exclude <b>${FIELD_KEYS[f.label]}:${f.value}</b></button>
                                    <button role="menuitem" onClick=${() => fieldAction('replace', f)}>Replace query with <b>${FIELD_KEYS[f.label]}:${f.value}</b></button>
                                  </div>`}
                                ${f.zoom && html`
                                  <div class="field-menu-group">
                                    <button role="menuitem" onClick=${() => fieldAction('zoom', f)}>Zoom to ±5 min around this event</button>
                                  </div>`}
                                ${!filterable && !f.zoom && html`
                                  <div class="field-menu-note">Not a filterable field</div>`}
                              </div>`}
                          </div>`;
                      })}
                      <div class="field-row field-row-raw">
                        <span class="field-label">raw</span>
                        <span class="field-value">
                          <button class="btn btn-secondary btn-sm"
                                  onClick=${() => showRaw(e.file, e.offset)}>
                            ${raw[e.offset] !== undefined ? 'hide' : 'show original line'}
                          </button>
                          ${raw[e.offset] !== undefined && html`<${JsonView} text=${raw[e.offset]} />`}
                        </span>
                      </div>
                    </div>`}
                </div>`;
            })}
            ${(() => {
              if (!data) return null;
              const shown = (data.entries || []).length + older.length;
              if (shown >= data.total) return null;
              if (exhausted) {
                return html`<div class="metrics-hint">No more events in this range.</div>`;
              }
              return html`
                <button class="stream-more" onClick=${loadOlder} disabled=${loadingOlder}>
                  ${loadingOlder ? 'Loading…' : `Load 200 older — showing ${shown.toLocaleString()} of ${data.total.toLocaleString()}`}
                </button>`;
            })()}
          </div>
        </section>
      </div>
    </div>`;
}

let mounted = false;
let applyUrlState = null;   // set by App while it is rendered

export function mountExplore() {
  const root = document.getElementById('explore-root');
  if (!root) return;
  if (mounted) {
    // Already rendered: adopt whatever the URL now says rather than showing the
    // previous query. Re-rendering from scratch would also work but would throw
    // away expanded rows and loaded pages on every view switch.
    applyUrlState?.();
    return;
  }
  render(html`<${App} />`, root);
  mounted = true;
}
