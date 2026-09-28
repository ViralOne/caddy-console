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
import { hasTerm, toggleTerm } from './explore-query.js';
import { CLASSES, Histogram } from './histogram.js';

const html = htm.bind(h);

const RANGES = [
  { key: '1h', label: 'last 1h' },
  { key: '6h', label: 'last 6h' },
  { key: '24h', label: 'last 24h' },
  { key: '7d', label: 'last 7d' },
  { key: 'all', label: 'everything read' },
];
const WINDOWS = [10, 25, 50, 100];
const FACET_GROUPS = [
  { key: 'host', title: 'Host' },
  { key: 'status_class', title: 'Status', queryKey: 'status' },
  { key: 'status', title: 'Status code', queryKey: 'status' },
  { key: 'method', title: 'Method' },
  { key: 'path', title: 'Path' },
];
const DEBOUNCE_MS = 250;
const FOLLOW_MS = 4000;
const STORE_KEY = 'explorePrefs';

function loadPrefs() {
  try { return JSON.parse(localStorage.getItem(STORE_KEY)) || {}; } catch (e) { return {}; }
}
function savePrefs(p) {
  try { localStorage.setItem(STORE_KEY, JSON.stringify(p)); } catch (e) { /* private mode */ }
}

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
  const prefs = loadPrefs();
  const [query, setQuery] = useState('');
  const [draft, setDraft] = useState('');          // what's in the input right now
  const [range, setRange] = useState(prefs.range || '24h');
  const [windowMb, setWindowMb] = useState(WINDOWS.includes(prefs.windowMb) ? prefs.windowMb : 10);
  const [custom, setCustom] = useState(null);      // {from, to} from a histogram drag
  const [follow, setFollow] = useState(false);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(null);
  const inflight = useRef(null);

  useEffect(() => savePrefs({ range, windowMb }), [range, windowMb]);

  // Debounce the input: one request when typing settles, not one per keystroke.
  useEffect(() => {
    const t = setTimeout(() => setQuery(draft), DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [draft]);

  const load = useCallback(async () => {
    const params = new URLSearchParams({ window_mb: String(windowMb), limit: '200' });
    if (query) params.set('q', query);
    if (custom) { params.set('from', String(custom.from)); params.set('to', String(custom.to)); }
    else if (range !== 'all') params.set('range', range);

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
  }, [query, range, windowMb, custom]);

  useEffect(() => { setLoading(true); load(); }, [load]);

  // Follow mode re-runs the same query on a timer. Disabled whenever a custom
  // range is pinned, since "live" and "a fixed window in the past" conflict.
  useEffect(() => {
    if (!follow || custom) return;
    const t = setInterval(load, FOLLOW_MS);
    return () => clearInterval(t);
  }, [follow, custom, load]);

  const toggleFacet = (key, value) => {
    const qk = FACET_GROUPS.find(g => g.key === key)?.queryKey || key;
    setDraft(toggleTerm(draft, qk, value));
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
               placeholder="host:nas.example.com status:5xx path:/api  —  or any text"
               value=${draft} onInput=${e => setDraft(e.target.value)} />
        ${draft && html`<button class="btn btn-secondary btn-sm" onClick=${() => setDraft('')}>Clear</button>`}
        <select class="select-inline" value=${custom ? 'custom' : range}
                onChange=${e => pickRange(e.target.value)}>
          ${custom && html`<option value="custom">${rangeLabel}</option>`}
          ${RANGES.map(r => html`<option value=${r.key}>${r.label}</option>`)}
        </select>
        <select class="select-inline" value=${String(windowMb)} title="How much of the log to read"
                onChange=${e => setWindowMb(Number(e.target.value))}>
          ${WINDOWS.map(mb => html`<option value=${String(mb)}>read ${mb} MB</option>`)}
        </select>
        <button class=${'btn btn-sm ' + (follow ? 'btn-validate' : 'btn-secondary')}
                disabled=${!!custom}
                title=${custom ? 'Pinned to a selected range — pick a preset range to follow again' : 'Stream new matching events'}
                onClick=${() => setFollow(f => !f)}>${follow ? '● Live' : 'Live'}</button>
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
                  const on = hasTerm(draft, qk, v.value);
                  return html`
                    <button class=${'facet-row' + (on ? ' on' : '')} key=${v.value}
                            onClick=${() => toggleFacet(group.key, v.value)}
                            title=${v.value}>
                      <span class="facet-check">${on ? '☑' : '☐'}</span>
                      <span class="facet-value">${v.value || '(none)'}</span>
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
              <span class="explore-meta">${rangeLabel} · read ${formatBytesShort(data.window.covered_bytes)} of ${formatBytesShort(data.window.file_size)}</span>
            </div>`}

          ${data && !data.exists && html`
            <div class="metrics-hint">No access log at ${data.path}. Add a log directive to your sites — see the README for the snippet.</div>`}

          ${data?.range?.truncated && html`
            <div class="metrics-hint">The selected range reaches further back than the ${windowMb} MB read from the log. Earliest event available: ${clockTime(data.range.earliest_ts)}. Read more of the log to see further back.</div>`}

          ${data?.dropped > 0 && html`
            <div class="metrics-hint">${data.dropped.toLocaleString()} oldest events dropped to stay within the in-memory cap, so counts cover less than the bytes read.</div>`}

          <div class="stream">
            ${data?.entries?.length === 0 && !loading && html`
              <div class="metrics-hint">No events match. ${draft ? 'Try removing a filter.' : ''}</div>`}
            ${(data?.entries || []).map(e => {
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
                    <dl class="stream-detail">
                      <dt>time</dt><dd>${new Date(e.ts * 1000).toISOString()}</dd>
                      <dt>host</dt><dd>${e.host}</dd>
                      <dt>request</dt><dd>${e.method} ${e.uri}</dd>
                      <dt>status</dt><dd>${e.status}</dd>
                      <dt>duration</dt><dd>${e.duration_ms} ms</dd>
                      <dt>size</dt><dd>${formatBytesShort(e.size)}</dd>
                      <dt>client</dt><dd>${e.client_ip || '(none)'}</dd>
                    </dl>`}
                </div>`;
            })}
            ${data && data.total > (data.entries || []).length && html`
              <div class="metrics-hint">Showing the newest ${(data.entries || []).length} of ${data.total.toLocaleString()} matches. Narrow the query or the range to see the rest.</div>`}
          </div>
        </section>
      </div>
    </div>`;
}

let mounted = false;

export function mountExplore() {
  if (mounted) return;  // Preact keeps its own state; re-mounting would reset it
  const root = document.getElementById('explore-root');
  if (!root) return;
  render(html`<${App} />`, root);
  mounted = true;
}
