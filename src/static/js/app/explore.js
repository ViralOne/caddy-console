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
  // An empty range says so once, in the hint below, not again as an empty chart.
  const emptyRange = !!data?.exists && data.total === 0 && !loading;

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

        ${!emptyRange && html`
          <${Histogram} histogram=${data?.histogram} total=${data?.total}
                        from=${data?.range?.from} to=${data?.range?.to}
                        loading=${loading} onRange=${onDragRange} />`}

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
