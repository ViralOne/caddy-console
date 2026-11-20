// Dashboard at /: is anything broken, and where do I look next.
//
// Opens on a verdict, then the figure tiles (each one a link into Explore with
// the matching filter, plus the config tile), then per-site rows (problems
// first) beside recent changes on wide screens. All wording and
// thresholds live in dashboard-model.js; this file only lays them out.
import { h, htm, render, useEffect, useState } from '../explore-vendor.js';
import { Icon } from './icons.js';
import { toast } from './ui/toast.js';
import { formatBytes, formatCount, formatMs, formatPercent } from './format.js';
import { RANGE, auditRow, configCard, exploreHref, kpis, siteRows, verdict } from './dashboard-model.js';

const html = htm.bind(h);
const REFRESH_MS = 15000;
const PROXY_DISMISS_KEY = 'dashboard.proxyIpDismissed';

function proxyDismissed(ip) {
  try { return localStorage.getItem(PROXY_DISMISS_KEY) === ip; } catch (e) { return false; }
}
function setProxyDismissed(ip) {
  try { if (ip) localStorage.setItem(PROXY_DISMISS_KEY, ip); else localStorage.removeItem(PROXY_DISMISS_KEY); } catch (e) { /* this page only */ }
}
// A proxy error page is not JSON; say which request failed and how.
async function getJson(url) {
  const r = await fetch(url);
  if (!r.ok) {
    const body = await r.json().catch(() => null);
    throw new Error((body && body.error) || `${url.split('?')[0]} returned HTTP ${r.status}`);
  }
  return r.json();
}
const openSite = (host) => document.dispatchEvent(new CustomEvent('app:open-site', { detail: { host } }));

const STROKE = { crit: 'var(--crit)', warn: 'var(--warn)' };

function Spark({ series, tone = null, w = 110, ht = 26, cls = 'spark' }) {
  const points = series || [];
  if (!points.length || !points.some(v => v)) return html`<span class="muted">—</span>`;
  const peak = Math.max(...points);
  const step = (w - 2) / Math.max(1, points.length - 1);
  const pts = points.map((v, i) => `${(1 + i * step).toFixed(1)},${(ht - 2 - (v / peak) * (ht - 4)).toFixed(1)}`).join(' ');
  return html`
    <svg class=${cls} viewBox=${`0 0 ${w} ${ht}`} preserveAspectRatio="none" aria-hidden="true" focusable="false">
      <polyline points=${pts} fill="none" stroke=${STROKE[tone] || 'var(--ink-3)'}
                stroke-width="1.5" stroke-linejoin="round" vector-effect="non-scaling-stroke" />
    </svg>`;
}

// A thin bar for a share (0..1); the figure next to it carries the number.
const Bar = ({ share }) => html`<span class="bar" aria-hidden="true"><i style=${{ width: `${Math.max(0, Math.min(1, share)) * 100}%` }}></i></span>`;

const Parts = ({ parts }) => parts.map((p, i) => (p.mono ? html`<span class="mono" key=${i}>${p.mono}</span>` : p.text));

function DownList({ down }) {
  return html`
    <ul class="downs" aria-label="Sites that are down">
      ${down.items.map(d => html`
        <li key=${d.host}>
          <span class="d-host mono">${d.host}</span>
          <span class="d-addr mono">${d.address}</span>
          <span class="d-since">${d.since}</span>
          <button class="btn sm" type="button" onClick=${() => openSite(d.host)}>Open block</button>
        </li>`)}
      ${down.moreText && html`<li class="d-more">${down.moreText}</li>`}
    </ul>`;
}

function Verdict({ v }) {
  const icon = v.severity === 'warn' ? 'warning' : 'status-down';
  return html`
    <section class=${'verdict sev-' + v.severity} role=${v.severity === 'ok' ? 'status' : 'alert'} aria-labelledby="dash-h">
      ${v.sev && html`<span class="sev"><${Icon} name=${icon} />${v.sev}</span>`}
      <h1 id="dash-h">${v.severity === 'ok' && html`<${Icon} name="status-ok" size=${20} class="verdict-ok" />`}${v.title}</h1>
      ${v.down && html`<${DownList} down=${v.down} />`}
      ${v.body.length > 0 && html`<p><${Parts} parts=${v.body} /></p>`}
      ${(v.primary || v.secondary) && html`
        <div class="acts">
          ${v.primary && html`<a class="btn btn-primary" href=${v.primary.href}
               data-view=${v.primary.href.startsWith('/explore') ? 'explore' : 'editor'}>${v.primary.label}</a>`}
          ${v.secondary && html`<button class="btn" type="button" onClick=${() => openSite(v.secondary.host)}>${v.secondary.label}</button>`}
        </div>`}
    </section>`;
}

const LEVEL_WORD = { crit: 'high', warn: 'elevated' };

function Figure({ f }) {
  return html`
    <a class="fig" href=${f.href} data-view="explore" title=${f.title || null}>
      <span class="lbl">${f.label}</span>
      <span class=${'fv-n' + (f.level ? ' lv-' + f.level : '')}>${f.level && html`<${Icon} name="warning" size=${18} />`}${f.value}${f.of && html` <span class="fv-of">${f.of}</span>`}${f.level && html` <span class="tag">${LEVEL_WORD[f.level]}</span>`}</span>
      ${f.spark && f.spark.some(v => v) && html`<${Spark} series=${f.spark} w=${200} ht=${28} cls="spark fig-spark" />`}
      ${f.share && html`<span class="sub share"><${Bar} share=${f.share.pct / 100} />${f.share.text}</span>`}
      ${!f.share && f.sub && html`<span class=${'sub' + (f.bad ? ' bad' : '')}>${f.bad && !f.level && html`<${Icon} name="warning" size=${14} /> `}${f.sub}</span>`}
    </a>`;
}

function ConfigFigure({ card }) {
  const icon = card.state === 'ok' ? 'status-ok' : card.state === 'bad' ? 'status-down' : 'status-unknown';
  return html`
    <a class=${'fig fig-cfg cfg-' + card.state} href="/editor" data-view="editor" title=${card.checks || null}>
      <span class="lbl">Config</span>
      <span class="cfg-state"><${Icon} name=${icon} size=${18} />${card.word}</span>
      ${card.state === 'bad' && card.checks && html`<span class="sub mono cfg-msg">${card.checks}</span>`}
      ${card.version && html`<span class="sub">Caddy ${card.version}</span>`}
      ${card.changed && html`<span class="sub">Changed <time title=${card.changed.abs}>${card.changed.rel}</time>${card.changed.by ? ` by ${card.changed.by}` : ''}</span>`}
      ${card.path && html`<span class="sub mono cfg-path" title=${card.path}>${card.path}</span>`}
    </a>`;
}

function Figures({ items, card }) {
  return html`
    <div class="figs" aria-label="Last hour">
      ${items.map(f => html`<${Figure} key=${f.key} f=${f} />`)}
      ${card && html`<${ConfigFigure} card=${card} />`}
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
        ${siteRows(sites, upstreams).map(({ site: s, health, tags, share, tone }) => {
          const q = 'host:' + s.host;
          return html`
            <tr key=${s.host} class=${health.state === 'down' ? 'is-crit' : ''}>
              <td class="c-site"><a class="host" href=${exploreHref(q)} data-view="explore">${s.host}</a></td>
              <td class="c-health"><span class=${'health h-' + health.state}><${Icon} name=${health.icon} size=${14} />${health.label}</span></td>
              <td class="num c-req" data-label="Requests"><a href=${exploreHref(q)} data-view="explore">${formatCount(s.requests)}</a><${Bar} share=${share} /></td>
              <td class="num" data-label="5xx"><a href=${exploreHref(q + ' status:5xx')} data-view="explore" title=${`${formatCount(s.errors)} server errors`}>${tags.includes('high')
                ? html`<span class="flag bad"><${Icon} name="warning" size=${14} />${formatPercent(s.error_rate, 2)} <span class="tag">high</span></span>`
                : formatPercent(s.error_rate, 2)}</a></td>
              <td class="num" data-label="p95"><a href=${exploreHref(q)} data-view="explore">${tags.includes('slow')
                ? html`<span class="flag slow"><${Icon} name="warning" size=${14} />${formatMs(s.p95_latency_ms)} <span class="tag">slow</span></span>`
                : formatMs(s.p95_latency_ms)}</a></td>
              <td class="num" data-label="Out"><a href=${exploreHref(q)} data-view="explore">${formatBytes(s.bytes_out)}</a></td>
              <td class="num c-spark"><${Spark} series=${s.series} tone=${tone} w=${160} ht=${28} /></td>
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
  const [error, setError] = useState(null);           // the last refresh failed
  const [, setDismissTick] = useState(0);

  const load = async () => {
    try {
      const [sites, upstreams, traffic, status, audit] = await Promise.all([
        getJson(`/api/sites?range=${RANGE}`), getJson('/api/upstreams'), getJson('/api/traffic'),
        getJson('/api/status'), getJson('/api/audit'),
      ]);
      // Caddy reports upstream health per address; fold it onto the upstream rows.
      const healthy = traffic.upstreams_healthy || {};
      const ups = (upstreams.upstreams || []).map(u => ({ ...u, healthy: healthy[u.address] }));
      setData({
        sites, upstreams: ups, upstreamsError: upstreams.error || null, trafficError: traffic.error || null,
        configuredSites: upstreams.configured_sites ?? null, status, audit, now: Date.now(),
      });
      setError(null);
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
  // A failed refresh keeps the last figures but never the last verdict.
  const v = verdict({
    sites, upstreams: data.upstreams, upstreamsError: data.upstreamsError, trafficError: data.trafficError,
    loadError: error, configuredSites: data.configuredSites, status: data.status, now: data.now,
  });
  const card = configCard(data.status, data.now);
  const figures = kpis({ sites, previousTotal: data.sites.previous_total ?? null, configuredSites: data.configuredSites, dropped: data.sites.dropped || 0 });
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
      ${data.sites.error && html`<p class="metrics-hint error">${data.sites.error}</p>`}
      <${Verdict} v=${v} />
      <${Figures} items=${figures} card=${card} />
      ${p && !proxyDismissed(p.ip) && html`<${ProxyNotice} p=${p} onDismiss=${dismiss} />`}

      <div class="dash-cols">
        <section class="dash-sites" aria-labelledby="dash-sites-h">
          <div class="h-sec"><h2 id="dash-sites-h">Sites</h2><p>Last hour, from the access log. Every figure opens in Explore.</p></div>
          ${sites.length
            ? html`<${SitesTable} sites=${sites} upstreams=${data.upstreamsError ? null : data.upstreams} />`
            : html`<p class="metrics-hint">No requests in the last hour${data.sites.skipped ? ` (${formatCount(data.sites.skipped)} log lines could not be indexed; check the log format)` : ''}.</p>`}
        </section>
        <section class="dash-changes" aria-labelledby="dash-changes-h">
          <div class="h-sec"><h2 id="dash-changes-h">Recent changes</h2><p>From this console's audit log.</p></div>
          <${Changes} entries=${(data.audit?.entries || []).slice(0, 8)} now=${data.now} />
        </section>
      </div>

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
