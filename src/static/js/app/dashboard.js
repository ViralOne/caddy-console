// Dashboard at /: is anything broken, and where do I look next.
//
// Opens on a verdict, then the figures (each one a link into Explore with the
// matching filter), then per-site rows and recent changes. All wording and
// thresholds live in dashboard-model.js; this file only lays them out.
import { h, htm, render, useEffect, useState } from '../explore-vendor.js';
import { Icon } from './icons.js';
import { toast } from './ui/toast.js';
import { formatBytes, formatCount, formatMs, formatPercent } from './format.js';
import { RANGE, auditRow, configCard, exploreHref, healthOf, kpis, siteTags, verdict } from './dashboard-model.js';

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

function Spark({ series, bad }) {
  const points = series || [];
  if (!points.length || !points.some(v => v)) return html`<span class="muted">—</span>`;
  const peak = Math.max(...points);
  const step = 108 / Math.max(1, points.length - 1);
  const pts = points.map((v, i) => `${(1 + i * step).toFixed(1)},${(24 - (v / peak) * 22).toFixed(1)}`).join(' ');
  return html`
    <svg class="spark" viewBox="0 0 110 26" aria-hidden="true" focusable="false">
      <polyline points=${pts} fill="none" stroke=${bad ? 'var(--crit)' : 'var(--ink-3)'}
                stroke-width="1.5" stroke-linejoin="round" vector-effect="non-scaling-stroke" />
    </svg>`;
}

const Parts = ({ parts }) => parts.map((p, i) => (p.mono ? html`<span class="mono" key=${i}>${p.mono}</span>` : p.text));

function ConfigCard({ card }) {
  const icon = card.state === 'ok' ? 'status-ok' : card.state === 'bad' ? 'status-down' : 'status-unknown';
  return html`
    <aside class=${'cfg cfg-' + card.state} aria-label="Config">
      <div class="ok"><${Icon} name=${icon} />${card.label}</div>
      <dl>
        ${card.checks && html`<dt>Checks</dt><dd class="chk">${card.checks}</dd>`}
        ${card.version && html`<dt>Caddy</dt><dd>${card.version}</dd>`}
        ${card.changed && html`<dt>Changed</dt><dd><time title=${card.changed.abs}>${card.changed.rel}</time>${card.changed.by ? ` by ${card.changed.by}` : ''}</dd>`}
        ${card.path && html`<dt>File</dt><dd class="mono">${card.path}</dd>`}
      </dl>
    </aside>`;
}

function Verdict({ v, card }) {
  const icon = v.severity === 'warn' ? 'warning' : 'status-down';
  return html`
    <section class=${'verdict sev-' + v.severity} role=${v.severity === 'ok' ? 'status' : 'alert'} aria-labelledby="dash-h">
      <div>
        ${v.sev && html`<span class="sev"><${Icon} name=${icon} />${v.sev}</span>`}
        <h1 id="dash-h">${v.severity === 'ok' && html`<${Icon} name="status-ok" size=${26} class="verdict-ok" />`}${v.title}</h1>
        ${v.body.length > 0 && html`<p><${Parts} parts=${v.body} /></p>`}
        ${(v.primary || v.secondary) && html`
          <div class="acts">
            ${v.primary && html`<a class="btn btn-primary" href=${v.primary.href}
                 data-view=${v.primary.href.startsWith('/explore') ? 'explore' : 'editor'}>${v.primary.label}</a>`}
            ${v.secondary && html`<button class="btn" type="button" onClick=${() => openSite(v.secondary.host)}>${v.secondary.label}</button>`}
          </div>`}
      </div>
      ${card && html`<${ConfigCard} card=${card} />`}
    </section>`;
}

function Figures({ items }) {
  return html`
    <div class="figs" aria-label="Last hour">
      ${items.map(f => html`
        <a class="fig" key=${f.key} href=${f.href} data-view="explore">
          <span class="lbl">${f.label}</span>
          <span class="fv-n">${f.value}${f.of && html` <span class="fv-of">${f.of}</span>`}</span>
          ${f.sub && html`<span class=${'sub' + (f.bad ? ' bad' : '')}>${f.bad && html`<${Icon} name="warning" size=${14} /> `}${f.sub}</span>`}
        </a>`)}
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
        ${sites.map((s) => {
          const health = healthOf(s.host, upstreams);
          const tags = siteTags(s);
          const q = 'host:' + s.host;
          return html`
            <tr key=${s.host} class=${health.state === 'down' ? 'is-crit' : ''}>
              <td class="c-site"><a class="host" href=${exploreHref(q)} data-view="explore">${s.host}</a></td>
              <td class="c-health"><span class=${'health h-' + health.state}><${Icon} name=${health.icon} size=${14} />${health.label}</span></td>
              <td class="num" data-label="Requests"><a href=${exploreHref(q)} data-view="explore">${formatCount(s.requests)}</a></td>
              <td class="num" data-label="5xx"><a href=${exploreHref(q + ' status:5xx')} data-view="explore" title=${`${formatCount(s.errors)} server errors`}>${tags.includes('high')
                ? html`<span class="flag bad"><${Icon} name="warning" size=${14} />${formatPercent(s.error_rate, 2)} <span class="tag">high</span></span>`
                : formatPercent(s.error_rate, 2)}</a></td>
              <td class="num" data-label="p95"><a href=${exploreHref(q)} data-view="explore">${tags.includes('slow')
                ? html`<span class="flag slow"><${Icon} name="warning" size=${14} />${formatMs(s.p95_latency_ms)} <span class="tag">slow</span></span>`
                : formatMs(s.p95_latency_ms)}</a></td>
              <td class="num" data-label="Out"><a href=${exploreHref(q)} data-view="explore">${formatBytes(s.bytes_out)}</a></td>
              <td class="num c-spark"><${Spark} series=${s.series} bad=${health.state === 'down' || tags.includes('high')} /></td>
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
      <${Verdict} v=${v} card=${card} />
      <${Figures} items=${figures} />
      ${p && !proxyDismissed(p.ip) && html`<${ProxyNotice} p=${p} onDismiss=${dismiss} />`}

      <div class="h-sec"><h2>Sites</h2><p>Last hour, from the access log. Every figure opens in Explore.</p></div>
      ${sites.length
        ? html`<${SitesTable} sites=${sites} upstreams=${data.upstreamsError ? null : data.upstreams} />`
        : html`<p class="metrics-hint">No requests in the last hour${data.sites.skipped ? ` (${formatCount(data.sites.skipped)} log lines could not be indexed; check the log format)` : ''}.</p>`}

      <div class="h-sec"><h2>Recent changes</h2><p>From this console's audit log.</p></div>
      <${Changes} entries=${(data.audit?.entries || []).slice(0, 8)} now=${data.now} />

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
