// Dashboard at /: is anything broken, and where do I look next.
//
// Every figure is a link into /explore with the matching filter prefilled, so
// this page answers "what" and hands off to Explore for "why". It deliberately
// does not repeat Explore's histogram or its per-path breakdown.
import { h, htm, render, useEffect, useState } from '../explore-vendor.js';

const html = htm.bind(h);

const RANGE = '1h';          // the dashboard is a "right now" view
const REFRESH_MS = 15000;

function formatBytes(n) {
  if (!n) return '0';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(n) / Math.log(1024));
  return (n / Math.pow(1024, i)).toFixed(i ? 1 : 0) + ' ' + units[i];
}
function formatMs(ms) {
  if (!ms) return '—';
  return ms >= 1000 ? (ms / 1000).toFixed(1) + 's' : Math.round(ms) + 'ms';
}
function formatCount(n) {
  if (n >= 10000) return (n / 1000).toFixed(1) + 'k';
  return n.toLocaleString();
}
function latencyTone(ms) {
  return ms > 1000 ? 'critical' : ms > 300 ? 'warn' : 'good';
}
// `caddy version` prints "v2.11.4 h1:XKxk…=" — the build hash is noise here.
function shortVersion(v) {
  return (v || '').split(/\s+/)[0];
}

// Config mtime arrives as an ISO string with microseconds; on a dashboard what
// matters is how long ago, not the exact instant.
function timeAgo(iso) {
  if (!iso) return 'unknown';
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return iso;
  const secs = Math.max(0, (Date.now() - then) / 1000);
  if (secs < 60) return 'just now';
  if (secs < 3600) return Math.floor(secs / 60) + 'm ago';
  if (secs < 86400) return Math.floor(secs / 3600) + 'h ago';
  return Math.floor(secs / 86400) + 'd ago';
}

function exploreHref(query) {
  const p = new URLSearchParams({ range: RANGE });
  if (query) p.set('q', query);
  return '/explore?' + p.toString();
}

// Sparkline: 24 buckets over the range, one path, no axes. A single series in a
// labelled row needs no legend.
function Spark({ series }) {
  const points = series || [];
  if (!points.length || !points.some(v => v)) return html`<span class="spark-empty">—</span>`;
  const peak = Math.max(...points);
  const step = 100 / Math.max(1, points.length - 1);
  const d = points
    .map((v, i) => `${i === 0 ? 'M' : 'L'}${(i * step).toFixed(1)},${(20 - (v / peak) * 18).toFixed(1)}`)
    .join(' ');
  return html`
    <svg class="spark" viewBox="0 0 100 20" preserveAspectRatio="none" aria-hidden="true">
      <path d=${d} fill="none" stroke="var(--accent)" stroke-width="1.5"
            vector-effect="non-scaling-stroke" />
    </svg>`;
}

function healthOf(host, upstreams) {
  // A site's health is its upstreams'. Sites that only respond directly (respond,
  // file_server) have no upstream, which is not the same as being unhealthy.
  const mine = (upstreams || []).filter(u => (u.domains || []).includes(host));
  if (!mine.length) return { state: 'none', label: 'no upstream' };
  if (mine.some(u => u.healthy === 0)) return { state: 'down', label: 'unhealthy' };
  if (mine.every(u => u.healthy === 1)) return { state: 'up', label: 'healthy' };
  return { state: 'unknown', label: 'not checked' };
}

function App() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  const load = async () => {
    try {
      const [sites, upstreams, traffic, status, audit] = await Promise.all([
        fetch(`/api/sites?range=${RANGE}`).then(r => r.json()),
        fetch('/api/upstreams').then(r => r.json()),
        fetch('/api/traffic').then(r => r.json()),
        fetch('/api/status').then(r => r.json()),
        fetch('/api/audit').then(r => r.json()),
      ]);
      // Caddy reports upstream health per address; fold it onto the upstream rows.
      const healthy = traffic.upstreams_healthy || {};
      const ups = (upstreams.upstreams || []).map(u => ({ ...u, healthy: healthy[u.address] }));
      setData({ sites, upstreams: ups, status, audit });
      setError(sites.error || upstreams.error || null);
    } catch (e) {
      setError(e.message);
    }
  };

  useEffect(() => {
    load();
    const t = setInterval(load, REFRESH_MS);
    return () => clearInterval(t);
  }, []);

  if (error && !data) return html`<div class="metrics-hint error">Could not load the dashboard: ${error}</div>`;
  if (!data) return html`<div class="metrics-hint">Loading…</div>`;

  const sites = data.sites.sites || [];
  const totals = sites.reduce((acc, s) => ({
    requests: acc.requests + s.requests,
    errors: acc.errors + s.errors,
    bytes: acc.bytes + s.bytes_out,
  }), { requests: 0, errors: 0, bytes: 0 });
  const errorRate = totals.requests ? (totals.errors / totals.requests * 100) : 0;
  const failing = data.upstreams.filter(u => u.healthy === 0);
  const cfg = data.status || {};

  return html`
    <div class="dash">
      ${error && html`<div class="metrics-hint error">${error}</div>`}

      <div class="dash-summary">
        <div class="dash-kpi">
          <div class="dash-kpi-label">Requests · last hour</div>
          <a class="dash-kpi-value" href=${exploreHref('')} data-view="explore">${formatCount(totals.requests)}</a>
        </div>
        <div class="dash-kpi">
          <div class="dash-kpi-label">5xx rate</div>
          <a class=${'dash-kpi-value tone-' + (errorRate > 5 ? 'critical' : errorRate > 0 ? 'warn' : 'good')}
             href=${exploreHref('status:5xx')} data-view="explore">${errorRate.toFixed(errorRate >= 10 ? 0 : 1)}%</a>
        </div>
        <div class="dash-kpi">
          <div class="dash-kpi-label">Sites with traffic</div>
          <div class="dash-kpi-value">${sites.length}</div>
        </div>
        <div class="dash-kpi">
          <div class="dash-kpi-label">Bandwidth out</div>
          <div class="dash-kpi-value">${formatBytes(totals.bytes)}</div>
        </div>
        <div class="dash-kpi dash-kpi-wide">
          <div class="dash-kpi-label">Config</div>
          <div class="dash-kpi-line">
            <span class=${'tone-' + (cfg.config_valid ? 'good' : 'critical')}>
              ${cfg.config_valid ? '● valid' : '● invalid'}
            </span>
            <span class="dash-muted">${shortVersion(cfg.caddy_version)}</span>
          </div>
          <div class="dash-kpi-line dash-muted" title=${cfg.last_modified || ''}>changed ${timeAgo(cfg.last_modified)}</div>
          <div class="dash-kpi-line dash-path" title=${cfg.config_path || ''}>${cfg.config_path || ''}</div>
        </div>
      </div>

      ${failing.length > 0 && html`
        <div class="dash-alert">
          <strong>${failing.length} upstream${failing.length > 1 ? 's' : ''} unhealthy:</strong>
          ${failing.map(u => html`<span class="dash-alert-item">${u.address}${u.domains?.length ? ' (' + u.domains.join(', ') + ')' : ''}</span>`)}
        </div>`}

      <div class="section-title">
        <span>Sites</span>
        <span class="section-basis">last hour, from the access log · click any figure to investigate</span>
      </div>

      ${!sites.length
        ? html`<div class="metrics-hint">No requests in the last hour${data.sites.skipped ? ` (${data.sites.skipped.toLocaleString()} log lines could not be indexed — check the log format)` : ''}.</div>`
        : html`
        <div class="dash-table">
          <div class="dash-row dash-head">
            <span>Site</span><span>Health</span><span class="num">Requests</span>
            <span class="num">5xx</span><span class="num">p95</span>
            <span class="num">Out</span><span>Last hour</span>
          </div>
          ${sites.map(s => {
            const health = healthOf(s.host, data.upstreams);
            return html`
              <div class="dash-row" key=${s.host}>
                <a class="dash-site" href=${exploreHref('host:' + s.host)} data-view="explore"
                   title=${'Explore ' + s.host}>${s.host}</a>
                <span class=${'dash-health ' + health.state}>● ${health.label}</span>
                <a class="num dash-link" href=${exploreHref('host:' + s.host)} data-view="explore">${formatCount(s.requests)}</a>
                ${s.errors
                  ? html`<a class=${'num dash-link tone-' + (s.error_rate > 5 ? 'critical' : 'warn')}
                            href=${exploreHref(`host:${s.host} status:5xx`)} data-view="explore"
                            title=${s.errors + ' server errors'}>${s.error_rate}%</a>`
                  : html`<span class="num dash-muted">0%</span>`}
                <span class=${'num tone-' + latencyTone(s.p95_latency_ms)}>${formatMs(s.p95_latency_ms)}</span>
                <span class="num dash-muted">${formatBytes(s.bytes_out)}</span>
                <${Spark} series=${s.series} />
              </div>`;
          })}
        </div>`}

      <div class="section-title">
        <span>Recent changes</span>
        <span class="section-basis">from the editor's audit log</span>
      </div>
      ${(() => {
        const entries = (data.audit?.entries || []).slice(0, 8);
        if (!entries.length) return html`<div class="metrics-hint">No editor activity recorded yet.</div>`;
        return html`
          <div class="dash-table">
            ${entries.map((a, i) => html`
              <div class="dash-audit" key=${i}>
                <span class="dash-audit-action">${a.action}</span>
                <span class="dash-audit-user">${a.user}</span>
                <span class="dash-audit-detail" title=${a.detail || ''}>${a.detail || ''}</span>
                <span class="dash-audit-time">${a.time}</span>
              </div>`)}
          </div>`;
      })()}

      <div class="metrics-footer">
        Read ${formatBytes(data.sites.window?.covered_bytes || 0)} of ${formatBytes(data.sites.window?.file_size || 0)} from the log · refreshes every ${REFRESH_MS / 1000}s
        ${data.sites.dropped ? ` · ${data.sites.dropped.toLocaleString()} oldest events dropped at the memory cap` : ''}
      </div>
    </div>`;
}

let mounted = false;

export function mountDashboard() {
  const root = document.getElementById('dashboard-root');
  if (!root || mounted) return;
  render(html`<${App} />`, root);
  mounted = true;
}
