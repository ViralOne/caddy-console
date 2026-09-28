// Metrics tab: overview cards, upstreams, per-site traffic, editor activity.
import { el, fetchJson, showError } from './core.js';
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
}

export async function loadMetrics() {
  const body = document.getElementById('metrics-body');
  body.textContent = 'Loading metrics...';

  let metrics, traffic, upstreams;
  try {
    [metrics, traffic, upstreams] = await Promise.all([
      fetchJson('/api/metrics'),
      fetchJson('/api/traffic'),
      fetchJson('/api/upstreams'),
    ]);
  } catch (e) {
    // Without this the tab sat on "Loading metrics..." forever with an
    // unhandled rejection in the console.
    if (e.status === 401) return;
    showError(body, 'Could not load metrics', e);
    return;
  }
  traffic.sites = traffic.sites || {};

  body.textContent = '';

  // --- Overview Cards ---
  const overviewSection = el('div', 'metrics-section');
  overviewSection.appendChild(el('div', 'section-title', 'Overview'));

  const overviewGrid = el('div', 'metrics-grid');
  const totalReqs = traffic.totals ? traffic.totals.requests : 0;
  const totalErrs = traffic.totals ? traffic.totals.errors : 0;
  const inFlight = traffic.totals ? traffic.totals.in_flight : 0;
  const bytesIn = traffic.totals ? traffic.totals.bytes_in : 0;
  const bytesOut = traffic.totals ? traffic.totals.bytes_out : 0;
  const errorRate = totalReqs > 0 ? (totalErrs / totalReqs * 100).toFixed(1) : '0.0';

  overviewGrid.appendChild(metricCard('Total Requests', totalReqs.toLocaleString(), '#4fc3f7'));
  overviewGrid.appendChild(metricCard('Error Rate', errorRate + '%', parseFloat(errorRate) > 5 ? '#ef5350' : '#66bb6a'));
  overviewGrid.appendChild(metricCard('In Flight', inFlight.toString(), '#ce93d8'));
  overviewGrid.appendChild(metricCard('Bandwidth In', formatBytes(bytesIn), '#ffa726'));
  overviewGrid.appendChild(metricCard('Bandwidth Out', formatBytes(bytesOut), '#4fc3f7'));
  overviewGrid.appendChild(metricCard('Sites', metrics.site_count.toString(), '#66bb6a'));
  overviewGrid.appendChild(metricCard('Total Saves', metrics.total_saves.toString(), '#90a4ae'));
  overviewGrid.appendChild(metricCard('Backups', metrics.backup_count.toString(), '#607d8b'));

  overviewSection.appendChild(overviewGrid);
  body.appendChild(overviewSection);

  // --- Upstreams ---
  const upstreamSection = el('div', 'metrics-section');
  upstreamSection.appendChild(el('div', 'section-title', 'Upstream Backends'));

  if (upstreams.error) {
    upstreamSection.appendChild(el('div', 'metrics-hint', upstreams.error));
  }

  if (upstreams.upstreams && upstreams.upstreams.length > 0) {
    const table = el('div', 'upstream-table');
    const header = el('div', 'upstream-row upstream-header');
    header.appendChild(el('span', 'upstream-cell', 'Domain'));
    header.appendChild(el('span', 'upstream-cell', 'Address'));
    header.appendChild(el('span', 'upstream-cell', 'In Flight'));
    header.appendChild(el('span', 'upstream-cell', 'Fails'));
    header.appendChild(el('span', 'upstream-cell', 'Health'));
    table.appendChild(header);

    upstreams.upstreams.forEach(u => {
      const row = el('div', 'upstream-row');

      const domainCell = el('span', 'upstream-cell upstream-domain');
      if (u.domains && u.domains.length) {
        domainCell.textContent = u.domains.join(', ');
        domainCell.title = u.domains.join('\n');
      } else {
        domainCell.textContent = 'not in current config';
        domainCell.className += ' muted';
        domainCell.title = 'This upstream is still registered in the running process but no site in the loaded config proxies to it.';
      }
      row.appendChild(domainCell);

      row.appendChild(el('span', 'upstream-cell upstream-addr', u.address));

      // num_requests is a live gauge of requests being proxied right now, not a
      // running total, so it reads 0 unless you happen to refresh mid-request.
      const inFlight = u.num_requests || 0;
      const flightCell = el('span', 'upstream-cell');
      flightCell.textContent = inFlight.toString();
      flightCell.title = 'Requests being proxied to this upstream at this instant. Not a cumulative total — see Per-Site Traffic below for totals.';
      if (inFlight > 0) flightCell.style.color = '#ce93d8';
      else flightCell.className += ' upstream-muted';
      row.appendChild(flightCell);

      // Without fail_duration, Caddy never records a failure here, so showing a
      // hard 0 would imply "no failures" when it really means "not measured".
      const failCell = el('span', 'upstream-cell');
      if (u.passive_health) {
        failCell.textContent = (u.fails || 0).toString();
        failCell.title = 'Failed requests remembered within fail_duration.';
        if (u.fails > 0) failCell.style.color = '#ef5350';
      } else {
        const badge = el('span', 'health-badge unknown has-tooltip', 'n/a');
        badge.appendChild(el('span', 'badge-tooltip', 'Not measured. Caddy only counts failures when passive health checks are enabled, which needs fail_duration (default 0 = off). Add inside reverse_proxy { }:\n\nfail_duration 30s\nmax_fails 3\nunhealthy_status 5xx'));
        failCell.appendChild(badge);
      }
      row.appendChild(failCell);

      const healthVal = traffic.upstreams_healthy ? traffic.upstreams_healthy[u.address] : undefined;
      const healthCell = el('span', 'upstream-cell');
      const badge = document.createElement('span');
      if (healthVal === 1) { badge.className = 'health-badge up'; badge.textContent = 'healthy'; }
      else if (healthVal === 0) { badge.className = 'health-badge down'; badge.textContent = 'unhealthy'; }
      else {
        badge.className = 'health-badge unknown has-tooltip';
        badge.textContent = 'n/a';
        const tooltip = el('span', 'badge-tooltip', 'No active health check. Add inside reverse_proxy { }:\n\nreverse_proxy 10.0.0.1:8080 {\n    health_uri /\n    health_interval 30s\n}');
        badge.appendChild(tooltip);
      }
      healthCell.appendChild(badge);
      row.appendChild(healthCell);

      table.appendChild(row);
    });
    upstreamSection.appendChild(table);
    upstreamSection.appendChild(el('div', 'metrics-hint', 'In Flight is a live gauge (requests in progress right now), so it is normally 0. Caddy does not export per-upstream request totals; use Per-Site Traffic for cumulative counts.'));
  } else if (!upstreams.error) {
    upstreamSection.appendChild(el('div', 'metrics-hint', 'No upstreams registered. Caddy reports upstreams only after traffic flows through reverse_proxy.'));
  }

  body.appendChild(upstreamSection);

  // --- Per-Site Traffic ---
  const sitesSection = el('div', 'metrics-section');
  sitesSection.appendChild(el('div', 'section-title', 'Per-Site Traffic'));

  if (traffic.error && !Object.keys(traffic.sites).length) {
    const hint = el('div', 'metrics-hint');
    hint.textContent = traffic.error;
    sitesSection.appendChild(hint);
  } else if (Object.keys(traffic.sites).length === 0) {
    sitesSection.appendChild(el('div', 'metrics-hint', 'No traffic recorded yet. Metrics appear after requests flow through Caddy.'));
  } else {
    const serverDomains = traffic.server_domains || {};
    const serverListen = traffic.server_listen || {};
    const sorted = Object.entries(traffic.sites).sort((a, b) => b[1].requests - a[1].requests);
    sorted.forEach(([server, data]) => {
      const card = el('div', 'site-metric-card');

      const headerDiv = el('div', 'site-metric-header');
      const domains = serverDomains[server];
      // Server names (srv0, srv1) are assigned by the adapter in no fixed
      // order, so label them with what they actually listen on.
      const listen = serverListen[server];
      const titleText = listen && listen.length ? `${server} · ${listen.join(', ')}` : server;
      headerDiv.appendChild(el('span', 'site-metric-name', titleText));
      if (data.error_rate > 0) {
        const errBadge = el('span', data.error_rate > 5 ? 'site-metric-err high' : 'site-metric-err low');
        errBadge.textContent = data.error_rate + '% errors';
        headerDiv.appendChild(errBadge);
      }
      card.appendChild(headerDiv);

      if (domains && domains.length > 0) {
        const domainList = el('div', 'site-metric-domains');
        domainList.textContent = domains.join(', ');
        card.appendChild(domainList);
      }

      const stats = el('div', 'site-metric-stats');
      stats.appendChild(statPill('Requests', data.requests.toLocaleString(), '#4fc3f7'));
      stats.appendChild(statPill('Avg Latency', data.avg_latency_ms + ' ms', data.avg_latency_ms > 1000 ? '#ef5350' : data.avg_latency_ms > 300 ? '#ffa726' : '#66bb6a'));
      stats.appendChild(statPill('5xx Errors', data.errors.toString(), data.errors > 0 ? '#ef5350' : '#66bb6a'));
      stats.appendChild(statPill('In', formatBytes(data.bytes_in), '#90a4ae'));
      stats.appendChild(statPill('Out', formatBytes(data.bytes_out), '#90a4ae'));
      card.appendChild(stats);

      sitesSection.appendChild(card);
    });
  }

  body.appendChild(sitesSection);

  // --- By Site (access log) ---
  // Rendered into its own container so the window selector can refresh just
  // this section without refetching metrics, traffic and upstreams.
  const logStatsSection = el('div', 'metrics-section');
  logStatsSection.id = 'logstats-section';
  body.appendChild(logStatsSection);
  renderLogStats();

  // --- Editor Activity ---
  const activitySection = el('div', 'metrics-section');
  activitySection.appendChild(el('div', 'section-title', 'Editor Activity'));
  const actGrid = el('div', 'metrics-grid');
  actGrid.appendChild(metricCard('Saves Today', metrics.saves_today.toString(), '#ffa726'));
  actGrid.appendChild(metricCard('Total Logins', metrics.total_logins.toString(), '#ce93d8'));
  actGrid.appendChild(metricCard('Unique Users', metrics.unique_users.toString(), '#4fc3f7'));
  actGrid.appendChild(metricCard('Config Lines', metrics.config_lines.toString(), '#607d8b'));
  activitySection.appendChild(actGrid);
  if (metrics.last_modified) {
    activitySection.appendChild(el('div', 'metrics-footer', 'Last config change: ' + metrics.last_modified));
  }
  body.appendChild(activitySection);
}

// --- By Site, from the access log -------------------------------------------
//
// Caddy's metrics have no host label, so Per-Site Traffic above is really
// per-server. These figures come from scanning the tail of the access log,
// which is the only place each request's host is recorded.

const LOGSTATS_WINDOWS = [10, 25, 50, 100];
const LOGSTATS_WINDOW_KEY = 'logstatsWindowMb';

function logStatsWindow() {
  const saved = parseInt(localStorage.getItem(LOGSTATS_WINDOW_KEY), 10);
  return LOGSTATS_WINDOWS.includes(saved) ? saved : LOGSTATS_WINDOWS[0];
}

async function renderLogStats() {
  const section = document.getElementById('logstats-section');
  if (!section) return;  // metrics tab was re-rendered or closed mid-flight

  let stats;
  try {
    stats = await fetchJson('/api/logstats?window_mb=' + logStatsWindow());
  } catch (e) {
    if (e.status === 401) return;
    section.textContent = '';
    section.appendChild(el('div', 'section-title', 'By Site'));
    // Only this section fails; the Prometheus figures above stay rendered.
    section.appendChild(el('div', 'metrics-hint error', 'Could not read per-site log stats: ' + e.message));
    return;
  }
  if (!document.getElementById('logstats-section')) return;

  section.textContent = '';

  const header = el('div', 'section-title');
  header.style.cssText = 'display:flex;align-items:center;gap:8px';
  header.appendChild(el('span', null, 'By Site'));
  header.appendChild(logStatsWindowPicker());
  section.appendChild(header);

  if (stats.error) {
    section.appendChild(el('div', 'metrics-hint error', stats.error));
    return;
  }
  if (!stats.exists) {
    section.appendChild(el('div', 'metrics-hint',
      `No access log at ${stats.path}. See the Logs tab for the log snippet to add.`));
    return;
  }

  const sites = stats.sites || {};
  const sorted = Object.entries(sites).sort((a, b) => b[1].requests - a[1].requests);
  if (!sorted.length) {
    section.appendChild(el('div', 'metrics-hint',
      'Access log is present but has no request entries yet. Entries appear once a site importing the log snippet is hit.'));
  }

  sorted.forEach(([host, data]) => {
    const card = el('div', 'site-metric-card');

    const headerDiv = el('div', 'site-metric-header');
    headerDiv.appendChild(el('span', 'site-metric-name', host));
    if (data.error_rate > 0) {
      const badge = el('span', data.error_rate > 5 ? 'site-metric-err high' : 'site-metric-err low');
      badge.textContent = data.error_rate + '% 5xx';
      headerDiv.appendChild(badge);
    }
    // Only offer the drill-down when there is something to drill into.
    const failing = failureCount(data.status);
    if (failing > 0) {
      const toggle = el('span', 'logstats-toggle');
      toggle.textContent = `▸ ${failing.toLocaleString()} failing`;
      toggle.style.cssText = 'cursor:pointer;color:#90a4ae;font-size:10px;margin-left:auto';
      toggle.title = 'Show which paths are returning 4xx/5xx for this site.';
      headerDiv.style.cursor = 'pointer';
      headerDiv.onclick = () => toggleFailures(host, card, toggle);
      headerDiv.appendChild(toggle);
    }
    card.appendChild(headerDiv);

    const classes = data.status || {};
    const order = ['2xx', '3xx', '4xx', '5xx', 'other'];
    const breakdown = order.filter(k => classes[k]).map(k => `${k} ${classes[k].toLocaleString()}`);
    if (breakdown.length) card.appendChild(el('div', 'site-metric-domains', breakdown.join('  ·  ')));

    const stats_ = el('div', 'site-metric-stats');
    stats_.appendChild(statPill('Requests', data.requests.toLocaleString(), '#4fc3f7'));
    stats_.appendChild(statPill('Avg', data.avg_latency_ms + ' ms', latencyColor(data.avg_latency_ms)));
    stats_.appendChild(statPill('p95', data.p95_latency_ms + ' ms', latencyColor(data.p95_latency_ms)));
    stats_.appendChild(statPill('Out', formatBytes(data.bytes_out), '#90a4ae'));
    card.appendChild(stats_);

    if (data.slowest && data.slowest.uri) {
      const slowest = el('div', 'site-metric-domains');
      slowest.textContent = `slowest: ${data.slowest.ms} ms  ${data.slowest.uri}`;
      slowest.title = 'Slowest single request seen in the scanned window.';
      card.appendChild(slowest);
    }

    section.appendChild(card);
  });

  section.appendChild(logStatsFooter(stats));
}

function failureCount(classes) {
  const c = classes || {};
  return (c['4xx'] || 0) + (c['5xx'] || 0);
}

function statusColor(status) {
  return status >= 500 ? '#ef5350' : status >= 400 ? '#ffa726' : '#90a4ae';
}

// Expand one site at a time: collapsing the others keeps the panel scannable
// when several sites are failing at once.
async function toggleFailures(host, card, toggle) {
  const open = card.querySelector('.logstats-failures');
  if (open) {
    open.remove();
    toggle.textContent = toggle.textContent.replace('▾', '▸');
    return;
  }
  document.querySelectorAll('#logstats-section .logstats-failures').forEach(n => n.remove());
  document.querySelectorAll('#logstats-section .logstats-toggle').forEach(t => {
    t.textContent = t.textContent.replace('▾', '▸');
  });

  const box = el('div', 'logstats-failures');
  box.style.cssText = 'margin-top:8px;border-top:1px solid #2a2a2a;padding-top:6px';
  box.appendChild(el('div', 'metrics-hint', 'Loading...'));
  card.appendChild(box);
  toggle.textContent = toggle.textContent.replace('▸', '▾');

  let detail;
  try {
    const params = `?window_mb=${logStatsWindow()}&host=${encodeURIComponent(host)}`;
    detail = (await fetchJson('/api/logstats' + params)).detail;
  } catch (e) {
    if (e.status === 401) return;
    box.textContent = '';
    box.appendChild(el('div', 'metrics-hint error', 'Could not load failures: ' + e.message));
    return;
  }
  if (!card.contains(box)) return;  // collapsed again while the fetch was in flight

  box.textContent = '';
  const rows = (detail && detail.failures) || [];
  if (!rows.length) {
    box.appendChild(el('div', 'metrics-hint', 'No 4xx or 5xx responses in the scanned window.'));
    return;
  }
  drawFailures(box, rows, detail, FAILURE_ROWS_SHOWN);
}

// Rows arrive worst-first, and a scanned site produces a long tail of paths hit
// once. Showing all of them buries the handful that matter, so the tail is
// collapsed behind a click.
const FAILURE_ROWS_SHOWN = 15;

function drawFailures(box, rows, detail, limit) {
  box.textContent = '';
  rows.slice(0, limit).forEach(f => box.appendChild(failureRow(f)));

  const hidden = rows.length - limit;
  if (hidden > 0) {
    const tail = rows.slice(limit).reduce((n, f) => n + f.count, 0);
    const more = el('div', 'metrics-hint');
    more.textContent = `▸ ${hidden.toLocaleString()} more paths (${tail.toLocaleString()} failures) — show all`;
    more.style.cursor = 'pointer';
    more.onclick = () => drawFailures(box, rows, detail, rows.length);
    box.appendChild(more);
  }

  if (detail.capped) {
    box.appendChild(el('div', 'metrics-hint',
      `Only the most common paths are tracked. ${detail.other.toLocaleString()} further failures were to paths beyond that limit, usually a scanner walking random URLs.`));
  }
}

function failureRow(f) {
  const row = el('div', 'logstats-failure-row');
  row.style.cssText = 'display:flex;gap:10px;font-size:11px;padding:2px 0;font-family:ui-monospace,monospace';

  const code = el('span', null, String(f.status));
  code.style.cssText = `color:${statusColor(f.status)};min-width:28px`;
  row.appendChild(code);

  const count = el('span', null, '×' + f.count.toLocaleString());
  count.style.cssText = 'color:#777;min-width:48px;text-align:right';
  row.appendChild(count);

  // Long paths must not push the count off the card.
  const path = el('span', null, f.path || '(no path)');
  path.style.cssText = 'color:#ccc;overflow:hidden;text-overflow:ellipsis;white-space:nowrap';
  path.title = f.path || '(no path)';
  row.appendChild(path);

  return row;
}

function latencyColor(ms) {
  return ms > 1000 ? '#ef5350' : ms > 300 ? '#ffa726' : '#66bb6a';
}

function logStatsWindowPicker() {
  const select = document.createElement('select');
  select.id = 'logstats-window';
  select.style.cssText = 'background:#1e1e1e;color:#ccc;border:1px solid #333;border-radius:3px;font-size:10px;padding:2px 4px';
  select.title = 'How far back into the access log to scan.';
  LOGSTATS_WINDOWS.forEach(mb => {
    const opt = document.createElement('option');
    opt.value = mb;
    opt.textContent = 'last ' + mb + ' MB';
    if (mb === logStatsWindow()) opt.selected = true;
    select.appendChild(opt);
  });
  select.onchange = () => {
    localStorage.setItem(LOGSTATS_WINDOW_KEY, select.value);
    renderLogStats();
  };
  return select;
}

function logStatsFooter(stats) {
  // covered_bytes is what the numbers actually describe, which is not the same
  // as the requested window: a smaller file covers less, and the scan
  // re-anchors as the file grows, so say what was really read.
  const parts = [
    `${stats.entries.toLocaleString()} entries over ${formatBytes(stats.covered_bytes)}`,
    `log file ${formatBytes(stats.file_size)}`,
  ];
  if (stats.truncated) parts.push('older entries outside the window are not counted');
  if (stats.skipped) parts.push(`${stats.skipped.toLocaleString()} lines skipped`);
  const footer = el('div', 'metrics-footer', parts.join(' · '));
  if (stats.skipped) {
    footer.title = 'Skipped lines are entries with no request host: Caddy runtime logs sharing the file, or a log format this panel cannot parse.';
  }
  return footer;
}

function metricCard(label, value, color) {
  const card = el('div', 'metric-card');
  const lbl = el('div', 'metric-label', label);
  const val = el('div', 'metric-value');
  val.textContent = value;
  val.style.color = color;
  card.appendChild(lbl);
  card.appendChild(val);
  return card;
}

function statPill(label, value, color) {
  const pill = el('span', 'stat-pill');
  pill.appendChild(el('span', 'stat-pill-label', label));
  const val = el('span', 'stat-pill-value');
  val.textContent = value;
  val.style.color = color;
  pill.appendChild(val);
  return pill;
}
