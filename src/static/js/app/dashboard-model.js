// The dashboard's derived state: verdict headline, figures row, config card,
// site health and tags, audit rows. Pure functions of the API payloads, so every
// wording and threshold is unit-tested without a DOM. Missing data hides a line;
// it never turns into a 0.
import {
  SLOW_MS, absoluteTime, backupDate, clockTime, formatBytes, formatCount, formatPercent,
  percentChange, relativeTime, shortDateTime, shortHost, toMs,
} from './format.js';

export const RANGE = '1h';
export const HIGH_5XX = 10;          // percent of a site's requests
export const SLOW_P95_MS = SLOW_MS;
const MIN_ERRORS = 5;                // a verdict needs more than a couple of failures
const SAME_CHANGE_MS = 15000;        // audit entry vs file mtime: save, then reload, then log

const plural = (n, one, many = one + 's') => (n === 1 ? one : many);
const text = (t) => ({ text: t });
const mono = (t) => ({ mono: t });

export function exploreHref(query) {
  const p = new URLSearchParams({ range: RANGE });
  if (query) p.set('q', query);
  return '/explore?' + p.toString();
}

/** A site's health is its upstreams'. No upstream (respond, file_server) is not "unhealthy". */
export function healthOf(host, upstreams) {
  const mine = (upstreams || []).filter(u => (u.domains || []).includes(host));
  if (!mine.length) return { state: 'none', label: 'No upstream', icon: 'status-none' };
  if (mine.some(u => u.healthy === 0)) return { state: 'down', label: 'Unhealthy', icon: 'status-down' };
  if (mine.every(u => u.healthy === 1)) return { state: 'up', label: 'Healthy', icon: 'status-ok' };
  return { state: 'unknown', label: 'Not checked', icon: 'status-unknown' };
}

export function siteTags(site) {
  const tags = [];
  if (site.error_rate >= HIGH_5XX) tags.push('high');
  if (site.p95_latency_ms >= SLOW_P95_MS) tags.push('slow');
  return tags;
}

export function totalsOf(sites) {
  const t = (sites || []).reduce((a, s) => ({
    requests: a.requests + s.requests, errors: a.errors + s.errors, bytes: a.bytes + s.bytes_out,
  }), { requests: 0, errors: 0, bytes: 0 });
  return { ...t, errorRate: t.requests ? (t.errors / t.requests) * 100 : 0 };
}

function worstErrorSite(sites) {
  return sites.filter(s => s.error_rate >= HIGH_5XX && s.errors >= MIN_ERRORS)
    .sort((a, b) => b.error_rate - a.error_rate)[0] || null;
}

function servingTitle(total) {
  if (!total) return 'No requests in the last hour';
  return total === 1 ? 'The site is serving' : `All ${total} sites are serving`;
}

export function verdict({
  sites = [], upstreams = [], upstreamsError = null, trafficError = null, loadError = null,
  configuredSites = null, status = null, now = Date.now(),
}) {
  // The last refresh failed: whatever the previous data said is no longer known.
  if (loadError) {
    return {
      severity: 'serious', sev: 'Dashboard data is out of date',
      title: 'The dashboard could not refresh',
      body: [text('The last request to the console failed: '), mono(String(loadError)),
        text('. The figures below are from the last successful refresh.')],
      primary: null, secondary: null,
    };
  }

  // Any error from /api/upstreams (unreachable, timed out, non-200) means Caddy's
  // admin API is not answering; an empty upstream list must not read as "all fine".
  if (upstreamsError) {
    return {
      severity: 'critical', sev: "Critical, Caddy's admin API is not answering",
      title: 'Caddy is not answering the console',
      body: [text("Asking Caddy's admin API for upstream health failed: "), mono(String(upstreamsError)),
        text('. Health, the live config and Save & Reload may be unavailable. Check that the Caddy container is running.')],
      primary: { label: 'Open Explore', href: exploreHref('') }, secondary: null,
    };
  }

  const down = upstreams.filter(u => u.healthy === 0);
  if (down.length) {
    const hosts = [...new Set(down.flatMap(u => u.domains || []))];
    const first = down[0];
    const title = hosts.length === 1 ? `${hosts[0]} is down`
      : hosts.length > 1 ? `${hosts.length} sites are down` : `Upstream ${first.address} is down`;
    const body = [text("Caddy's health check to "), mono(first.address),
      text(first.unhealthy_since ? ` has failed since ${clockTime(first.unhealthy_since, now)}` : ' is failing')];
    if (down.length > 1) body.push(text(` (and ${down.length - 1} more ${plural(down.length - 1, 'upstream')})`));
    body.push(text('.'));
    const others = (configuredSites ?? sites.length) - hosts.length;
    const worst = worstErrorSite(sites.filter(s => !hosts.includes(s.host)));
    if (others > 0) body.push(text(` The other ${others} ${plural(others, 'site')} ${others === 1 ? 'is' : 'are'} serving`));
    if (worst) body.push(text(`${others > 0 ? ';' : ''} ${worst.host} is answering ${formatPercent(worst.error_rate, 0)} of requests with 5xx`));
    if (others > 0 || worst) body.push(text('.'));
    return {
      severity: 'critical', sev: `Critical, ${down.length} unhealthy ${plural(down.length, 'upstream')}`, title, body,
      primary: { label: 'Investigate in Explore', href: exploreHref(hosts[0] ? `host:${hosts[0]}` : 'status:5xx') },
      secondary: hosts[0] ? { label: `Open ${hosts[0]} block`, host: hosts[0] } : null,
    };
  }

  if (status && status.config_valid === false && status.config_check_level !== 'unavailable') {
    return {
      severity: 'serious', sev: 'Config check failed', title: 'The Caddyfile on disk does not pass Caddy’s check',
      body: [text(status.config_check_message || 'Caddy rejected the file on disk.')],
      primary: { label: 'Open the Editor', href: '/editor' }, secondary: null,
    };
  }

  const worst = worstErrorSite(sites);
  if (worst) {
    return {
      severity: 'warn', sev: 'Warning, high 5xx rate',
      title: `${worst.host} is failing ${formatPercent(worst.error_rate, 0)} of requests`,
      body: [text(`${formatCount(worst.errors)} of ${formatCount(worst.requests)} requests in the last hour were answered with 5xx.`)],
      primary: { label: 'Investigate in Explore', href: exploreHref(`host:${worst.host} status:5xx`) },
      secondary: { label: `Open ${worst.host} block`, host: worst.host },
    };
  }

  // Health comes from Caddy's metrics. With upstreams but no health for any of
  // them, "serving" would be a guess.
  const unknown = upstreams.filter(u => u.healthy !== 0 && u.healthy !== 1);
  if (upstreams.length && (trafficError || unknown.length === upstreams.length)) {
    const body = trafficError
      ? [text("Caddy's metrics did not answer ("), mono(String(trafficError)), text('), so the console cannot tell whether upstreams are healthy.')]
      : [text('Caddy reported no health for any upstream, so the console cannot tell whether they are up.')];
    body.push(text(' Upstream health is read from Caddy\'s metrics: enable them with '), mono('servers { metrics }'),
      text(' in the global options, and add '), mono('health_uri'), text(' to a reverse_proxy for active checks.'));
    return {
      severity: 'warn', sev: 'Warning, no health data', title: 'Upstream health unavailable', body,
      primary: { label: 'Open Explore', href: exploreHref('') }, secondary: null,
    };
  }

  const total = configuredSites ?? sites.length;
  if (unknown.length) {
    return {
      severity: 'ok', sev: null, title: total ? `No problems found on ${total} ${plural(total, 'site')}` : servingTitle(total),
      body: [text(`Caddy reported no health for ${unknown.length} ${plural(unknown.length, 'upstream')}.`)],
      primary: null, secondary: null,
    };
  }
  return { severity: 'ok', sev: null, title: servingTitle(total), body: [], primary: null, secondary: null };
}

export function kpis({ sites = [], previousTotal = null, configuredSites = null, dropped = 0 }) {
  const tot = totalsOf(sites);
  // Events dropped at the memory cap shrink one window and not the other, so
  // the comparison would be wrong; leave it out rather than mislead.
  const change = dropped > 0 ? null : percentChange(tot.requests, previousTotal);
  const byErrors = [...sites].sort((a, b) => b.errors - a.errors)[0];
  const byBytes = [...sites].sort((a, b) => b.bytes_out - a.bytes_out)[0];
  const mostly = byErrors && tot.errors && byErrors.errors / tot.errors >= 0.5 ? `, mostly ${shortHost(byErrors.host)}` : '';
  // More hosts with traffic than configured sites (wildcards, removed sites,
  // stray Host headers) would read "7 of 4": leave the comparison out.
  const known = configuredSites != null && sites.length <= configuredSites;
  const missing = known ? configuredSites - sites.length : 0;
  return [
    {
      key: 'requests', label: 'Requests, last hour', value: formatCount(tot.requests), of: null,
      sub: change == null ? null : change === 0 ? 'Same as the previous hour' : `${change > 0 ? '+' : '−'}${Math.abs(change)}% vs previous hour`,
      bad: false, href: exploreHref(''),
    },
    {
      key: 'errors', label: '5xx rate', value: formatPercent(tot.errorRate, 1), of: null,
      sub: tot.errors ? `${formatCount(tot.errors)} ${plural(tot.errors, 'error')}${mostly}` : 'No server errors',
      bad: tot.errors > 0, href: exploreHref('status:5xx'),
    },
    {
      key: 'sites', label: 'Sites with traffic', value: String(sites.length),
      of: known ? `of ${configuredSites}` : null,
      sub: !known ? null : missing <= 0 ? 'all configured sites' : `${missing} configured ${plural(missing, 'site')} without traffic`,
      bad: false, href: exploreHref(''),
    },
    {
      key: 'bytes', label: 'Bandwidth out', value: formatBytes(tot.bytes), of: null,
      sub: sites.length > 1 && tot.bytes > 0 ? `${byBytes.host} is ${Math.round((byBytes.bytes_out / tot.bytes) * 100)}%` : null,
      bad: false, href: exploreHref(sites.length > 1 && byBytes ? `host:${byBytes.host}` : ''),
    },
  ];
}

export function configCard(status, now = Date.now()) {
  if (!status) return null;
  const level = status.config_check_level;
  const state = status.config_valid === true ? 'ok' : level === 'unavailable' ? 'unknown' : 'bad';
  const label = { ok: 'Config valid', unknown: 'Config not checked', bad: 'Config check failed' }[state];
  const checks = state === 'ok' ? (level === 'adapted' ? 'Syntax and modules OK' : 'Passed local validation')
    : (status.config_check_message || null);
  const version = String(status.caddy_version || '').split(/\s+/)[0];
  const mtime = toMs(status.last_modified);
  const lc = status.last_change || null;
  // Attribute the change only if the audit entry is this file version's; an
  // edit made behind the console's back must not borrow the last user's name.
  const by = lc && Number.isFinite(mtime) && Math.abs(toMs(lc.ts) - mtime) <= SAME_CHANGE_MS ? lc.user : null;
  return {
    state, label, checks,
    version: version && version !== 'unknown' ? version : null,
    changed: Number.isFinite(mtime) ? { rel: relativeTime(mtime, now), abs: absoluteTime(mtime), by } : null,
    path: status.config_path || null,
  };
}

const VERBS = {
  login: ['Signed in', 'key'], logout: ['Signed out', 'logout'], login_denied: ['Sign-in denied', 'status-down'],
  save_reload: ['Saved', 'save'], save_no_reload: ['Saved, not reloaded', 'warning'],
  save_reload_unknown: ['Saved, reload unconfirmed', 'warning'], save_reload_failed: ['Rejected by Caddy', 'status-down'],
  save_failed: ['Save rejected', 'status-down'], save_conflict: ['Save blocked', 'warning'],
  save_write_failed: ['Write failed', 'status-down'], save_rollback_failed: ['Rollback failed', 'status-down'],
  restore_reload: ['Restored', 'restore'], restore_no_reload: ['Restored, not reloaded', 'warning'],
  restore_reload_unknown: ['Restored, reload unconfirmed', 'warning'], restore_reload_failed: ['Restore rejected by Caddy', 'status-down'],
  restore_failed: ['Restore rejected', 'status-down'], restore_write_failed: ['Write failed', 'status-down'],
  restore_rollback_failed: ['Rollback failed', 'status-down'], backup_deleted: ['Deleted backup', 'close'],
};

const backupWhen = (name) => { const d = backupDate(name); return d ? `Backup from ${shortDateTime(d)}` : ''; };

function detailOf(action, detail) {
  const from = /(?:^|,\s*)from=(Caddyfile\.[^,\s]+)/.exec(detail);
  if (from) return backupWhen(from[1]) || detail;
  if (action === 'backup_deleted') return backupWhen(detail) || detail;
  if (action === 'save_conflict') return 'The file had changed on disk';
  if (/^backup=[^,]*$/.test(detail)) return '';   // a plain save: the backup's name is noise here
  return detail;
}

export function auditRow(entry, now = Date.now()) {
  const action = String(entry.action || '');
  const [verb, icon] = VERBS[action]
    || [action ? action.charAt(0).toUpperCase() + action.slice(1).replace(/_/g, ' ') : 'Activity', 'info'];
  return {
    verb, icon, user: entry.user || '',
    detail: detailOf(action, String(entry.detail || '')),
    rel: relativeTime(entry.time, now), abs: absoluteTime(entry.time),
  };
}
