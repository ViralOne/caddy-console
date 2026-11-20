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
export const WARN_5XX = 1;           // percent of all requests: the 5xx figure turns warn
export const CRIT_5XX = 5;           // ... and crit
export const DOWN_LIST_MAX = 5;      // down sites listed in the verdict before "+N more"
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

/** A site's health is its upstreams'. No upstream (respond, file_server) is not "unhealthy".
 *  upstreams === null means the list could not be loaded, so nothing is known. */
export function healthOf(host, upstreams) {
  if (upstreams === null) return { state: 'unknown', label: 'Not checked', icon: 'status-unknown' };
  const mine = (upstreams || []).filter(u => (u.domains || []).includes(host));
  if (!mine.length) return { state: 'none', label: 'No upstream', icon: 'status-none' };
  if (mine.some(u => u.healthy === 0)) return { state: 'down', label: 'Unhealthy', icon: 'status-down' };
  // Caddy reports healthy=1 for an upstream it never checks. Only rows that say
  // so (both flags present and false) count; older payloads without the flags keep
  // the reported health.
  const unchecked = (u) => !u.active_health && !u.passive_health && ('active_health' in u || 'passive_health' in u);
  if (mine.every(unchecked)) return { state: 'unchecked', label: 'Not checked', icon: 'status-unknown' };
  if (mine.every(u => u.healthy === 1)) return { state: 'up', label: 'Healthy', icon: 'status-ok' };
  return { state: 'unknown', label: 'Not checked', icon: 'status-unknown' };
}

export function siteTags(site) {
  const tags = [];
  if (site.error_rate >= HIGH_5XX) tags.push('high');
  if (site.p95_latency_ms >= SLOW_P95_MS) tags.push('slow');
  return tags;
}

const rank = (health, tags) => (health.state === 'down' ? 0 : tags.includes('high') ? 1 : tags.includes('slow') ? 2 : 3);

/** The sites table, problems first: down, then high 5xx, then slow, then the rest,
 *  each group by requests (desc). share is requests / the busiest site's requests;
 *  tone is the row's colour (sparkline): crit when down, warn when high 5xx. */
export function siteRows(sites, upstreams) {
  const list = sites || [];
  const max = Math.max(0, ...list.map(s => s.requests || 0));
  return list.map((site) => {
    const health = healthOf(site.host, upstreams);
    const tags = siteTags(site);
    return {
      site, health, tags, rank: rank(health, tags),
      share: max ? (site.requests || 0) / max : 0,
      tone: health.state === 'down' ? 'crit' : tags.includes('high') ? 'warn' : null,
    };
  }).sort((a, b) => a.rank - b.rank || b.site.requests - a.site.requests);
}

/** Requests over time for the whole server: every site's series summed point by point. */
export function sumSeries(sites) {
  const out = [];
  for (const s of sites || []) {
    (s.series || []).forEach((v, i) => { out[i] = (out[i] || 0) + (Number(v) || 0); });
  }
  return Array.from(out, v => v || 0);
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
    // Several sites down: list each one (earliest failure first) instead of one sentence.
    if (hosts.length > 1) {
      const earliest = (u) => (u.unhealthy_since == null ? Infinity : toMs(u.unhealthy_since));
      const rows = hosts.map((host) => {
        const u = down.filter(x => (x.domains || []).includes(host)).sort((a, b) => earliest(a) - earliest(b))[0];
        return { host, address: u.address, at: earliest(u),
          since: u.unhealthy_since ? `failed since ${clockTime(u.unhealthy_since, now)}` : 'failing' };
      }).sort((a, b) => a.at - b.at);
      const more = Math.max(0, rows.length - DOWN_LIST_MAX);
      const worstOther = worstErrorSite(sites.filter(s => !hosts.includes(s.host)));
      const tail = [];
      if (others > 0) tail.push(text(`The other ${others} ${plural(others, 'site')} ${others === 1 ? 'is' : 'are'} serving`));
      if (worstOther) tail.push(text(`${others > 0 ? ';' : ''} ${worstOther.host} is answering ${formatPercent(worstOther.error_rate, 0)} of requests with 5xx`));
      if (tail.length) tail.push(text('.'));
      return {
        severity: 'critical', sev: `Critical, ${down.length} unhealthy ${plural(down.length, 'upstream')}`,
        title: `${hosts.length} sites are down`, body: tail,
        down: {
          items: rows.slice(0, DOWN_LIST_MAX).map(({ host, address, since }) => ({ host, address, since })),
          more, moreText: more ? `+${more} more` : null,
        },
        primary: { label: 'Investigate in Explore', href: exploreHref(rows.map(r => `host:${r.host}`).join(' ')) },
        secondary: null,
      };
    }
    const worst = worstErrorSite(sites.filter(s => !hosts.includes(s.host)));
    if (others > 0) body.push(text(` The other ${others} ${plural(others, 'site')} ${others === 1 ? 'is' : 'are'} serving`));
    if (worst) body.push(text(`${others > 0 ? ';' : ''} ${worst.host} is answering ${formatPercent(worst.error_rate, 0)} of requests with 5xx`));
    if (others > 0 || worst) body.push(text('.'));
    return {
      severity: 'critical', sev: `Critical, ${down.length} unhealthy ${plural(down.length, 'upstream')}`, title, body,
      primary: { label: 'Investigate in Explore', href: exploreHref(hosts[0] ? `host:${hosts[0]}` : 'status:5xx') },
      secondary: hosts[0] ? { label: `Open ${hosts[0]} block`, host: hosts[0] } : null,
      down: null,
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
  const shareOk = sites.length > 1 && tot.bytes > 0;
  const sharePct = shareOk ? Math.round((byBytes.bytes_out / tot.bytes) * 100) : null;
  const missing = known ? configuredSites - sites.length : 0;
  return [
    {
      key: 'requests', label: 'Requests, last hour', value: formatCount(tot.requests), of: null,
      sub: change == null ? null : change === 0 ? 'Same as the previous hour' : `${change > 0 ? '+' : '−'}${Math.abs(change)}% vs previous hour`,
      bad: false, href: exploreHref(''), spark: sumSeries(sites),
    },
    {
      key: 'errors', label: '5xx rate', value: formatPercent(tot.errorRate, 1), of: null,
      sub: tot.errors ? `${formatCount(tot.errors)} ${plural(tot.errors, 'error')}${mostly}` : 'No server errors',
      bad: tot.errors > 0, href: exploreHref('status:5xx'),
      level: tot.errorRate >= CRIT_5XX ? 'crit' : tot.errorRate >= WARN_5XX ? 'warn' : null,
    },
    {
      key: 'sites', label: 'Sites with traffic', value: String(sites.length),
      of: known ? `of ${configuredSites}` : null,
      sub: !known ? null : missing <= 0 ? 'all configured sites' : `${missing} configured ${plural(missing, 'site')} without traffic`,
      bad: false, href: exploreHref(''),
    },
    {
      // Only sites that import access_log are counted, and only response bodies.
      key: 'bytes', label: 'Sent to visitors, last hour', value: formatBytes(tot.bytes), of: null,
      title: 'Response bodies Caddy sent for logged requests (sites that import access_log)',
      // sub is the older wording, kept for callers; the tile shows share instead.
      sub: shareOk ? `${byBytes.host} is ${sharePct}%` : null,
      share: shareOk ? { text: `${sharePct}% from ${byBytes.host}`, pct: sharePct } : null,
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
  // Prefer the epoch: last_modified is the server's local time without an offset.
  const mtime = toMs(status.last_modified_ts ?? status.last_modified);
  const lc = status.last_change || null;
  // Attribute the change only if the audit entry is this file version's; an
  // edit made behind the console's back must not borrow the last user's name.
  const by = lc && Number.isFinite(mtime) && Math.abs(toMs(lc.ts) - mtime) <= SAME_CHANGE_MS ? lc.user : null;
  return {
    state, label, checks, word: { ok: 'Valid', unknown: 'Not checked', bad: 'Check failed' }[state],
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
    rel: relativeTime(entry.ts ?? entry.time, now), abs: absoluteTime(entry.ts ?? entry.time),
  };
}
