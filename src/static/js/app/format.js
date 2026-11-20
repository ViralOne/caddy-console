// Display formatting shared by the views: times, sizes, durations, countries and
// HTTP status text. Pure functions with no DOM, so tests import this directly.

export const SLOW_MS = 2000;   // a duration or p95 at or above this is "slow"

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const pad = (n) => String(n).padStart(2, '0');
const ok = (ms) => typeof ms === 'number' && Number.isFinite(ms);
const hm = (d) => `${pad(d.getHours())}:${pad(d.getMinutes())}`;
const dayMonth = (d) => `${d.getDate()} ${MONTHS[d.getMonth()]}`;
const sameDay = (a, b) => a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();

/** Epoch seconds, epoch ms, an ISO string or a Date -> epoch ms (NaN if none of those). */
export function toMs(value) {
  if (value instanceof Date) return value.getTime();
  if (typeof value === 'number') return value < 1e12 ? value * 1000 : value;
  if (typeof value === 'string' && value) {
    // Python's isoformat() writes microseconds; keep the milliseconds every engine parses.
    return Date.parse(value.replace(/(\.\d{3})\d+/, '$1'));
  }
  return NaN;
}

export function relativeTime(value, now = Date.now()) {
  const ms = toMs(value);
  if (!ok(ms)) return '';
  const secs = Math.max(0, Math.round((now - ms) / 1000));
  if (secs < 60) return 'just now';
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.floor(mins / 60);
  const rem = mins % 60;
  if (hours < 6) return rem ? `${hours}h ${rem}m ago` : `${hours}h ago`;
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days === 1) return 'yesterday';
  if (days < 7) return `${days} days ago`;
  return dayMonth(new Date(ms));
}

export function absoluteTime(value) {
  const ms = toMs(value);
  if (!ok(ms)) return '';
  const d = new Date(ms);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${hm(d)}:${pad(d.getSeconds())}`;
}

export function clockTime(value, now = Date.now()) {
  const ms = toMs(value);
  if (!ok(ms)) return '';
  const d = new Date(ms);
  return sameDay(d, new Date(now)) ? hm(d) : `${dayMonth(d)}, ${hm(d)}`;
}

export function dayLabel(value, now = Date.now()) {
  const ms = toMs(value);
  if (!ok(ms)) return '';
  const d = new Date(ms);
  const today = new Date(now);
  const yesterday = new Date(today.getFullYear(), today.getMonth(), today.getDate() - 1);
  if (sameDay(d, today)) return `Today, ${hm(d)}`;
  if (sameDay(d, yesterday)) return `Yesterday, ${hm(d)}`;
  const year = d.getFullYear() === today.getFullYear() ? '' : ` ${d.getFullYear()}`;
  return `${dayMonth(d)}${year}, ${hm(d)}`;
}

/** "Caddyfile.20261120-142410[-N]" -> that local time, or null. */
export function backupDate(name) {
  const m = /^Caddyfile\.(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})(?:-\d+)?$/.exec(name || '');
  if (!m) return null;
  const [y, mo, d, h, mi, s] = m.slice(1).map(Number);
  return new Date(y, mo - 1, d, h, mi, s);
}

export function backupLabel(name, now = Date.now()) {
  const d = backupDate(name);
  return d ? dayLabel(d, now) : String(name || '').replace(/^Caddyfile\./, '');
}

// Cloudflare's CF-IPCountry specials, which are not ISO regions.
const COUNTRY_SPECIAL = { XX: 'Unknown country', T1: 'Tor network' };
let regionNames = null;

export function countryName(code) {
  if (!code) return '';
  const up = String(code).toUpperCase();
  if (COUNTRY_SPECIAL[up]) return COUNTRY_SPECIAL[up];
  try {
    regionNames ||= new Intl.DisplayNames(['en'], { type: 'region' });
    const name = regionNames.of(up);
    return name && name !== up ? name : up;
  } catch {
    return up;   // not a region code, or Intl without region names
  }
}

const STATUS_TEXT = {
  100: 'Continue', 101: 'Switching protocols', 200: 'OK', 201: 'Created', 202: 'Accepted',
  204: 'No content', 206: 'Partial content', 301: 'Moved permanently', 302: 'Found',
  303: 'See other', 304: 'Not modified', 307: 'Temporary redirect', 308: 'Permanent redirect',
  400: 'Bad request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not found',
  405: 'Method not allowed', 408: 'Request timeout', 409: 'Conflict', 410: 'Gone',
  413: 'Content too large', 414: 'URI too long', 415: 'Unsupported media type',
  421: 'Misdirected request', 429: 'Too many requests', 499: 'Client closed request',
  500: 'Internal server error', 501: 'Not implemented', 502: 'Bad gateway',
  503: 'Service unavailable', 504: 'Gateway timeout', 505: 'HTTP version not supported',
};
export function statusText(code) { return STATUS_TEXT[Number(code)] || ''; }
export function durationNote(status) { return Number(status) === 504 ? 'upstream timeout' : ''; }

export function formatBytes(n) {
  if (!Number.isFinite(n) || n <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${units[i]}`;
}

export function formatMs(ms) {
  if (ms == null || !Number.isFinite(ms)) return '—';
  if (ms < 1000) return `${ms < 10 ? ms.toFixed(1) : Math.round(ms)} ms`;
  const s = ms / 1000;
  return `${s >= 100 ? Math.round(s) : s.toFixed(1)} s`;
}

export function formatCount(n) {
  if (!Number.isFinite(n)) return '0';
  return n >= 10000 ? `${(n / 1000).toFixed(1)}k` : n.toLocaleString('en-US');
}

export function formatPercent(p, digits = 1) {
  return `${(Number.isFinite(p) ? p : 0).toFixed(digits)}%`;
}

/** Whole-percent change, or null when there is no meaningful baseline. */
export function percentChange(current, previous) {
  if (previous == null || !(previous > 0) || !Number.isFinite(current)) return null;
  return Math.round(((current - previous) / previous) * 100);
}

export function shortHost(host) { return String(host || '').split('.')[0]; }

/** "19 Nov, 08:10" whatever today is: for naming a backup inside a sentence. */
export function shortDateTime(value) {
  const ms = toMs(value);
  if (!ok(ms)) return '';
  const d = new Date(ms);
  return `${dayMonth(d)}, ${hm(d)}`;
}
