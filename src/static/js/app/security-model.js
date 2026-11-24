// Wording and state for the Security view and the IP popover, kept DOM-free so
// node can test it. Everything returned is plain text; callers render it as
// text children, never as HTML.

import { absoluteTime, relativeTime } from './format.js';

export const DURATIONS = [
  { id: '4h', label: '4 hours' },
  { id: '24h', label: '24 hours' },
  { id: '7d', label: '7 days' },
  { id: 'permanent', label: 'Permanent' },
];
export const REASON_MAX = 500;

const PROTECTED = {
  loopback: 'loopback', private: 'private network', link_local: 'link-local', cgnat: 'carrier-grade NAT',
  ula: 'IPv6 unique local', special: 'reserved or multicast', docker: 'Docker network', never: 'BANS_NEVER',
  operator: 'your verified console address', profile: 'client-IP profile',
};
export const protectedLabel = (category) => PROTECTED[category] || 'protected range';
export const durationLabel = (id) => (DURATIONS.find(d => d.id === id) || {}).label || '';

/** A table time cell: relative text, absolute time for the title tooltip (as the dashboard does). */
export function createdCell(value, now = Date.now()) {
  return { text: relativeTime(value, now), title: absoluteTime(value) };
}

export function expiryLabel(expiresAt, now = Date.now()) {
  if (!expiresAt) return 'Never expires';
  const t = Date.parse(expiresAt);
  if (!Number.isFinite(t)) return '';
  const left = t - now;
  if (left <= 0) return 'Expired';
  const min = Math.round(left / 60000);
  if (min < 60) return `Expires in ${Math.max(1, min)} min`;
  const hours = Math.round(min / 60);
  if (hours < 48) return `Expires in ${hours} h`;
  return `Expires in ${Math.round(hours / 24)} days`;
}

export function banPayload({ value, duration, reason } = {}) {
  const v = String(value ?? '').trim();
  if (!v) throw new Error('Enter an IP address or CIDR range.');
  if (!DURATIONS.some(d => d.id === duration)) throw new Error('Choose a duration.');
  const r = String(reason ?? '');
  if ([...r].length > REASON_MAX) throw new Error(`Keep the reason to ${REASON_MAX} characters.`);
  return { value: v, duration, reason: r };
}

export function errorMessage(body, status) {
  if (body && typeof body.message === 'string' && body.message) return body.message;
  if (body && typeof body.error === 'string' && body.error) return body.error;
  return status ? `Request failed (HTTP ${status}).` : 'Request failed.';
}

export function outcomeText(body, verb) {
  const value = body?.record?.value || body?.value || '';
  const done = `${verb === 'unban' ? 'Unbanned' : 'Banned'} ${value}`.trim();
  const covered = body?.still_covered_by || [];
  const still = verb === 'unban' && covered.length ? ` It is still banned by ${covered.join(', ')}.` : '';
  switch (body?.enforcement) {
    case 'enforced': return { kind: 'ok', text: `${done}. Caddy reloaded.${still}` };
    case 'not_enabled': return { kind: 'info', text: `${done}. No site imports the ban list yet, so it is not enforced.${still}` };
    case 'held': return { kind: 'warn', text: `${done}, but the ban file differs from the stored state. Re-apply in Security.` };
    case 'unchanged': return { kind: 'ok', text: `${done}. The effective ban list did not change.${still}` };
    default: return { kind: 'warn', text: `${done}. ${body?.message || ''}`.trim() };
  }
}

/** What the IP popover can offer for one address, from GET /api/bans?covering=. */
export function banState(lookup) {
  const records = lookup?.records || [];
  const exact = lookup?.exact_ids || [];
  const coveredBy = [...new Set(records.filter(r => !exact.includes(r.id)).map(r => r.value))];
  const prot = lookup?.protected || null;
  return {
    banned: records.length > 0,
    exact,
    coveredBy,
    coveredText: coveredBy.length ? `${exact.length ? 'Also covered by' : 'Banned by'} ${coveredBy.join(', ')}` : '',
    protectedText: prot ? `Protected (${protectedLabel(prot)}), cannot be banned` : '',
    canBan: !prot && exact.length === 0,
    canUnban: exact.length > 0,
  };
}

export const SOURCE_LABELS = { manual: 'Manual', crowdsec: 'CrowdSec' };
export const LIST_ORIGIN_WARNING = 'CAPI and list origins can hold tens of thousands of decisions. Stock Caddy file mode has a finite matcher budget (BANS_MAX); prefer plugin mode for them once it is available.';

const TONE_RANK = { none: 0, ok: 1, warn: 2, crit: 3 };
const LAPI_STATES = {
  ok: ['Connected to CrowdSec', 'ok'],
  starting: ['Starting', 'none'],
  unreachable: ['CrowdSec unreachable, last synced list kept', 'warn'],
  auth_failed: ['CrowdSec refused the bouncer key', 'crit'],
  malformed: ['CrowdSec sent an unusable response', 'warn'],
  missing_key: ['No bouncer key configured', 'crit'],
};
const APPLY_STATES = {
  ok: ['', 'ok'],
  pending: ['Waiting for the first sync', 'none'],
  capacity_exceeded: ['Over capacity: automatic apply paused', 'crit'],
  held: ['CrowdSec file differs from state: sync paused', 'warn'],
  degraded: ['Ban state needs attention: sync paused', 'crit'],
  failed: ['Applying CrowdSec decisions failed', 'crit'],
};

export function crowdsecState(src, now = Date.now()) {
  if (!src?.enabled) {
    return { tone: 'none', title: 'CrowdSec is not configured', detail: 'Stored CrowdSec decisions stay enforced until they expire or are reset. Start the docker-compose.crowdsec.yaml overlay to sync again.' };
  }
  const s = src.sync;
  if (!s) return { tone: 'warn', title: 'No CrowdSec sync report yet', detail: 'No console worker has polled CrowdSec yet. If this lasts, check the console logs.' };
  if (src.stale) {
    return { tone: 'warn', title: 'CrowdSec sync report is out of date', detail: `Last report ${relativeTime(s.updated_at, now) || 'unknown'}; no worker is polling CrowdSec right now.` };
  }
  const [lapiTitle, lapiTone] = LAPI_STATES[s.lapi_state] || ['Unknown CrowdSec state', 'warn'];
  const [applyTitle, applyTone] = APPLY_STATES[s.apply_state] || APPLY_STATES.failed;
  const tone = TONE_RANK[applyTone] > TONE_RANK[lapiTone] ? applyTone : lapiTone;
  const n = Number(s.decisions) || 0;
  const noun = n === 1 ? 'decision' : 'decisions';
  const applying = s.pending_apply === true && s.apply_state === 'ok';
  const synced = applying ? `${n} ${noun} synced, applying…` : `${n} active ${noun} synced`;
  const title = s.lapi_state !== 'ok' ? lapiTitle : (applyTitle || synced);
  const last = s.last_success_at ? `Last successful poll ${relativeTime(s.last_success_at, now)}.` : '';
  const wait = applying && s.lapi_state === 'ok'
    ? `New decisions are written to the CrowdSec file within BANS_SYNC_INTERVAL (${Number(s.sync_interval) || 30} s).` : '';
  const detail = [s.lapi_state !== 'ok' ? s.lapi_message : '', s.apply_state !== 'ok' ? s.apply_message : '', wait, last]
    .filter(Boolean).join(' ');
  return { tone, title, detail };
}

export function syncTimes(sync, now = Date.now()) {
  return [['Last snapshot', sync?.last_snapshot_at], ['Last successful poll', sync?.last_success_at], ['Last apply', sync?.last_apply_at]]
    .map(([label, at]) => ({ label, text: at ? relativeTime(at, now) : 'Never', title: at ? absoluteTime(at) : '' }));
}

const IGNORED = {
  not_ban: 'Not a ban (captcha or another remediation)', scope: 'Scope other than Ip or Range',
  origin: 'Origin not in CROWDSEC_ORIGINS', expired: 'Already expired', invalid_value: 'Invalid address',
  too_wide: 'Range wider than /16 (IPv4) or /48 (IPv6)',
};

export function ignoredRows(ignored) {
  return Object.entries(ignored || {}).filter(([, n]) => Number(n) > 0)
    .map(([reason, count]) => ({
      reason, count: Number(count),
      label: reason.startsWith('protected:') ? `Protected (${protectedLabel(reason.slice('protected:'.length))})` : (IGNORED[reason] || reason),
    }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
}

/** Synced decisions per CrowdSec origin, e.g. "crowdsec 5, cscli 1". */
export function originCountsText(sync) {
  return Object.entries(sync?.by_origin || {}).filter(([, n]) => Number(n) > 0)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([origin, n]) => `${origin} ${n}`).join(', ');
}

/** Copy-only text; the id is checked so nothing else can ride along. */
export function cscliDeleteCommand(record) {
  const id = String(record?.source_id ?? '');
  return /^[0-9]{1,20}$/.test(id) ? `cscli decisions delete --id ${id}` : '';
}

export function capacityText(limits) {
  const by = Object.entries(limits?.by_source || {});
  const name = (n) => (n === 'manual' ? 'manual' : SOURCE_LABELS[n] || n);
  const parts = by.length > 1 ? ` (${by.map(([n, c]) => `${name(n)} ${c}`).join(', ')})` : '';
  return `${limits?.used ?? 0} of ${limits?.max_prefixes ?? 0} prefixes rendered${parts}.`;
}

const SITE = {
  enforced: ['Protected', 'ok'],
  enforced_pre_handler: ['Protected, pre-handler present', 'warn'],
  imported_empty: ['Imported, no active bans', 'ok'],
  not_imported: ['Not enforced', 'none'],
  not_loaded: ['Not loaded yet', 'none'],
  caddy_unreachable: ['Unknown while Caddy is unreachable', 'warn'],
  unknown: ['Enforcement not verified', 'warn'],
  management: ['Console site, never banned', 'none'],
  management_imported: ['Console site imports the ban list: lockout risk', 'crit'],
};

export function siteStatus(site) {
  const [label, tone] = SITE[site.status] || ['Unknown', 'warn'];
  const detail = {
    enforced_pre_handler: `These run before the ban check: ${(site.pre_handlers || []).join(', ')}. They do not serve the application, but they may redirect or contact an auth service first.`,
    not_imported: 'This site does not import the ban list.',
    not_loaded: 'Save & Reload to load this site into Caddy.',
    caddy_unreachable: 'The Caddy admin API did not answer, so whether this site enforces the ban list cannot be checked. The import line on disk is shown as it is.',
    management: 'The console is excluded so a ban cannot lock you out.',
    management_imported: 'A ban that matches your address would block the console itself. Remove the import line from this site in the editor, then Save & Reload.',
  }[site.status] || site.detail || '';
  return { label, tone, detail };
}

export function siteActions(site) {
  if (['enforced', 'enforced_pre_handler', 'imported_empty', 'management', 'management_imported'].includes(site.status)) return [];
  if (site.import?.present) return [];
  return site.source === 'external' ? ['copy'] : ['insert', 'copy'];
}

const RELOAD_UNKNOWN = ['live_mismatch', 'caddy_unreachable'];

const policiesOf = (site) => Object.values(site.policies || { manual: site });

function baseState(status, recordCount) {
  if (!status) return { tone: 'none', title: 'Loading…', body: '' };
  if (!status.available) return { tone: 'crit', title: 'Unavailable, not enforced', body: status.unavailable?.message || '' };
  const d = status.degraded;
  if (d && (RELOAD_UNKNOWN.includes(d.reason) || ['reload_unknown', 'reload_failed'].includes(d.phase))) {
    return { tone: 'crit', title: 'Reload state unknown', body: d.message || '' };
  }
  if (d) return { tone: 'crit', title: 'Degraded', body: d.message || '' };
  // The per-site statuses are proven from the running config; with no admin API
  // there is no such proof, so they must not be summarised as "Enforced".
  if (status.caddy && status.caddy.reachable === false) {
    return { tone: 'crit', title: 'Caddy unreachable, enforcement unknown', body: status.caddy.message || 'The Caddy admin API did not answer, so the running configuration could not be checked.' };
  }
  const held = Object.entries(status.sources || {}).filter(([, s]) => s?.hold).map(([n]) => SOURCE_LABELS[n] || n);
  if (held.length) {
    return { tone: 'warn', title: 'Policy differs from state', body: `The ${held.join(' and ')} ban file was changed outside the console. Fix the records, then Re-apply.` };
  }
  if ((status.sites || []).some(s => policiesOf(s).some(p => p.status === 'management_imported'))) {
    return { tone: 'crit', title: 'Console site imports the ban list: lockout risk', body: 'Remove the import line from the console site in the editor, then Save & Reload.' };
  }
  const cs = status.sources?.crowdsec;
  if (cs?.enabled && crowdsecState(cs).tone === 'crit') {
    return { tone: 'warn', title: 'CrowdSec sync needs attention', body: crowdsecState(cs).title };
  }
  const ENFORCING = ['enforced', 'enforced_pre_handler', 'imported_empty'];
  const n = (status.sites || []).filter(s => policiesOf(s).some(p => ENFORCING.includes(p.status))).length;
  if (n) return { tone: 'ok', title: `Enforced on ${n} ${n === 1 ? 'site' : 'sites'}`, body: '' };
  if (recordCount > 0) return { tone: 'warn', title: 'Stored but not imported', body: 'No site imports the ban list, so these bans are not enforced yet.' };
  return { tone: 'none', title: 'No site imports the ban list', body: 'Add the import line to a site to enforce bans there.' };
}

// Tones for which enforcement cannot be confirmed, so the operator is pointed at
// recovery (spec 1.8) even when the console has no recovery action to offer.
const NEEDS_RECOVERY_HINT = new Set([
  'Unavailable, not enforced', 'Reload state unknown', 'Degraded', 'Caddy unreachable, enforcement unknown',
]);

/** `stale` is true when the latest refresh failed: the data is the last known
 * good one, so it must never read as a current "all enforced". */
export function overallState(status, recordCount = 0, { stale = false } = {}) {
  const v = baseState(status, recordCount);
  const recoveryHint = NEEDS_RECOVERY_HINT.has(v.title);
  if (stale && status && (v.tone === 'ok' || v.tone === 'none')) {
    return { tone: 'warn', title: 'Status may be out of date', body: `Last known: ${v.title}.`, recoveryHint };
  }
  return { ...v, recoveryHint };
}

export const staleNotice = (loadedAt, format = (t) => new Date(t).toISOString()) =>
  `Could not refresh security status${loadedAt ? ` \u2014 last known state from ${format(loadedAt)}` : ''}.`;

export const HOST_RECOVERY_URL = 'https://github.com/ViralOne/caddy-console/blob/master/docs/security.md#host-recovery';

export const recoveryActionLabel = (action) => ({
  use_candidate: 'Keep the new files and reload',
  use_previous: 'Restore the previous files and reload',
  restore_backup: 'Restore this backup',
}[action] || action);
