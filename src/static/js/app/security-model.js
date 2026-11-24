// Wording and state for the Security view and the IP popover, kept DOM-free so
// node can test it. Everything returned is plain text; callers render it as
// text children, never as HTML.

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

const SITE = {
  enforced: ['Protected', 'ok'],
  enforced_pre_handler: ['Protected, pre-handler present', 'warn'],
  imported_empty: ['Imported, no active bans', 'ok'],
  not_imported: ['Not enforced', 'none'],
  not_loaded: ['Not loaded yet', 'none'],
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
  if (status.sources?.manual?.hold) {
    return { tone: 'warn', title: 'Policy differs from state', body: 'The ban file was changed outside the console. Fix the records, then Re-apply.' };
  }
  if ((status.sites || []).some(s => s.status === 'management_imported')) {
    return { tone: 'crit', title: 'Console site imports the ban list: lockout risk', body: 'Remove the import line from the console site in the editor, then Save & Reload.' };
  }
  const n = (status.sites || []).filter(s => ['enforced', 'enforced_pre_handler', 'imported_empty'].includes(s.status)).length;
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
