// Tests for src/static/js/app/security-model.js, plus a scan that no Security
// file writes HTML. Run with: node tests/security-model.test.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const APP = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app');
const M = await import(path.join(APP, 'security-model.js'));

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };
const NOW = Date.parse('2026-11-23T20:00:00Z');

console.log('\n--- durations and expiry ---');
check('durations are exactly the four spec values', () =>
  assert.deepEqual(M.DURATIONS.map(d => d.id), ['4h', '24h', '7d', 'permanent']));
check('expiry labels', () => {
  assert.equal(M.expiryLabel(null, NOW), 'Never expires');
  assert.equal(M.expiryLabel('2026-11-23T19:00:00Z', NOW), 'Expired');
  assert.equal(M.expiryLabel('2026-11-23T20:30:00Z', NOW), 'Expires in 30 min');
  assert.equal(M.expiryLabel('2026-11-24T01:00:00Z', NOW), 'Expires in 5 h');
  assert.equal(M.expiryLabel('2026-11-26T20:00:00Z', NOW), 'Expires in 3 days');
  assert.equal(M.expiryLabel('garbage', NOW), '');
});

console.log('\n--- input and errors ---');
check('banPayload trims and validates', () => {
  assert.deepEqual(M.banPayload({ value: ' 203.0.113.7 ', duration: '4h', reason: '' }),
    { value: '203.0.113.7', duration: '4h', reason: '' });
  assert.throws(() => M.banPayload({ value: ' ', duration: '4h' }), /IP address or CIDR/);
  assert.throws(() => M.banPayload({ value: '203.0.113.7', duration: '1h' }), /duration/);
  assert.equal(M.banPayload({ value: 'x', duration: '7d', reason: '😀'.repeat(500) }).reason.length, 1000);
  assert.throws(() => M.banPayload({ value: 'x', duration: '7d', reason: '😀'.repeat(501) }), /500/);
});
check('errorMessage returns plain text unchanged', () => {
  assert.equal(M.errorMessage({ message: '<img src=x onerror=alert(1)>' }, 400), '<img src=x onerror=alert(1)>');
  assert.equal(M.errorMessage({ error: 'csrf token missing or invalid' }, 403), 'csrf token missing or invalid');
  assert.equal(M.errorMessage(null, 502), 'Request failed (HTTP 502).');
});
check('outcome wording follows enforcement', () => {
  assert.deepEqual(M.outcomeText({ enforcement: 'enforced', record: { value: '203.0.113.7' } }, 'ban'),
    { kind: 'ok', text: 'Banned 203.0.113.7. Caddy reloaded.' });
  assert.equal(M.outcomeText({ enforcement: 'not_enabled', record: { value: 'x' } }, 'ban').kind, 'info');
  assert.equal(M.outcomeText({ enforcement: 'held', record: { value: 'x' } }, 'ban').kind, 'warn');
  assert.match(M.outcomeText({ enforcement: 'enforced', value: '203.0.113.8', still_covered_by: ['203.0.113.0/24'] }, 'unban').text,
    /still banned by 203\.0\.113\.0\/24/);
});

console.log('\n--- state and sites ---');
const site = (status, extra = {}) => ({ label: 'a.example.com', status, pre_handlers: [], detail: '', source: 'main', import: { present: false }, ...extra });
check('overall state, worst first', () => {
  const down = { available: true, caddy: { reachable: false }, sources: { manual: {} }, sites: [site('enforced')] };
  assert.equal(M.overallState(down, 1).title, 'Caddy unreachable, enforcement unknown');
  assert.notEqual(M.overallState(down, 1).tone, 'ok');
  assert.equal(M.overallState({ ...down, caddy: { reachable: true } }, 1).title, 'Enforced on 1 site');
  assert.equal(M.overallState({ available: false, unavailable: { message: 'm' } }).title, 'Unavailable, not enforced');
  assert.equal(M.overallState({ available: true, degraded: { reason: 'live_mismatch', message: 'm' } }).title, 'Reload state unknown');
  assert.equal(M.overallState({ available: true, degraded: { reason: 'state_corrupt', message: 'm' } }).title, 'Degraded');
  assert.equal(M.overallState({ available: true, sources: { manual: { hold: true } }, sites: [] }).title, 'Policy differs from state');
  assert.equal(M.overallState({ available: true, sources: { manual: {} }, sites: [site('enforced'), site('not_imported')] }).title, 'Enforced on 1 site');
  assert.equal(M.overallState({ available: true, sources: { manual: {} }, sites: [site('not_imported')] }, 2).title, 'Stored but not imported');
  assert.equal(M.overallState({ available: true, sources: { manual: {} }, sites: [] }, 0).title, 'No site imports the ban list');
});
check('pre-handler sites name what runs first', () => {
  const s = M.siteStatus(site('enforced_pre_handler', { pre_handlers: ['redir', 'basic_auth'] }));
  assert.equal(s.label, 'Protected, pre-handler present');
  assert.match(s.detail, /redir, basic_auth/);
});
check('site actions: external is copy only, enforced and console sites get none', () => {
  assert.deepEqual(M.siteActions(site('not_imported')), ['insert', 'copy']);
  assert.deepEqual(M.siteActions(site('not_imported', { source: 'external' })), ['copy']);
  assert.deepEqual(M.siteActions(site('enforced')), []);
  assert.deepEqual(M.siteActions(site('management')), []);
  assert.deepEqual(M.siteActions(site('management_imported', { import: { present: true } })), []);
  assert.deepEqual(M.siteActions(site('management_imported', { source: 'external' })), []);
  assert.deepEqual(M.siteActions(site('not_loaded', { import: { present: true } })), []);
});
check('a console site that imports the ban list is a critical lockout risk, never "safe"', () => {
  const s = M.siteStatus(site('management_imported'));
  assert.equal(s.tone, 'crit');
  assert.match(s.label, /lockout/i);
  assert.match(s.detail, /[Rr]emove the import/);
  assert.doesNotMatch(s.label + s.detail, /never banned/);
  assert.equal(M.siteStatus(site('management')).label, 'Console site, never banned');
  const v = M.overallState({ available: true, sources: { manual: {} }, sites: [site('enforced'), site('management_imported')] }, 1);
  assert.equal(v.tone, 'crit');
  assert.match(v.title, /lockout/i);
});
check('protected labels', () => {
  assert.equal(M.protectedLabel('private'), 'private network');
  assert.equal(M.protectedLabel('nope'), 'protected range');
});

console.log('\n--- recovery hint, stale data, network failure ---');
check('unknown-enforcement states carry a recovery hint; healthy ones do not', () => {
  const down = { available: true, caddy: { reachable: false }, sources: { manual: {} }, sites: [] };
  assert.equal(M.overallState(down).recoveryHint, true);
  assert.equal(M.overallState({ available: true, degraded: { reason: 'live_mismatch', message: 'm' } }).recoveryHint, true);
  assert.equal(M.overallState({ available: false, unavailable: {} }).recoveryHint, true);
  assert.equal(M.overallState({ available: true, sources: { manual: {} }, sites: [site('enforced')] }, 1).recoveryHint, false);
});
check('a stale refresh never shows an ok verdict', () => {
  const ok = { available: true, sources: { manual: {} }, sites: [site('enforced')] };
  assert.equal(M.overallState(ok, 1).tone, 'ok');
  const s = M.overallState(ok, 1, { stale: true });
  assert.equal(s.tone, 'warn');
  assert.match(s.body, /Enforced on 1 site/);
  assert.equal(M.overallState({ available: false, unavailable: {} }, 0, { stale: true }).tone, 'crit');
  assert.match(M.staleNotice(1000, () => 'T'), /Could not refresh security status .* last known state from T/);
});
{
  const { requestJson } = await import(path.join(APP, 'security-api.js'));
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new TypeError('Failed to fetch'); };
  try { assert.deepEqual(await requestJson('/api/security'), { ok: false, status: 0, body: null }); }
  finally { globalThis.fetch = realFetch; }
  assert.equal(M.errorMessage(null, 0), 'Request failed.');
  passed++; console.log('  ok  requestJson turns a network failure into status 0');
}

console.log('\n--- popover ban state ---');
const look = (records, exact, prot = null) => ({ ip: '203.0.113.8', protected: prot, records, exact_ids: exact });
const exactRec = { id: 'e1', value: '203.0.113.8' };
const rangeRec = { id: 'r1', value: '203.0.113.0/24' };
check('a protected address offers no Ban', () => {
  const s = M.banState(look([], [], 'private'));
  assert.equal(s.canBan, false);
  assert.match(s.protectedText, /private network/);
});
check('an exact record offers Unban', () => {
  const s = M.banState(look([exactRec], ['e1']));
  assert.deepEqual([s.banned, s.canUnban, s.canBan], [true, true, false]);
});
check('banState after removing the exact record still reports the covering range', () => {
  const s = M.banState(look([rangeRec], []));
  assert.deepEqual([s.banned, s.canUnban, s.canBan], [true, false, true]);
  assert.equal(s.coveredText, 'Banned by 203.0.113.0/24');
});
check('both exact and range', () => {
  assert.equal(M.banState(look([exactRec, rangeRec], ['e1'])).coveredText, 'Also covered by 203.0.113.0/24');
});

console.log('\n--- no HTML sinks ---');
for (const f of ['security.js', 'security-model.js', 'ban-dialog.js', 'ip-popover.js', 'snippet-insert.js', 'panels.js', 'ui/dialog.js']) {
  const p = path.join(APP, f);
  if (!fs.existsSync(p)) continue;
  check(`${f} never writes HTML`, () =>
    assert.doesNotMatch(fs.readFileSync(p, 'utf8'), /innerHTML|outerHTML|insertAdjacentHTML|dangerouslySetInnerHTML/));
}
console.log(`\n${passed} passed`);
