// Tests for src/static/js/app/security-model.js, plus a scan that no Security
// file writes HTML. Run with: node tests/security-model.test.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const APP = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app');
const M = await import(path.join(APP, 'security-model.js'));

const F = await import(path.join(APP, 'format.js'));
let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };
const NOW = Date.parse('2026-11-23T20:00:00Z');

check('the save notice reflects the real reload status', () => {
  assert.deepEqual(M.saveNotice('Country policy', { reload_status: 'applied' }), { kind: 'ok', text: 'Country policy saved; Caddy reloaded.' });
  assert.equal(M.saveNotice('X', { reload_status: 'not_required' }).kind, 'ok');
  const bad = M.saveNotice('X', { reload_status: 'unknown', message: 'Check Caddy.' });
  assert.equal(bad.kind, 'warn');
  assert.match(bad.text, /did not confirm the reload \(unknown\)\. Check Caddy\./);
  assert.doesNotMatch(M.saveNotice('X', {}).text, /Caddy reloaded/);
});
check('the list-origin warning points at plugin mode, which exists now', () => {
  assert.ok(M.LIST_ORIGIN_WARNING.includes('docs/security.md#crowdsec-plugin'));
  assert.ok(!M.LIST_ORIGIN_WARNING.includes('once it is available'));
});

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

console.log('\n--- CrowdSec ---');
const CS_OK = { enabled: true, stale: false, origins: ['crowdsec', 'cscli'], list_origins: [],
  sync: { lapi_state: 'ok', apply_state: 'ok', decisions: 3, updated_at: '2026-11-23T19:59:50Z',
          last_success_at: '2026-11-23T19:59:50Z', last_snapshot_at: '2026-11-23T19:00:00Z', last_apply_at: null } };
check('CrowdSec health wording and tone', () => {
  assert.deepEqual([M.crowdsecState(CS_OK, NOW).tone, M.crowdsecState(CS_OK, NOW).title], ['ok', '3 active decisions synced']);
  const down = { ...CS_OK, sync: { ...CS_OK.sync, lapi_state: 'unreachable', lapi_message: 'LAPI is unreachable (ConnectionError).' } };
  const s = M.crowdsecState(down, NOW);
  assert.deepEqual([s.tone, s.title], ['warn', 'CrowdSec unreachable, last synced list kept']);
  assert.match(s.detail, /ConnectionError.*Last successful poll just now/);
  const key = M.crowdsecState({ ...CS_OK, sync: { ...CS_OK.sync, lapi_state: 'auth_failed' } }, NOW);
  assert.equal(key.tone, 'crit');
  const cap = M.crowdsecState({ ...CS_OK, sync: { ...CS_OK.sync, apply_state: 'capacity_exceeded', apply_message: 'too many' } }, NOW);
  assert.deepEqual([cap.tone, cap.title], ['crit', 'Over capacity: automatic apply paused']);
  assert.equal(M.crowdsecState({ ...CS_OK, stale: true }, NOW).title, 'CrowdSec sync report is out of date');
  assert.equal(M.crowdsecState({ ...CS_OK, sync: null }, NOW).title, 'No CrowdSec sync report yet');
  assert.equal(M.crowdsecState({ enabled: false }, NOW).title, 'CrowdSec is not configured');
});
check('a stale report is never shown as healthy', () => {
  const s = M.crowdsecState({ ...CS_OK, stale: true }, NOW);
  assert.notEqual(s.tone, 'ok');
  assert.doesNotMatch(s.title, /synced|Connected/);
});
check('sync times are relative with an absolute title', () => {
  const t = M.syncTimes(CS_OK.sync, NOW);
  assert.deepEqual(t.map(x => [x.label, x.text]), [['Last snapshot', '1h ago'], ['Last successful poll', 'just now'], ['Last apply', 'Never']]);
  assert.equal(t[0].title, F.absoluteTime('2026-11-23T19:00:00Z'));
});
check('ignored counts are labelled and sorted', () => {
  assert.deepEqual(M.ignoredRows({ origin: 1, 'protected:private': 4, not_ban: 0, odd: 2 }).map(r => [r.label, r.count]), [
    ['Protected (private network)', 4], ['odd', 2], ['Origin not in CROWDSEC_ORIGINS', 1]]);
  assert.deepEqual(M.ignoredRows(undefined), []);
});
check('the cscli command only ever carries a numeric decision id', () => {
  assert.equal(M.cscliDeleteCommand({ source_id: '42' }), 'cscli decisions delete --id 42');
  for (const bad of ['42; rm -rf /', '', null, '4 2', 'x']) assert.equal(M.cscliDeleteCommand({ source_id: bad }), '');
});
check('capacity by source', () => {
  assert.equal(M.capacityText({ max_prefixes: 10000, used: 5, by_source: { manual: 3, crowdsec: 2 } }),
    '5 of 10000 prefixes rendered (manual 3, CrowdSec 2).');
  assert.equal(M.capacityText({ max_prefixes: 10000, used: 3, by_source: { manual: 3 } }), '3 of 10000 prefixes rendered.');
});
check('sync by_origin counts are listed, largest first', () => {
  assert.equal(M.originCountsText({ by_origin: { cscli: 1, crowdsec: 5 } }), 'crowdsec 5, cscli 1');
  assert.equal(M.originCountsText({ by_origin: {} }), '');
  assert.equal(M.originCountsText(null), '');
});
check('overall state counts any enforcing source and any held file', () => {
  const base = { available: true, caddy: { reachable: true }, sources: { manual: { hold: false }, crowdsec: { ...CS_OK, hold: false } } };
  const sites = [{ status: 'not_imported', policies: { manual: { status: 'not_imported' }, crowdsec: { status: 'enforced' } } }];
  assert.equal(M.overallState({ ...base, sites }, 0).title, 'Enforced on 1 site');
  const held = { ...base, sites, sources: { ...base.sources, crowdsec: { ...base.sources.crowdsec, hold: true } } };
  assert.equal(M.overallState(held, 0).title, 'Policy differs from state');
  const risk = [{ status: 'management', policies: { manual: { status: 'management' }, crowdsec: { status: 'management_imported' } } }];
  assert.equal(M.overallState({ ...base, sites: risk }, 0).tone, 'crit');
  const capped = { ...base, sites, sources: { ...base.sources, crowdsec: { ...CS_OK, hold: false, sync: { ...CS_OK.sync, apply_state: 'capacity_exceeded' } } } };
  assert.deepEqual([M.overallState(capped, 0).tone, M.overallState(capped, 0).title], ['warn', 'CrowdSec sync needs attention']);
});

console.log('\n--- no HTML sinks ---');
for (const f of ['security.js', 'security-crowdsec.js', 'security-plugin.js', 'security-client-ip.js', 'security-country.js', 'security-model.js', 'ban-dialog.js', 'ip-popover.js', 'snippet-insert.js', 'panels.js', 'ui/dialog.js']) {
  const p = path.join(APP, f);
  if (!fs.existsSync(p)) continue;
  check(`${f} never writes HTML`, () =>
    assert.doesNotMatch(fs.readFileSync(p, 'utf8'), /innerHTML|outerHTML|insertAdjacentHTML|dangerouslySetInnerHTML/));
}
console.log('\n--- Phase 1 polish ---');
check('Created is relative, with the absolute time as its title', () => {
  const c = M.createdCell('2026-11-23T19:00:00Z', NOW);
  assert.equal(c.text, '1h ago');
  assert.equal(c.title, F.absoluteTime('2026-11-23T19:00:00Z'));
  assert.deepEqual(M.createdCell('garbage', NOW), { text: '', title: '' });
});
check('a site is unknown, not "not loaded", while Caddy is unreachable', () => {
  const s = M.siteStatus({ status: 'caddy_unreachable' });
  assert.equal(s.label, 'Unknown while Caddy is unreachable');
  assert.equal(s.tone, 'warn');
  assert.doesNotMatch(s.detail, /Save & Reload/);
  assert.match(s.detail, /admin API/);
  assert.deepEqual(M.siteActions({ status: 'caddy_unreachable', source: 'main', import: { present: true } }), []);
  assert.deepEqual(M.siteActions({ status: 'caddy_unreachable', source: 'main', import: { present: false } }), ['insert', 'copy']);
});
console.log('\n--- Phase 2 follow-ups ---');
check('synced decisions that are not applied yet read as applying, not active', () => {
  const pending = { ...CS_OK, sync: { ...CS_OK.sync, decisions: 1, pending_apply: true } };
  const s = M.crowdsecState(pending, NOW);
  assert.equal(s.title, '1 decision synced, applying…');
  assert.equal(s.tone, 'ok');
  assert.match(s.detail, /within BANS_SYNC_INTERVAL/);
  assert.equal(M.crowdsecState({ ...CS_OK, sync: { ...CS_OK.sync, pending_apply: false } }, NOW).title, '3 active decisions synced');
  // Older reports have no field: unchanged wording.
  assert.equal(M.crowdsecState(CS_OK, NOW).title, '3 active decisions synced');
  // An apply problem still wins over "applying".
  const cap = { ...pending, sync: { ...pending.sync, apply_state: 'capacity_exceeded', apply_message: 'too many' } };
  assert.equal(M.crowdsecState(cap, NOW).title, 'Over capacity: automatic apply paused');
});

console.log('\n--- CrowdSec plugin ---');
const PLUG = {
  enabled: true, module: true, refused: false, admin: null, key_mode: 'env', key_file: null,
  placeholder: '{env.CROWDSEC_PLUGIN_BOUNCER_KEY}', ticker_interval: '10s',
  app: { api_url: 'http://crowdsec:8080', ticker_interval: '10s', streaming: true, hard_fails: false, key_form: 'expected', key_placeholder: null },
  definition: { file: '/etc/caddy/console/crowdsec-plugin-protect.caddy', import_line: 'import /etc/caddy/console/crowdsec-plugin-protect*.caddy',
    site_import: 'import protect_crowdsec', present: true, hash: '0123456789ab', current: true, hold: false, hold_reason: null, imported: true },
  allowlist: 'cscli allowlists add caddy_console_protected 127.0.0.0/8\n', check_command: 'crowdsec/check-plugin-isolation.sh -- ...',
};
check('plugin health wording, worst problem first', () => {
  assert.equal(M.pluginState({ enabled: false }), null);
  assert.deepEqual([M.pluginState(PLUG).tone, M.pluginState(PLUG).title], ['ok', 'Near-real-time without reload, polling every 10s']);
  const refused = M.pluginState({ ...PLUG, refused: true, admin: { code: 'admin_wildcard', message: 'listens on every interface' } });
  assert.deepEqual([refused.tone, refused.title, refused.detail], ['crit', 'Plugin mode refused: the admin API would be exposed', 'listens on every interface']);
  assert.equal(M.pluginState({ ...PLUG, module: false }).title, 'The running Caddy has no crowdsec module');
  assert.equal(M.pluginState({ ...PLUG, app: { ...PLUG.app, key_form: 'literal' } }).tone, 'crit');
  assert.doesNotMatch(M.pluginState({ ...PLUG, app: { ...PLUG.app, key_form: 'literal' } }).detail, /[0-9a-f]{16}/);
  assert.match(M.pluginState({ ...PLUG, app: { ...PLUG.app, key_form: 'placeholder', key_placeholder: '{file./run/secrets/x}' } }).detail, /\{file\.\/run\/secrets\/x\}.*\{env\.CROWDSEC_PLUGIN_BOUNCER_KEY\}/);
  assert.equal(M.pluginState({ ...PLUG, app: null }).title, 'Plugin app not loaded');
  assert.equal(M.pluginState({ ...PLUG, definition: { ...PLUG.definition, current: false } }).title, 'Protected route definition is out of date');
  assert.equal(M.pluginState({ ...PLUG, definition: { ...PLUG.definition, hold: true, hold_reason: 'differs' } }).title, 'Protected route differs from state');
  assert.equal(M.pluginState({ ...PLUG, app: { ...PLUG.app, streaming: false } }).tone, 'warn');
});
const pol = (crowdsec, plugin) => ({ policies: { manual: { status: 'enforced' }, crowdsec: { status: crowdsec }, plugin: { status: plugin } } });
check('each site says which path CrowdSec decisions take', () => {
  assert.deepEqual(M.crowdsecPath(pol('enforced', 'not_imported')), { text: 'CrowdSec decisions: file sync', tone: 'ok' });
  assert.deepEqual(M.crowdsecPath(pol('imported_empty', 'enforced')), { text: 'CrowdSec decisions: file sync and plugin (redundant, both enforce)', tone: 'warn' });
  assert.deepEqual(M.crowdsecPath(pol('not_imported', 'enforced')), { text: 'CrowdSec decisions: plugin', tone: 'ok' });
  assert.deepEqual(M.crowdsecPath(pol('not_imported', 'not_imported')), { text: 'CrowdSec decisions: not enforced', tone: 'none' });
  assert.deepEqual(M.crowdsecPath(pol('not_imported', 'plugin_unprotected')), { text: 'CrowdSec decisions: plugin without the protected ranges', tone: 'crit' });
  assert.equal(M.crowdsecPath({ policies: { manual: {} } }), null, 'no plugin rows: nothing to say');
});
check('a bare crowdsec handler is critical and offers no insert', () => {
  const s = M.siteStatus({ status: 'plugin_unprotected', detail: 'x' });
  assert.deepEqual([s.label, s.tone], ['Plugin runs without the protected ranges', 'crit']);
  assert.match(s.detail, /import protect_crowdsec/);
});
check('the plugin site import is offered only when the plugin is ready', () => {
  const site = { source: 'main' };
  const p = { status: 'not_imported', import: { present: false } };
  assert.deepEqual(M.pluginSiteActions(p, site, PLUG), ['insert', 'copy']);
  assert.deepEqual(M.pluginSiteActions(p, { source: 'external' }, PLUG), ['copy']);
  assert.deepEqual(M.pluginSiteActions(p, site, { ...PLUG, app: null }), []);
  assert.deepEqual(M.pluginSiteActions(p, site, { ...PLUG, refused: true }), []);
  assert.deepEqual(M.pluginSiteActions(p, site, { ...PLUG, definition: { ...PLUG.definition, imported: false } }), []);
  assert.deepEqual(M.pluginSiteActions({ ...p, status: 'enforced' }, site, PLUG), []);
});
check('a refused or held plugin shows in the overall verdict', () => {
  const base = { available: true, degraded: null, caddy: { reachable: true }, sources: { manual: {} }, sites: [{ policies: { manual: { status: 'enforced' } } }] };
  assert.equal(M.overallState({ ...base, plugin: PLUG }).tone, 'ok');
  const refused = M.overallState({ ...base, plugin: { ...PLUG, refused: true, admin: { code: 'admin_wildcard', message: 'm' } } });
  assert.deepEqual([refused.tone, refused.title], ['crit', 'Plugin mode refused: the admin API would be exposed']);
  const held = M.overallState({ ...base, plugin: { ...PLUG, definition: { ...PLUG.definition, hold: true } } });
  assert.equal(held.title, 'Policy differs from state');
  assert.match(held.body, /CrowdSec plugin route/);
});
check('SOURCE_LABELS name the plugin', () => assert.equal(M.SOURCE_LABELS.plugin, 'CrowdSec plugin'));


console.log('\n--- Phase 4: client IP ---');
check('every mode has a plain-language explanation and unknown ids fall back to direct', () => {
  assert.deepEqual(M.CLIENT_IP_MODES.map(m => m.id), ['direct', 'cloudflare-proxied', 'cloudflare-tunnel']);
  for (const m of M.CLIENT_IP_MODES) assert.ok(m.explain.length > 40, m.id);
  assert.equal(M.clientIpMode('nope').id, 'direct');
});
check('clientIpPayload validates the mode and the tunnel peer', () => {
  assert.deepEqual(M.clientIpPayload({ mode: 'direct', peersText: '10.0.0.1' }), { mode: 'direct' });
  assert.deepEqual(M.clientIpPayload({ mode: 'cloudflare-proxied' }), { mode: 'cloudflare-proxied' });
  assert.deepEqual(M.clientIpPayload({ mode: 'cloudflare-tunnel', peersText: ' 172.18.0.5, 172.18.1.0/24 ', tunnelOnly: true }),
    { mode: 'cloudflare-tunnel', tunnel_peers: ['172.18.0.5', '172.18.1.0/24'], tunnel_only: true });
  assert.throws(() => M.clientIpPayload({ mode: 'cloudflare-tunnel', peersText: '  ' }), /cloudflared address/);
  assert.throws(() => M.clientIpPayload({ mode: 'bogus' }), /Choose/);
});
check('the confirmation names what Caddy will trust', () => {
  assert.match(M.clientIpConfirm({ mode: 'cloudflare-tunnel', tunnel_peers: ['172.18.0.5'] }).body, /172\.18\.0\.5/);
  assert.equal(M.clientIpConfirm({ mode: 'direct' }).danger, false);
  assert.equal(M.clientIpConfirm({ mode: 'cloudflare-proxied' }).danger, true);
  assert.match(M.clientIpConfirm({ mode: 'direct' }).body, /stops trusting/);
});
check('range age, source and overdue notices', () => {
  assert.equal(M.rangesAgeText({ source: 'official', age_seconds: 3 * 86400 }), 'Fetched 3 days ago');
  assert.equal(M.rangesAgeText({ source: 'official', age_seconds: 5 * 3600 }), 'Fetched 5 h ago');
  assert.equal(M.rangesAgeText({ source: 'bundled', age_seconds: null }), 'Using the bundled list');
  assert.equal(M.rangesNotice({ age_seconds: 10 * 86400 }, 'cloudflare-proxied') !== '', true);
  assert.match(M.rangesNotice({ last_error: 'timeout', age_seconds: 5 }, 'cloudflare-proxied'), /timeout/);
  assert.equal(M.rangesNotice({ age_seconds: 10 * 86400 }, 'direct'), '');
});
check('client-IP state: corrupt, hold, missing peer, stale file, live mismatch, ok', () => {
  const ok = { mode: 'cloudflare-proxied', present: true, current: true, live: [{ matches: true }] };
  assert.equal(M.clientIpState(ok).tone, 'ok');
  assert.equal(M.clientIpState({ ...ok, corrupt: 'bad' }).tone, 'crit');
  assert.equal(M.clientIpState({ ...ok, hold: 'x' }).tone, 'warn');
  assert.equal(M.clientIpState({ ...ok, current: false }).tone, 'warn');
  assert.equal(M.clientIpState({ ...ok, live: [{ matches: false }] }).tone, 'warn');
  assert.match(M.clientIpState({ mode: 'cloudflare-tunnel', tunnel_peers: [] }).title, /no cloudflared/);
  assert.equal(M.clientIpState({ mode: 'direct', present: false, live: [] }).tone, 'ok');
});

console.log('\n--- Phase 4: country policy ---');
const names = { of: (c) => ({ RO: 'Romania', DE: 'Germany' }[c] || c) };
const INFO = { iso_codes: ['RO', 'DE', 'ZZ'], special_codes: ['XX', 'T1'] };
check('country options are named, sorted, fall back to the code and put XX/T1 last', () => {
  const o = M.countryOptions(INFO, names);
  assert.deepEqual(o.map(x => x.code), ['DE', 'RO', 'ZZ', 'T1', 'XX']);
  assert.deepEqual(o.map(x => x.name), ['Germany (DE)', 'Romania (RO)', 'ZZ', 'Tor exit nodes (T1)', 'Unknown country (XX)']);
  assert.deepEqual(o.map(x => x.special), [false, false, false, true, true]);
  assert.equal(M.countryOptions(INFO, null)[0].name, 'DE');
  assert.equal(M.countryName('RO', { of: () => { throw new RangeError('x'); } }), 'RO');
});
check('toggling keeps a sorted unique list and special codes are flagged', () => {
  assert.deepEqual(M.toggleCode(['RO'], 'DE', true), ['DE', 'RO']);
  assert.deepEqual(M.toggleCode(['DE', 'RO'], 'DE', false), ['RO']);
  assert.deepEqual(M.toggleCode(['RO'], 'RO', true), ['RO']);
  assert.deepEqual(M.specialSelected(['RO', 'XX'], INFO), ['XX']);
  assert.match(M.SPECIAL_WARNING, /XX.*T1/);
});
check('countryPayload needs a country to enable and carries the Cloudflare confirmation', () => {
  assert.throws(() => M.countryPayload({ enabled: true, countries: [] }), /at least one/);
  assert.deepEqual(M.countryPayload({ enabled: false, countries: [] }), { enabled: false, countries: [] });
  assert.deepEqual(M.countryPayload({ enabled: true, countries: ['RO', 'DE'], confirmed: true, shape: 'cloudflare' }),
    { enabled: true, countries: ['DE', 'RO'], cloudflare_geolocation_confirmed: true });
  assert.deepEqual(M.countryPayload({ enabled: true, countries: ['RO'], shape: 'direct' }), { enabled: true, countries: ['RO'] });
});
check('prefix counts, warning and cap wording', () => {
  const s = { prefixes: { v4: 800, v6: 200, total: 1000 }, cap: 20000, warn: 10000 };
  assert.equal(M.countryPrefixText(s), '800 IPv4 and 200 IPv6 prefixes (1000 of 20000 allowed)');
  assert.match(M.countryPrefixText({ ...s, prefixes: { v4: 9000, v6: 2000, total: 11000 } }), /Above 10000.*Cloudflare WAF/);
  assert.equal(M.countryPrefixText({ prefixes: {} }), '');
});
check('country state: off, unconfirmed Cloudflare, live mismatch, healthy', () => {
  const base = { effective: true, shape: 'direct', countries: ['RO'], present: true, summary: { healthy: true, live_ok: true } };
  assert.deepEqual([M.countryState(base).tone, M.countryState(base).title], ['ok', 'Allowing 1 country']);
  // The UI toggle is the only switch now: a stray env_enabled: false no longer reads as "disabled for this deployment".
  assert.equal(M.countryState({ ...base, env_enabled: false }).tone, 'ok');
  assert.equal(M.countryState({ ...base, effective: false }).title, 'Country policy is off');
  assert.equal(M.countryState({ ...base, shape: 'cloudflare', cloudflare_geolocation_confirmed: false, summary: { healthy: false } }).title, 'Cloudflare IP geolocation is not confirmed');
  assert.equal(M.countryState({ ...base, summary: { healthy: false, live_ok: false } }).title, 'Caddy runs a different country policy');
  assert.equal(M.countryState({ ...base, present: true, summary: { healthy: false, trust_ok: false } }).title, 'Cloudflare trusted proxies do not match');
  assert.equal(M.countryState({ ...base, error: { message: 'dataset missing' } }).tone, 'crit');
  assert.equal(M.countryState({ ...base, corrupt: 'bad json' }).tone, 'crit');
});
check('country rows have their own labels and never count as ban enforcement', () => {
  assert.equal(M.siteStatus({ status: 'enforced' }, 'country').label, 'Countries enforced');
  assert.equal(M.siteStatus({ status: 'imported_empty' }, 'country').label, 'Imported, country policy off');
  assert.equal(M.siteStatus({ status: 'imported_empty' }).label, 'Imported, no active bans');
  assert.match(M.siteStatus({ status: 'not_imported' }, 'country').detail, /country policy/);
  const only = { available: true, caddy: { reachable: true }, sources: {}, sites: [{ policies: { manual: { status: 'not_imported' }, country: { status: 'enforced' } } }] };
  assert.equal(M.overallState(only, 0).title, 'No site imports the ban list');
});
console.log(`\n${passed} passed`);
