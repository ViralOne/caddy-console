// Tests for src/static/js/app/dashboard-model.js
// Run with: node tests/dashboard-model.test.mjs
import assert from 'node:assert/strict';
import path from 'node:path';

const SRC = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app', 'dashboard-model.js');
const m = await import(SRC);

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };
const plain = (parts) => parts.map(p => p.text ?? p.mono).join('');
const at = (...a) => new Date(...a).getTime();
const NOW = at(2026, 10, 20, 15, 0, 0);

const site = (host, requests, errors, p95 = 120, bytes = 1000) =>
  ({ host, requests, errors, error_rate: requests ? Math.round(errors / requests * 10000) / 100 : 0, p95_latency_ms: p95, bytes_out: bytes, series: [] });
const SITES = [
  site('nas.example.com', 279, 3, 141, 10_000_000), site('photos.example.com', 172, 2, 61, 6_500_000),
  site('watch.example.com', 163, 1, 180, 5_600_000), site('grafana.example.com', 78, 0, 272, 3_000_000),
  site('torrent.example.com', 65, 21, 12400, 1_300_000), site('ha.example.com', 59, 0, 92, 2_300_000),
  site('radarr.example.com', 41, 1, 306, 1_300_000),
];
const UP = (address, domains, healthy, since = null) => ({ address, domains, healthy, unhealthy_since: since });
const HEALTHY = [UP('127.0.0.1:5000', ['nas.example.com'], 1), UP('127.0.0.1:2283', ['photos.example.com'], 1)];

console.log('\n--- verdict ---');
check('calm when nothing is wrong', () => {
  const v = m.verdict({ sites: SITES.map(s => (s.host.startsWith('torrent') ? site(s.host, 65, 0) : s)), upstreams: HEALTHY, configuredSites: 7, now: NOW });
  assert.equal(v.severity, 'ok'); assert.equal(v.title, 'All 7 sites are serving'); assert.equal(v.sev, null);
});
check('a down upstream names the site, the check, the time and the others', () => {
  const since = at(2026, 10, 20, 14, 31) / 1000;
  const v = m.verdict({ sites: SITES, upstreams: [HEALTHY[0], UP('127.0.0.1:2283', ['photos.example.com'], 0, since)], configuredSites: 7, now: NOW });
  assert.equal(v.severity, 'critical');
  assert.equal(v.sev, 'Critical, 1 unhealthy upstream');
  assert.equal(v.title, 'photos.example.com is down');
  assert.equal(plain(v.body), "Caddy's health check to 127.0.0.1:2283 has failed since 14:31. The other 6 sites are serving; torrent.example.com is answering 32% of requests with 5xx.");
  assert.deepEqual(v.secondary, { label: 'Open photos.example.com block', host: 'photos.example.com' });
  assert.equal(v.primary.href, '/explore?range=1h&q=host%3Aphotos.example.com');
});
check('without unhealthy_since the time is left out, not invented', () => {
  const v = m.verdict({ sites: [], upstreams: [UP('10.0.0.9:80', ['a.example.com'], 0)], configuredSites: 1, now: NOW });
  assert.equal(plain(v.body), "Caddy's health check to 10.0.0.9:80 is failing.");
});
check('an admin API outage outranks everything', () => {
  const v = m.verdict({ sites: SITES, upstreams: [], upstreamsError: 'Caddy admin API not reachable', now: NOW });
  assert.equal(v.severity, 'critical'); assert.equal(v.title, 'Caddy is not answering the console');
});
check('a hung admin API (read timeout) is critical and shows the error', () => {
  const err = "HTTPConnectionPool(host='caddy', port=2019): Read timed out. (read timeout=5)";
  const v = m.verdict({ sites: SITES, upstreams: [], upstreamsError: err, configuredSites: 7, now: NOW });
  assert.equal(v.severity, 'critical'); assert.equal(v.title, 'Caddy is not answering the console');
  assert.ok(plain(v.body).includes(err));
});
check('a non-200 from the admin API is critical and shows the error', () => {
  const v = m.verdict({ sites: SITES, upstreams: [], upstreamsError: 'Caddy returned 500', configuredSites: 7, now: NOW });
  assert.equal(v.severity, 'critical'); assert.ok(plain(v.body).includes('Caddy returned 500'));
});
check('metrics unavailable with upstreams present: health unavailable, never "serving"', () => {
  const ups = HEALTHY.map(u => ({ ...u, healthy: undefined }));
  const calm = SITES.map(s => (s.host.startsWith('torrent') ? site(s.host, 65, 0) : s));
  const v = m.verdict({ sites: calm, upstreams: ups, trafficError: 'Metrics endpoint not found (404)', configuredSites: 7, now: NOW });
  assert.equal(v.severity, 'warn'); assert.equal(v.title, 'Upstream health unavailable');
  assert.ok(plain(v.body).includes('Metrics endpoint not found (404)'));
  assert.ok(!/serving/.test(v.title));
  // No metrics error, but Caddy reported no health for any upstream: same verdict.
  assert.equal(m.verdict({ sites: calm, upstreams: ups, configuredSites: 7, now: NOW }).title, 'Upstream health unavailable');
});
check('ok stays ok when health is known', () => {
  const calm = SITES.map(s => (s.host.startsWith('torrent') ? site(s.host, 65, 0) : s));
  const v = m.verdict({ sites: calm, upstreams: HEALTHY, trafficError: null, configuredSites: 7, now: NOW });
  assert.equal(v.severity, 'ok'); assert.equal(v.title, 'All 7 sites are serving');
});
check('a failed refresh replaces the verdict, whatever the last data said', () => {
  const calm = SITES.map(s => (s.host.startsWith('torrent') ? site(s.host, 65, 0) : s));
  const v = m.verdict({ sites: calm, upstreams: HEALTHY, configuredSites: 7, loadError: 'Failed to fetch', now: NOW });
  assert.equal(v.severity, 'serious'); assert.equal(v.title, 'The dashboard could not refresh');
  assert.ok(plain(v.body).includes('Failed to fetch'));
});
check('a failing config check is serious', () => {
  const v = m.verdict({ sites: [], upstreams: [], status: { config_valid: false, config_check_level: 'adapted', config_check_message: 'boom' }, now: NOW });
  assert.equal(v.severity, 'serious'); assert.equal(plain(v.body), 'boom');
});
check('a high 5xx rate is a warning', () => {
  const v = m.verdict({ sites: SITES, upstreams: HEALTHY, configuredSites: 7, now: NOW });
  assert.equal(v.severity, 'warn'); assert.equal(v.title, 'torrent.example.com is failing 32% of requests');
});
check('a couple of errors on a quiet site is not a verdict', () => {
  const v = m.verdict({ sites: [site('quiet.example.com', 2, 1)], upstreams: [], configuredSites: 1, now: NOW });
  assert.equal(v.severity, 'ok'); assert.equal(v.title, 'The site is serving');
});

console.log('\n--- figures ---');
check('requests compare with the previous hour when known', () => {
  const [req] = m.kpis({ sites: [site('a', 112, 0)], previousTotal: 100, configuredSites: 1 });
  assert.equal(req.sub, '+12% vs previous hour');
  assert.equal(m.kpis({ sites: [site('a', 88, 0)], previousTotal: 100 })[0].sub, '−12% vs previous hour');
});
check('no previous window means no comparison line, never 0', () => {
  assert.equal(m.kpis({ sites: [site('a', 5, 0)], previousTotal: null })[0].sub, null);
  assert.equal(m.kpis({ sites: [site('a', 5, 0)], previousTotal: 0 })[0].sub, null);
});
check('dropped events at the memory cap hide the comparison', () => {
  assert.equal(m.kpis({ sites: [site('a', 112, 0)], previousTotal: 100, dropped: 1 })[0].sub, null);
  assert.equal(m.kpis({ sites: [site('a', 112, 0)], previousTotal: 100, dropped: 0 })[0].sub, '+12% vs previous hour');
});
check('5xx names the site with most of the errors', () => {
  const k = m.kpis({ sites: SITES, previousTotal: null, configuredSites: 7 });
  assert.equal(k[1].value, '3.3%'); assert.equal(k[1].sub, '28 errors, mostly torrent'); assert.equal(k[1].bad, true);
});
check('sites with traffic "of N" only when the config count is known', () => {
  const k = m.kpis({ sites: SITES, previousTotal: null, configuredSites: 7 });
  assert.equal(k[2].of, 'of 7'); assert.equal(k[2].sub, 'all configured sites');
  const unknown = m.kpis({ sites: SITES, previousTotal: null, configuredSites: null });
  assert.equal(unknown[2].of, null); assert.equal(unknown[2].sub, null);
  assert.equal(m.kpis({ sites: SITES.slice(0, 5), configuredSites: 7 })[2].sub, '2 configured sites without traffic');
});
check('more sites with traffic than configured hides "of N"', () => {
  const k = m.kpis({ sites: SITES, configuredSites: 4 });
  assert.equal(k[2].value, '7'); assert.equal(k[2].of, null); assert.equal(k[2].sub, null);
});
check('bandwidth names the biggest site', () => assert.equal(m.kpis({ sites: SITES })[3].sub, 'nas.example.com is 33%'));

console.log('\n--- config card ---');
const status = (extra) => ({ config_valid: true, config_check_level: 'adapted', caddy_version: 'v2.11.9 h1:abc=',
  config_path: '/etc/caddy/Caddyfile', last_modified: '2026-11-20T11:24:00.123456', last_change: null, ...extra });
check('valid, version without the build hash, path', () => {
  const c = m.configCard(status(), NOW);
  assert.equal(c.state, 'ok'); assert.equal(c.checks, 'Syntax and modules OK'); assert.equal(c.version, 'v2.11.9');
  assert.equal(c.changed.rel, '3h 36m ago'); assert.equal(c.changed.by, null);
});
check('"by" only when the last change matches the file time', () => {
  const ts = at(2026, 10, 20, 11, 24, 2) / 1000;
  assert.equal(m.configCard(status({ last_change: { action: 'save', user: 'ops@example.com', ts } }), NOW).changed.by, 'ops@example.com');
  assert.equal(m.configCard(status({ last_change: { action: 'save', user: 'ops@example.com', ts: ts - 3600 } }), NOW).changed.by, null);
});
check('the epoch file time wins over the naive local string', () => {
  const ts = at(2026, 10, 20, 14, 30, 0) / 1000;
  const c = m.configCard(status({ last_modified: '2026-11-20T12:30:00.000000', last_modified_ts: ts,
    last_change: { action: 'save', user: 'ops@example.com', ts: ts + 1 } }), NOW);
  assert.equal(c.changed.rel, '30 min ago'); assert.equal(c.changed.by, 'ops@example.com');
});
check('unknown mtime hides the line', () => assert.equal(m.configCard(status({ last_modified: 'unknown' }), NOW).changed, null));

console.log('\n--- health, tags, audit ---');
check('health labels', () => {
  assert.equal(m.healthOf('nas.example.com', HEALTHY).label, 'Healthy');
  assert.equal(m.healthOf('x.example.com', HEALTHY).label, 'No upstream');
  assert.equal(m.healthOf('a', [UP('1:1', ['a'], 0)]).label, 'Unhealthy');
  assert.equal(m.healthOf('a', [UP('1:1', ['a'], undefined)]).label, 'Not checked');
});
check('no upstream data (admin API down) reads Not checked, not No upstream', () => {
  assert.equal(m.healthOf('a', null).label, 'Not checked');
});
check('tags at the thresholds', () => {
  assert.deepEqual(m.siteTags({ error_rate: 10, p95_latency_ms: 2000 }), ['high', 'slow']);
  assert.deepEqual(m.siteTags({ error_rate: 9.99, p95_latency_ms: 1999 }), []);
});
check('audit verbs and details', () => {
  const t = '2026-11-20T14:44:10.000001';
  assert.deepEqual(m.auditRow({ action: 'save_reload', user: 'ops@example.com', detail: 'backup=Caddyfile.20261120-144410', time: t }, NOW),
    { verb: 'Saved', icon: 'save', user: 'ops@example.com', detail: '', rel: '15 min ago', abs: '2026-11-20 14:44:10' });
  assert.equal(m.auditRow({ action: 'restore_reload', detail: 'backup=Caddyfile.20261120-100000, from=Caddyfile.20261119-081000', time: t }, NOW).detail, 'Backup from 19 Nov, 08:10');
  assert.equal(m.auditRow({ action: 'login', time: t }, NOW).verb, 'Signed in');
  assert.equal(m.auditRow({ action: 'frobnicate', time: 'nope' }, NOW).verb, 'Frobnicate');
  assert.equal(m.auditRow({ action: 'frobnicate', time: 'nope' }, NOW).rel, '');
});
check('audit time uses the epoch when present', () => {
  const r = m.auditRow({ action: 'login', time: '2026-11-20T12:50:00.000000', ts: at(2026, 10, 20, 14, 50, 0) / 1000 }, NOW);
  assert.equal(r.rel, '10 min ago'); assert.equal(r.abs, '2026-11-20 14:50:00');
});
console.log('\n--- dashboard improvements ---');
const CHECKED = (address, domains, healthy, since = null) => ({ ...UP(address, domains, healthy, since), active_health: true, passive_health: false });
check('health is "Not checked" when no upstream of the site has an active or passive check', () => {
  const unchecked = { ...UP('1:1', ['a'], 1), active_health: false, passive_health: false };
  const h = m.healthOf('a', [unchecked]);
  assert.equal(h.label, 'Not checked'); assert.equal(h.state, 'unchecked');
  assert.equal(m.healthOf('a', [unchecked, CHECKED('1:2', ['a'], 1)]).label, 'Healthy');
  assert.equal(m.healthOf('a', [{ ...UP('1:1', ['a'], 1), active_health: false, passive_health: true }]).label, 'Healthy');
  // A failing upstream is still Unhealthy, checks configured or not; no upstream stays No upstream.
  assert.equal(m.healthOf('a', [{ ...unchecked, healthy: 0 }]).label, 'Unhealthy');
  assert.equal(m.healthOf('b', [unchecked]).label, 'No upstream');
});
check('site rows: down first, then high 5xx, then slow, then the rest by requests', () => {
  const sites = [
    site('big.example.com', 500, 0), site('slow.example.com', 50, 0, 2500), site('high.example.com', 40, 10),
    site('down.example.com', 30, 0), site('mid.example.com', 200, 0), site('highslow.example.com', 20, 5, 3000),
  ];
  const rows = m.siteRows(sites, [CHECKED('9:9', ['down.example.com'], 0), CHECKED('9:8', ['big.example.com'], 1)]);
  assert.deepEqual(rows.map(r => r.site.host),
    ['down.example.com', 'high.example.com', 'highslow.example.com', 'slow.example.com', 'big.example.com', 'mid.example.com']);
  assert.deepEqual(rows.map(r => r.tone), ['crit', 'warn', 'warn', null, null, null]);
  assert.equal(rows[0].health.label, 'Unhealthy');
  assert.equal(rows.find(r => r.site.host === 'big.example.com').share, 1);
  assert.equal(rows.find(r => r.site.host === 'mid.example.com').share, 0.4);
  // Input order is left alone.
  assert.equal(sites[0].host, 'big.example.com');
});
check('several down sites are listed, earliest failure first, capped at 5 with "+N more"', () => {
  const t = (h, min) => at(2026, 10, 20, h, min) / 1000;
  const ups = [
    CHECKED('10.0.0.1:80', ['a.example.com'], 0, t(14, 40)), CHECKED('10.0.0.2:80', ['b.example.com'], 0, t(14, 10)),
    CHECKED('10.0.0.3:80', ['c.example.com'], 0), CHECKED('10.0.0.4:80', ['d.example.com'], 0, t(14, 20)),
    CHECKED('10.0.0.5:80', ['e.example.com'], 0, t(14, 50)), CHECKED('10.0.0.6:80', ['f.example.com'], 0, t(14, 55)),
    CHECKED('10.0.0.7:80', ['g.example.com'], 0, t(14, 58)), CHECKED('10.0.0.8:80', ['h.example.com'], 1),
  ];
  const v = m.verdict({ sites: [], upstreams: ups, configuredSites: 8, now: NOW });
  assert.equal(v.severity, 'critical'); assert.equal(v.title, '7 sites are down');
  assert.deepEqual(v.down.items.map(d => d.host), ['b.example.com', 'd.example.com', 'a.example.com', 'e.example.com', 'f.example.com']);
  assert.deepEqual(v.down.items[0], { host: 'b.example.com', address: '10.0.0.2:80', since: 'failed since 14:10' });
  assert.equal(v.down.more, 2);
  assert.equal(v.down.moreText, '+2 more');
  // Without a time it reads "failing" and sorts after the timed ones.
  const short = m.verdict({ sites: [], upstreams: [ups[2], ups[0]], configuredSites: 2, now: NOW });
  assert.deepEqual(short.down.items.map(d => [d.host, d.since]), [['a.example.com', 'failed since 14:40'], ['c.example.com', 'failing']]);
  assert.equal(short.down.more, 0); assert.equal(short.down.moreText, null);
  // Explore gets every down host at once (Explore ORs repeated host: terms).
  const q = new URLSearchParams(v.primary.href.split('?')[1]).get('q');
  assert.equal(q, 'host:b.example.com host:d.example.com host:a.example.com host:e.example.com host:f.example.com host:g.example.com host:c.example.com');
});
check('one down site keeps the single-site verdict without a list', () => {
  const v = m.verdict({ sites: [], upstreams: [CHECKED('10.0.0.1:80', ['a.example.com'], 0)], configuredSites: 1, now: NOW });
  assert.equal(v.down, null);
});
check('sent to visitors: "N% from host" with a share, hidden with one site', () => {
  const sites = [site('nas.example.com', 10, 0, 100, 3_000_000), site('b.example.com', 10, 0, 100, 7_000_000)];
  const bytes = m.kpis({ sites }).find(k => k.key === 'bytes');
  assert.equal(bytes.label, 'Sent to visitors, last hour');
  assert.deepEqual(bytes.share, { text: '70% from b.example.com', pct: 70 });
  assert.equal(bytes.title, 'Response bodies Caddy sent for logged requests (sites that import access_log)');
  assert.equal(m.kpis({ sites: [site('nas.example.com', 279, 3, 141, 3_000_000), site('x', 1, 0, 1, 7_000_000)] })[3].share.text, '70% from x');
  assert.equal(m.kpis({ sites: [site('a', 1, 0, 1, 500)] })[3].share, null);
  assert.equal(m.kpis({ sites: [site('a', 1, 0, 1, 0), site('b', 1, 0, 1, 0)] })[3].share, null);
  const s30 = [site('nas.example.com', 1, 0, 1, 30), site('a', 1, 0, 1, 25), site('b', 1, 0, 1, 25), site('c', 1, 0, 1, 20)];
  assert.equal(m.kpis({ sites: s30 })[3].share.text, '30% from nas.example.com');
});
check('requests sparkline sums every site\'s series point by point', () => {
  const a = { ...site('a', 6, 0), series: [1, 2, 3] };
  const b = { ...site('b', 6, 0), series: [4, 0, 2] };
  const c = { ...site('c', 0, 0), series: [] };
  assert.deepEqual(m.sumSeries([a, b, c]), [5, 2, 5]);
  assert.deepEqual(m.sumSeries([a, { ...b, series: [1, 1, 1, 1] }]), [2, 3, 4, 1]);
  assert.deepEqual(m.sumSeries([]), []);
  assert.deepEqual(m.sumSeries([{ ...a, series: undefined }]), []);
  assert.deepEqual(m.kpis({ sites: [a, b] })[0].spark, [5, 2, 5]);
});
check('5xx rate level: warn at 1%, crit at 5%', () => {
  assert.equal(m.kpis({ sites: [site('a', 1000, 9)] })[1].level, null);
  assert.equal(m.kpis({ sites: [site('a', 1000, 10)] })[1].level, 'warn');
  assert.equal(m.kpis({ sites: [site('a', 1000, 50)] })[1].level, 'crit');
});
check('config card has a short state word for the tile', () => {
  assert.equal(m.configCard(status(), NOW).word, 'Valid');
  assert.equal(m.configCard(status({ config_valid: false }), NOW).word, 'Check failed');
  assert.equal(m.configCard(status({ config_valid: null, config_check_level: 'unavailable' }), NOW).word, 'Not checked');
});
console.log(`\n${passed} passed`);
