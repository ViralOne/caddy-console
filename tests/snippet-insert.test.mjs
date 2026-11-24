// Tests for src/static/js/app/snippet-insert.js and the shipped ban snippets.
// Run with: node tests/snippet-insert.test.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.join(import.meta.dirname, '..');
const { COUNTRY_FILE, COUNTRY_IMPORT_AFTER, IMPORT_AFTER, PLUGIN_IMPORT_AFTER, PLUGIN_SNIPPET, SOURCE_FILES, globToRegExp, clientIpGate, globalOptionsBlock, importMatches, planGlobalOptionInsertion, planServersInsertion, planSiteInsertion, planTopLevelInsertion, pluginGate } = await import(path.join(ROOT, 'src', 'static', 'js', 'app', 'snippet-insert.js'));
let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };

const T = '/etc/caddy/console/bans-manual.caddy';
const CODE = 'import /etc/caddy/console/bans-manual*.caddy\n';
const OPTS = { target: T, managementHosts: ['console.example.com'] };
const CF = [
  '{', '\tadmin 0.0.0.0:2019', '}', '',                                   // 1-4
  '(snip) {', '\theader -Server', '}', '',                                // 5-8
  '&(app) {', '\trespond "x"', '}', '',                                   // 9-12
  'a.example.com {', '\treverse_proxy 127.0.0.1:9', '}', '',              // 13-16
  'b.example.com {', '    encode gzip', '    reverse_proxy 127.0.0.1:9', '}', '',   // 17-21
  'c.example.com {', '\troute {', '\t\timport /etc/caddy/console/*.caddy', '\t}', '}', '',  // 22-27
  'console.example.com {', '\treverse_proxy caddy-console:9090', '}',    // 28-30
].join('\n');
const applyPlan = (text, plan) => {
  const lines = text.split('\n');
  lines.splice(plan.line - 1, 0, plan.text.replace(/\n$/, ''));
  return lines.join('\n');
};

check('inserts first in the site, with the block indentation', () => {
  for (const cursor of [13, 14, 15]) {
    const p = planSiteInsertion(CF, cursor, CODE, OPTS);
    assert.deepEqual([p.ok, p.line, p.text], [true, 14, '\timport /etc/caddy/console/bans-manual*.caddy\n']);
  }
  const b = planSiteInsertion(CF, 18, CODE, OPTS);
  assert.deepEqual([b.line, b.text], [18, '    import /etc/caddy/console/bans-manual*.caddy\n']);
});
check('outside a site block nothing is inserted', () => {
  for (const cursor of [2, 6, 10, 16]) assert.equal(planSiteInsertion(CF, cursor, CODE, OPTS).reason, 'outside-site', `line ${cursor}`);
});
check('an equivalent import is never inserted twice', () => {
  assert.deepEqual([planSiteInsertion(CF, 23, CODE, OPTS).reason, planSiteInsertion(CF, 23, CODE, OPTS).line], ['duplicate', 24]);
  const once = applyPlan(CF, planSiteInsertion(CF, 14, CODE, OPTS));
  assert.equal(planSiteInsertion(once, 14, CODE, OPTS).reason, 'duplicate');
});
check('the console site is never offered the import', () =>
  assert.equal(planSiteInsertion(CF, 29, CODE, OPTS).reason, 'management-site'));
check('glob matching follows Caddy', () => {
  assert.equal(importMatches('access_log', T), false);
  assert.equal(importMatches('/etc/caddy/*.caddy', T), false);
  assert.equal(importMatches('/etc/caddy/console/*.caddy', T), true);
  assert.equal(importMatches('console/bans-manual*.caddy', T), true);
  assert.equal(globToRegExp('/a/b?.caddy').test('/a/bx.caddy'), true);
});

check('management hosts compare case-insensitively', () =>
  assert.equal(planSiteInsertion(CF, 29, CODE, { target: T, managementHosts: ['Console.Example.COM'] }).reason, 'management-site'));
check('a site opened on the last line (no trailing newline) appends after it', () => {
  const p = planSiteInsertion('a.example.com {', 1, CODE, OPTS);
  assert.deepEqual([p.ok, p.line, p.text], [true, 2, '\n\timport /etc/caddy/console/bans-manual*.caddy']);
  assert.equal(p.atEnd, true);
});
const snippets = JSON.parse(fs.readFileSync(path.join(ROOT, 'src', 'snippets.json'), 'utf8'));
check('the site snippet carries the spec metadata', () => {
  const s = snippets.find(x => x.id === 'manual-bans-site');
  assert.deepEqual({ id: s.id, phase: s.phase, scope: s.scope, supported_modes: s.supported_modes, prerequisites: s.prerequisites, code: s.code }, {
    id: 'manual-bans-site', phase: 'manual', scope: 'site',
    supported_modes: ['direct', 'cloudflare-proxied', 'cloudflare-tunnel'], prerequisites: ['BANS_ENABLED'],
    code: 'import /etc/caddy/console/bans-manual*.caddy\n',
  });
});
check('scopes: ban imports insert first in a site, everything else is copy only', () => {
  for (const s of snippets.filter(x => x.scope && x.phase !== 'plugin' && x.phase !== 'cloudflare')) {
    const importsBans = s.scope === 'site' && /^import \S*(bans-\w+|geo)\*\.caddy\n$/.test(s.code);
    assert.equal(s.insert, importsBans ? 'site-first' : 'copy-only', s.id);
  }
  assert.doesNotMatch(snippets.find(x => x.id === 'manual-bans-recovery').code, /^import /m);
});
const CS_T = '/etc/caddy/console/bans-crowdsec.caddy';
const CS_CODE = 'import /etc/caddy/console/bans-crowdsec*.caddy\n';
const CS_OPTS = { target: CS_T, managementHosts: ['console.example.com'], after: [T] };
const WITH_MANUAL = ['a.example.com {', '\timport /etc/caddy/console/bans-manual*.caddy', '\treverse_proxy 127.0.0.1:9', '}', ''].join('\n');
check('the CrowdSec import goes directly after the manual import', () => {
  const p = planSiteInsertion(WITH_MANUAL, 1, CS_CODE, CS_OPTS);
  assert.deepEqual([p.ok, p.line, p.text], [true, 3, '\timport /etc/caddy/console/bans-crowdsec*.caddy\n']);
});
check('without a manual import the CrowdSec import goes first', () => {
  const p = planSiteInsertion(CF, 13, CS_CODE, CS_OPTS);
  assert.deepEqual([p.ok, p.line], [true, 14]);
});
check('the CrowdSec import is not inserted twice, nor into the console site', () => {
  const twice = applyPlan(WITH_MANUAL, planSiteInsertion(WITH_MANUAL, 1, CS_CODE, CS_OPTS));
  assert.equal(planSiteInsertion(twice, 1, CS_CODE, CS_OPTS).reason, 'duplicate');
  assert.equal(planSiteInsertion(CF, 29, CS_CODE, CS_OPTS).reason, 'management-site');
});
check('the CrowdSec snippets carry their metadata', () => {
  const s = snippets.find(x => x.id === 'crowdsec-bans-site');
  assert.deepEqual([s.phase, s.scope, s.insert, s.prerequisites, s.code],
    ['crowdsec', 'site', 'site-first', ['BANS_ENABLED', 'CROWDSEC_URL'], CS_CODE]);
  const f = snippets.find(x => x.id === 'crowdsec-log-fields');
  assert.deepEqual([f.scope, f.insert, f.prerequisites], ['site', 'copy-only', ['BANS_ENABLED', 'CROWDSEC_URL']]);
  assert.match(f.code, /^log_append <user_agent \{http\.request\.header\.User-Agent\}$/m);
  assert.match(f.code, /^log_append auth_challenge \{http\.response\.header\.Www-Authenticate\}$/m);
  assert.doesNotMatch(f.code, /Authorization|Cookie/i);
});
check('IMPORT_AFTER mirrors render.AFTER in src/bans/render.py', () => {
  const py = fs.readFileSync(path.join(ROOT, 'src', 'bans', 'render.py'), 'utf8');
  const m = py.match(/^AFTER = \{(.*)\}$/m);
  assert.ok(m, 'render.AFTER not found');
  const parsed = {};
  for (const [, k, v] of m[1].matchAll(/"(\w+)":\s*\(([^)]*)\)/g)) parsed[k] = [...v.matchAll(/"(\w+)"/g)].map(x => x[1]);
  assert.deepEqual(IMPORT_AFTER, parsed);
});
check('SOURCE_FILES mirrors the PolicySource file names', () => {
  const py = fs.readFileSync(path.join(ROOT, 'src', 'bans', 'render.py'), 'utf8');
  for (const [name, file] of Object.entries(SOURCE_FILES)) assert.match(py, new RegExp(`"${name}": PolicySource\\("${name}", "${file}"`));
});
console.log('\n--- CrowdSec plugin scopes ---');
const FIX = path.join(ROOT, 'tests', 'fixtures', 'plugin');
const fixture = (n) => fs.readFileSync(path.join(FIX, n), 'utf8');
const byId = Object.fromEntries(snippets.filter(s => s.id).map(s => [s.id, s]));
const DIR = '/etc/caddy/console';
const DEF_T = `${DIR}/crowdsec-plugin-protect.caddy`;
const SITE_OPTS = { snippetName: PLUGIN_SNIPPET, managementHosts: ['console.example.com'],
  after: PLUGIN_IMPORT_AFTER.map(a => `${DIR}/${SOURCE_FILES[a]}`) };
const insertAll = (text, globalId) => {
  let t = applyPlan(text, planGlobalOptionInsertion(text, byId[globalId].code));
  t = applyPlan(t, planTopLevelInsertion(t, byId['crowdsec-plugin-definition'].code, { target: DEF_T }));
  const site = t.split('\n').indexOf('plugin.example.com {') + 1;
  return applyPlan(t, planSiteInsertion(t, site, byId['crowdsec-plugin-site'].code, SITE_OPTS));
};
check('the shipped plugin snippets produce exactly the adapted fixtures, in both secret modes', () => {
  assert.equal(insertAll(fixture('base.Caddyfile'), 'crowdsec-plugin-global-env'), fixture('env.Caddyfile'));
  assert.equal(insertAll(fixture('base.Caddyfile'), 'crowdsec-plugin-global-file'), fixture('file.Caddyfile'));
});
check('the global options block is found, and created when missing', () => {
  assert.deepEqual(globalOptionsBlock(fixture('base.Caddyfile')), { start: 1, end: 5 });
  assert.equal(globalOptionsBlock('a.example.com {\n}\n'), null);
  assert.equal(globalOptionsBlock('# c\n\n{\n\tdebug\n}\n').start, 3);
  const p = planGlobalOptionInsertion('a.example.com {\n\trespond 200\n}\n', 'order crowdsec first\n');
  assert.deepEqual([p.ok, p.line, p.text], [true, 1, '{\n\torder crowdsec first\n}\n\n']);
});
check('the global app is never inserted twice', () => {
  const env = fixture('env.Caddyfile');
  const p = planGlobalOptionInsertion(env, byId['crowdsec-plugin-global-file'].code);
  assert.deepEqual([p.ok, p.reason, p.line], [false, 'duplicate-global', 5]);
});
check('the definition goes below the global options, once, at top level only', () => {
  const env = fixture('env.Caddyfile');
  assert.equal(planTopLevelInsertion(env, byId['crowdsec-plugin-definition'].code, { target: DEF_T }).reason, 'duplicate');
  const bare = 'a.example.com {\n\trespond 200\n}\n';
  const p = planTopLevelInsertion(bare, byId['crowdsec-plugin-definition'].code, { target: DEF_T });
  assert.deepEqual([p.line, p.text], [1, `import ${DIR}/crowdsec-plugin-protect*.caddy\n\n`]);
  const end = planTopLevelInsertion('{\n\tdebug\n}', byId['crowdsec-plugin-definition'].code, { target: DEF_T });
  assert.deepEqual([end.line, end.atEnd, end.text], [4, true, `\n\nimport ${DIR}/crowdsec-plugin-protect*.caddy`]);
  // An import of the definition inside a site is not a top-level duplicate.
  const inSite = `a.example.com {\n\timport ${DIR}/crowdsec-plugin-protect*.caddy\n}\n`;
  assert.equal(planTopLevelInsertion(inSite, byId['crowdsec-plugin-definition'].code, { target: DEF_T }).ok, true);
});
check('the site import follows the ban imports, is matched by name, and never goes into the console site', () => {
  const env = fixture('env.Caddyfile');
  const site = env.split('\n').indexOf('plugin.example.com {') + 1;
  assert.equal(planSiteInsertion(env, site, 'import protect_crowdsec\n', SITE_OPTS).reason, 'duplicate');
  const file = env.split('\n').indexOf('file.example.com {') + 1;
  const p = planSiteInsertion(env, file, 'import protect_crowdsec\n', SITE_OPTS);
  assert.deepEqual([p.ok, p.line], [true, file + 3], 'after the manual and CrowdSec file imports');
  assert.equal(planSiteInsertion(CF, 29, 'import protect_crowdsec\n', SITE_OPTS).reason, 'management-site');
  // Without snippetName the name is never a duplicate of a file glob (old behaviour kept).
  assert.equal(importMatches('protect_crowdsec', DEF_T), false);
});
check('plugin snippets are offered only when their prerequisites hold', () => {
  const ok = { module: true, blocked: '', app_live: true, definition_import: true, definition_current: true };
  const site = byId['crowdsec-plugin-site'];
  const def = byId['crowdsec-plugin-definition'];
  const glob = byId['crowdsec-plugin-global-env'];
  assert.equal(pluginGate(site, ok), null);
  assert.equal(pluginGate(site, null), 'plugin-unavailable');
  assert.equal(pluginGate(glob, { ...ok, module: false }), 'plugin-module-missing');
  assert.equal(pluginGate(glob, { ...ok, module: null }), null, 'unknown build: Check will tell');
  assert.equal(pluginGate(glob, { ...ok, blocked: 'Caddy admin listens on every interface' }), 'plugin-blocked');
  assert.equal(pluginGate(def, { ...ok, definition_current: false }), 'plugin-definition-stale');
  assert.equal(pluginGate(site, { ...ok, app_live: false }), 'plugin-app-missing');
  assert.equal(pluginGate(site, { ...ok, definition_import: false }), 'plugin-definition-missing');
  assert.equal(pluginGate(site, { ...ok, definition_current: false }), 'plugin-definition-missing');
  assert.equal(pluginGate(glob, { ...ok, app_live: false, definition_import: false }), null);
});
check('plugin snippet scopes', () => {
  assert.deepEqual(['crowdsec-plugin-global-env', 'crowdsec-plugin-global-file', 'crowdsec-plugin-definition',
    'crowdsec-plugin-site', 'crowdsec-plugin-allowlist'].map(id => [byId[id].scope, byId[id].insert]),
  [['global', 'global-options'], ['global', 'global-options'], ['top-level', 'top-level'], ['site', 'site-first'], ['host', 'copy-only']]);
});

console.log('\n--- Phase 4 snippets ---');
const GEO_T = `${DIR}/${COUNTRY_FILE}`;
const GEO_OPTS = { target: GEO_T, managementHosts: ['console.example.com'], after: COUNTRY_IMPORT_AFTER.map(a => `${DIR}/${SOURCE_FILES[a]}`) };
check('the old ambiguous Cloudflare Only snippet is gone and the four new ones are shipped', () => {
  assert.equal(snippets.some(s => s.name === 'Cloudflare Only'), false);
  assert.deepEqual(['cloudflare-proxied-real-ip', 'cloudflare-tunnel-real-ip', 'country-policy-site', 'cloudflare-origin-guard']
    .map(id => [byId[id].scope, byId[id].insert]), [['servers', 'servers'], ['servers', 'servers'], ['site', 'site-first'], ['site', 'site-first']]);
  assert.deepEqual(['cloudflare-proxied-real-ip', 'cloudflare-tunnel-real-ip'].map(id => byId[id].code),
    Array(2).fill('import /etc/caddy/console/cloudflare-trusted-proxies*.caddy\nclient_ip_headers CF-Connecting-IP\n'));
  assert.equal(byId['country-policy-site'].code, 'import /etc/caddy/console/geo*.caddy\n');
});
check('the origin guard matches remote_ip and never a forwarding header', () => {
  const g = byId['cloudflare-origin-guard'].code;
  assert.match(g, /^@not_cloudflare_origin not remote_ip 173\.245\.48\.0\/20 .*2400:cb00::\/32 .*192\.168\.1\.0\/24$/m);
  assert.match(g, /^handle @not_cloudflare_origin \{\n\trespond 403\n\}\n$/m);
  assert.doesNotMatch(g, /^respond /m, 'a bare respond runs after handle');
  assert.match(byId['cloudflare-origin-guard'].description, /Replace the example LAN range/);
  assert.doesNotMatch(g, /header|client_ip|CF-|X-Forwarded/i);
});
check('the country import follows the ban imports and is never inserted twice or into the console site', () => {
  const geo = 'import /etc/caddy/console/geo*.caddy\n';
  const p = planSiteInsertion(WITH_MANUAL, 1, geo, GEO_OPTS);
  assert.deepEqual([p.ok, p.line, p.text], [true, 3, '\timport /etc/caddy/console/geo*.caddy\n']);
  assert.equal(planSiteInsertion(applyPlan(WITH_MANUAL, p), 1, geo, GEO_OPTS).reason, 'duplicate');
  assert.equal(planSiteInsertion(CF, 29, geo, GEO_OPTS).reason, 'management-site');
});
check('the origin guard is inserted with every line indented, once, and never into the console site', () => {
  const guard = 'a.example.com {\n\treverse_proxy 127.0.0.1:9\n}\n';
  const o = { marker: '@not_cloudflare_origin', managementHosts: ['console.example.com'] };
  const p = planSiteInsertion(guard, 1, 'x\nhandle @y {\n\trespond 403\n}\n', o);
  assert.equal(p.text, '\tx\n\thandle @y {\n\t\trespond 403\n\t}\n');
  const code = byId['cloudflare-origin-guard'].code;
  const once = applyPlan(guard, planSiteInsertion(guard, 1, code, o));
  assert.match(once, /^\t@not_cloudflare_origin not remote_ip /m);
  assert.match(once, /^\thandle @not_cloudflare_origin \{\n\t\trespond 403\n\t\}$/m);
  assert.equal(planSiteInsertion(once, 1, code, o).reason, 'duplicate');
  assert.equal(planSiteInsertion(CF, 29, code, o).reason, 'management-site');
});
const SRV_T = `${DIR}/cloudflare-trusted-proxies.caddy`;
const SRV = byId['cloudflare-proxied-real-ip'].code;
check('servers snippets create the global options and servers block when missing', () => {
  const p = planServersInsertion('a.example.com {\n}\n', SRV, { target: SRV_T });
  assert.deepEqual([p.ok, p.line], [true, 1]);
  assert.equal(p.text, '{\n\tservers {\n\t\timport /etc/caddy/console/cloudflare-trusted-proxies*.caddy\n\t\tclient_ip_headers CF-Connecting-IP\n\t}\n}\n\n');
  const q = planServersInsertion(CF, SRV, { target: SRV_T });
  assert.equal(q.line, 3);
  assert.match(applyPlan(CF, q), /\tadmin 0\.0\.0\.0:2019\n\tservers \{\n\t\timport .*\n\t\tclient_ip_headers CF-Connecting-IP\n\t\}\n\}/);
});
check('servers snippets add only the missing lines to an existing bare servers block, and never twice', () => {
  const base = '{\n\tservers {\n\t\ttimeouts {\n\t\t\tidle 5m\n\t\t}\n\t}\n}\n\na.example.com {\n}\n';
  const p = planServersInsertion(base, SRV, { target: SRV_T });
  assert.deepEqual([p.ok, p.line], [true, 6]);
  const done = applyPlan(base, p);
  assert.match(done, /\t\t\}\n\t\timport .*cloudflare-trusted-proxies\*\.caddy\n\t\tclient_ip_headers CF-Connecting-IP\n\t\}/);
  assert.equal(planServersInsertion(done, SRV, { target: SRV_T }).reason, 'duplicate');
  const partial = '{\n\tservers {\n\t\tclient_ip_headers CF-Connecting-IP\n\t}\n}\n';
  const r = planServersInsertion(partial, SRV, { target: SRV_T });
  assert.equal(r.text, '\t\timport /etc/caddy/console/cloudflare-trusted-proxies*.caddy\n');
});
check('a named servers block is left alone', () => {
  const named = '{\n\tservers :8443 {\n\t\tprotocols h1\n\t}\n}\n';
  assert.equal(planServersInsertion(named, SRV, { target: SRV_T }).line, 5);
});
check('the client-IP gate matches the snippet to the saved profile', () => {
  const proxied = byId['cloudflare-proxied-real-ip'], tunnel = byId['cloudflare-tunnel-real-ip'], guard = byId['cloudflare-origin-guard'];
  const ctx = { mode: 'cloudflare-proxied', current: true, peers: ['1.0.0.0/8'] };
  assert.equal(clientIpGate(proxied, ctx), null);
  assert.equal(clientIpGate(guard, ctx), null);
  assert.equal(clientIpGate(proxied, null), 'client-ip-unavailable');
  assert.equal(clientIpGate(tunnel, ctx), 'client-ip-mode');
  assert.equal(clientIpGate(proxied, { ...ctx, mode: 'direct' }), 'client-ip-mode');
  assert.equal(clientIpGate(proxied, { ...ctx, current: false }), 'client-ip-stale');
  assert.equal(clientIpGate(tunnel, { mode: 'cloudflare-tunnel', current: true, peers: [] }), 'client-ip-peer');
  assert.equal(clientIpGate(tunnel, { mode: 'cloudflare-tunnel', current: true, peers: ['172.18.0.5'] }), null);
  assert.equal(clientIpGate(byId['country-policy-site'], null), null);
});
check('COUNTRY constants mirror src/bans/render.py', () => {
  const py = fs.readFileSync(path.join(ROOT, 'src', 'bans', 'render.py'), 'utf8');
  assert.match(py, new RegExp(`COUNTRY = PolicySource\\("country", "${COUNTRY_FILE}"`));
  assert.match(py, new RegExp(`COUNTRY_AFTER = \\(${COUNTRY_IMPORT_AFTER.map(a => `"${a}"`).join(', ')}\\)`));
});
console.log(`\n${passed} passed`);
