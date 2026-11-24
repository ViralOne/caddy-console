// Tests for src/static/js/app/snippet-insert.js and the shipped ban snippets.
// Run with: node tests/snippet-insert.test.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.join(import.meta.dirname, '..');
const { globToRegExp, importMatches, planSiteInsertion } = await import(path.join(ROOT, 'src', 'static', 'js', 'app', 'snippet-insert.js'));
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

const snippets = JSON.parse(fs.readFileSync(path.join(ROOT, 'src', 'snippets.json'), 'utf8'));
check('the site snippet carries the spec metadata', () => {
  const s = snippets.find(x => x.id === 'manual-bans-site');
  assert.deepEqual({ id: s.id, phase: s.phase, scope: s.scope, supported_modes: s.supported_modes, prerequisites: s.prerequisites, code: s.code }, {
    id: 'manual-bans-site', phase: 'manual', scope: 'site',
    supported_modes: ['direct', 'cloudflare-proxied', 'cloudflare-tunnel'], prerequisites: ['BANS_ENABLED'],
    code: 'import /etc/caddy/console/bans-manual*.caddy\n',
  });
});
check('scopes: site snippets insert first, host snippets are copy only', () => {
  for (const s of snippets.filter(x => x.scope)) {
    assert.equal(s.insert, s.scope === 'site' ? 'site-first' : 'copy-only', s.id);
  }
  assert.doesNotMatch(snippets.find(x => x.id === 'manual-bans-recovery').code, /^import /m);
});
console.log(`\n${passed} passed`);
