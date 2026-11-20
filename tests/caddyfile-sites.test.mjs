// Tests for src/static/js/app/caddyfile-sites.js
// Run with: node tests/caddyfile-sites.test.mjs
import assert from 'node:assert/strict';
import path from 'node:path';

const SRC = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app', 'caddyfile-sites.js');
const { hostOf, siteBlocks, findSiteBlockLine, sitesForLines } = await import(SRC);

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };

const CF = [
  '{', '\temail ops@example.com', '}', '',                              // 1-4 global options
  '(security_headers) {', '\theader -Server', '}', '',                  // 5-8 snippet
  'nas.example.com {', '\treverse_proxy 127.0.0.1:5000', '}', '',       // 9-12
  'http://a.example.com, b.example.com:8443 {',                         // 13
  '\trespond "hi {remote_host}" 200', '}', '',                          // 14-16
  '*.wild.example.com {', '\trespond 200', '}',                         // 17-19
  '# photos.example.com {', '',                                         // 20-21 commented out
].join('\n');

check('hostOf strips scheme, port and path', () => {
  assert.equal(hostOf('http://A.example.com:8443/x'), 'a.example.com');
  assert.equal(hostOf(':8080'), '');
});
check('site blocks skip global options and snippets', () => assert.deepEqual(
  siteBlocks(CF).map(b => [b.hosts, b.start, b.end]),
  [[['nas.example.com'], 9, 11], [['a.example.com', 'b.example.com'], 13, 15], [['*.wild.example.com'], 17, 19]]));
check('finds a host in a comma list with a scheme and a port', () => assert.equal(findSiteBlockLine(CF, 'b.example.com'), 13));
check('is case-insensitive', () => assert.equal(findSiteBlockLine(CF, 'NAS.example.com'), 9));
check('falls back to a one-label wildcard', () => {
  assert.equal(findSiteBlockLine(CF, 'x.wild.example.com'), 17);
  assert.equal(findSiteBlockLine(CF, 'a.b.wild.example.com'), null);
});
check('commented-out and unknown hosts are not found', () => {
  assert.equal(findSiteBlockLine(CF, 'photos.example.com'), null);
  assert.equal(findSiteBlockLine(CF, ''), null);
});
check('sitesForLines names each touched block once', () => assert.deepEqual(
  sitesForLines(CF, [10, 14, 15, 2]), ['nas.example.com', 'a.example.com']));
console.log(`\n${passed} passed`);
