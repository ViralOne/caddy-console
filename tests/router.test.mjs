// Tests for src/static/js/app/router.js
//
// The URL is the contract for shared links, so the state <-> query-string
// mapping is worth pinning down. Run with: node tests/router.test.mjs
import assert from 'node:assert/strict';
import path from 'node:path';

// The module reads location/history only inside the navigation helpers, but stub
// them so an accidental touch fails loudly rather than crashing the import.
globalThis.location = { pathname: '/', search: '', origin: 'http://x' };
globalThis.history = { state: null, pushState() {}, replaceState() {} };

const SRC = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app', 'router.js');
const { viewFromPath, pathFor, exploreStateFromSearch, exploreStateToSearch } = await import(SRC);

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };

console.log('\n--- viewFromPath ---');
check('root is the dashboard', () => assert.equal(viewFromPath('/'), 'dashboard'));
check('editor and explore map to themselves', () => {
  assert.equal(viewFromPath('/editor'), 'editor');
  assert.equal(viewFromPath('/explore'), 'explore');
});
check('trailing slashes are tolerated', () => {
  assert.equal(viewFromPath('/editor/'), 'editor');
  assert.equal(viewFromPath('/explore//'), 'explore');
});
check('unknown paths fall back to the dashboard', () => {
  // Flask 404s unknown paths, so this only matters for in-app navigation.
  assert.equal(viewFromPath('/nope'), 'dashboard');
  assert.equal(viewFromPath(''), 'dashboard');
  assert.equal(viewFromPath(undefined), 'dashboard');
});

console.log('\n--- pathFor ---');
check('round-trips every view', () => {
  for (const v of ['dashboard', 'editor', 'explore']) {
    assert.equal(viewFromPath(pathFor(v)), v);
  }
});
check('an unknown view is the dashboard path', () => assert.equal(pathFor('wat'), '/'));

console.log('\n--- exploreStateFromSearch ---');
check('an empty query string gives the defaults', () => {
  const s = exploreStateFromSearch('');
  assert.deepEqual(s, { q: '', range: '30m', custom: null, live: false });
});
check('reads q, range and window', () => {
  const s = exploreStateFromSearch('?q=status%3A5xx&range=1h');
  assert.equal(s.q, 'status:5xx');
  assert.equal(s.range, '1h');
});
check('an absolute range needs both ends', () => {
  assert.deepEqual(exploreStateFromSearch('?from=100&to=200').custom, { from: 100, to: 200 });
  assert.equal(exploreStateFromSearch('?from=100').custom, null);
  assert.equal(exploreStateFromSearch('?to=200').custom, null);
  assert.equal(exploreStateFromSearch('?from=abc&to=200').custom, null);
});
check('live is only true for 1', () => {
  assert.equal(exploreStateFromSearch('?live=1').live, true);
  assert.equal(exploreStateFromSearch('?live=0').live, false);
  assert.equal(exploreStateFromSearch('?live=yes').live, false);
});

console.log('\n--- exploreStateToSearch ---');
check('defaults are omitted, keeping a plain URL clean', () => {
  assert.equal(exploreStateToSearch({ q: '', range: '30m', custom: null, live: false }), '');
});
check('writes only what differs', () => {
  const s = exploreStateToSearch({ q: 'status:5xx', range: '30m', custom: null, live: false });
  assert.equal(s, 'q=status%3A5xx');
});
check('an absolute range replaces range, so a link cannot drift', () => {
  const s = exploreStateToSearch({ q: '', range: '1h', custom: { from: 100.7, to: 200.2 }, live: false });
  const p = new URLSearchParams(s);
  assert.equal(p.get('from'), '100');   // floored
  assert.equal(p.get('to'), '201');     // ceiled, so the range never loses an event
  assert.equal(p.has('range'), false);
});
check('live is recorded', () => {
  assert.ok(new URLSearchParams(exploreStateToSearch({ q: '', range: '30m', custom: null, live: true })).has('live'));
});

console.log('\n--- round trip ---');
check('state survives a serialise/parse cycle', () => {
  const cases = [
    { q: 'host:a status:5xx', range: '1h', custom: null, live: false },
    { q: '', range: '7d', custom: null, live: true },
    { q: 'timeout', range: '30m', custom: { from: 1790000000, to: 1790003600 }, live: false },
  ];
  for (const want of cases) {
    const got = exploreStateFromSearch('?' + exploreStateToSearch(want));
    assert.deepEqual(got, want, JSON.stringify(want));
  }
});
check('a query with quoted spaces survives the round trip', () => {
  const want = { q: 'path:"/a b"', range: '30m', custom: null, live: false };
  assert.deepEqual(exploreStateFromSearch('?' + exploreStateToSearch(want)), want);
});

console.log(`\n${passed} checks passed\n`);
