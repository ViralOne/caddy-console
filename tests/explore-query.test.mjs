// Tests for src/static/js/app/explore-query.js
//
// Pure module, so it imports directly — no DOM stub needed. Run with:
//   node tests/explore-query.test.mjs
import assert from 'node:assert/strict';
import path from 'node:path';

const SRC = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app', 'explore-query.js');
const {
  tokenize, term, hasTerm, termState, setTermState, cycleTerm, removeKey, activeKeys,
  placeholderFor,
} = await import(SRC);

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };

console.log('\n--- tokenize ---');
check('splits on whitespace', () => {
  assert.deepEqual(tokenize('host:a status:5xx'), ['host:a', 'status:5xx']);
});
check('keeps quoted values together', () => {
  assert.deepEqual(tokenize('path:"/a b" x'), ['path:/a b', 'x']);
});
check('empty and whitespace-only give nothing', () => {
  assert.deepEqual(tokenize(''), []);
  assert.deepEqual(tokenize('   '), []);
  assert.deepEqual(tokenize(undefined), []);
});
check('collapses runs of whitespace', () => {
  assert.deepEqual(tokenize('a   b\tc'), ['a', 'b', 'c']);
});

console.log('\n--- term + hasTerm ---');
check('builds a plain term', () => assert.equal(term('host', 'a.example.com'), 'host:a.example.com'));
check('negates', () => assert.equal(term('status', '2xx', true), '-status:2xx'));
check('quotes values containing spaces', () => assert.equal(term('path', '/a b'), 'path:"/a b"'));
check('finds a present term', () => assert.ok(hasTerm('host:a status:5xx', 'host', 'a')));
check('is case-insensitive', () => assert.ok(hasTerm('HOST:A', 'host', 'a')));
check('does not match a different value', () => assert.ok(!hasTerm('host:a', 'host', 'b')));
check('does not match a prefix', () => assert.ok(!hasTerm('host:abc', 'host', 'ab')));
check('an excluded value is not "included"', () => assert.ok(!hasTerm('-host:a', 'host', 'a')));
check('matches a value that had to be quoted', () => {
  // The token loses its quotes when tokenised, so matching on the rendered
  // string would never fire for a value containing a space.
  assert.ok(hasTerm('path:"/a b"', 'path', '/a b'));
});

console.log('\n--- termState ---');
check('off when absent', () => assert.equal(termState('status:5xx', 'host', 'a'), 'off'));
check('include for a plain term', () => assert.equal(termState('host:a', 'host', 'a'), 'include'));
check('exclude for a negated term', () => assert.equal(termState('-host:a', 'host', 'a'), 'exclude'));
check('is case-insensitive in both polarities', () => {
  assert.equal(termState('HOST:A', 'host', 'a'), 'include');
  assert.equal(termState('-HOST:A', 'host', 'a'), 'exclude');
});
check('a different value is still off', () => assert.equal(termState('-host:a', 'host', 'b'), 'off'));

console.log('\n--- setTermState ---');
check('adds when absent', () => assert.equal(setTermState('', 'host', 'a', 'include'), 'host:a'));
check('appends to an existing query', () => {
  assert.equal(setTermState('status:5xx', 'host', 'a', 'include'), 'status:5xx host:a');
});
check('writes the negated form', () => assert.equal(setTermState('', 'host', 'a', 'exclude'), '-host:a'));
check('off removes the term in either polarity', () => {
  assert.equal(setTermState('host:a status:5xx', 'host', 'a', 'off'), 'status:5xx');
  assert.equal(setTermState('-host:a status:5xx', 'host', 'a', 'off'), 'status:5xx');
});
check('flips polarity in place, so the query does not reorder', () => {
  assert.equal(setTermState('host:a status:5xx', 'host', 'a', 'exclude'), '-host:a status:5xx');
  assert.equal(setTermState('-host:a status:5xx', 'host', 'a', 'include'), 'host:a status:5xx');
});
check('is idempotent — setting the state it already has changes nothing', () => {
  assert.equal(setTermState('-host:a', 'host', 'a', 'exclude'), '-host:a');
  assert.equal(setTermState('host:a', 'host', 'a', 'include'), 'host:a');
});
check('collapses a duplicated value to one term', () => {
  assert.equal(setTermState('host:a host:a', 'host', 'a', 'exclude'), '-host:a');
});
check('leaves the other values for the same key alone', () => {
  assert.equal(setTermState('host:a host:b', 'host', 'a', 'exclude'), '-host:a host:b');
});
check('keeps free text untouched', () => {
  assert.equal(setTermState('timeout', 'host', 'a', 'exclude'), 'timeout -host:a');
});
check('preserves quoting when reassembling', () => {
  // The value with a space must not silently split into two terms.
  const q = setTermState('path:"/a b"', 'host', 'x', 'include');
  assert.equal(q, 'path:"/a b" host:x');
  assert.deepEqual(tokenize(q), ['path:/a b', 'host:x']);
});
check('quotes a negated value that needs it', () => {
  assert.equal(setTermState('', 'path', '/a b', 'exclude'), '-path:"/a b"');
});

console.log('\n--- cycleTerm ---');
check('unset -> include -> unset', () => {
  const a = cycleTerm('', 'host', 'a');
  assert.equal(a, 'host:a');
  assert.equal(cycleTerm(a, 'host', 'a'), '');
});
check('never reaches exclude — that has its own control', () => {
  let q = '';
  for (let i = 0; i < 6; i++) {
    q = cycleTerm(q, 'host', 'a');
    assert.ok(!q.includes('-host:a'), `click ${i + 1} produced ${q}`);
  }
});
check('clears an excluded value in one click', () => {
  assert.equal(cycleTerm('-host:a', 'host', 'a'), '');
});
check('toggles one value without disturbing the rest of the query', () => {
  let q = 'status:5xx timeout';
  q = cycleTerm(q, 'host', 'a');
  assert.equal(q, 'status:5xx timeout host:a');
  q = cycleTerm(q, 'host', 'a');
  assert.equal(q, 'status:5xx timeout');
});
check('two clicks return to the starting query', () => {
  const start = 'method:GET';
  let q = start;
  for (let i = 0; i < 2; i++) q = cycleTerm(q, 'path', '/api/v1');
  assert.equal(q, start);
});

console.log('\n--- removeKey ---');
check('drops every term for a key', () => {
  assert.equal(removeKey('host:a host:b status:5xx', 'host'), 'status:5xx');
});
check('drops negated terms too', () => {
  assert.equal(removeKey('-host:a status:5xx', 'host'), 'status:5xx');
});
check('leaves free text alone', () => {
  assert.equal(removeKey('host:a timeout', 'host'), 'timeout');
});
check('is a no-op for an absent key', () => {
  assert.equal(removeKey('status:5xx', 'host'), 'status:5xx');
});

console.log('\n--- activeKeys ---');
check('reports constrained keys', () => {
  assert.deepEqual([...activeKeys('host:a status:5xx')].sort(), ['host', 'status']);
});
check('counts negated terms as constraining', () => {
  assert.deepEqual([...activeKeys('-status:2xx')], ['status']);
  assert.deepEqual([...activeKeys('-path:/api')], ['path']);
});
check('ignores free text and unknown keys', () => {
  assert.deepEqual([...activeKeys('timeout wat:x')], []);
});

console.log('\n--- placeholderFor ---');
check('uses the busiest host in the window', () => {
  const data = { facets: { host: [{ value: 'a.example.com', count: 9 }, { value: 'b.example.com', count: 2 }] } };
  assert.equal(placeholderFor(data), 'host:a.example.com -status:2xx  \u2014  or any text');
});
check('never hardcodes a hostname when there is no data', () => {
  for (const empty of [null, undefined, {}, { facets: {} }, { facets: { host: [] } }]) {
    assert.match(placeholderFor(empty), /^host:\u2026 /);
  }
});
check('skips the unnameable host so the example is filterable', () => {
  // The empty host is a real facet value but not something you can type.
  const data = { facets: { host: [{ value: '', count: 5 }, { value: 'real.example.com', count: 1 }] } };
  assert.match(placeholderFor(data), /^host:real\.example\.com /);
});
check('quotes a host that would otherwise split', () => {
  const data = { facets: { host: [{ value: 'weird host', count: 1 }] } };
  assert.ok(placeholderFor(data).startsWith('host:"weird host"'));
});

console.log(`\n${passed} checks passed\n`);
