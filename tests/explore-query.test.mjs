// Tests for src/static/js/app/explore-query.js
//
// Pure module, so it imports directly — no DOM stub needed. Run with:
//   node tests/explore-query.test.mjs
import assert from 'node:assert/strict';
import path from 'node:path';

const SRC = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app', 'explore-query.js');
const { tokenize, term, hasTerm, toggleTerm, removeKey, activeKeys } = await import(SRC);

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

console.log('\n--- toggleTerm ---');
check('adds when absent', () => assert.equal(toggleTerm('', 'host', 'a'), 'host:a'));
check('appends to an existing query', () => {
  assert.equal(toggleTerm('status:5xx', 'host', 'a'), 'status:5xx host:a');
});
check('removes when present', () => assert.equal(toggleTerm('host:a status:5xx', 'host', 'a'), 'status:5xx'));
check('round-trips', () => {
  const once = toggleTerm('status:5xx', 'host', 'a');
  assert.equal(toggleTerm(once, 'host', 'a'), 'status:5xx');
});
check('keeps free text untouched', () => {
  assert.equal(toggleTerm('timeout', 'host', 'a'), 'timeout host:a');
});
check('preserves quoting when reassembling', () => {
  // The value with a space must not silently split into two terms.
  const q = toggleTerm('path:"/a b"', 'host', 'x');
  assert.equal(q, 'path:"/a b" host:x');
  assert.deepEqual(tokenize(q), ['path:/a b', 'host:x']);
});
check('toggling one of two values for a key leaves the other', () => {
  assert.equal(toggleTerm('host:a host:b', 'host', 'a'), 'host:b');
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
});
check('ignores free text and unknown keys', () => {
  assert.deepEqual([...activeKeys('timeout wat:x')], []);
});

console.log(`\n${passed} checks passed\n`);
