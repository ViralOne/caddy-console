// Tests for collapseOps in src/static/js/app/diff.js: a diff shows the changes
// with a few lines of context, not the whole file.
// Run with: node tests/diff-collapse.test.mjs
import assert from 'node:assert/strict';
import path from 'node:path';

const SRC = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app', 'diff.js');
const { diffLines, collapseOps } = await import(SRC);

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };
const lines = (n, from = 1) => Array.from({ length: n }, (_, i) => `line ${i + from}`);
const kinds = (rows) => rows.map(r => r.kind === 'skip' ? `skip${r.count}` : r.kind).join(' ');

console.log('\n--- collapseOps ---');

check('no changes collapses to nothing', () => {
  const a = lines(20);
  assert.deepEqual(collapseOps(diffLines(a, a)), []);
});

check('one change in the middle keeps 3 lines of context each side', () => {
  const a = lines(40);
  const b = a.slice(); b[19] = 'changed';
  const rows = collapseOps(diffLines(a, b));
  assert.equal(kinds(rows), 'skip16 eq eq eq del ins eq eq eq skip17');
  const del = rows.find(r => r.kind === 'del');
  assert.equal(del.aLn, 20);
  assert.equal(rows.find(r => r.kind === 'ins').bLn, 20);
  assert.equal(rows[1].aLn, 17, 'first context line is line 17');
});

check('hidden rows carry their own line numbers for expanding', () => {
  const a = lines(40);
  const b = a.slice(); b[19] = 'changed';
  const skip = collapseOps(diffLines(a, b))[0];
  assert.equal(skip.rows.length, 16);
  assert.deepEqual([skip.rows[0].aLn, skip.rows[15].aLn], [1, 16]);
  assert.equal(skip.rows[0].line, 'line 1');
});

check('a change near the start has no leading skip', () => {
  const a = lines(20);
  const b = a.slice(); b[1] = 'changed';
  assert.equal(kinds(collapseOps(diffLines(a, b))), 'eq del ins eq eq eq skip15');
});

check('two nearby changes share their context instead of a tiny skip', () => {
  const a = lines(30);
  const b = a.slice(); b[9] = 'x'; b[15] = 'y';
  // 5 unchanged lines between the changes: fewer than 2*context+minSkip, so all shown
  assert.equal(kinds(collapseOps(diffLines(a, b))),
    'skip6 eq eq eq del ins eq eq eq eq eq del ins eq eq eq skip11');
});

check('short unchanged runs are not collapsed', () => {
  const a = lines(8);
  const b = a.slice(); b[3] = 'changed';
  assert.equal(collapseOps(diffLines(a, b)).some(r => r.kind === 'skip'), false);
});

check('context is configurable', () => {
  const a = lines(40);
  const b = a.slice(); b[19] = 'changed';
  assert.equal(kinds(collapseOps(diffLines(a, b), 1)), 'skip18 eq del ins eq skip19');
});

console.log(`\n${passed} passed`);
