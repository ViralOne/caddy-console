// The save dialog's summary: counts, line numbers and the sites a change touches.
// Run with: node tests/diff-summary.test.mjs
import assert from 'node:assert/strict';
import path from 'node:path';

const APP = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app');
globalThis.document = { createElement: () => ({}), createDocumentFragment: () => ({}), getElementById: () => ({}) };
const { summarizeOps } = await import(path.join(APP, 'diff.js'));
const { affectedSites } = await import(path.join(APP, 'caddyfile-sites.js'));

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };

check('summarizeOps numbers removed lines in the old text and added lines in the new', () => {
  const ops = [{ type: 'equal' }, { type: 'delete' }, { type: 'insert' }, { type: 'equal' }, { type: 'insert' }, { type: 'insert' }];
  assert.deepEqual(summarizeOps(ops), { added: 3, removed: 1, oldLines: [2], newLines: [2, 4, 5] });
});
check('affectedSites names each site once, from both sides of the diff', () => {
  const oldText = 'a.example.com {\n\treverse_proxy 1:1\n}\nb.example.com {\n\trespond 200\n}\n';
  const newText = 'a.example.com {\n\treverse_proxy 1:2\n}\nc.example.com {\n\trespond 200\n}\n';
  assert.deepEqual(affectedSites({ oldLines: [2, 4], newLines: [2, 4] }, oldText, newText),
    ['a.example.com', 'c.example.com', 'b.example.com']);
});
check('no site blocks touched gives an empty list', () =>
  assert.deepEqual(affectedSites({ oldLines: [1], newLines: [1] }, '{\n}\n', '{\n\tdebug\n}\n'), []));
console.log(`\n${passed} passed`);
