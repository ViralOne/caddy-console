// Tests for src/static/js/app/warnings.js
// Run with: node tests/warnings.test.mjs
import assert from 'node:assert/strict';
import path from 'node:path';

const SRC = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app', 'warnings.js');
const { parseWarning, withoutFormat } = await import(SRC);

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };
const FMT = 'Line 12: not formatted — Check will fix whitespace on 2 lines';
const DNS = 'Line 58: upstream radarr:7878 could not be resolved from the console container';

check('line-linked format warning', () => assert.deepEqual(parseWarning(FMT),
  { line: 12, text: 'Not formatted — Check will fix whitespace on 2 lines', kind: 'fmt' }));
check('line-linked resolve warning', () => assert.deepEqual(parseWarning(DNS),
  { line: 58, text: 'Upstream radarr:7878 could not be resolved from the console container', kind: 'dns' }));
check('a warning without a line keeps its text', () => assert.deepEqual(
  parseWarning("Access logging is enabled without 'format filter'"),
  { line: null, text: "Access logging is enabled without 'format filter'", kind: 'other' }));
check('blockingWarnings drops the format warning', () => assert.deepEqual(withoutFormat([FMT, DNS]), [DNS]));
console.log(`\n${passed} passed`);
