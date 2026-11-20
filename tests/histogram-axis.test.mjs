// Tests for src/static/js/app/histogram-axis.js
// Run with: node tests/histogram-axis.test.mjs
import assert from 'node:assert/strict';
import path from 'node:path';

const SRC = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app', 'histogram-axis.js');
const { axisTicks, formatSpan, formatTick, stepIndex } = await import(SRC);

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };
const sec = (...a) => new Date(...a).getTime() / 1000;
const FROM = sec(2026, 10, 20, 13, 40);
const TO = sec(2026, 10, 20, 14, 40);

check('five labels, edges aligned inward so none is clipped', () => {
  const t = axisTicks({ from: FROM, to: TO, bucketSeconds: 60, now: TO });
  assert.deepEqual(t.map(x => x.label), ['13:40', '13:55', '14:10', '14:25', 'now, 14:40']);
  assert.deepEqual(t.map(x => x.align), ['start', 'middle', 'middle', 'middle', 'end']);
  assert.deepEqual(t.map(x => x.pct), [0, 25, 50, 75, 100]);
});
check('a past range does not say "now"', () =>
  assert.equal(axisTicks({ from: FROM, to: TO, bucketSeconds: 60, now: TO + 3600 }).at(-1).label, '14:40'));
check('day buckets label dates', () => assert.equal(formatTick(sec(2026, 10, 3, 12), 86400), '11/03'));
check('stepIndex starts at the newest bucket and clamps', () => {
  assert.equal(stepIndex(null, -1, 10), 9);
  assert.equal(stepIndex(5, -1, 10), 4);
  assert.equal(stepIndex(0, -1, 10), 0);
  assert.equal(stepIndex(9, 1, 10), 9);
  assert.equal(stepIndex(3, 1, 0), null);
});
check('formatSpan', () => { assert.equal(formatSpan(300), '5m'); assert.equal(formatSpan(3600), '1h'); });
console.log(`\n${passed} passed`);
