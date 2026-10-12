// Tests for src/static/js/app/ip-info.js. Run with:
//   node tests/ip-info.test.mjs
import assert from 'node:assert/strict';
import path from 'node:path';

const SRC = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app', 'ip-info.js');
const { asnLine, flagOf, kindLabel, kindNote, placeLine, placement, sourceLine } = await import(SRC);

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };

check('flag from a country code', () => {
  assert.equal(flagOf('US'), '\u{1F1FA}\u{1F1F8}');
  assert.equal(flagOf('ro'), '\u{1F1F7}\u{1F1F4}');
});
check('no flag for junk', () => {
  for (const bad of [undefined, null, '', 'USA', '1A', 'ZZZ']) assert.equal(flagOf(bad), '');
});
check('place skips missing and repeated parts', () => {
  assert.equal(placeLine({ city: 'Oakland', region: 'California', country: 'United States' }),
               'Oakland, California, United States');
  assert.equal(placeLine({ city: 'Singapore', region: 'Singapore', country: 'Singapore' }), 'Singapore');
  assert.equal(placeLine({ city: null, region: null, country: 'France' }), 'France');
  assert.equal(placeLine(null), '');
});
check('asn line', () => {
  assert.equal(asnLine({ number: 7018, org: 'AT&T' }), 'AS7018 · AT&T');
  assert.equal(asnLine({ number: null, org: null }), '');
  assert.equal(asnLine(null), '');
});
check('kinds have labels, and non-public ones explain themselves', () => {
  assert.equal(kindLabel('public'), 'Public IP');
  assert.equal(kindLabel('???'), 'IP address');
  assert.equal(kindNote('public'), '');
  assert.ok(kindNote('private').length > 0);
});
check('source line covers every state', () => {
  assert.equal(sourceLine({ available: true, name: 'DB-IP', version: '2026-10' }), 'IP data by DB-IP · 2026-10');
  assert.match(sourceLine({ available: false, downloading: true }), /Downloading/);
  assert.match(sourceLine({ available: false, last_error: 'HTTP 500' }), /failed: HTTP 500/);
  assert.match(sourceLine({ available: false }), /docs\/setup.md/);
});

check('opens below the IP when there is room', () => {
  const p = placement({ top: 100, bottom: 120, left: 300 }, { width: 1400, height: 900 });
  assert.equal(p.top, 124);
  assert.equal(p.bottom, undefined);
  assert.equal(p.maxHeight, 900 - 120 - 4 - 8);
});
check('flips above near the bottom of the screen', () => {
  const p = placement({ top: 800, bottom: 820, left: 300 }, { width: 1400, height: 900 });
  assert.equal(p.bottom, 900 - 800 + 4);
  assert.equal(p.top, undefined);
});
check('never runs off the right edge', () => {
  const p = placement({ top: 100, bottom: 120, left: 1300 }, { width: 1400, height: 900 });
  assert.equal(p.left, 1400 - 340 - 8);
});

console.log(`\n${passed} checks passed\n`);
