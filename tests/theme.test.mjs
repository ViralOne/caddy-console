// Tests for src/static/js/app/theme.js
//
// Run with: node tests/theme.test.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const store = new Map();
globalThis.localStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
};
const attrs = {};
globalThis.document = { documentElement: { getAttribute: (k) => attrs[k] ?? null, setAttribute: (k, v) => { attrs[k] = v; } } };
let mqListener = null;
let osLight = false;
globalThis.matchMedia = () => ({ get matches() { return osLight; }, addEventListener: (_, fn) => { mqListener = fn; } });
const events = [];
globalThis.dispatchEvent = (e) => events.push(e);

const SRC = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app', 'theme.js');
const { THEMES, getThemePref, setThemePref, resolveTheme, applyTheme, currentTheme, watchSystemTheme } = await import(SRC);

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };

console.log('\n--- theme preference ---');
check('offers system, dark and light', () => assert.deepEqual(THEMES.map(t => t.id), ['system', 'dark', 'light']));
check('defaults to system', () => assert.equal(getThemePref(), 'system'));
check('stores dark and light, and system removes the key', () => {
  setThemePref('light'); assert.equal(store.get('ui.theme'), 'light'); assert.equal(getThemePref(), 'light');
  setThemePref('system'); assert.equal(store.has('ui.theme'), false); assert.equal(getThemePref(), 'system');
});
check('refuses unknown values', () => assert.throws(() => setThemePref('sepia')));
check('an unknown stored value reads as system', () => { store.set('ui.theme', 'sepia'); assert.equal(getThemePref(), 'system'); store.delete('ui.theme'); });
check('resolveTheme: explicit wins, system follows the OS', () => {
  assert.equal(resolveTheme('dark', true), 'dark');
  assert.equal(resolveTheme('light', false), 'light');
  assert.equal(resolveTheme('system', true), 'light');
  assert.equal(resolveTheme('system', false), 'dark');
});
check('applyTheme sets data-theme and announces a change once', () => {
  events.length = 0;
  assert.equal(applyTheme('light'), 'light');
  assert.equal(attrs['data-theme'], 'light');
  assert.equal(currentTheme(), 'light');
  applyTheme('light');
  assert.equal(events.length, 1);
  assert.equal(events[0].detail.theme, 'light');
});
check('watchSystemTheme follows the OS only while the preference is system', () => {
  watchSystemTheme();
  setThemePref('system'); osLight = false; applyTheme();
  osLight = true; mqListener();
  assert.equal(attrs['data-theme'], 'light');
  setThemePref('dark'); applyTheme();
  osLight = false; mqListener(); osLight = true; mqListener();
  assert.equal(attrs['data-theme'], 'dark');
});
check('blocked storage falls back to system without throwing', () => {
  const saved = globalThis.localStorage;
  globalThis.localStorage = { getItem() { throw new Error('denied'); }, setItem() { throw new Error('denied'); }, removeItem() { throw new Error('denied'); } };
  try {
    assert.equal(getThemePref(), 'system');
    assert.doesNotThrow(() => setThemePref('dark'));
  } finally { globalThis.localStorage = saved; }
});
check('the inline boot script uses the same key', () => {
  const py = fs.readFileSync(path.join(import.meta.dirname, '..', 'src', 'theme_boot.py'), 'utf8');
  assert.match(py, /localStorage\.getItem\('ui\.theme'\)/);
});

console.log(`\n${passed} passed`);
