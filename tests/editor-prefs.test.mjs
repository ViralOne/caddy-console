// Tests for src/static/js/app/editor-prefs.js
//
// Run with: node tests/editor-prefs.test.mjs
import assert from 'node:assert/strict';
import path from 'node:path';

const store = new Map();
globalThis.localStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
};

const SRC = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app', 'editor-prefs.js');
const { KEYMAPS, getKeymap, setKeymap } = await import(SRC);

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };

console.log('\n--- editor keymap preference ---');
check('offers standard and vim', () => assert.deepEqual(KEYMAPS.map(k => k.id), ['standard', 'vim']));
check('defaults to standard when nothing is saved', () => assert.equal(getKeymap(), 'standard'));
check('round-trips vim', () => {
  setKeymap('vim');
  assert.equal(getKeymap(), 'vim');
});
check('round-trips back to standard', () => {
  setKeymap('standard');
  assert.equal(getKeymap(), 'standard');
});
check('an unknown stored value falls back to standard', () => {
  store.set('editor.keymap', 'emacs');
  assert.equal(getKeymap(), 'standard');
});
check('refuses to store an unknown value', () => {
  setKeymap('vim');
  assert.throws(() => setKeymap('nano'));
  assert.equal(getKeymap(), 'vim');
});
check('storage that throws (private mode, disabled) falls back to standard', () => {
  const saved = globalThis.localStorage;
  globalThis.localStorage = { getItem() { throw new Error('denied'); }, setItem() { throw new Error('denied'); } };
  try {
    assert.equal(getKeymap(), 'standard');
    assert.doesNotThrow(() => setKeymap('vim'));
  } finally {
    globalThis.localStorage = saved;
  }
});

console.log(`\n${passed} passed`);
