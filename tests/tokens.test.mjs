// Tests for src/static/css/tokens.css
//
// Every var(--x) the app uses must be defined, and every text colour must meet
// WCAG AA (4.5:1) on all three surfaces in both themes.
// Run with: node tests/tokens.test.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.join(import.meta.dirname, '..', 'src');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const tokens = read('static/css/tokens.css');

function block(selectorRe) {
  const m = tokens.match(new RegExp(selectorRe + '\\s*\\{([^}]*)\\}'));
  assert.ok(m, `missing block ${selectorRe}`);
  return Object.fromEntries([...m[1].matchAll(/--([\w-]+)\s*:\s*([^;]+);/g)].map(x => [x[1], x[2].trim()]));
}
const dark = block(':root,\\s*\\[data-theme="dark"\\]');
const light = block('\\[data-theme="light"\\]');

function lum(hex) {
  const v = hex.replace('#', '');
  const [r, g, b] = [0, 2, 4].map(i => parseInt(v.slice(i, i + 2), 16) / 255)
    .map(c => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };

console.log('\n--- contrast ---');
for (const [name, theme] of [['dark', dark], ['light', light]]) {
  for (const fg of ['ink', 'ink-2', 'ink-3', 'accent', 'good', 'warn', 'serious', 'crit', 'info', 'other']) {
    for (const bg of ['bg', 'bg-2', 'bg-3']) {
      check(`${name}: --${fg} on --${bg} >= 4.5`, () => {
        const r = ratio(theme[fg], theme[bg]);
        assert.ok(r >= 4.5, `${theme[fg]} on ${theme[bg]} is ${r.toFixed(2)}`);
      });
    }
  }
  check(`${name}: --accent-ink on --accent >= 4.5`, () => assert.ok(ratio(theme['accent-ink'], theme.accent) >= 4.5));
  check(`${name}: --selection-ink on --selection-bg >= 4.5`, () => assert.ok(ratio(theme['selection-ink'], theme['selection-bg']) >= 4.5));
}

console.log('\n--- every referenced variable is defined ---');
const defined = new Set([...tokens.matchAll(/--([\w-]+)\s*:/g)].map(m => m[1]));
const style = read('static/css/style.css');
for (const m of style.matchAll(/(?:^|[;{\s])--([\w-]+)\s*:/g)) defined.add(m[1]);   // component-local custom props
const sources = [
  ['static/css/style.css', style],
  ...fs.readdirSync(path.join(ROOT, 'static/js/app'), { recursive: true })
    .filter(f => String(f).endsWith('.js'))
    .map(f => [`static/js/app/${f}`, read(`static/js/app/${f}`)]),
  ...fs.readdirSync(path.join(ROOT, 'templates')).map(f => [`templates/${f}`, read(`templates/${f}`)]),
];
for (const [file, text] of sources) {
  const missing = [...new Set([...text.matchAll(/var\(--([\w-]+)/g)].map(m => m[1]))].filter(v => !defined.has(v));
  check(`${file} uses only defined variables`, () => assert.deepEqual(missing, []));
}

console.log(`\n${passed} passed`);
