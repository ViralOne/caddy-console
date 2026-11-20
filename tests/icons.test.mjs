// Every icon name the app uses has a symbol in the sprite.
// Run with: node tests/icons.test.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const SRC = path.join(import.meta.dirname, '..', 'src');
const sprite = fs.readFileSync(path.join(SRC, 'templates', '_icons.html'), 'utf8');
const symbols = new Set([...sprite.matchAll(/<symbol id="i-([\w-]+)"/g)].map(m => m[1]));
const iconsJs = fs.readFileSync(path.join(SRC, 'static', 'js', 'app', 'icons.js'), 'utf8');
const listed = [...iconsJs.match(/export const ICONS = \[([\s\S]*?)\];/)[1].matchAll(/'([\w-]+)'/g)].map(m => m[1]);

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };

check('every ICONS entry has a sprite symbol', () => assert.deepEqual(listed.filter(n => !symbols.has(n)), []));
for (const f of fs.readdirSync(path.join(SRC, 'static', 'js', 'app'), { recursive: true }).map(String).filter(f => f.endsWith('.js'))) {
  const text = fs.readFileSync(path.join(SRC, 'static', 'js', 'app', f), 'utf8');
  const used = [
    ...text.matchAll(/<\$\{Icon\} name="([\w-]+)"/g),
    ...text.matchAll(/iconEl\('([\w-]+)'/g),
    ...text.matchAll(/\bicon: '([\w-]+)'/g),
  ].map(m => m[1]);
  check(`${f} uses only listed icons`, () => assert.deepEqual(used.filter(n => !listed.includes(n)), []));
}
for (const f of fs.readdirSync(path.join(SRC, 'templates'))) {
  const text = fs.readFileSync(path.join(SRC, 'templates', f), 'utf8');
  const used = [...text.matchAll(/href="#i-([\w-]+)"/g)].map(m => m[1]);
  check(`templates/${f} references existing symbols`, () => assert.deepEqual(used.filter(n => !symbols.has(n)), []));
}
console.log(`\n${passed} passed`);
