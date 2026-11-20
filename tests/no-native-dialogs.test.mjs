// No native alert()/confirm()/prompt() anywhere in the app's own scripts: they
// block the page, ignore the theme and cannot carry consequence copy.
// Run with: node tests/no-native-dialogs.test.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const JS = path.join(import.meta.dirname, '..', 'src', 'static', 'js');
const BUNDLES = new Set(['editor.bundle.js', 'explore-vendor.js']);
const files = fs.readdirSync(JS, { recursive: true })
  .map(String).filter(f => f.endsWith('.js') && !BUNDLES.has(path.basename(f)));
const NATIVE = /(?<![\w$.])(?:window\.)?(alert|confirm|prompt)\s*\(/;

let passed = 0;
for (const f of files) {
  const code = fs.readFileSync(path.join(JS, f), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:'"`])\/\/.*$/gm, '$1');
  const hit = code.split('\n').find(line => NATIVE.test(line));
  assert.equal(hit, undefined, `${f} still calls a native dialog: ${hit && hit.trim()}`);
  passed++;
  console.log(`  ok  ${f}`);
}
console.log(`\n${passed} passed`);
