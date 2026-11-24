// Structural checks on the app shell template.
// Run with: node tests/shell.test.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const html = fs.readFileSync(path.join(import.meta.dirname, '..', 'src', 'templates', 'index.html'), 'utf8');
let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };

check('tabs are Dashboard, Explore, Editor, plus Security only behind the bans flag', () => {
  const tabs = [...html.matchAll(/class="tab" data-view="(\w+)"/g)].map(m => m[1]);
  assert.deepEqual(tabs, ['dashboard', 'explore', 'editor', 'security']);
  assert.match(html, /{% if bans_enabled %}<a class="tab" data-view="security"/);
});
check('the Security tab and view render only when bans are enabled', () => {
  for (const marker of ['data-view="security"', 'id="tab-security"']) {
    const at = html.indexOf(marker);
    const open = html.lastIndexOf('{% if bans_enabled %}', at);
    const close = html.lastIndexOf('{% endif %}', at);
    assert.ok(at > 0 && open >= 0 && open > close, `${marker} is not inside {% if bans_enabled %}`);
  }
});
check('the status bar lives inside the editor view', () => {
  const start = html.indexOf('id="tab-editor"');
  const end = html.indexOf('</section>', start);
  const sbar = html.indexOf('class="sbar"');
  assert.ok(start > 0 && sbar > start && sbar < end, 'status bar outside #tab-editor');
});
check('editor tools start hidden', () => assert.match(html, /class="etools" data-for-view="editor" hidden/));
check('one inline script, the hashed theme boot', () => assert.equal((html.match(/<script>/g) || []).length, 1));
check('no inline event handlers', () => assert.doesNotMatch(html, /\son[a-z]+="/));
console.log(`\n${passed} passed`);
