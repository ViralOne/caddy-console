// The editor must fill its row. `.editor-wrap` is a row flexbox, so CodeMirror's
// root element only spans the full width if it is allowed to grow; without that
// it shrinks to its widest line and leaves the rest of the screen empty.
// Run with: node tests/editor-layout.test.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const css = fs.readFileSync(
  path.join(import.meta.dirname, '..', 'src', 'static', 'css', 'style.css'), 'utf8');

const rule = css.match(/#cm-editor \.cm-editor\{([^}]*)\}/);
assert.ok(rule, 'a `#cm-editor .cm-editor{…}` rule exists');
const body = rule[1].replace(/\s+/g, '');
assert.match(body, /(^|;)flex:1(;|$)/, 'CodeMirror grows to fill the editor row');
assert.match(body, /(^|;)min-width:0(;|$)/, 'long lines scroll inside the editor instead of widening it');
assert.match(body, /(^|;)height:100%(;|$)/, 'CodeMirror fills the editor height');

console.log('  ok  editor fills its row\n\n1 passed');
