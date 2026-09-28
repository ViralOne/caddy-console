// Tests for src/static/js/app/jsonview.js
//
// The colouriser is a text tokeniser, so it is checked directly rather than
// through a rendered DOM. Run with: node tests/jsonview.test.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const SRC = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app', 'jsonview.js');
const source = fs.readFileSync(SRC, 'utf8');

// Re-create the module's tokeniser against a recording stub, so the classes it
// assigns and the text it emits can both be asserted without a DOM.
const TOKEN = new RegExp(
  source.match(/const TOKEN = \/(.*)\/g;/)[1], 'g');
const classOf = new Function('match', 'keyColon', source
  .match(/function classOf\(match, keyColon\) \{([\s\S]*?)\n\}/)[1]);

function tokenise(text) {
  const out = [];
  let last = 0, m;
  TOKEN.lastIndex = 0;
  while ((m = TOKEN.exec(text)) !== null) {
    if (m.index > last) out.push({ text: text.slice(last, m.index) });
    out.push({ text: m[0], cls: classOf(m[0], m[1]) });
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push({ text: text.slice(last) });
  return out;
}

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };

console.log('\n--- token classes ---');
check('a string followed by a colon is a key', () => {
  const t = tokenise('{\n  "host": "a.example.com"\n}');
  assert.equal(t.find(x => x.text.startsWith('"host"')).cls, 'jv-key');
  assert.equal(t.find(x => x.text === '"a.example.com"').cls, 'jv-string');
});
check('numbers, booleans and null are distinguished', () => {
  const t = tokenise('{"a": 1, "b": 1.5, "c": -2e3, "d": true, "e": null}');
  const cls = (v) => t.find(x => x.text === v)?.cls;
  assert.equal(cls('1'), 'jv-number');
  assert.equal(cls('1.5'), 'jv-number');
  assert.equal(cls('-2e3'), 'jv-number');
  assert.equal(cls('true'), 'jv-bool');
  assert.equal(cls('null'), 'jv-null');
});
check('a string containing a colon is not mistaken for a key', () => {
  const t = tokenise('{"uri": "/a:b"}');
  assert.equal(t.find(x => x.text === '"/a:b"').cls, 'jv-string');
});
check('escaped quotes do not end a string early', () => {
  const t = tokenise('{"q": "say \\"hi\\" now"}');
  const str = t.find(x => x.cls === 'jv-string');
  assert.equal(str.text, '"say \\"hi\\" now"');
});

console.log('\n--- no text is lost ---');
check('concatenating the tokens reproduces the input exactly', () => {
  // Nothing may be dropped: this view exists to show the real bytes.
  const samples = [
    '{"ts": 1790000000.5, "request": {"host": "a", "uri": "/x?y=1"}, "status": 502}',
    '{}',
    '{"a": [1, 2, {"b": null}]}',
    '{"weird": "a\\\\b", "n": -0.5}',
  ];
  for (const s of samples) {
    const formatted = JSON.stringify(JSON.parse(s), null, 2);
    assert.equal(tokenise(formatted).map(t => t.text).join(''), formatted, s);
  }
});

console.log('\n--- markup cannot be smuggled in ---');
check('a log line containing HTML stays text', () => {
  // Tokens become text nodes, so this is about the tokeniser not treating the
  // markup specially and the renderer never being handed raw HTML.
  const line = '{"uri": "/<img src=x onerror=alert(1)>"}';
  const formatted = JSON.stringify(JSON.parse(line), null, 2);
  const tokens = tokenise(formatted);
  const str = tokens.find(t => t.cls === 'jv-string');
  assert.ok(str.text.includes('<img'));
  assert.equal(tokens.map(t => t.text).join(''), formatted);
  assert.ok(!source.includes('dangerouslySetInnerHTML'));
  assert.ok(!source.includes('innerHTML'));
});

console.log('\n--- formatting ---');
check('a one-line entry becomes indented lines', () => {
  const line = '{"ts":1,"request":{"host":"a","uri":"/x"},"status":200}';
  const formatted = JSON.stringify(JSON.parse(line), null, 2);
  assert.ok(formatted.split('\n').length > 5);
  assert.ok(formatted.includes('\n  "request": {'));
});
check('key order from the original line is preserved', () => {
  const line = '{"z":1,"a":2,"m":3}';
  const formatted = JSON.stringify(JSON.parse(line), null, 2);
  assert.deepEqual(formatted.match(/"[zam]"/g), ['"z"', '"a"', '"m"']);
});

console.log(`\n${passed} checks passed\n`);
