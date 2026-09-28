// Correctness + performance tests for src/static/js/app/diff.js
//
// diff.js is an ES module, so it is imported directly against a stubbed global
// `document`. Run with: node tests/diff.test.mjs
import path from 'node:path';
import assert from 'node:assert/strict';

const SRC = path.join(import.meta.dirname, '..', 'src', 'static', 'js', 'app', 'diff.js');

function loadDiff() {
  const makeEl = (isFragment = false) => ({
    style: {}, _text: '', children: [], isFragment,
    set textContent(v) { this._text = v; this.children.length = 0; },
    get textContent() { return this._text; },
    // Mirror the real DOM: appending a fragment moves its children into the
    // parent and leaves the fragment empty.
    appendChild(c) {
      if (c.isFragment) { this.children.push(...c.children); c.children.length = 0; }
      else this.children.push(c);
      return c;
    },
  });
  // diff.js only touches the DOM inside its functions, so a global stub is
  // enough and the module can be imported normally.
  globalThis.document = {
    createElement: () => makeEl(),
    createDocumentFragment: () => makeEl(true),
    getElementById: () => makeEl(),
  };
  return { makeEl };
}

const { makeEl } = loadDiff();
const { diffLines, renderDiffInto } = await import(SRC);

// --- Reference implementation: the original O(n*m) LCS. Slow but known-correct,
// and it produces a provably minimal number of changes.
function referenceDiff(a, b) {
  const n = a.length, m = b.length;
  const dp = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = 1; i <= n; i++)
    for (let j = 1; j <= m; j++)
      dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] + 1 : Math.max(dp[i - 1][j], dp[i][j - 1]);
  const ops = [];
  let i = n, j = m;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && a[i - 1] === b[j - 1]) { ops.unshift({ type: 'equal', line: a[i - 1] }); i--; j--; }
    else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) { ops.unshift({ type: 'insert', line: b[j - 1] }); j--; }
    else { ops.unshift({ type: 'delete', line: a[i - 1] }); i--; }
  }
  return ops;
}

const changeCount = (ops) => ops.filter(o => o.type !== 'equal').length;

// An op list is valid iff replaying it reconstructs BOTH sides exactly:
// equal+delete must rebuild `a`, equal+insert must rebuild `b`.
function assertReconstructs(ops, a, b, label) {
  const gotA = ops.filter(o => o.type === 'equal' || o.type === 'delete').map(o => o.line);
  const gotB = ops.filter(o => o.type === 'equal' || o.type === 'insert').map(o => o.line);
  assert.deepEqual(gotA, a, `${label}: equal+delete must reconstruct the old side`);
  assert.deepEqual(gotB, b, `${label}: equal+insert must reconstruct the new side`);
}

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`  ok  ${name}`); };

console.log('\n--- fixed cases ---');

check('both sides empty', () => {
  assertReconstructs(diffLines([], []), [], [], 'empty');
});

check('identical input yields zero changes', () => {
  const a = ['a', 'b', 'c'];
  const ops = diffLines(a, a.slice());
  assertReconstructs(ops, a, a, 'identical');
  assert.equal(changeCount(ops), 0);
});

check('insert into empty', () => {
  const b = ['x', 'y'];
  const ops = diffLines([], b);
  assertReconstructs(ops, [], b, 'insert-into-empty');
  assert.deepEqual(ops.map(o => o.type), ['insert', 'insert']);
});

check('delete everything', () => {
  const a = ['x', 'y'];
  const ops = diffLines(a, []);
  assertReconstructs(ops, a, [], 'delete-all');
  assert.deepEqual(ops.map(o => o.type), ['delete', 'delete']);
});

check('single line changed in the middle', () => {
  const a = ['1', '2', '3', '4', '5'];
  const b = ['1', '2', 'CHANGED', '4', '5'];
  const ops = diffLines(a, b);
  assertReconstructs(ops, a, b, 'single-change');
  assert.equal(changeCount(ops), 2, 'one replaced line = 1 delete + 1 insert');
});

check('duplicate lines are handled', () => {
  const a = ['x', 'x', 'x', 'x'];
  const b = ['x', 'x'];
  const ops = diffLines(a, b);
  assertReconstructs(ops, a, b, 'duplicates');
  assert.equal(changeCount(ops), 2);
});

check('completely disjoint input', () => {
  const a = ['a', 'b', 'c'];
  const b = ['x', 'y', 'z'];
  assertReconstructs(diffLines(a, b), a, b, 'disjoint');
});

check('reordered blocks', () => {
  const a = ['A1', 'A2', 'B1', 'B2'];
  const b = ['B1', 'B2', 'A1', 'A2'];
  assertReconstructs(diffLines(a, b), a, b, 'reorder');
});

check('trailing empty line from split("\\n")', () => {
  const a = 'one\ntwo\n'.split('\n');
  const b = 'one\ntwo\nthree\n'.split('\n');
  assertReconstructs(diffLines(a, b), a, b, 'trailing-newline');
});

console.log('\n--- randomized cases vs the reference LCS ---');

// Deterministic PRNG so failures are reproducible.
let seed = 12345;
const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
const pick = (n) => Math.floor(rnd() * n);

check('500 random edit scenarios reconstruct correctly', () => {
  for (let t = 0; t < 500; t++) {
    const n = pick(40);
    // Small alphabet forces lots of duplicate lines, the tricky case.
    const a = Array.from({ length: n }, () => String(pick(6)));
    const b = a.slice();
    const edits = pick(6);
    for (let e = 0; e < edits; e++) {
      if (b.length === 0 || rnd() < 0.4) b.splice(pick(b.length + 1), 0, String(pick(6)));
      else if (rnd() < 0.5) b.splice(pick(b.length), 1);
      else b[pick(b.length)] = String(pick(6));
    }
    assertReconstructs(diffLines(a, b), a, b, `random#${t} (a=${a.join()} b=${b.join()})`);
  }
});

check('change counts stay within 1.5x of the minimal LCS diff', () => {
  let worst = 0;
  for (let t = 0; t < 200; t++) {
    const n = 10 + pick(50);
    const a = Array.from({ length: n }, (_, i) => `line ${i} ${pick(3)}`);
    const b = a.slice();
    for (let e = 0; e < 1 + pick(5); e++) {
      const r = rnd();
      if (r < 0.34) b.splice(pick(b.length + 1), 0, `new ${pick(99)}`);
      else if (r < 0.67 && b.length) b.splice(pick(b.length), 1);
      else if (b.length) b[pick(b.length)] = `edited ${pick(99)}`;
    }
    const mine = changeCount(diffLines(a, b));
    const best = changeCount(referenceDiff(a, b));
    if (best > 0) worst = Math.max(worst, mine / best);
    assert.ok(mine <= best * 1.5 + 2, `random#${t}: ${mine} changes vs minimal ${best}`);
  }
  console.log(`      (worst ratio vs minimal: ${worst.toFixed(2)}x)`);
});

console.log('\n--- renderDiffInto ---');

check('renders every line plus a "no differences" note when identical', () => {
  const el = makeEl();
  renderDiffInto(el, 'a\nb', 'a\nb');
  assert.equal(el.children.length, 3, '2 context rows + the note');
  assert.match(el.children.at(-1).textContent, /no differences/);
});

check('renders a row per line with +/- markers', () => {
  const el = makeEl();
  renderDiffInto(el, 'keep\nold', 'keep\nnew');
  const text = el.children.map(c => c.textContent);
  assert.equal(text.length, 3);
  assert.ok(text.some(t => t.startsWith('-')), 'expected a deletion row');
  assert.ok(text.some(t => t.startsWith('+')), 'expected an insertion row');
});

console.log('\n--- performance (the regression this replaces) ---');

const genCaddyfile = (sites) => {
  const L = [];
  for (let s = 0; s < sites; s++) {
    L.push(`http://site${s}.example.com {`, '\timport access_log', `\treverse_proxy 192.168.0.103:${8000 + s}`, '}', '');
  }
  return L;
};

check('10,000-line file with a one-line edit diffs in under 150ms', () => {
  const a = genCaddyfile(2000);
  const b = a.slice();
  b[Math.floor(b.length / 2)] = '\treverse_proxy 192.168.0.199:9999';
  const t = process.hrtime.bigint();
  const ops = diffLines(a, b);
  const ms = Number(process.hrtime.bigint() - t) / 1e6;
  assertReconstructs(ops, a, b, 'perf-1-line');
  assert.equal(changeCount(ops), 2);
  console.log(`      10,000 lines, 1 edit: ${ms.toFixed(1)} ms`);
  assert.ok(ms < 150, `expected < 150ms, got ${ms.toFixed(1)}ms`);
});

check('10,000-line file with 200 scattered edits diffs in under 1s', () => {
  const a = genCaddyfile(2000);
  const b = a.slice();
  for (let i = 0; i < 200; i++) b[pick(b.length)] = `\treverse_proxy 10.0.0.${i}:1234`;
  const t = process.hrtime.bigint();
  const ops = diffLines(a, b);
  const ms = Number(process.hrtime.bigint() - t) / 1e6;
  assertReconstructs(ops, a, b, 'perf-200-edits');
  console.log(`      10,000 lines, ~200 edits: ${ms.toFixed(1)} ms`);
  assert.ok(ms < 1000, `expected < 1000ms, got ${ms.toFixed(1)}ms`);
});

check('40,000-line file stays responsive and bounded in memory', () => {
  const a = genCaddyfile(8000);
  const b = a.slice();
  b.splice(20000, 0, '# inserted block', 'http://brand-new.example.com {', '}', '');
  const before = process.memoryUsage().heapUsed;
  const t = process.hrtime.bigint();
  const ops = diffLines(a, b);
  const ms = Number(process.hrtime.bigint() - t) / 1e6;
  const mb = (process.memoryUsage().heapUsed - before) / 1048576;
  assertReconstructs(ops, a, b, 'perf-40k');
  console.log(`      40,000 lines, 1 inserted block: ${ms.toFixed(1)} ms, ~${mb.toFixed(0)} MB`);
  assert.ok(ms < 1000, `expected < 1000ms, got ${ms.toFixed(1)}ms`);
});

console.log(`\n${passed} checks passed\n`);
