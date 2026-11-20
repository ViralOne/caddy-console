// Line-based diff rendering (used by the backups preview and the save modal).
const DIFF_MAX_D = 1200;

// Safety net: patience splitting always shrinks the range, but cap recursion
// anyway so a deep chain of anchors can't overflow the stack.
const DIFF_MAX_DEPTH = 24;

export function renderDiff(current, backup) {
  renderDiffInto(document.getElementById('diff-content'), current, backup);
}

export function renderDiffInto(container, oldText, newText, { context = DIFF_CONTEXT } = {}) {
  container.textContent = '';
  const a = oldText.split('\n'), b = newText.split('\n');
  const ops = diffLines(a, b);
  // Identical texts show in full with a note; real diffs show only the changes
  // with a little context, so the reader lands on what changed.
  const rows = collapseOps(ops, context);
  const shown = rows.length ? rows : allRows(ops);
  // Build off-document and attach once: appending thousands of rows directly to
  // a live container forces a style recalc per row.
  const frag = document.createDocumentFragment();
  for (const row of shown) frag.appendChild(row.kind === 'skip' ? skipButton(row) : rowEl(row));
  if (!rows.length) {
    const d = document.createElement('div');
    d.className = 'diff-meta';
    d.textContent = '(no differences)';
    frag.appendChild(d);
  }
  container.appendChild(frag);
  return summarizeOps(ops);
}

// Lines of unchanged text kept around each change, and the smallest run worth
// collapsing (hiding one or two lines behind a button costs more than it saves).
const DIFF_CONTEXT = 3;
const MIN_SKIP = 4;

function allRows(ops) {
  let aLn = 1, bLn = 1;
  return ops.map(op => ({ kind: 'eq', line: op.line, aLn: aLn++, bLn: bLn++ }));
}

function rowEl(row) {
  const d = document.createElement('div');
  if (row.kind === 'eq') { d.className = 'diff-eq'; d.textContent = ` ${String(row.aLn).padStart(3)} ${row.line}`; }
  else if (row.kind === 'del') { d.className = 'diff-del'; d.textContent = `-${String(row.aLn).padStart(3)} ${row.line}`; }
  else { d.className = 'diff-ins'; d.textContent = `+${String(row.bLn).padStart(3)} ${row.line}`; }
  return d;
}

/** A collapsed run of unchanged lines; clicking it puts the lines back in place. */
function skipButton(row) {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'diff-skip';
  btn.textContent = `Show ${row.count} unchanged ${row.count === 1 ? 'line' : 'lines'}`;
  btn.addEventListener('click', () => {
    const frag = document.createDocumentFragment();
    for (const r of row.rows) frag.appendChild(rowEl(r));
    btn.replaceWith(frag);
  });
  return btn;
}

/** The rows a diff shows: every change, `context` unchanged lines around each,
 *  and longer unchanged runs folded into {kind:'skip', count, rows}. No changes
 *  gives []. Rows carry the old (aLn) and new (bLn) line numbers. */
export function collapseOps(ops, context = DIFF_CONTEXT) {
  const all = [];
  let aLn = 1, bLn = 1;
  for (const op of ops) {
    if (op.type === 'equal') all.push({ kind: 'eq', line: op.line, aLn: aLn++, bLn: bLn++ });
    else if (op.type === 'delete') all.push({ kind: 'del', line: op.line, aLn: aLn++, bLn });
    else all.push({ kind: 'ins', line: op.line, aLn, bLn: bLn++ });
  }
  if (!all.some(r => r.kind !== 'eq')) return [];
  // Distance from each row to the nearest change, so context can be kept on both sides.
  const keep = new Array(all.length).fill(false);
  let last = -Infinity;
  for (let i = 0; i < all.length; i++) {
    if (all[i].kind !== 'eq') last = i;
    if (i - last <= context) keep[i] = true;
  }
  last = Infinity;
  for (let i = all.length - 1; i >= 0; i--) {
    if (all[i].kind !== 'eq') last = i;
    if (last - i <= context) keep[i] = true;
  }
  const out = [];
  for (let i = 0; i < all.length;) {
    if (keep[i]) { out.push(all[i++]); continue; }
    let j = i;
    while (j < all.length && !keep[j]) j++;
    const run = all.slice(i, j);
    if (run.length >= MIN_SKIP) out.push({ kind: 'skip', count: run.length, rows: run });
    else out.push(...run);
    i = j;
  }
  return out;
}

/** Counts and line numbers of a diff: removed lines in the old text, added in the new. */
export function summarizeOps(ops) {
  let a = 1, b = 1;
  const out = { added: 0, removed: 0, oldLines: [], newLines: [] };
  for (const op of ops) {
    if (op.type === 'equal') { a++; b++; }
    else if (op.type === 'delete') { out.removed++; out.oldLines.push(a); a++; }
    else { out.added++; out.newLines.push(b); b++; }
  }
  return out;
}

export function diffLines(a, b) {
  // Intern lines to integers once, so the inner loops compare numbers instead
  // of re-comparing strings that are usually long and share prefixes.
  const idOf = new Map();
  const intern = (lines) => {
    const out = new Int32Array(lines.length);
    for (let i = 0; i < lines.length; i++) {
      let id = idOf.get(lines[i]);
      if (id === undefined) { id = idOf.size; idOf.set(lines[i], id); }
      out[i] = id;
    }
    return out;
  };
  const ops = [];
  diffRange(intern(a), intern(b), 0, a.length, 0, b.length, a, b, ops, 0);
  return ops;
}

// Emits ops for a[lo1,hi1) vs b[lo2,hi2) in order.
function diffRange(ia, ib, lo1, hi1, lo2, hi2, a, b, ops, depth) {
  // Shared prefix: emit now.
  while (lo1 < hi1 && lo2 < hi2 && ia[lo1] === ib[lo2]) {
    ops.push({ type: 'equal', line: a[lo1] });
    lo1++; lo2++;
  }
  // Shared suffix: hold back until the middle has been emitted.
  let suffix = 0;
  while (hi1 > lo1 && hi2 > lo2 && ia[hi1 - 1] === ib[hi2 - 1]) { hi1--; hi2--; suffix++; }

  if (lo1 === hi1 || lo2 === hi2) {
    for (let i = lo1; i < hi1; i++) ops.push({ type: 'delete', line: a[i] });
    for (let j = lo2; j < hi2; j++) ops.push({ type: 'insert', line: b[j] });
  } else {
    const anchors = depth < DIFF_MAX_DEPTH ? uniqueAnchors(ia, ib, lo1, hi1, lo2, hi2) : [];
    if (anchors.length === 0) {
      myers(ia, ib, lo1, hi1, lo2, hi2, a, b, ops);
    } else {
      // Each anchor is a line that is unique on both sides, so it must pair up.
      // Recurse on the gaps; every gap excludes at least the anchor itself, so
      // the ranges strictly shrink.
      let ci = lo1, cj = lo2;
      for (let k = 0; k < anchors.length; k += 2) {
        const ai = anchors[k], bj = anchors[k + 1];
        diffRange(ia, ib, ci, ai, cj, bj, a, b, ops, depth + 1);
        ops.push({ type: 'equal', line: a[ai] });
        ci = ai + 1; cj = bj + 1;
      }
      diffRange(ia, ib, ci, hi1, cj, hi2, a, b, ops, depth + 1);
    }
  }

  for (let s = 0; s < suffix; s++) ops.push({ type: 'equal', line: a[hi1 + s] });
}

// Lines occurring exactly once in both ranges, as a flat [aIdx, bIdx, ...] list
// kept in increasing order on both sides (longest increasing subsequence of the
// b positions, so crossing pairs from reordered blocks are dropped).
function uniqueAnchors(ia, ib, lo1, hi1, lo2, hi2) {
  const countA = new Map(), countB = new Map();
  for (let i = lo1; i < hi1; i++) countA.set(ia[i], (countA.get(ia[i]) || 0) + 1);
  for (let j = lo2; j < hi2; j++) countB.set(ib[j], (countB.get(ib[j]) || 0) + 1);

  const posB = new Map();
  for (let j = lo2; j < hi2; j++) if (countB.get(ib[j]) === 1) posB.set(ib[j], j);

  const ai = [], bj = [];
  for (let i = lo1; i < hi1; i++) {
    if (countA.get(ia[i]) === 1 && countB.get(ia[i]) === 1) { ai.push(i); bj.push(posB.get(ia[i])); }
  }
  if (ai.length === 0) return [];

  // Patience sort for the longest strictly-increasing subsequence of bj.
  const tailIdx = [];   // tailIdx[len-1] = index into bj of the smallest tail
  const prev = new Int32Array(bj.length).fill(-1);
  for (let n = 0; n < bj.length; n++) {
    let lo = 0, hi = tailIdx.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (bj[tailIdx[mid]] < bj[n]) lo = mid + 1; else hi = mid;
    }
    if (lo > 0) prev[n] = tailIdx[lo - 1];
    tailIdx[lo] = n;
  }
  const out = [];
  for (let n = tailIdx[tailIdx.length - 1]; n !== -1; n = prev[n]) out.push(ai[n], bj[n]);
  // Collected tail-first; flip back to increasing order, preserving pairs.
  const res = new Array(out.length);
  for (let k = 0; k < out.length; k += 2) {
    res[out.length - k - 2] = out[k];
    res[out.length - k - 1] = out[k + 1];
  }
  return res;
}

// Myers' O((N+M)D) diff over a[lo1,hi1) vs b[lo2,hi2), with the edit-distance
// search bounded by DIFF_MAX_D.
function myers(ia, ib, lo1, hi1, lo2, hi2, a, b, ops) {
  const n = hi1 - lo1, m = hi2 - lo2;
  const maxD = Math.min(n + m, DIFF_MAX_D);
  const off = maxD, size = 2 * maxD + 1;

  let v = new Int32Array(size).fill(-1);
  v[off + 1] = 0;
  const trace = [];
  let found = -1;

  search:
  for (let d = 0; d <= maxD; d++) {
    trace.push(Int32Array.prototype.slice.call(v));
    for (let k = -d; k <= d; k += 2) {
      let x;
      if (k === -d || (k !== d && v[off + k - 1] < v[off + k + 1])) x = v[off + k + 1];
      else x = v[off + k - 1] + 1;
      let y = x - k;
      while (x < n && y < m && ia[lo1 + x] === ib[lo2 + y]) { x++; y++; }
      v[off + k] = x;
      if (x >= n && y >= m) { found = d; break search; }
    }
  }

  if (found === -1) {
    // Too different to align within the cap: show it as a wholesale replacement.
    for (let i = lo1; i < hi1; i++) ops.push({ type: 'delete', line: a[i] });
    for (let j = lo2; j < hi2; j++) ops.push({ type: 'insert', line: b[j] });
    return;
  }

  // Walk the trace backwards, then flip. (The old code used unshift() here,
  // which is O(n) per op and made the backtrack quadratic on its own.)
  const rev = [];
  let x = n, y = m;
  for (let d = found; d > 0; d--) {
    const vPrev = trace[d];
    const k = x - y;
    let prevK;
    if (k === -d || (k !== d && vPrev[off + k - 1] < vPrev[off + k + 1])) prevK = k + 1;
    else prevK = k - 1;
    const prevX = vPrev[off + prevK], prevY = prevX - prevK;
    while (x > prevX && y > prevY) { rev.push({ type: 'equal', line: a[lo1 + --x] }); y--; }
    if (x === prevX) rev.push({ type: 'insert', line: b[lo2 + --y] });
    else rev.push({ type: 'delete', line: a[lo1 + --x] });
  }
  while (x > 0 && y > 0) { rev.push({ type: 'equal', line: a[lo1 + --x] }); y--; }
  for (let i = rev.length - 1; i >= 0; i--) ops.push(rev[i]);
}
