// Find / replace bar.
//
// Every match is highlighted, the current one is emphasised, and its whole row
// is tinted and scrolled to the middle of the viewport so it's obvious where the
// editor jumped to.
const { Decoration, StateEffect, StateField, RangeSetBuilder } = window.CM;

// The full match list plus which one is current. Ranges are mapped through
// document changes so the highlights survive an edit or a Replace.
const setSearchState = StateEffect.define();

const searchHighlightField = StateField.define({
  create: () => ({ matches: [], current: -1 }),
  update(value, tr) {
    for (const e of tr.effects) if (e.is(setSearchState)) return e.value;
    if (!tr.docChanged || value.matches.length === 0) return value;
    const matches = [];
    for (const m of value.matches) {
      const from = tr.changes.mapPos(m.from, 1), to = tr.changes.mapPos(m.to, -1);
      if (to > from) matches.push({ from, to });
    }
    return { matches, current: Math.min(value.current, matches.length - 1) };
  },
});

const matchMark = Decoration.mark({ class: 'cm-find-match' });
const currentMark = Decoration.mark({ class: 'cm-find-match-current' });
const currentLine = Decoration.line({ class: 'cm-find-row' });

const searchHighlighter = EditorView.decorations.compute([searchHighlightField], (state) => {
  const { matches, current } = state.field(searchHighlightField);
  if (matches.length === 0) return Decoration.none;
  const builder = new RangeSetBuilder();
  // A RangeSetBuilder needs ranges added in document order, and a line
  // decoration at the start of a line sorts before a mark inside it.
  const currentFrom = current >= 0 && matches[current] ? matches[current].from : -1;
  const lineStart = currentFrom >= 0 ? state.doc.lineAt(currentFrom).from : -1;
  let linePlaced = false;
  for (let i = 0; i < matches.length; i++) {
    const m = matches[i];
    if (!linePlaced && lineStart >= 0 && lineStart <= m.from) {
      builder.add(lineStart, lineStart, currentLine);
      linePlaced = true;
    }
    builder.add(m.from, m.to, i === current ? currentMark : matchMark);
  }
  if (!linePlaced && lineStart >= 0) builder.add(lineStart, lineStart, currentLine);
  return builder.finish();
});

// Registered from initEditor().
const findHighlightExtension = [searchHighlightField, searchHighlighter];

function _query() { return document.getElementById('search-input').value; }

function _findMatches(query) {
  if (!query) return [];
  const hay = getContent().toLowerCase();
  const needle = query.toLowerCase();
  const out = [];
  let i = hay.indexOf(needle);
  while (i !== -1) {
    out.push({ from: i, to: i + needle.length });
    i = hay.indexOf(needle, i + Math.max(needle.length, 1));
  }
  return out;
}

function _state() { return editorView.state.field(searchHighlightField); }

function _showCount(matches, current) {
  const label = document.getElementById('match-count');
  if (matches.length === 0) {
    label.textContent = _query() ? 'no matches' : '';
    label.style.color = _query() ? '#ef5350' : '#666';
    return;
  }
  label.style.color = '#8b949e';
  if (current < 0) {
    label.textContent = `${matches.length} match${matches.length !== 1 ? 'es' : ''}`;
  } else {
    const line = editorView.state.doc.lineAt(matches[current].from).number;
    label.textContent = `${current + 1} / ${matches.length} · line ${line}`;
  }
}

// Selects a match, tints its row, and centres it in the viewport.
function _goto(matches, index) {
  const m = matches[index];
  editorView.dispatch({
    selection: { anchor: m.from, head: m.to },
    effects: [
      setSearchState.of({ matches, current: index }),
      EditorView.scrollIntoView(m.from, { y: 'center' }),
    ],
  });
  editorView.focus();
  _showCount(matches, index);
}

// Recompute matches as the user types, keeping the highlight on the match
// nearest the cursor without yanking the viewport around.
window.doSearch = function() {
  const matches = _findMatches(_query());
  const cursor = editorView.state.selection.main.from;
  let current = matches.findIndex(m => m.from >= cursor);
  if (current === -1) current = matches.length ? 0 : -1;
  editorView.dispatch({ effects: setSearchState.of({ matches, current }) });
  _showCount(matches, current);
};

window.searchNext = function() { _step(1); };
window.searchPrev = function() { _step(-1); };

function _step(dir) {
  let { matches, current } = _state();
  const query = _query();
  if (!query) return;
  if (matches.length === 0) {
    matches = _findMatches(query);
    if (matches.length === 0) { _showCount(matches, -1); return; }
    current = -1;
  }
  // Wrap around in both directions.
  const next = current < 0
    ? (dir > 0 ? 0 : matches.length - 1)
    : (current + dir + matches.length) % matches.length;
  _goto(matches, next);
}

window.toggleSearch = function() {
  const bar = document.getElementById('search-bar');
  bar.classList.toggle('open');
  if (bar.classList.contains('open')) {
    const input = document.getElementById('search-input');
    input.focus();
    input.select();
    if (input.value) window.doSearch();
  } else {
    window.closeSearch();
  }
};

window.closeSearch = function() {
  document.getElementById('search-bar').classList.remove('open');
  document.getElementById('match-count').textContent = '';
  if (!editorView) return;  // editor never initialised (e.g. load failed)
  editorView.dispatch({ effects: setSearchState.of({ matches: [], current: -1 }) });
  editorView.focus();
};

window.replaceOne = function() {
  const q = _query(); if (!q) return;
  const r = document.getElementById('replace-input').value;
  const sel = editorView.state.selection.main;
  const selText = getContent().slice(sel.from, sel.to);
  if (sel.from !== sel.to && selText.toLowerCase() === q.toLowerCase()) {
    editorView.dispatch({
      changes: { from: sel.from, to: sel.to, insert: r },
      selection: { anchor: sel.from + r.length },
    });
    setDot('yellow');
    // The replacement itself is no longer a match, so recompute from scratch.
    const matches = _findMatches(q);
    const after = sel.from + r.length;
    let current = matches.findIndex(m => m.from >= after);
    if (current === -1) current = matches.length ? 0 : -1;
    if (current >= 0) { _goto(matches, current); return; }
    editorView.dispatch({ effects: setSearchState.of({ matches, current: -1 }) });
    _showCount(matches, -1);
    return;
  }
  window.searchNext();
};

window.replaceAll = function() {
  const q = _query(); if (!q) return;
  const r = document.getElementById('replace-input').value;
  const matches = _findMatches(q);
  if (matches.length === 0) { _showCount(matches, -1); return; }
  editorView.dispatch({
    changes: matches.map(m => ({ from: m.from, to: m.to, insert: r })),
    effects: setSearchState.of({ matches: [], current: -1 }),
  });
  setDot('yellow');
  setStatus(`Replaced ${matches.length} match${matches.length !== 1 ? 'es' : ''}`, 'info');
  window.doSearch();
};
