// The find bar's CodeMirror extension: match highlighting and current-row tint.
//
// Split out from search.js so core.js can register the extension without
// importing the find-bar actions, which themselves need core. Nothing here
// imports core, so the dependency runs one way.
const { Decoration, StateEffect, StateField, RangeSetBuilder, EditorView } = window.CM;

// The full match list plus which one is current. Ranges are mapped through
// document changes so the highlights survive an edit or a Replace.
export const setSearchState = StateEffect.define();

export const searchHighlightField = StateField.define({
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
export const findHighlightExtension = [searchHighlightField, searchHighlighter];
