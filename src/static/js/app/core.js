// Core: CodeMirror setup, shared editor state, and small DOM/status helpers
// used across the other modules.
//
// window.CM is set by editor.bundle.js, a classic script. Classic scripts all
// run before any module body, so it is always populated by the time this runs.
import { findHighlightExtension } from './search-highlight.js';
import { doSave } from './validate.js';
import { getKeymap } from './editor-prefs.js';
import { currentTheme } from './theme.js';

const {
  basicSetup, EditorView, EditorState, keymap, StreamLanguage, indentWithTab,
  HighlightStyle, syntaxHighlighting, tags, Compartment, Prec, vim, Vim,
} = window.CM;

// The keymap (Standard / Vim) lives in its own compartment so switching swaps
// just that slot: the document, undo history and cursor all survive.
const keymapSlot = new Compartment();

// Vim's ex commands map onto the app's own save, since there is nothing to quit.
// Vim's state is global to the page, so these are registered once.
for (const [name, prefix] of [['write', 'w'], ['wq', 'wq'], ['xit', 'x']]) {
  Vim.defineEx(name, prefix, () => { doSave(); });
}

// Highest precedence so Vim sees keys before basicSetup's default keymap.
// `status` shows the mode (and pending ex command) in a bar under the editor.
const keymapExtension = (id) => (id === 'vim' ? Prec.highest(vim({ status: true })) : []);

// The editor used to ship oneDark, a second dark theme with its own surface and
// syntax hues sitting inside a UI built on tokens.css — two palettes on one
// screen. Both the chrome and the highlighting now come from those tokens, so the
// editor is part of the app rather than an embedded widget, and a token change
// reaches it too. var() resolves because CodeMirror injects these as real CSS.
const EDITOR_THEME_SPEC = {
  '&': { height: '100%', backgroundColor: 'var(--bg)', color: 'var(--ink)' },
  '.cm-scroller': { overflow: 'auto', fontFamily: 'var(--mono)', lineHeight: '1.6' },
  '.cm-content': { fontFamily: 'var(--mono)', fontSize: 'var(--t-sm)', caretColor: 'var(--accent)' },
  '.cm-cursor, .cm-dropCursor': { borderLeftColor: 'var(--accent)', borderLeftWidth: '2px' },
  '.cm-gutters': {
    backgroundColor: 'var(--bg)', color: 'var(--ink-3)',
    border: 'none', borderRight: '1px solid var(--line)',
  },
  '.cm-activeLine': { backgroundColor: 'var(--active-line-bg)' },
  '.cm-activeLineGutter': { backgroundColor: 'var(--bg-2)', color: 'var(--ink-2)' },
  '.cm-selectionBackground, &.cm-focused .cm-selectionBackground': {
    backgroundColor: 'var(--selection-bg)',
  },
  '.cm-content ::selection': {
    backgroundColor: 'var(--selection-bg)', color: 'var(--selection-ink)',
  },
  '.cm-matchingBracket, &.cm-focused .cm-matchingBracket': {
    backgroundColor: 'var(--accent-soft)', outline: '1px solid var(--accent)', color: 'inherit',
  },
  '.cm-foldPlaceholder': {
    backgroundColor: 'var(--bg-2)', border: '1px solid var(--line)', color: 'var(--ink-3)',
  },
  '.cm-panels': { backgroundColor: 'var(--bg-3)', color: 'var(--ink)' },
  // Vim mode: block cursor and the mode / ex-command bar.
  '.cm-fat-cursor': { background: 'var(--accent)', color: 'var(--bg)', outline: 'none' },
  '&:not(.cm-focused) .cm-fat-cursor': { background: 'none', outline: '1px solid var(--accent)', color: 'transparent' },
  '.cm-vim-panel': {
    fontFamily: 'var(--mono)', fontSize: 'var(--t-sm)', padding: '2px var(--space-2)',
    borderTop: '1px solid var(--line)',
  },
  '.cm-vim-panel input': { fontFamily: 'inherit', fontSize: 'inherit', color: 'var(--ink)', background: 'transparent', border: 'none', outline: 'none' },
  '.cm-tooltip': {
    backgroundColor: 'var(--bg-3)', border: '1px solid var(--line-2)',
    color: 'var(--ink)',
  },
};

// The colours are CSS variables, so they follow data-theme by themselves; the
// `dark` flag only picks CodeMirror's own base styles, so it lives in a
// compartment and is swapped when the theme changes.
const themeSlot = new Compartment();
const themeExtension = (theme) => EditorView.theme(EDITOR_THEME_SPEC, { dark: theme === 'dark' });

export function applyEditorTheme(theme) {
  if (!editorView) return;
  editorView.dispatch({ effects: themeSlot.reconfigure(themeExtension(theme)) });
}
window.addEventListener('themechange', (e) => applyEditorTheme(e.detail.theme));

// Syntax colours come from the --code-* tokens, which both themes define.
const editorHighlight = HighlightStyle.define([
  { tag: tags.comment, color: 'var(--code-com)', fontStyle: 'italic' },
  { tag: tags.keyword, color: 'var(--code-kw)' },
  { tag: tags.atom, color: 'var(--code-mt)' },
  { tag: tags.labelName, color: 'var(--code-mt)' },
  { tag: tags.heading, color: 'var(--code-site)', fontWeight: '600' },
  { tag: tags.variableName, color: 'var(--code-ph)' },
  { tag: tags.string, color: 'var(--code-str)' },
  { tag: tags.number, color: 'var(--code-num)' },
  { tag: tags.bracket, color: 'var(--ink-3)' },
]);

const caddyfileLanguage = StreamLanguage.define({
  startState: () => ({ depth: 0 }),
  token(stream, state) {
    if (stream.sol() && state.depth === 0 && stream.match(/^[^\s{#(][^\s{]*/)) return 'heading';
    if (stream.match(/^#.*/)) return 'comment';
    if (stream.match(/^"[^"]*"/)) return 'string';
    if (stream.match(/^\{[^{}\s]+\}/)) return 'variableName';
    if (stream.match(/^\{/)) { state.depth++; return 'bracket'; }
    if (stream.match(/^\}/)) { state.depth = Math.max(0, state.depth - 1); return 'bracket'; }
    if (stream.match(/^@[\w-]+/)) return 'labelName';
    if (stream.match(/^\b(reverse_proxy|header|encode|file_server|root|try_files|redir|respond|log|basicauth|basic_auth|rate_limit|import|tls|route|handle|handle_path|rewrite|uri|request_body)\b/)) return 'keyword';
    if (stream.match(/^\b(email|auto_https|servers|admin|debug|order|storage|acme_ca|on_demand_tls|metrics)\b/)) return 'atom';
    if (stream.match(/^\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b/)) return 'number';
    if (stream.match(/^\blocalhost:\d+\b/)) return 'number';
    stream.next();
    return null;
  },
});

// Shared editor state. `editorView` and `originalContent` are exported as live
// bindings: other modules read the current value but cannot assign to them,
// which is why the writes below go through setVersion()/markSaved().
export let editorView;
export let originalContent = '';
let originalLength = 0;
let currentVersion = '';
let lastSavedTime = null;
let lastSavedBy = '';

export function getContent() { return editorView.state.doc.toString(); }
export function setContent(text) {
  editorView.dispatch({ changes: { from: 0, to: editorView.state.doc.length, insert: text } });
  refreshDocState();
}

// The last content known to match the file on disk. Always go through this so
// the length shortcut in isDirty() stays correct.
export function setOriginal(text) { originalContent = text; originalLength = text.length; refreshDocState(); }

// The version token guarding against concurrent saves. Written by the save,
// rollback and load paths, which live in other modules — an imported binding
// can't be assigned, so they call setVersion().
export function getVersion() { return currentVersion; }
export function setVersion(version) { currentVersion = version; }

// Cheap on the hot path: comparing lengths avoids building a multi-megabyte
// string on every keystroke in a large file. Only equal-length edits fall
// through to the full comparison.
export function isDirty() {
  if (!editorView) return false;
  const doc = editorView.state.doc;
  if (doc.length !== originalLength) return true;
  return doc.toString() !== originalContent;
}

// Keeps the Save button and the footer counters in step with the document, so
// unsaved changes are visible at the button you would press rather than only as a
// coloured dot in the corner.
export function refreshDocState() {
  const dirty = isDirty();
  const button = document.getElementById('btn-save');
  const label = document.getElementById('save-label');
  if (button) button.disabled = !dirty;
  if (label) label.textContent = dirty ? 'Save & Reload' : 'No changes';
  const stats = document.getElementById('doc-stats');
  if (stats && editorView) {
    const lines = editorView.state.doc.lines;
    const bytes = editorView.state.doc.length;
    stats.textContent = `${lines} lines · ${bytes.toLocaleString()} chars${dirty ? ' · modified' : ''}`;
  }
}

export function initEditor(content) {
  editorView = new EditorView({
    state: EditorState.create({
      doc: content,
      extensions: [
        keymapSlot.of(keymapExtension(getKeymap())),
        basicSetup,
        themeSlot.of(themeExtension(currentTheme())),
        syntaxHighlighting(editorHighlight),
        caddyfileLanguage,
        findHighlightExtension,
        EditorView.updateListener.of(update => {
          if (update.docChanged) { setDot(isDirty() ? 'yellow' : 'green'); refreshDocState(); }
          if (update.selectionSet) {
            const pos = update.state.selection.main.head;
            const line = update.state.doc.lineAt(pos);
            document.getElementById('cursor-pos').textContent = `Ln ${line.number}, Col ${pos - line.from + 1}`;
          }
        }),
        keymap.of([
          { key: 'Mod-s', run: () => { doSave(); return true; } },
          indentWithTab,
        ]),
      ],
    }),
    parent: document.getElementById('cm-editor'),
  });
  refreshDocState();
}

/** Switch the open editor between keymaps ('standard' | 'vim') in place. */
export function applyEditorKeymap(id) {
  if (!editorView) return;
  editorView.dispatch({ effects: keymapSlot.reconfigure(keymapExtension(id)) });
  editorView.focus();
}

window.addEventListener('beforeunload', (e) => {
  if (isDirty()) { e.preventDefault(); e.returnValue = ''; }
});

export function updateLastSaved() {
  if (!lastSavedTime) return;
  const node = document.getElementById('last-saved');
  const diff = Math.floor((Date.now() - lastSavedTime) / 1000);
  let text = diff < 5 ? 'just now' : diff < 60 ? `${diff}s ago` : diff < 3600 ? `${Math.floor(diff/60)}m ago` : `${Math.floor(diff/3600)}h ago`;
  node.textContent = `Saved ${text}` + (lastSavedBy ? ` by ${lastSavedBy}` : '');
}
setInterval(updateLastSaved, 10000);

// The save flow and the backup rollback both finish the same way. Keeping it
// here means the "Saved …" footer can't drift between the two call sites.
export function markSaved() {
  lastSavedTime = Date.now();
  lastSavedBy = document.getElementById('user-info').textContent;
  updateLastSaved();
}

// --- shared helpers ---
export function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text) e.textContent = text;
  return e;
}

// fetch + JSON with a useful error: non-2xx responses throw an Error whose
// message is the server's `error`/`message` field (or the HTTP status).
export async function fetchJson(url, opts) {
  const res = await fetch(url, opts);
  let data = null;
  try { data = await res.json(); } catch (e) { /* not JSON (e.g. an HTML 500 page) */ }
  if (!res.ok) {
    const err = new Error((data && (data.error || data.message)) || `HTTP ${res.status}`);
    err.status = res.status; err.data = data;
    throw err;
  }
  return data;
}

// Replace a container's content with a single error note.
export function showError(container, prefix, err) {
  container.textContent = '';
  container.appendChild(el('div', 'metrics-hint error', `${prefix}: ${err && err.message ? err.message : err}`));
}

export function setStatus(msg, cls) { const node = document.getElementById('status-msg'); node.textContent = msg; node.className = 'status-msg ' + (cls||''); }
// The status line's state, as a shape and a colour (never colour alone): the
// message text beside it always says the same thing in words.
const DOT_STATE = { green: ['ok', 'status-ok'], yellow: ['modified', 'warning'], red: ['error', 'status-down'] };
export function setDot(c) {
  const [state, icon] = DOT_STATE[c] || DOT_STATE.green;
  const line = document.getElementById('status-line');
  if (line) line.dataset.state = state;
  document.getElementById('status-icon')?.setAttribute('href', '#i-' + icon);
}
