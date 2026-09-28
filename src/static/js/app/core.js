// Core: CodeMirror setup, shared editor state, and small DOM/status helpers
// used across the other modules.
//
// window.CM is set by editor.bundle.js, a classic script. Classic scripts all
// run before any module body, so it is always populated by the time this runs.
import { findHighlightExtension } from './search-highlight.js';
import { doSave } from './validate.js';

const {
  basicSetup, EditorView, EditorState, keymap, StreamLanguage, indentWithTab,
  HighlightStyle, syntaxHighlighting, tags,
} = window.CM;

// The editor used to ship oneDark, a second dark theme with its own surface and
// syntax hues sitting inside a UI built on tokens.css — two palettes on one
// screen. Both the chrome and the highlighting now come from those tokens, so the
// editor is part of the app rather than an embedded widget, and a token change
// reaches it too. var() resolves because CodeMirror injects these as real CSS.
const editorTheme = EditorView.theme({
  '&': { height: '100%', backgroundColor: 'var(--bg)', color: 'var(--ink)' },
  '.cm-scroller': { overflow: 'auto', fontFamily: 'var(--font-mono)', lineHeight: '1.6' },
  '.cm-content': { fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)', caretColor: 'var(--accent)' },
  '.cm-cursor, .cm-dropCursor': { borderLeftColor: 'var(--accent)', borderLeftWidth: '2px' },
  '.cm-gutters': {
    backgroundColor: 'var(--bg)', color: 'var(--ink-muted)',
    border: 'none', borderRight: '1px solid var(--border)',
  },
  '.cm-activeLine': { backgroundColor: 'var(--surface)' },
  '.cm-activeLineGutter': { backgroundColor: 'var(--surface)', color: 'var(--ink-secondary)' },
  '.cm-selectionBackground, &.cm-focused .cm-selectionBackground, ::selection': {
    backgroundColor: 'var(--accent-quiet)',
  },
  '.cm-matchingBracket, &.cm-focused .cm-matchingBracket': {
    backgroundColor: 'var(--accent-quiet)', outline: '1px solid var(--accent)', color: 'inherit',
  },
  '.cm-foldPlaceholder': {
    backgroundColor: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--ink-muted)',
  },
  '.cm-panels': { backgroundColor: 'var(--surface-raised)', color: 'var(--ink)' },
  '.cm-tooltip': {
    backgroundColor: 'var(--surface-raised)', border: '1px solid var(--border-strong)',
    color: 'var(--ink)',
  },
}, { dark: true });

// Six token types, mapped to tokens rather than to invented colours. Status hues
// appear here as syntax, which is the one place that is legitimate: they are not
// encoding state anywhere in this view.
const editorHighlight = HighlightStyle.define([
  { tag: tags.comment, color: 'var(--ink-muted)', fontStyle: 'italic' },
  { tag: tags.keyword, color: 'var(--accent)' },
  { tag: tags.atom, color: 'var(--status-serious)' },
  { tag: tags.string, color: 'var(--status-good)' },
  { tag: tags.number, color: 'var(--status-warn)' },
  { tag: tags.bracket, color: 'var(--ink-secondary)' },
]);

const caddyfileLanguage = StreamLanguage.define({
  token(stream) {
    if (stream.match(/^#.*/)) return 'comment';
    if (stream.match(/^"[^"]*"/)) return 'string';
    if (stream.match(/^\{|\}/)) return 'bracket';
    if (stream.match(/^\b(reverse_proxy|header|encode|file_server|root|try_files|redir|respond|log|basicauth|rate_limit|import|tls|route|handle|handle_path|rewrite|uri)\b/)) return 'keyword';
    if (stream.match(/^\b(email|auto_https|servers|admin|debug|order|storage|acme_ca|on_demand_tls)\b/)) return 'atom';
    if (stream.match(/^\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b/)) return 'number';
    if (stream.match(/^\blocalhost:\d+\b/)) return 'number';
    stream.next();
    return null;
  }
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
        basicSetup,
        editorTheme,
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
export function setDot(c) { document.getElementById('status-dot').className = 'status-dot ' + c; }
