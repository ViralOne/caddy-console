// Core: CodeMirror setup, shared editor state, and small DOM/status helpers
// used across the other feature scripts.
const { basicSetup, EditorView, EditorState, keymap, oneDark, StreamLanguage, indentWithTab } = window.CM;

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

// Shared editor state (referenced by other scripts via the shared global scope).
let editorView;
let originalContent = '';
let originalLength = 0;
let currentVersion = '';
let lastSavedTime = null;
let lastSavedBy = '';

function getContent() { return editorView.state.doc.toString(); }
function setContent(text) { editorView.dispatch({ changes: { from: 0, to: editorView.state.doc.length, insert: text } }); }

// The last content known to match the file on disk. Always go through this so
// the length shortcut in isDirty() stays correct.
function setOriginal(text) { originalContent = text; originalLength = text.length; }

// Cheap on the hot path: comparing lengths avoids building a multi-megabyte
// string on every keystroke in a large file. Only equal-length edits fall
// through to the full comparison.
function isDirty() {
  if (!editorView) return false;
  const doc = editorView.state.doc;
  if (doc.length !== originalLength) return true;
  return doc.toString() !== originalContent;
}

function initEditor(content) {
  editorView = new EditorView({
    state: EditorState.create({
      doc: content,
      extensions: [
        basicSetup,
        oneDark,
        caddyfileLanguage,
        findHighlightExtension,
        EditorView.updateListener.of(update => {
          if (update.docChanged) setDot(isDirty() ? 'yellow' : 'green');
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
        EditorView.theme({
          '&': { height: '100%' },
          '.cm-scroller': { overflow: 'auto' },
          '.cm-content': { fontFamily: "'JetBrains Mono','Fira Code','Consolas',monospace", fontSize: '13px' },
          '.cm-gutters': { background: '#0d1117', borderRight: '1px solid #21262d' },
        }),
      ],
    }),
    parent: document.getElementById('cm-editor'),
  });
}

window.addEventListener('beforeunload', (e) => {
  if (isDirty()) { e.preventDefault(); e.returnValue = ''; }
});

function updateLastSaved() {
  if (!lastSavedTime) return;
  const el = document.getElementById('last-saved');
  const diff = Math.floor((Date.now() - lastSavedTime) / 1000);
  let text = diff < 5 ? 'just now' : diff < 60 ? `${diff}s ago` : diff < 3600 ? `${Math.floor(diff/60)}m ago` : `${Math.floor(diff/3600)}h ago`;
  el.textContent = `Saved ${text}` + (lastSavedBy ? ` by ${lastSavedBy}` : '');
}
setInterval(updateLastSaved, 10000);

// --- shared helpers ---
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text) e.textContent = text;
  return e;
}

// fetch + JSON with a useful error: non-2xx responses throw an Error whose
// message is the server's `error`/`message` field (or the HTTP status).
async function fetchJson(url, opts) {
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
function showError(container, prefix, err) {
  container.textContent = '';
  container.appendChild(el('div', 'metrics-hint error', `${prefix}: ${err && err.message ? err.message : err}`));
}

function setStatus(msg, cls) { const el = document.getElementById('status-msg'); el.textContent = msg; el.className = 'status-msg ' + (cls||''); }
function setDot(c) { document.getElementById('status-dot').className = 'status-dot ' + c; }
