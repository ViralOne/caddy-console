// Side panels (Snippets, Backups): one open at a time, toggled from the header.
import { clearPreview, loadBackups } from './backups.js';
import { editorView, fetchJson, setDot, showError } from './core.js';
import { toast } from './ui/toast.js';

const panel = (name) => document.getElementById(`panel-${name}`);
const headerButton = (name) => document.getElementById(`panel-btn-${name}`);

export function closeAllPanels() {
  document.querySelectorAll('.panel').forEach(p => { p.hidden = true; });
  document.querySelectorAll('[id^="panel-btn-"]').forEach(b => b.setAttribute('aria-pressed', 'false'));
  clearPreview();
}

export function togglePanel(name) {
  const wasOpen = !panel(name).hidden;
  closeAllPanels();
  if (wasOpen) { headerButton(name)?.focus(); return; }
  panel(name).hidden = false;
  headerButton(name)?.setAttribute('aria-pressed', 'true');
  panel(name).querySelector('[data-close]')?.focus();
  if (name === 'backups') loadBackups();
  if (name === 'snippets') loadSnippets();
}

export function closePanel(name) {
  const wasOpen = !panel(name).hidden;
  closeAllPanels();
  if (wasOpen) headerButton(name)?.focus();
}

export async function loadSnippets() {
  const list = document.getElementById('snippets-list');
  let data;
  try { data = await fetchJson('/api/snippets'); }
  catch (e) { showError(list, 'Could not load snippets', e); return; }
  list.textContent = '';
  data.snippets.forEach((s) => {
    const card = document.createElement('button');
    card.type = 'button';
    card.className = 'snip';
    const name = document.createElement('b');
    name.textContent = s.name;
    const desc = document.createElement('span');
    desc.textContent = s.description;
    card.append(name, desc);
    card.addEventListener('click', () => insertSnippet(s));
    list.appendChild(card);
  });
}

function insertSnippet(s) {
  const pos = editorView.state.selection.main.head;
  const line = editorView.state.doc.lineAt(pos).number;
  editorView.dispatch({ changes: { from: pos, insert: s.code } });
  setDot('yellow');
  closePanel('snippets');
  toast(`Inserted "${s.name}" at line ${line}`, { kind: 'ok' });
}
