// Side panels: open/close behaviour + Audit, Status, and Snippets loaders.
import { clearPreview, loadBackups } from './backups.js';
import { editorView, fetchJson, setDot } from './core.js';
export function togglePanel(name) {
  const panel = document.getElementById(`panel-${name}`); const isOpen = panel.classList.contains('open');
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('open'));
  document.querySelectorAll('[id^="panel-btn-"]').forEach(b => b.classList.remove('panel-active'));
  if (isOpen) { if (name === 'backups') clearPreview(); return; }
  panel.classList.add('open');
  const btn = document.getElementById(`panel-btn-${name}`);
  if (btn) btn.classList.add('panel-active');
  if (name === 'backups') loadBackups();
  if (name === 'snippets') loadSnippets();
}
export function closePanel(name) {
  document.getElementById(`panel-${name}`).classList.remove('open');
  document.querySelectorAll('[id^="panel-btn-"]').forEach(b => b.classList.remove('panel-active'));
  if (name === 'backups') clearPreview();
}

export async function loadSnippets() {
  const list = document.getElementById('snippets-list');
  let data;
  try { data = await fetchJson('/api/snippets'); }
  catch (e) { showError(list, 'Could not load snippets', e); return; }
  list.textContent = '';
  data.snippets.forEach(s => {
    const card = document.createElement('div'); card.className = 'snippet-card'; card.onclick = () => insertSnippet(s.code);
    const name = document.createElement('div'); name.className = 'name'; name.textContent = s.name;
    const desc = document.createElement('div'); desc.className = 'desc'; desc.textContent = s.description;
    card.appendChild(name); card.appendChild(desc); list.appendChild(card);
  });
}
function insertSnippet(code) { const pos = editorView.state.selection.main.head; editorView.dispatch({ changes: { from: pos, insert: code } }); setDot('yellow'); closePanel('snippets'); }
