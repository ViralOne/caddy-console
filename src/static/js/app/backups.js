// Backups panel: list, preview, diff, load-to-editor, and rollback+reload.
import {
  fetchJson, getContent, markSaved, setContent, setDot, setOriginal, setStatus,
  setVersion, showError,
} from './core.js';
import { renderDiff } from './diff.js';
import { closePanel } from './panels.js';
let previewBackupContent = '';
let currentPreviewName = '';

export async function loadBackups() {
  const list = document.getElementById('backups-list');
  clearPreview();
  let data;
  try { data = await fetchJson('/api/backups'); }
  catch (e) { showError(list, 'Could not load backups', e); return; }
  list.textContent = '';
  if (!data.backups.length) { list.textContent = 'No backups yet.'; return; }
  data.backups.forEach(b => {
    const card = document.createElement('div'); card.className = 'snippet-card';
    const row = document.createElement('div'); row.className = 'backup-row';
    const left = document.createElement('div'); left.className = 'backup-row-main'; left.onclick = () => previewBackup(b);
    const name = document.createElement('div'); name.className = 'name'; name.textContent = b.replace('Caddyfile.','');
    const desc = document.createElement('div'); desc.className = 'desc'; desc.textContent = 'Click to preview';
    left.appendChild(name); left.appendChild(desc);
    const delBtn = document.createElement('button'); delBtn.className = 'btn btn-danger btn-sm'; delBtn.textContent = 'Delete';
    delBtn.onclick = async (e) => {
      e.stopPropagation();
      if (!confirm(`Delete backup ${b.replace('Caddyfile.','')}?`)) return;
      try { await fetchJson(`/api/backups/${encodeURIComponent(b)}`, {method:'DELETE'}); loadBackups(); }
      catch (err) { alert('Delete failed: ' + err.message); }
    };
    row.appendChild(left); row.appendChild(delBtn); card.appendChild(row);
    list.appendChild(card);
  });
}

async function previewBackup(name) {
  let data;
  try { data = await fetchJson(`/api/backups/${encodeURIComponent(name)}`); }
  catch (e) { setStatus(`Could not load backup: ${e.message}`, 'err'); return; }
  previewBackupContent = data.content; currentPreviewName = name;
  document.getElementById('backups-list').style.display = 'none'; document.getElementById('backup-preview').style.display = 'block';
  document.getElementById('preview-name').textContent = name.replace('Caddyfile.','');
  document.getElementById('preview-content').textContent = data.content;
  renderDiff(getContent(), data.content); showPreviewTab('diff');
}

export function showPreviewTab(tab) {
  document.getElementById('preview-content').style.display = tab==='preview'?'block':'none';
  document.getElementById('diff-content').style.display = tab==='diff'?'block':'none';
  document.getElementById('tab-btn-preview').classList.toggle('active', tab==='preview');
  document.getElementById('tab-btn-diff').classList.toggle('active', tab==='diff');
}

// Drop the preview text and rendered diff so they aren't kept in the DOM (and
// memory) after the panel closes. Safe to call when nothing is open.
export function clearPreview() {
  previewBackupContent = ''; currentPreviewName = '';
  document.getElementById('preview-content').textContent = '';
  document.getElementById('diff-content').textContent = '';
  document.getElementById('backup-preview').style.display = 'none';
  document.getElementById('backups-list').style.display = 'block';
}
export function closePreview() { clearPreview(); }
export function restoreFromPreview() { setContent(previewBackupContent); setStatus('Backup loaded (unsaved)', 'info'); setDot('yellow'); closePanel('backups'); };
export async function rollbackFromPreview() {
  if (!currentPreviewName) return;
  const label = currentPreviewName.replace('Caddyfile.', '');
  if (!confirm(`Restore backup ${label} AND reload Caddy now?\n\nThis replaces the live config immediately.`)) return;
  setStatus('Restoring + reloading...', 'info'); setDot('yellow');
  let res, data = null;
  try {
    res = await fetch(`/api/backups/${encodeURIComponent(currentPreviewName)}/restore`, { method: 'POST', headers: {'Content-Type': 'application/json'} });
    try { data = await res.json(); } catch (e) {}
  } catch (e) { setStatus(`Restore failed: ${e.message}`, 'err'); setDot('red'); return; }
  if (data && data.ok) {
    const restored = data.content || previewBackupContent;
    setContent(restored); setOriginal(restored); if (data.version) setVersion(data.version);
    setStatus(data.message, 'ok'); setDot('green');
    markSaved();
    closePanel('backups');
  } else {
    const msg = (data && (data.message || data.error)) || `HTTP ${res.status}`;
    if (data && data.version) setVersion(data.version);
    setStatus(msg, 'err'); setDot('red');
    alert('Restore failed: ' + msg);
  }
}
