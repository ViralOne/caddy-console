// Backups panel: list, preview, diff, load-to-editor, and rollback+reload.
import {
  fetchJson, getContent, getVersion, markSaved, setContent, setDot, setOriginal, setStatus,
  setVersion, showError,
} from './core.js';
import { renderDiff } from './diff.js';
import { backupLabel } from './format.js';
import { closePanel } from './panels.js';
import { alertDialog, confirmDialog } from './ui/dialog.js';
import { toast } from './ui/toast.js';
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
      const label = backupLabel(b);
      const ok = await confirmDialog({
        title: `Delete the backup from ${label}?`,
        body: 'The file is removed from disk and cannot be restored. Your live Caddyfile is not affected.',
        confirmLabel: 'Delete backup',
        danger: true,
      });
      if (!ok) return;
      try {
        await fetchJson(`/api/backups/${encodeURIComponent(b)}`, { method: 'DELETE' });
        toast(`Deleted the backup from ${label}`, { kind: 'ok' });
        loadBackups();
      } catch (err) { toast(`Delete failed: ${err.message}`, { kind: 'error' }); }
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
export function restoreFromPreview() {
  setContent(previewBackupContent);
  setStatus('Backup loaded (unsaved)', 'info'); setDot('yellow');
  toast(`Loaded the backup from ${backupLabel(currentPreviewName)} into the editor. Save & Reload to apply it.`, { kind: 'info' });
  closePanel('backups');
}

export async function rollbackFromPreview() {
  if (!currentPreviewName) return;
  const name = currentPreviewName;
  const label = backupLabel(name);
  const go = await confirmDialog({
    title: `Roll back to the backup from ${label}?`,
    body: 'This writes the backup to the live Caddyfile and reloads Caddy. The current file is backed up first, and unsaved editor changes are discarded.',
    confirmLabel: 'Roll back and reload',
    danger: true,
  });
  if (!go) return;
  setStatus('Restoring and reloading…', 'info'); setDot('yellow');
  let res, data = null;
  try {
    res = await fetch(`/api/backups/${encodeURIComponent(name)}/restore`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ version: getVersion() }),
    });
    try { data = await res.json(); } catch (e) {}
  } catch (e) {
    setStatus(`Restore failed: ${e.message}`, 'err'); setDot('red');
    toast(`Restore failed: ${e.message}`, { kind: 'error' });
    return;
  }
  if (data && data.ok) {
    const restored = data.content || previewBackupContent;
    setContent(restored); setOriginal(restored); if (data.version) setVersion(data.version);
    setStatus(data.message, 'ok'); setDot('green');
    markSaved();
    toast(`Rolled back to ${label}. Caddy reloaded.`, { kind: 'ok' });
    closePanel('backups');
  } else if (data && data.conflict) {
    if (data.version) setVersion(data.version);
    setStatus('Restore blocked: file changed on disk', 'err'); setDot('red');
    await alertDialog({ title: 'Restore blocked: the file changed on disk', body: data.message || 'The live Caddyfile changed. Reload it before restoring a backup.' });
  } else if (data && data.saved) {
    const restored = data.content || previewBackupContent;
    setContent(restored); setOriginal(restored); if (data.version) setVersion(data.version);
    setStatus(data.message, 'warn'); setDot('yellow');
    toast(data.message, { kind: 'warn' });
    closePanel('backups');
  } else {
    const msg = (data && (data.message || data.error)) || `HTTP ${res.status}`;
    if (data && data.version) setVersion(data.version);
    setStatus(msg, 'err'); setDot('red');
    await alertDialog({ title: 'Restore failed', body: 'The live Caddyfile was not changed.', detail: msg });
  }
}
