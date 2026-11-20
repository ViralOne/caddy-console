// Backups panel: list, preview, diff, load-to-editor, and rollback+reload.
import {
  el, fetchJson, getContent, getVersion, markSaved, setContent, setDot, setOriginal, setStatus,
  setVersion, showError,
} from './core.js';
import { renderDiff } from './diff.js';
import { backupLabel } from './format.js';
import { closePanel } from './panels.js';
import { alertDialog, confirmDialog } from './ui/dialog.js';
import { segmented } from './ui/seg.js';
import { lintCurrent } from './validate.js';
import { toast } from './ui/toast.js';
let previewBackupContent = '';
let currentPreviewName = '';

let previewSeg = null;

export async function loadBackups() {
  const list = document.getElementById('backups-list');
  clearPreview();
  let data;
  try { data = await fetchJson('/api/backups'); }
  catch (e) { showError(list, 'Could not load backups', e); return; }
  list.textContent = '';
  if (!data.backups.length) {
    list.append(el('p', 'panel-note', 'No backups yet. One is taken before every save and restore.'));
    return;
  }
  const now = Date.now();
  data.backups.forEach((b) => {
    const label = backupLabel(b, now);
    const row = el('div', 'bk');
    const open = el('button', 'open');
    open.type = 'button';
    open.append(el('b', '', label), el('span', 'muted', b.replace('Caddyfile.', '')));
    open.addEventListener('click', () => previewBackup(b));
    const del = el('button', 'btn sm btn-danger', 'Delete');
    del.type = 'button';
    del.setAttribute('aria-label', `Delete the backup from ${label}`);
    del.addEventListener('click', async (e) => {
      e.stopPropagation();
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
    });
    row.append(open, del);
    list.append(row);
  });
  const n = data.backups.length;
  list.append(el('p', 'panel-note', `${n === 1 ? 'One backup' : `The ${n} newest backups`}. One is taken before every save and restore.`));
}

async function previewBackup(name) {
  let data;
  try { data = await fetchJson(`/api/backups/${encodeURIComponent(name)}`); }
  catch (e) { toast(`Could not load backup: ${e.message}`, { kind: 'error' }); return; }
  previewBackupContent = data.content; currentPreviewName = name;
  document.getElementById('backups-list').hidden = true;
  document.getElementById('backup-preview').hidden = false;
  document.getElementById('bk-back').hidden = false;
  document.getElementById('bk-h').textContent = 'Backup';
  document.getElementById('preview-name').textContent = backupLabel(name);
  document.getElementById('preview-meta').textContent = `${name.replace('Caddyfile.', '')}, ${data.content.split('\n').length} lines`;
  document.getElementById('preview-content').textContent = data.content;
  renderDiff(getContent(), data.content);
  if (!previewSeg) {
    previewSeg = segmented({
      label: 'Preview mode', value: 'diff', onChange: showPreviewTab,
      options: [{ id: 'preview', label: 'Preview' }, { id: 'diff', label: 'Diff vs editor' }],
    });
    document.getElementById('preview-tabs').append(previewSeg.el);
  }
  showPreviewTab('diff');
  document.getElementById('bk-back').focus();
}

export function showPreviewTab(tab) {
  previewSeg?.set(tab);
  document.getElementById('preview-content').hidden = tab !== 'preview';
  document.getElementById('diff-content').hidden = tab !== 'diff';
}

// Drop the preview text and rendered diff so they aren't kept in the DOM after
// the panel closes. Safe to call when nothing is open.
export function clearPreview() {
  previewBackupContent = ''; currentPreviewName = '';
  document.getElementById('preview-content').textContent = '';
  document.getElementById('diff-content').textContent = '';
  document.getElementById('backup-preview').hidden = true;
  document.getElementById('backups-list').hidden = false;
  document.getElementById('bk-back').hidden = true;
  document.getElementById('bk-h').textContent = 'Backups';
}

export function closePreview() {
  clearPreview();
  document.querySelector('#backups-list .open')?.focus();
}
export function restoreFromPreview() {
  setContent(previewBackupContent);
  setStatus('Backup loaded (unsaved)', 'info'); setDot('yellow');
  toast(`Loaded the backup from ${backupLabel(currentPreviewName)} into the editor. Save & Reload to apply it.`, { kind: 'info' });
  closePanel('backups');
  lintCurrent();
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
    lintCurrent();
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
    lintCurrent();
  } else {
    const msg = (data && (data.message || data.error)) || `HTTP ${res.status}`;
    if (data && data.version) setVersion(data.version);
    setStatus(msg, 'err'); setDot('red');
    await alertDialog({ title: 'Restore failed', body: 'The live Caddyfile was not changed.', detail: msg });
  }
}
