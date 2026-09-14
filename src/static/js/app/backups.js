// Backups panel: list, preview, diff, load-to-editor, and rollback+reload.
let previewBackupContent = '';
let currentPreviewName = '';

async function loadBackups() {
  const list = document.getElementById('backups-list');
  clearPreview();
  let data;
  try { data = await fetchJson('/api/backups'); }
  catch (e) { showError(list, 'Could not load backups', e); return; }
  list.textContent = '';
  if (!data.backups.length) { list.textContent = 'No backups yet.'; return; }
  data.backups.forEach(b => {
    const card = document.createElement('div'); card.className = 'snippet-card';
    const row = document.createElement('div'); row.style.cssText = 'display:flex;align-items:center;justify-content:space-between;width:100%';
    const left = document.createElement('div'); left.style.cursor = 'pointer'; left.style.flex = '1'; left.onclick = () => previewBackup(b);
    const name = document.createElement('div'); name.className = 'name'; name.textContent = b.replace('Caddyfile.','');
    const desc = document.createElement('div'); desc.className = 'desc'; desc.textContent = 'Click to preview';
    left.appendChild(name); left.appendChild(desc);
    const delBtn = document.createElement('button'); delBtn.className = 'btn btn-danger'; delBtn.textContent = 'Delete';
    delBtn.style.cssText = 'padding:3px 8px;font-size:10px;margin-left:8px';
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
  renderDiff(getContent(), data.content); window.showPreviewTab('diff');
}

window.showPreviewTab = function(tab) {
  document.getElementById('preview-content').style.display = tab==='preview'?'block':'none';
  document.getElementById('diff-content').style.display = tab==='diff'?'block':'none';
  document.getElementById('tab-btn-preview').classList.toggle('active', tab==='preview');
  document.getElementById('tab-btn-diff').classList.toggle('active', tab==='diff');
};

// Drop the preview text and rendered diff so they aren't kept in the DOM (and
// memory) after the panel closes. Safe to call when nothing is open.
function clearPreview() {
  previewBackupContent = ''; currentPreviewName = '';
  document.getElementById('preview-content').textContent = '';
  document.getElementById('diff-content').textContent = '';
  document.getElementById('backup-preview').style.display = 'none';
  document.getElementById('backups-list').style.display = 'block';
}
window.closePreview = function() { clearPreview(); };
window.restoreFromPreview = function() { setContent(previewBackupContent); setStatus('Backup loaded (unsaved)', 'info'); setDot('yellow'); window.closePanel('backups'); };
window.rollbackFromPreview = async function() {
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
    setContent(restored); setOriginal(restored); if (data.version) currentVersion = data.version;
    setStatus(data.message, 'ok'); setDot('green');
    lastSavedTime = Date.now(); lastSavedBy = document.getElementById('user-info').textContent; updateLastSaved();
    window.closePanel('backups');
  } else {
    const msg = (data && (data.message || data.error)) || `HTTP ${res.status}`;
    if (data && data.version) currentVersion = data.version;
    setStatus(msg, 'err'); setDot('red');
    alert('Restore failed: ' + msg);
  }
};
