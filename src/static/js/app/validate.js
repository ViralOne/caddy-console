// Validate / Save flow, the pre-save diff modal, and warnings UI.

async function _validateRequest(content) {
  const res = await fetch('/api/validate', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({content}) });
  if (!res.ok) {
    // 401 is already being handled by the fetch wrapper; anything else is a
    // server problem, not a config problem, and must not read as "invalid".
    let msg = `HTTP ${res.status}`;
    try { const d = await res.json(); msg = d.error || d.message || msg; } catch (e) {}
    throw new Error(`Validation request failed: ${msg}`);
  }
  return res.json();
}

window.doValidate = async function() {
  setStatus('Validating + formatting...', 'info'); hideWarnings();
  let data;
  try { data = await _validateRequest(getContent()); }
  catch (e) { setStatus(e.message, 'err'); setDot('red'); return; }
  if (data.formatted) { setContent(data.formatted); setStatus('Formatted + valid', 'ok'); setDot(isDirty() ? 'yellow' : 'green'); }
  else if (data.valid && !data.warnings.length) { setStatus('Valid config', 'ok'); setDot(isDirty() ? 'yellow' : 'green'); }
  else if (data.valid && data.warnings.length) { setStatus('Valid with warnings', 'ok'); setDot('yellow'); showWarnings(data.warnings); }
  else { setStatus(data.message, 'err'); setDot('red'); }
};

// Only one save flow at a time: a second Cmd+S while the diff modal is open
// used to start a second validation and orphan the first modal's promise.
let _saving = false;

window.doSave = async function() {
  if (_saving) return;
  _saving = true;
  try { await _doSave(); }
  finally { _saving = false; }
};

async function _doSave() {
  setStatus('Validating before save...', 'info');
  const content = getContent();
  let valData;
  try { valData = await _validateRequest(content); }
  catch (e) { setStatus(e.message, 'err'); setDot('red'); return; }
  if (!valData.valid) { setStatus(valData.message, 'err'); setDot('red'); alert('Cannot save: config is invalid.\n\n' + valData.message); return; }
  if (valData.warnings && valData.warnings.length) { showWarnings(valData.warnings); setDot('yellow'); setStatus('Warnings found (review before saving)', 'warn'); if (!confirm('Warnings found:\n\n' + valData.warnings.join('\n') + '\n\nSave anyway?')) return; }

  // Pre-save live diff: show editor (new) vs the config currently on disk (current).
  setStatus('Building diff preview...', 'info');
  let live = originalContent;
  try { const ld = await fetchJson('/api/caddyfile'); live = ld.content; } catch (e) {}
  // Yield a frame so the status above actually paints before the diff runs;
  // rendering is synchronous and blocks the main thread on large files.
  await new Promise(r => requestAnimationFrame(() => setTimeout(r, 0)));
  renderDiffInto(document.getElementById('save-diff-content'), live, content);
  const proceed = await openSaveModal();
  if (!proceed) { setStatus('Save cancelled', 'info'); return; }

  setStatus('Saving...', 'info');
  let res;
  try {
    res = await fetch('/api/save', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({content, version: currentVersion}) });
  } catch (e) { setStatus(`Save failed: ${e.message}`, 'err'); setDot('red'); return; }
  let data = null;
  try { data = await res.json(); } catch (e) {}
  if (res.status === 409) {
    setStatus('Save blocked: file changed on disk', 'err'); setDot('red');
    if (confirm(((data && data.message) || 'The config changed on disk.') + '\n\nReload the latest version now? (Your unsaved edits will be lost.)')) { await loadCaddyfile(); }
    return;
  }
  if (!data) { setStatus(`Save failed: HTTP ${res.status}`, 'err'); setDot('red'); return; }
  if (data.ok) {
    if (data.content) setContent(data.content);
    setOriginal(data.content || content);
    if (data.version) currentVersion = data.version;
    setStatus(data.message, 'ok'); setDot('green');
    lastSavedTime = Date.now(); lastSavedBy = document.getElementById('user-info').textContent; updateLastSaved(); hideWarnings();
  } else {
    // Caddy rejected it and the server rolled the file back; keep its version
    // so a retry after fixing the config isn't reported as a conflict.
    if (data.version) currentVersion = data.version;
    setStatus(data.message, 'err'); setDot('red');
  }
}

// --- Save diff modal (promise-based confirm) ---
let _saveResolver = null;
function openSaveModal() {
  document.getElementById('save-diff-modal').classList.add('open');
  return new Promise(resolve => { _saveResolver = resolve; });
}
window.resolveSaveModal = function(value) {
  document.getElementById('save-diff-modal').classList.remove('open');
  // Drop the rendered diff (tens of thousands of rows for a big file) rather
  // than keeping it in the DOM until the next save.
  document.getElementById('save-diff-content').textContent = '';
  if (_saveResolver) { _saveResolver(value); _saveResolver = null; }
};

function showWarnings(warnings) {
  const el = document.getElementById('warnings'); el.textContent = '';
  warnings.forEach(w => { const div = document.createElement('div'); div.textContent = '⚠ ' + w; el.appendChild(div); });
  el.classList.add('show');
}
function hideWarnings() { document.getElementById('warnings').classList.remove('show'); }
