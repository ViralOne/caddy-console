// Validate / Save flow, the pre-save diff dialog, and the warnings strip.
import { loadCaddyfile } from './caddyfile.js';
import {
  fetchJson, getContent, getVersion, isDirty, markSaved, originalContent,
  setContent, setDot, setOriginal, setStatus, setVersion,
} from './core.js';
import { renderDiffInto } from './diff.js';
import { alertDialog, confirmDialog } from './ui/dialog.js';
import { toast } from './ui/toast.js';
import { withoutFormat } from './warnings.js';

const plural = (n, one) => `${n} ${one}${n === 1 ? '' : 's'}`;

async function _validateRequest(content) {
  const res = await fetch('/api/validate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ content }) });
  if (!res.ok) {
    // 401 is already being handled by the fetch wrapper; anything else is a
    // server problem, not a config problem, and must not read as "invalid".
    let msg = `HTTP ${res.status}`;
    try { const d = await res.json(); msg = d.error || d.message || msg; } catch (e) {}
    throw new Error(`Validation request failed: ${msg}`);
  }
  return res.json();
}

export async function doValidate() {
  setStatus('Checking and formatting…', 'info');
  let data;
  try { data = await _validateRequest(getContent()); }
  catch (e) { setStatus(e.message, 'err'); setDot('red'); toast(e.message, { kind: 'error' }); return; }
  if (!data.valid) {
    hideWarnings();
    setStatus(data.message, 'err'); setDot('red');
    toast('Check failed. Caddy’s message is in the status bar.', { kind: 'error' });
    return;
  }
  const passed = data.check_level === 'adapted'
    ? 'Syntax and modules accepted; the full check runs on save'
    : 'Config passed local validation';
  // The formatted text is applied now, so "not formatted" no longer applies.
  const warnings = data.formatted ? withoutFormat(data.warnings) : data.warnings;
  if (data.formatted) setContent(data.formatted);
  showWarnings(warnings);
  setDot(warnings.length || isDirty() ? 'yellow' : 'green');
  if (warnings.length) {
    setStatus(`Check passed with ${plural(warnings.length, 'warning')}`, 'warn');
    toast('Check passed, with warnings', { kind: 'warn' });
  } else {
    setStatus(data.formatted ? `Formatted. ${passed}` : passed, 'ok');
    toast(data.formatted ? 'Check passed and the file was formatted' : 'Check passed', { kind: 'ok' });
  }
}

// Only one save flow at a time: a second Cmd+S while the diff dialog is open
// used to start a second validation and orphan the first dialog's promise.
let _saving = false;

export async function doSave() {
  if (_saving) return;
  _saving = true;
  try { await _doSave(); }
  finally { _saving = false; }
}

async function _doSave() {
  setStatus('Validating before save…', 'info');
  const content = getContent();
  let valData;
  try { valData = await _validateRequest(content); }
  catch (e) { setStatus(e.message, 'err'); setDot('red'); toast(e.message, { kind: 'error' }); return; }
  if (!valData.valid) {
    setStatus(valData.message, 'err'); setDot('red');
    await alertDialog({ title: 'Cannot save: the config is invalid', body: 'Nothing was written. Caddy reported:', detail: valData.message });
    return;
  }
  const all = valData.warnings || [];
  showWarnings(all);
  // Save formats on the server, so "not formatted" is not worth a question.
  const blocking = withoutFormat(all);
  if (blocking.length) {
    setDot('yellow'); setStatus('Warnings found (review before saving)', 'warn');
    const go = await confirmDialog({
      title: `Save with ${plural(blocking.length, 'warning')}?`,
      body: 'The config is valid, but these look wrong:',
      detail: blocking.join('\n'),
      confirmLabel: 'Save anyway',
    });
    if (!go) { setStatus('Save cancelled', 'info'); return; }
  }

  // Pre-save live diff: editor (new) against the config currently on disk.
  setStatus('Building diff preview…', 'info');
  let live = originalContent;
  try { const ld = await fetchJson('/api/caddyfile'); live = ld.content; } catch (e) {}
  // Yield a frame so the status above paints before the synchronous diff.
  await new Promise(r => requestAnimationFrame(() => setTimeout(r, 0)));
  const summary = renderDiffInto(document.getElementById('save-diff-content'), live, content);
  const proceed = await openSaveModal(summary, live, content);
  if (!proceed) { setStatus('Save cancelled', 'info'); return; }

  setStatus('Saving…', 'info');
  let res;
  try {
    res = await fetch('/api/save', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ content, version: getVersion() }) });
  } catch (e) { setStatus(`Save failed: ${e.message}`, 'err'); setDot('red'); toast(`Save failed: ${e.message}`, { kind: 'error' }); return; }
  let data = null;
  try { data = await res.json(); } catch (e) {}
  if (res.status === 409) {
    setStatus('Save blocked: file changed on disk', 'err'); setDot('red');
    const reload = await confirmDialog({
      title: 'The Caddyfile changed on disk',
      body: `${(data && data.message) || 'Someone saved a newer version.'} Reloading replaces your unsaved edits with the version on disk.`,
      confirmLabel: 'Reload the latest version',
      cancelLabel: 'Keep my edits',
      danger: true,
    });
    if (reload) { await loadCaddyfile(); toast('Loaded the latest version from disk', { kind: 'info' }); }
    return;
  }
  if (!data) {
    setStatus(`Save failed: HTTP ${res.status}`, 'err'); setDot('red');
    toast(`Save failed: HTTP ${res.status}`, { kind: 'error' });
    return;
  }
  if (data.ok) {
    if (data.content) setContent(data.content);
    setOriginal(data.content || content);
    if (data.version) setVersion(data.version);
    setStatus(data.message, 'ok'); setDot('green');
    markSaved(); hideWarnings();
    toast('Saved and reloaded. Caddy accepted the new config.', { kind: 'ok' });
  } else if (data.saved) {
    // Written to disk, but Caddy could not reload or did not confirm. Keep the
    // editor in step with disk without claiming the running config matches.
    if (data.content) setContent(data.content);
    setOriginal(data.content || content);
    if (data.version) setVersion(data.version);
    setStatus(data.message, 'warn'); setDot('yellow');
    toast(data.message, { kind: 'warn' });
  } else {
    // Not saved: a 400 from the server's own check, Caddy rejecting the reload
    // (the server rolls the file back and says so in its message), CSRF, 503...
    // Keep its version so a retry isn't reported as a conflict.
    if (data.version) setVersion(data.version);
    const msg = data.message || data.error || `Save failed: HTTP ${res.status}`;
    setStatus(msg, 'err'); setDot('red');
    // A 401 already has the session-expired dialog from csrf.js.
    if (res.status !== 401) toast(msg.length > 240 ? msg.slice(0, 240) + '…' : msg, { kind: 'error' });
  }
}

// --- Save diff dialog (promise-based) ---
let _saveResolver = null;
const saveDialog = () => document.getElementById('save-diff-modal');

// `summary`, `live` and `next` are used by Task 15 to name the affected sites.
function openSaveModal(summary, live, next) {
  const sum = document.getElementById('save-diff-summary');
  sum.textContent = '';
  for (const [cls, text] of [['a', `+${summary.added} added`], ['d', `\u2212${summary.removed} removed`]]) {
    const s = document.createElement('span');
    s.className = cls;
    s.textContent = text;
    sum.append(s);
  }
  saveDialog().showModal();
  saveDialog().querySelector('[data-act="confirm-save"]').focus();
  return new Promise(resolve => { _saveResolver = resolve; });
}

export function resolveSaveModal(value) {
  if (saveDialog().open) saveDialog().close();
  // Drop the rendered diff (tens of thousands of rows for a big file).
  document.getElementById('save-diff-content').textContent = '';
  if (_saveResolver) { _saveResolver(value); _saveResolver = null; }
}

// Esc on a native dialog fires `cancel`: treat it as Cancel so the flow never hangs.
saveDialog().addEventListener('cancel', (e) => { e.preventDefault(); resolveSaveModal(false); });
// Any other way the dialog closes must not leave the save flow waiting.
saveDialog().addEventListener('close', () => resolveSaveModal(false));

export function showWarnings(warnings) {
  const box = document.getElementById('warnings');
  box.textContent = '';
  (warnings || []).forEach(w => { const div = document.createElement('div'); div.textContent = w; box.appendChild(div); });
  box.classList.toggle('show', !!(warnings && warnings.length));
}
export function hideWarnings() { document.getElementById('warnings').classList.remove('show'); }
