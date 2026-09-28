// Entry point: global keyboard shortcuts, CSP-safe event delegation, and app
// bootstrap. The only script index.html loads; everything else arrives through
// these imports.
import './csrf.js';  // patches window.fetch before init() issues any request
import { closePreview, restoreFromPreview, rollbackFromPreview, showPreviewTab, clearPreview } from './backups.js';
import { init, showView, syncViewFromUrl } from './caddyfile.js';
import { closePanel, togglePanel } from './panels.js';
import { interceptLinks, onNavigate } from './router.js';
import { closeSearch, doSearch, replaceAll, replaceOne, searchNext, searchPrev, toggleSearch } from './search.js';
import { doSave, doValidate, resolveSaveModal } from './validate.js';

document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('open'));
  document.querySelectorAll('[id^="panel-btn-"]').forEach(b => b.classList.remove('panel-active'));
  clearPreview();
  // Only touch the editor if the find bar is actually open; otherwise Escape
  // in another tab would yank focus into the editor.
  if (document.getElementById('search-bar').classList.contains('open')) closeSearch();
  // Resolve the save modal's promise, don't just hide it, or the save flow
  // stays stuck on "Building diff preview..." forever.
  if (document.getElementById('save-diff-modal').classList.contains('open')) resolveSaveModal(false);
});

// Cmd/Ctrl+F opens the find/replace bar (capture phase to preempt the editor).
document.addEventListener('keydown', e => {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'f') { e.preventDefault(); e.stopPropagation(); toggleSearch(); }
}, true);

// --- Event delegation (CSP-safe: no inline handlers) ---
document.addEventListener('click', e => {
  const t = e.target.closest('[data-act],[data-panel],[data-close],[data-ptab]');
  if (!t) return;
  if (t.dataset.panel) { togglePanel(t.dataset.panel); return; }
  if (t.dataset.close) { closePanel(t.dataset.close); return; }
  if (t.dataset.ptab) { showPreviewTab(t.dataset.ptab); return; }
  switch (t.dataset.act) {
    case 'validate': return doValidate();
    case 'save': return doSave();
    case 'find': return toggleSearch();
    case 'search-next': return searchNext();
    case 'search-prev': return searchPrev();
    case 'replace-one': return replaceOne();
    case 'replace-all': return replaceAll();
    case 'search-close': return closeSearch();
    case 'restore-preview': return restoreFromPreview();
    case 'rollback-preview': return rollbackFromPreview();
    case 'close-preview': return closePreview();
    case 'confirm-save': return resolveSaveModal(true);
    case 'cancel-save': return resolveSaveModal(false);
  }
});
document.getElementById('search-input').addEventListener('input', () => doSearch());

// Enter steps to the next match, Shift+Enter to the previous one.
document.getElementById('search-input').addEventListener('keydown', e => {
  if (e.key !== 'Enter') return;
  e.preventDefault();
  if (e.shiftKey) searchPrev(); else searchNext();
});

// Links marked data-view route in-app; Back/Forward re-reads the path.
interceptLinks(view => showView(view, { push: false }));
onNavigate(view => showView(view, { push: false }));

syncViewFromUrl();
init();
