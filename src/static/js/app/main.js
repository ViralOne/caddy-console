// Entry point: global keyboard shortcuts, CSP-safe event delegation, and app
// bootstrap. The only script index.html loads; everything else arrives through
// these imports.
import './csrf.js';  // patches window.fetch before init() issues any request
import { closePreview, restoreFromPreview, rollbackFromPreview } from './backups.js';
import { init, showView, syncViewFromUrl } from './caddyfile.js';
import { revealLine, revealSite } from './core.js';
import { closeAllPanels, closePanel, insertBanImportAtLine, togglePanel } from './panels.js';
import { interceptLinks, onNavigate } from './router.js';
import { closeSearch, doSearch, replaceAll, replaceOne, searchNext, searchPrev, toggleSearch } from './search.js';
import { doSave, doValidate, resolveSaveModal } from './validate.js';
import { applyTheme, watchSystemTheme } from './theme.js';

document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  if (document.querySelector('dialog[open]')) return;
  // Esc with the account menu open closes only the menu (usermenu.js handles it).
  if (e.defaultPrevented || document.querySelector('#acct-menu:not([hidden])')) return;
  // Closing the panel that has focus hands it back to the header button; Esc
  // typed in the editor (Vim) closes panels without moving the cursor away.
  const open = document.querySelector('.panel:not([hidden])');
  if (open && open.contains(document.activeElement)) closePanel(open.id.replace('panel-', ''));
  else closeAllPanels();
  // Only touch the editor if the find bar is actually open; otherwise Escape
  // in another tab would yank focus into the editor.
  if (document.getElementById('search-bar').classList.contains('open')) closeSearch();
});

// Cmd/Ctrl+F opens the find/replace bar (capture phase to preempt the editor).
// Cmd/Ctrl+F opens the find bar, but only where there is a document to search;
// elsewhere the browser's own find is the useful behaviour.
document.addEventListener('keydown', e => {
  if (!(e.metaKey || e.ctrlKey) || e.key.toLowerCase() !== 'f') return;
  if (!document.getElementById('tab-editor').classList.contains('active')) return;
  e.preventDefault(); e.stopPropagation(); toggleSearch();
}, true);

// --- Event delegation (CSP-safe: no inline handlers) ---
document.addEventListener('click', e => {
  const t = e.target.closest('[data-act],[data-panel],[data-close]');
  if (!t) return;
  if (t.dataset.panel) { togglePanel(t.dataset.panel); return; }
  if (t.dataset.close) { closePanel(t.dataset.close); return; }
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

applyTheme();          // matches what the <head> script already set; arms the change event
watchSystemTheme();
// Dashboard "Open <site> block": switch to the Editor and land on that block.
document.addEventListener('app:open-site', (e) => {
  showView('editor');
  revealSite(e.detail.host);
});

// Security "Add import in editor": insert in the editor buffer only; on a refusal, show the site.
document.addEventListener('app:insert-ban-import', async (e) => {
  showView('editor');
  if (!(await insertBanImportAtLine(e.detail.line, e.detail.source || 'manual'))) revealLine(e.detail.line);
});

syncViewFromUrl();
init();
