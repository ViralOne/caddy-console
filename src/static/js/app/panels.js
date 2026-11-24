// Side panels (Snippets, Backups): one open at a time, toggled from the header.
import { clearPreview, loadBackups } from './backups.js';
import { editorView, fetchJson, setDot, showError } from './core.js';
import { planSiteInsertion } from './snippet-insert.js';
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

let snippetData = null;

async function loadSnippetData() {
  if (!snippetData) snippetData = await fetchJson('/api/snippets');
  return snippetData;
}

export async function loadSnippets() {
  const list = document.getElementById('snippets-list');
  let data;
  // Refresh on open (the console site list comes from the file on disk), but keep
  // the old data until the new fetch succeeds: the console-site guard needs it.
  try { data = await fetchJson('/api/snippets'); snippetData = data; }
  catch (e) { showError(list, 'Could not load snippets', e); return; }
  list.textContent = '';
  data.snippets.forEach((s) => {
    const card = document.createElement('button');
    card.type = 'button';
    card.className = 'snip';
    const name = document.createElement('b');
    name.textContent = s.name;
    const desc = document.createElement('span');
    desc.textContent = s.insert === 'copy-only' ? `${s.description} (copies to the clipboard)` : s.description;
    card.append(name, desc);
    card.addEventListener('click', () => insertSnippet(s));
    list.appendChild(card);
  });
}

const REFUSED = {
  'outside-site': 'Put the cursor inside a site block first; the import goes first in that site.',
  duplicate: 'This site already imports the ban list.',
  'management-site': "This is the console's own site; a ban there could lock you out, so the import is not offered.",
};

function copySnippet(s) {
  navigator.clipboard.writeText(s.code).then(
    () => toast(`Copied "${s.name}"`, { kind: 'ok' }),
    () => toast('Could not copy to the clipboard', { kind: 'error' }));
}

/** Insert a site-scoped snippet first in the site under cursorLine. Returns whether the buffer changed. */
export function insertSiteFirst(s, cursorLine) {
  const ctx = snippetData?.context;
  if (!ctx) {   // fail closed: without the console site list the guard cannot work
    toast('Snippet settings are not loaded yet, so the import was not inserted.',
      { kind: 'warn', action: { label: 'Copy', run: () => copySnippet(s) } });
    return false;
  }
  const plan = planSiteInsertion(editorView.state.doc.toString(), cursorLine, s.code, {
    target: `${ctx.bans_dir || '/etc/caddy/console'}/bans-manual.caddy`,
    managementHosts: ctx.management_hosts || [],
  });
  if (!plan.ok) {
    toast(REFUSED[plan.reason], { kind: 'warn', action: { label: 'Copy', run: () => copySnippet(s) } });
    return false;
  }
  const doc = editorView.state.doc;
  const from = plan.atEnd ? doc.length : doc.line(plan.line).from;
  editorView.dispatch({ changes: { from, insert: plan.text } });
  setDot('yellow');
  closePanel('snippets');
  toast(`Inserted "${s.name}" at line ${plan.line}. Review it, then Save & Reload.`, { kind: 'ok' });
  return true;
}

/** Security view entry: a site with no known line (external import) gets Copy only. */
export async function insertBanImportAtLine(siteLine) {
  let data;
  try { data = await loadSnippetData(); }
  catch (e) { snippetData = null; toast(`Could not load snippets: ${e.message}`, { kind: 'error' }); return false; }
  const s = data.snippets.find(x => x.id === 'manual-bans-site');
  if (!s) return false;
  if (!Number.isInteger(siteLine)) {
    toast('This site is not defined in the editor buffer (for example an imported file), so the import cannot be inserted here.',
      { kind: 'warn', action: { label: 'Copy', run: () => copySnippet(s) } });
    return false;
  }
  return insertSiteFirst(s, siteLine);
}

function insertSnippet(s) {
  if (s.insert === 'copy-only') { copySnippet(s); return; }
  const pos = editorView.state.selection.main.head;
  const line = editorView.state.doc.lineAt(pos).number;
  if (s.insert === 'site-first') { insertSiteFirst(s, line); return; }
  editorView.dispatch({ changes: { from: pos, insert: s.code } });
  setDot('yellow');
  closePanel('snippets');
  toast(`Inserted "${s.name}" at line ${line}`, { kind: 'ok' });
}
