// Side panels (Snippets, Backups): one open at a time, toggled from the header.
import { clearPreview, loadBackups } from './backups.js';
import { editorView, fetchJson, setDot, showError } from './core.js';
import {
  IMPORT_AFTER, PLUGIN_IMPORT_AFTER, PLUGIN_SNIPPET, SOURCE_FILES, planGlobalOptionInsertion, planSiteInsertion,
  planTopLevelInsertion, pluginGate,
} from './snippet-insert.js';
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

const SOURCE_SNIPPETS = { manual: 'manual-bans-site', crowdsec: 'crowdsec-bans-site', plugin: 'crowdsec-plugin-site' };

const REFUSED = {
  'outside-site': 'Put the cursor inside a site block first; the import goes first in that site.',
  duplicate: 'This site already imports this ban list.',
  'management-site': "This is the console's own site; a ban there could lock you out, so the import is not offered.",
  'duplicate-global': 'The global options already configure crowdsec.',
};

const PLUGIN_REFUSED = {
  'plugin-unavailable': () => 'Plugin mode is not available: CrowdSec is not configured or the running Caddy has no crowdsec module.',
  'plugin-module-missing': () => 'The running Caddy build has no crowdsec module. Start the plugin image (docker-compose.crowdsec-plugin.yaml) first.',
  'plugin-blocked': (p) => `Plugin mode is refused: ${p.blocked}`,
  'plugin-definition-stale': () => 'The protected route file is missing or out of date. Re-apply the plugin route in Security first.',
  'plugin-app-missing': () => 'Caddy has not loaded the CrowdSec plugin app yet. Insert the global app, Save & Reload, then protect sites.',
  'plugin-definition-missing': () => 'Load the protected route definition (top level) and Save & Reload before protecting a site.',
};

/** Toast why a plugin snippet is not inserted now; true when it was refused. */
function refusePlugin(s, ctx) {
  const gate = pluginGate(s, ctx.plugin);
  if (!gate) return false;
  toast(PLUGIN_REFUSED[gate](ctx.plugin || {}), { kind: 'warn', action: { label: 'Copy', run: () => copySnippet(s) } });
  return true;
}

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
  const isPlugin = s.phase === 'plugin';
  if (isPlugin && refusePlugin(s, ctx)) return false;
  const dir = ctx.bans_dir || '/etc/caddy/console';
  const source = Object.keys(SOURCE_SNIPPETS).find(k => SOURCE_SNIPPETS[k] === s.id) || 'manual';
  const opts = isPlugin
    ? { snippetName: PLUGIN_SNIPPET, managementHosts: ctx.management_hosts || [],
        after: PLUGIN_IMPORT_AFTER.map(a => `${dir}/${SOURCE_FILES[a]}`) }
    : { target: `${dir}/${SOURCE_FILES[source]}`, managementHosts: ctx.management_hosts || [],
        after: (IMPORT_AFTER[source] || []).map(a => `${dir}/${SOURCE_FILES[a]}`) };
  const plan = planSiteInsertion(editorView.state.doc.toString(), cursorLine, s.code, opts);
  if (!plan.ok) {
    const msg = isPlugin && plan.reason === 'duplicate' ? 'This site already imports protect_crowdsec.' : REFUSED[plan.reason];
    toast(msg, { kind: 'warn', action: { label: 'Copy', run: () => copySnippet(s) } });
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
export async function insertBanImportAtLine(siteLine, source = 'manual') {
  let data;
  try { data = await loadSnippetData(); }
  catch (e) { toast(`Could not load snippets: ${e.message}`, { kind: 'error' }); return false; }
  const s = data.snippets.find(x => x.id === SOURCE_SNIPPETS[source]);
  if (!s) {
    toast(source === 'plugin' ? PLUGIN_REFUSED['plugin-unavailable']() : 'This ban list is not available: CrowdSec is not configured.',
      { kind: 'warn' });
    return false;
  }
  if (!Number.isInteger(siteLine)) {
    toast('This site is not defined in the editor buffer (for example an imported file), so the import cannot be inserted here.',
      { kind: 'warn', action: { label: 'Copy', run: () => copySnippet(s) } });
    return false;
  }
  return insertSiteFirst(s, siteLine);
}

/** Insert a global-options or top-level plugin snippet at its own scope, never at the cursor. */
function insertScoped(s) {
  const ctx = snippetData?.context;
  if (!ctx) {
    toast('Snippet settings are not loaded yet, so the snippet was not inserted.',
      { kind: 'warn', action: { label: 'Copy', run: () => copySnippet(s) } });
    return false;
  }
  if (refusePlugin(s, ctx)) return false;
  const text = editorView.state.doc.toString();
  const plan = s.insert === 'global-options'
    ? planGlobalOptionInsertion(text, s.code)
    : planTopLevelInsertion(text, s.code, { target: ctx.plugin.definition_target });
  if (!plan.ok) {
    const msg = plan.reason === 'duplicate' ? 'The protected route definition is already imported at top level.'
      : REFUSED[plan.reason] || 'This snippet is already in the Caddyfile.';
    toast(msg, { kind: 'warn' });
    return false;
  }
  const doc = editorView.state.doc;
  const from = plan.atEnd ? doc.length : doc.line(plan.line).from;
  editorView.dispatch({ changes: { from, insert: plan.text } });
  setDot('yellow');
  closePanel('snippets');
  const hash = s.insert === 'top-level' && ctx.plugin.definition_hash ? ` (protected ranges ${ctx.plugin.definition_hash})` : '';
  const unknown = ctx.plugin.module === null ? ' Caddy did not answer, so Check will tell whether this build has the crowdsec module.' : '';
  toast(`Inserted "${s.name}" at line ${plan.line}${hash}. Review it, then Save & Reload.${unknown}`, { kind: unknown ? 'warn' : 'ok' });
  return true;
}

function insertSnippet(s) {
  if (s.insert === 'copy-only') { copySnippet(s); return; }
  if (s.insert === 'global-options' || s.insert === 'top-level') { insertScoped(s); return; }
  const pos = editorView.state.selection.main.head;
  const line = editorView.state.doc.lineAt(pos).number;
  if (s.insert === 'site-first') { insertSiteFirst(s, line); return; }
  editorView.dispatch({ changes: { from: pos, insert: s.code } });
  setDot('yellow');
  closePanel('snippets');
  toast(`Inserted "${s.name}" at line ${line}`, { kind: 'ok' });
}
