// Bootstrap: load the current user + Caddyfile, and tab switching.
import {
  editorView, fetchJson, initEditor, setContent, setDot, setOriginal, setStatus, setVersion,
} from './core.js';
import { mountExplore } from './explore.js';
import { mountDashboard } from './dashboard.js';
import { mountSecurity } from './security.js';
import { closeAllPanels } from './panels.js';
import { navigate, pathFor, viewFromPath } from './router.js';
import { initUserMenu } from './usermenu.js';
import { lintCurrent } from './validate.js';

export async function init() {
  // A 401 here is handled by the fetch wrapper (redirects to sign-in).
  const res = await fetch('/api/me');
  if (res.status === 401) return;
  if (!res.ok) { setStatus(`Cannot load user: HTTP ${res.status}`, 'err'); setDot('red'); return; }
  const user = await res.json();
  document.getElementById('user-info').textContent = user.email;
  initUserMenu(user);
  await loadCaddyfile();
}

export async function loadCaddyfile() {
  let data;
  try { data = await fetchJson('/api/caddyfile'); }
  catch (e) { if (e.status !== 401) { setStatus(`Cannot load Caddyfile: ${e.message}`, 'err'); setDot('red'); } return; }
  setOriginal(data.content);
  setVersion(data.version || '');
  if (!editorView) initEditor(data.content); else setContent(data.content);
  setDot('green');
  setStatus('Loaded', 'ok');
  lintCurrent();
}

/** Show a view. `push` is false when responding to the URL (initial load, Back). */
export function showView(name, { push = true } = {}) {
  const known = ['dashboard', 'editor', 'explore'];
  // The Security view exists only when the server rendered it (BANS_ENABLED).
  if (document.getElementById('tab-security')) known.push('security');
  const view = known.includes(name) ? name : 'dashboard';
  document.querySelectorAll('.tab').forEach(t => {
    if (t.dataset.view === view) t.setAttribute('aria-current', 'page');
    else t.removeAttribute('aria-current');
  });
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelector(`.tab-content#tab-${view}`).classList.add('active');
  // Only show actions that do something here: Check, Save, Find, Snippets and
  // Backups all act on the editor.
  document.querySelectorAll('[data-for-view]').forEach(n => { n.hidden = n.dataset.forView !== view; });
  // A panel left open while switching away would float over an unrelated view.
  if (view !== 'editor') closeAllPanels();
  // Explore owns its query string; switching to any other view drops it so the
  // URL never advertises filters that are not in effect.
  if (push) navigate(view, view === 'explore' ? location.search : '');
  if (view === 'dashboard') mountDashboard();
  if (view === 'explore') mountExplore();
  if (view === 'security') mountSecurity();
}

export function syncViewFromUrl() {
  showView(viewFromPath(), { push: false });
}
