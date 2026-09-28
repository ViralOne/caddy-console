// Bootstrap: load the current user + Caddyfile, and tab switching.
import {
  editorView, fetchJson, initEditor, setContent, setDot, setOriginal, setStatus, setVersion,
} from './core.js';
import { mountExplore } from './explore.js';
import { loadMetrics } from './metrics.js';
import { navigate, pathFor, viewFromPath } from './router.js';

export async function init() {
  // A 401 here is handled by the fetch wrapper (redirects to sign-in).
  const res = await fetch('/api/me');
  if (res.status === 401) return;
  if (!res.ok) { setStatus(`Cannot load user: HTTP ${res.status}`, 'err'); setDot('red'); return; }
  const user = await res.json();
  document.getElementById('user-info').textContent = user.email;
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
}

/** Show a view. `push` is false when responding to the URL (initial load, Back). */
export function showView(name, { push = true } = {}) {
  const view = ['dashboard', 'editor', 'explore'].includes(name) ? name : 'dashboard';
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.view === view));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelector(`.tab-content#tab-${view}`).classList.add('active');
  // Explore owns its query string; switching to any other view drops it so the
  // URL never advertises filters that are not in effect.
  if (push) navigate(view, view === 'explore' ? location.search : '');
  if (view === 'dashboard') loadMetrics();
  if (view === 'explore') mountExplore();
}

export function syncViewFromUrl() {
  showView(viewFromPath(), { push: false });
}
