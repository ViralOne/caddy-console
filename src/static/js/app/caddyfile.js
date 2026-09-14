// Bootstrap: load the current user + Caddyfile, and tab switching.
async function init() {
  // A 401 here is handled by the fetch wrapper (redirects to sign-in).
  const res = await fetch('/api/me');
  if (res.status === 401) return;
  if (!res.ok) { setStatus(`Cannot load user: HTTP ${res.status}`, 'err'); setDot('red'); return; }
  const user = await res.json();
  document.getElementById('user-info').textContent = user.email;
  await loadCaddyfile();
}

async function loadCaddyfile() {
  let data;
  try { data = await fetchJson('/api/caddyfile'); }
  catch (e) { if (e.status !== 401) { setStatus(`Cannot load Caddyfile: ${e.message}`, 'err'); setDot('red'); } return; }
  setOriginal(data.content);
  currentVersion = data.version || '';
  if (!editorView) initEditor(data.content); else setContent(data.content);
  setDot('green');
  setStatus('Loaded', 'ok');
}

window.switchTab = function(name, tabEl) {
  stopLogs();
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelector(`.tab-content#tab-${name}`).classList.add('active');
  if (tabEl) tabEl.classList.add('active');
  else document.querySelector(`.tab[data-tab="${name}"]`)?.classList.add('active');
  if (name === 'metrics') loadMetrics();
  if (name === 'logs') startLogs();
};
