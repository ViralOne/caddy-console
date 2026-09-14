// Side panels: open/close behaviour + Audit, Status, and Snippets loaders.
window.togglePanel = function(name) {
  const panel = document.getElementById(`panel-${name}`); const isOpen = panel.classList.contains('open');
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('open'));
  document.querySelectorAll('[id^="panel-btn-"]').forEach(b => b.classList.remove('panel-active'));
  if (isOpen) { if (name === 'backups') clearPreview(); return; }
  panel.classList.add('open');
  const btn = document.getElementById(`panel-btn-${name}`);
  if (btn) btn.classList.add('panel-active');
  if (name==='backups') loadBackups(); if (name==='audit') loadAudit(); if (name==='status') loadStatusPanel(); if (name==='snippets') loadSnippets();
};
window.closePanel = function(name) {
  document.getElementById(`panel-${name}`).classList.remove('open');
  document.querySelectorAll('[id^="panel-btn-"]').forEach(b => b.classList.remove('panel-active'));
  if (name === 'backups') clearPreview();
};

async function loadAudit() {
  const list = document.getElementById('audit-list');
  let data;
  try { data = await fetchJson('/api/audit'); }
  catch (e) { showError(list, 'Could not load audit log', e); return; }
  list.textContent = '';
  if (!data.entries.length) { list.textContent = 'No activity yet.'; return; }
  data.entries.forEach(e => {
    const item = document.createElement('div'); item.className = 'audit-item';
    const action = document.createElement('span'); action.className = 'action'; action.textContent = e.action;
    const user = document.createElement('span'); user.className = 'user'; user.textContent = ' ' + e.user;
    const time = document.createElement('span'); time.className = 'time'; time.textContent = e.time + ' ' + (e.detail||'');
    item.appendChild(action); item.appendChild(user); item.appendChild(document.createElement('br')); item.appendChild(time); list.appendChild(item);
  });
}

async function loadStatusPanel() {
  const body = document.getElementById('status-body');
  let data;
  try { data = await fetchJson('/api/status'); }
  catch (e) { showError(body, 'Could not load status', e); return; }
  body.textContent = '';
  [['Caddy Version',data.caddy_version],['Config Valid',data.config_valid?'Valid':'Invalid'],['Config Path',data.config_path],['Last Modified',data.last_modified]].forEach(([label,value]) => {
    const card = document.createElement('div'); card.className = 'status-card';
    const lbl = document.createElement('label'); lbl.textContent = label;
    const val = document.createElement('div'); val.className = 'value'; val.textContent = value;
    if (label === 'Config Valid') val.style.color = data.config_valid ? '#66bb6a' : '#ef5350';
    card.appendChild(lbl); card.appendChild(val); body.appendChild(card);
  });
}

async function loadSnippets() {
  const list = document.getElementById('snippets-list');
  let data;
  try { data = await fetchJson('/api/snippets'); }
  catch (e) { showError(list, 'Could not load snippets', e); return; }
  list.textContent = '';
  data.snippets.forEach(s => {
    const card = document.createElement('div'); card.className = 'snippet-card'; card.onclick = () => insertSnippet(s.code);
    const name = document.createElement('div'); name.className = 'name'; name.textContent = s.name;
    const desc = document.createElement('div'); desc.className = 'desc'; desc.textContent = s.description;
    card.appendChild(name); card.appendChild(desc); list.appendChild(card);
  });
}
function insertSnippet(code) { const pos = editorView.state.selection.main.head; editorView.dispatch({ changes: { from: pos, insert: code } }); setDot('yellow'); window.closePanel('snippets'); }
