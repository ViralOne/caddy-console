// Logs tab: poll the Caddy log file and tail it incrementally.
import { el } from './core.js';

let logsPos = null, logsTimer = null, logsFileExisted = false;
// Bumped by startLogs()/stopLogs() so a poll that was in flight when the user
// switched tabs can't append stale lines to a freshly cleared panel.
let logsGeneration = 0;

async function pollLogs() {
  const gen = logsGeneration;
  try {
    const res = await fetch('/api/logs' + (logsPos != null ? `?pos=${logsPos}` : ''));
    if (gen !== logsGeneration) return;
    if (!res.ok) return;  // 401 handled by the fetch wrapper; otherwise retry next tick
    const data = await res.json();
    if (gen !== logsGeneration) return;
    const body = document.getElementById('logs-body');
    if (!data.exists) {
      if (!logsFileExisted) {
        body.textContent = '';
        const hint = el('div', 'metrics-hint');
        hint.style.whiteSpace = 'pre-wrap';
        // The filter wrapper is part of the suggestion on purpose: a bare
        // `format json` writes every request header, including auth tokens,
        // to disk and then into this panel.
        hint.textContent = `No log file at ${data.path}.\n\nAdd a log snippet and import it in each site block:\n\n(access_log) {\n    log {\n        output file ${data.path} {\n            roll_size 10mb\n            roll_keep 3\n            roll_keep_for 168h\n        }\n        format filter {\n            wrap json\n            request>headers delete\n            resp_headers delete\n        }\n    }\n}\n\nyourdomain.com {\n    import access_log\n    reverse_proxy ...\n}\n\nLogs appear after the first HTTP request hits a site with the import.`;
        body.appendChild(hint);
      }
      logsPos = null;
      return;
    }
    logsFileExisted = true;
    if (logsPos === null || data.pos !== logsPos) {
      logsPos = data.pos;
      if (data.lines && data.lines.length) {
        const atBottom = body.scrollHeight - body.scrollTop - body.clientHeight < 40;
        const frag = document.createDocumentFragment();
        data.lines.forEach(line => { const d = document.createElement('div'); d.className = 'log-line'; d.textContent = line; frag.appendChild(d); });
        body.appendChild(frag);
        while (body.children.length > 1000) body.removeChild(body.firstChild);
        if (atBottom) body.scrollTop = body.scrollHeight;
      }
    }
    updateLogsStatus(data.size, body.children.length);
  } catch (e) { /* keep polling */ }
}
function updateLogsStatus(size, lineCount) {
  const status = document.getElementById('logs-status');
  let info = status.querySelector('.logs-info');
  if (!info) {
    status.textContent = '';
    info = el('span', 'logs-info');
    status.appendChild(info);
    const spacer = el('span', 'spacer');
    status.appendChild(spacer);
    const btn = el('button', 'btn btn-secondary', 'Ping Caddy');
    btn.style.cssText = 'padding:2px 8px;font-size:10px';
    btn.onclick = async () => { btn.textContent = '...'; try { await fetch('/api/logs/ping', {method:'POST'}); } catch(e){} btn.textContent = 'Ping Caddy'; };
    status.appendChild(btn);
  }
  const sizeKB = (size / 1024).toFixed(1);
  info.textContent = 'File: ' + sizeKB + ' KB • Lines: ' + lineCount + ' • Polling every 3s';
}
export function startLogs() {
  stopLogs();
  logsGeneration++;
  const body = document.getElementById('logs-body'); body.textContent = '';
  document.getElementById('logs-status').textContent = '';
  logsPos = null; logsFileExisted = false;
  pollLogs();
  logsTimer = setInterval(pollLogs, 3000);
}
export function stopLogs() { logsGeneration++; if (logsTimer) { clearInterval(logsTimer); logsTimer = null; } }
