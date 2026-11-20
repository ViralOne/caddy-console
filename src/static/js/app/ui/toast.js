// Transient results ("Saved and reloaded", "Copied"), bottom centre.
//
// Each toast carries an icon for its kind, so success and failure differ in
// shape, not only in wording. Errors stay until dismissed; the rest time out.
import { iconEl } from '../icons.js';

const ICON = { ok: 'check', info: 'info', warn: 'warning', error: 'status-down' };
const MAX = 3;
let host = null;

function container() {
  if (!host || !host.isConnected) {
    host = document.createElement('div');
    host.className = 'toasts';
    host.setAttribute('aria-live', 'polite');
    document.body.append(host);
  }
  return host;
}

export function toast(message, { kind = 'ok', action = null, timeout } = {}) {
  const t = document.createElement('div');
  t.className = 'toast toast-' + kind;
  t.setAttribute('role', kind === 'error' ? 'alert' : 'status');
  t.append(iconEl(ICON[kind] || 'check', { size: 16 }));
  const text = document.createElement('span');
  text.textContent = message;
  t.append(text);
  let timer = null;
  const dismiss = () => { clearTimeout(timer); t.remove(); };
  if (action) {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = action.label;
    b.addEventListener('click', () => { dismiss(); action.run(); });
    t.append(b);
  }
  const close = document.createElement('button');
  close.type = 'button';
  close.className = 'toast-x';
  close.setAttribute('aria-label', 'Dismiss');
  close.append(iconEl('close', { size: 14 }));
  close.addEventListener('click', dismiss);
  t.append(close);
  const box = container();
  box.append(t);
  while (box.children.length > MAX) box.firstChild.remove();
  const ms = timeout ?? (kind === 'error' ? 0 : action ? 8000 : 5000);
  if (ms > 0) timer = setTimeout(dismiss, ms);
  return { dismiss };
}
