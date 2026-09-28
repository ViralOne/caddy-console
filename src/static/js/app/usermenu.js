// Account menu: avatar + email in the header, opening a small panel.
//
// Chrome rather than a data view, so plain DOM — Preact is reserved for the
// dashboard and Explore, where derived state actually earns it.
import { iconEl } from './icons.js';

const SHORTCUTS = [
  ['Save & reload', 'Cmd/Ctrl + S'],
  ['Find in config', 'Cmd/Ctrl + F'],
  ['Next / previous match', 'Enter / Shift + Enter'],
  ['Close panel, find bar or dialog', 'Esc'],
];

/** Initials from an email: "dev@local" -> "DE", "a.b@x.com" -> "AB". */
function initialsOf(email) {
  const local = (email || '?').split('@')[0];
  const parts = local.split(/[._\-+]/).filter(Boolean);
  const letters = parts.length > 1 ? parts[0][0] + parts[1][0] : local.slice(0, 2);
  return letters.toUpperCase();
}

function expiryLine(user) {
  if (user.auth_mode === 'cloudflare') {
    // Access owns the session here; this app cannot say when it ends.
    return 'Signed in via Cloudflare Access';
  }
  if (!user.session_expires_at) return 'Signed in with Google';
  const secs = user.session_expires_at * 1000 - Date.now();
  if (secs <= 0) return 'Session expired — reload to sign in again';
  const hours = Math.floor(secs / 3600000);
  const mins = Math.round((secs % 3600000) / 60000);
  return `Session ends in ${hours ? hours + 'h ' : ''}${mins}m`;
}

function row(label, value, cls) {
  const div = document.createElement('div');
  div.className = 'menu-row' + (cls ? ' ' + cls : '');
  const l = document.createElement('span');
  l.className = 'menu-row-label';
  l.textContent = label;
  const v = document.createElement('span');
  v.className = 'menu-row-value';
  v.textContent = value;
  div.append(l, v);
  return div;
}

export function initUserMenu(user) {
  const host = document.getElementById('user-menu');
  if (!host) return;
  host.textContent = '';

  const button = document.createElement('button');
  button.className = 'menu-trigger';
  button.type = 'button';
  button.setAttribute('aria-expanded', 'false');
  button.setAttribute('aria-haspopup', 'true');

  const avatar = document.createElement('span');
  avatar.className = 'avatar';
  avatar.textContent = initialsOf(user.email);
  avatar.setAttribute('aria-hidden', 'true');

  const label = document.createElement('span');
  label.className = 'menu-trigger-email';
  label.textContent = user.email;

  const caret = iconEl('chevron-down', { size: 14, cls: 'menu-caret' });

  button.append(avatar, label, caret);

  const menu = document.createElement('div');
  menu.className = 'menu';
  menu.setAttribute('role', 'menu');

  const head = document.createElement('div');
  head.className = 'menu-head';
  const headAvatar = document.createElement('span');
  headAvatar.className = 'avatar avatar-lg';
  headAvatar.textContent = initialsOf(user.email);
  const headText = document.createElement('div');
  const name = document.createElement('div');
  name.className = 'menu-name';
  name.textContent = user.name && user.name !== user.email ? user.name : user.email;
  const sub = document.createElement('div');
  sub.className = 'menu-sub';
  sub.textContent = user.name && user.name !== user.email ? user.email : '';
  headText.append(name, sub);
  head.append(headAvatar, headText);

  const session = document.createElement('div');
  session.className = 'menu-session';
  const refreshExpiry = () => { session.textContent = expiryLine(user); };
  refreshExpiry();

  const shortcuts = document.createElement('div');
  shortcuts.className = 'menu-section';
  shortcuts.appendChild(Object.assign(document.createElement('div'),
    { className: 'menu-section-title', textContent: 'Shortcuts' }));
  SHORTCUTS.forEach(([l, v]) => shortcuts.appendChild(row(l, v)));

  const logout = document.createElement('a');
  logout.className = 'menu-action';
  logout.href = '/logout';
  logout.setAttribute('role', 'menuitem');
  logout.append(iconEl('logout'), document.createTextNode('Log out'));

  // Which build you are running, where you look when something behaves oddly.
  const version = document.createElement('div');
  version.className = 'menu-version';
  version.textContent = `Caddy Console ${user.version || ''}`.trim();

  menu.append(head, session, shortcuts, logout, version);
  host.append(button, menu);

  let open = false;
  const setOpen = (next) => {
    open = next;
    host.classList.toggle('open', open);
    button.setAttribute('aria-expanded', String(open));
    // The remaining time is only recomputed when the menu opens, so it is never
    // shown stale, and no timer runs while it is closed.
    if (open) refreshExpiry();
  };

  // Set the closed state explicitly rather than relying on the markup starting
  // without the class, so the trigger's aria-expanded and the panel can never
  // disagree about whether the menu is open.
  setOpen(false);

  button.addEventListener('click', (e) => { e.stopPropagation(); setOpen(!open); });
  document.addEventListener('click', (e) => { if (open && !host.contains(e.target)) setOpen(false); });
  document.addEventListener('keydown', (e) => { if (open && e.key === 'Escape') { e.stopPropagation(); setOpen(false); } });
}
