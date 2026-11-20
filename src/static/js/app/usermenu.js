// Account menu: avatar + email in the header, opening a panel with the session,
// the Theme and Editor-keys pickers, shortcuts and log out.
//
// Chrome rather than a data view, so plain DOM; Preact is reserved for the
// dashboard and Explore, where derived state actually earns it.
import { applyEditorKeymap } from './core.js';
import { KEYMAPS, getKeymap, setKeymap } from './editor-prefs.js';
import { iconEl } from './icons.js';
import { THEMES, applyTheme, getThemePref, setThemePref } from './theme.js';
import { segmented } from './ui/seg.js';

const SHORTCUTS = [
  ['Save & reload', ['Ctrl/⌘', 'S']],
  ['Find in config', ['Ctrl/⌘', 'F']],
  ['Next / previous match', ['Enter', 'Shift+Enter']],
  ['Close panel, find bar or dialog', ['Esc']],
];
const VIM_SHORTCUTS = [
  ['Save & reload (Vim)', [':w']],
  ['Normal mode (Vim)', ['Esc']],
];
const shortcutsFor = (id) => (id === 'vim' ? [...SHORTCUTS, ...VIM_SHORTCUTS] : SHORTCUTS);

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text) e.textContent = text;
  return e;
}

/** Initials from an email: "dev@local" -> "DE", "a.b@x.com" -> "AB". */
function initialsOf(email) {
  const local = (email || '?').split('@')[0];
  const parts = local.split(/[._\-+]/).filter(Boolean);
  const letters = parts.length > 1 ? parts[0][0] + parts[1][0] : local.slice(0, 2);
  return letters.toUpperCase();
}

/** [what, via] for the session row. Cloudflare Access owns its session, so no expiry. */
function sessionLine(user) {
  if (user.auth_mode === 'cloudflare') return ['Signed in via Cloudflare Access', 'Cloudflare'];
  if (!user.session_expires_at) return ['Signed in', 'Google'];
  const ms = user.session_expires_at * 1000 - Date.now();
  if (ms <= 0) return ['Session expired. Reload to sign in again.', 'Google'];
  const hours = Math.floor(ms / 3600000);
  const mins = Math.round((ms % 3600000) / 60000);
  return [`Session ends in ${hours ? hours + 'h ' : ''}${mins}m`, 'Google'];
}

function avatar(email) {
  const a = el('span', 'avatar', initialsOf(email));
  a.setAttribute('aria-hidden', 'true');
  return a;
}

function renderShortcuts(dl, keymap) {
  dl.textContent = '';
  for (const [label, keys] of shortcutsFor(keymap)) {
    const dd = el('dd');
    keys.forEach((k) => dd.append(el('span', 'kbd', k)));
    dl.append(el('dt', '', label), dd);
  }
}

export function initUserMenu(user) {
  const host = document.getElementById('user-menu');
  if (!host) return;
  host.textContent = '';
  const name = user.name && user.name !== user.email ? user.name : '';

  const button = el('button', 'acct-btn');
  button.type = 'button';
  button.setAttribute('aria-haspopup', 'dialog');
  button.setAttribute('aria-controls', 'acct-menu');
  button.append(avatar(user.email), el('span', 'em', user.email),
    iconEl('chevron-down', { size: 14 }), el('span', 'sr', 'Account menu'));

  const menu = el('div', 'pop acct-menu');
  menu.id = 'acct-menu';
  menu.setAttribute('role', 'dialog');
  menu.setAttribute('aria-label', 'Account');

  const idSection = el('section', 'acct-id');
  const who = el('div');
  who.append(el('b', '', name || user.email));
  if (name) who.append(el('span', 'muted', user.email));
  idSection.append(avatar(user.email), who);

  const session = el('section', 'acct-session');
  const sessionRow = el('div', 'row');
  const refreshSession = () => {
    const [text, via] = sessionLine(user);
    sessionRow.textContent = '';
    sessionRow.append(el('span', '', text), el('span', 'muted', via));
  };
  session.append(sessionRow);

  const themeSection = el('section');
  const themeRow = el('div', 'row');
  const themeSeg = segmented({
    label: 'Theme', options: THEMES, value: getThemePref(),
    onChange: (pref) => { setThemePref(pref); applyTheme(pref); },
  });
  themeRow.append(el('h2', '', 'Theme'), themeSeg.el);
  themeSection.append(themeRow);

  const keysSection = el('section');
  const keysRow = el('div', 'row');
  const dl = el('dl', 'shortcuts');
  const keySeg = segmented({
    label: 'Editor keymap', options: KEYMAPS, value: getKeymap(),
    onChange: (id) => { setKeymap(id); renderShortcuts(dl, id); applyEditorKeymap(id); },
  });
  keysRow.append(el('h2', '', 'Editor keys'), keySeg.el);
  renderShortcuts(dl, getKeymap());
  keysSection.append(keysRow, el('h2', 'acct-sub', 'Shortcuts'), dl);

  const foot = el('section', 'acct-foot');
  const logout = el('a', 'menu-item');
  logout.href = '/logout';
  logout.append(iconEl('logout'), document.createTextNode('Log out'));
  foot.append(logout, el('div', 'version', `Caddy Console ${user.version || ''}`.trim()));

  menu.append(idSection, session, themeSection, keysSection, foot);
  host.append(button, menu);

  // The remaining session time is recomputed when the menu opens, so it is
  // never shown stale and no timer runs while it is closed.
  const setOpen = (open, { focusButton = false } = {}) => {
    menu.hidden = !open;
    button.setAttribute('aria-expanded', String(open));
    if (open) { refreshSession(); themeSeg.el.querySelector('[aria-checked="true"]')?.focus(); }
    else if (focusButton) button.focus();
  };
  setOpen(false);
  button.addEventListener('click', (e) => { e.stopPropagation(); setOpen(menu.hidden); });
  document.addEventListener('click', (e) => { if (!menu.hidden && !host.contains(e.target)) setOpen(false); });
  document.addEventListener('keydown', (e) => {
    if (!menu.hidden && e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); setOpen(false, { focusButton: true }); }
  });
}
