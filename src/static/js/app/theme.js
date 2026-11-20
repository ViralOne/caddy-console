// Theme preference: System (follow the OS), Dark or Light, kept per browser.
//
// The inline script in <head> (src/theme_boot.py) applies the stored choice
// before first paint; this module owns every change after that. The two agree
// on the storage key and its values: "dark", "light", or absent for System.
// Storage can be blocked (private mode, policy); the page then follows the OS.

const KEY = 'ui.theme';

export const THEMES = [
  { id: 'system', label: 'System', icon: 'monitor' },
  { id: 'dark', label: 'Dark', icon: 'moon' },
  { id: 'light', label: 'Light', icon: 'sun' },
];

const isKnown = (id) => THEMES.some(t => t.id === id);

export function getThemePref() {
  try {
    const v = localStorage.getItem(KEY);
    return v === 'dark' || v === 'light' ? v : 'system';
  } catch {
    return 'system';
  }
}

export function setThemePref(pref) {
  if (!isKnown(pref)) throw new Error(`unknown theme: ${pref}`);
  try {
    if (pref === 'system') localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, pref);
  } catch {
    // Not persisted; applyTheme() still switches this page.
  }
}

export function resolveTheme(pref, prefersLight) {
  if (pref === 'dark' || pref === 'light') return pref;
  return prefersLight ? 'light' : 'dark';
}

function osPrefersLight() {
  try { return !!globalThis.matchMedia?.('(prefers-color-scheme: light)').matches; } catch { return false; }
}

export function currentTheme() {
  return globalThis.document?.documentElement?.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
}

/** Put the theme on <html>; announce it with a `themechange` event if it changed. */
export function applyTheme(pref = getThemePref()) {
  const theme = resolveTheme(pref, osPrefersLight());
  const root = globalThis.document?.documentElement;
  if (root && root.getAttribute('data-theme') !== theme) {
    root.setAttribute('data-theme', theme);
    globalThis.dispatchEvent?.(new CustomEvent('themechange', { detail: { theme } }));
  }
  return theme;
}

/** While the preference is System, follow OS changes live. */
export function watchSystemTheme() {
  const mq = globalThis.matchMedia?.('(prefers-color-scheme: light)');
  mq?.addEventListener?.('change', () => { if (getThemePref() === 'system') applyTheme('system'); });
}
