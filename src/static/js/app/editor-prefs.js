// Editor keymap preference, kept per browser in localStorage.
//
// Storage can be unavailable (private mode, disabled by policy); the editor then
// just uses the standard keymap and switching works for the current page only.

const KEY = 'editor.keymap';

export const KEYMAPS = [
  { id: 'standard', label: 'Standard' },
  { id: 'vim', label: 'Vim' },
];

const isKnown = (id) => KEYMAPS.some(k => k.id === id);

export function getKeymap() {
  try {
    const v = localStorage.getItem(KEY);
    return isKnown(v) ? v : 'standard';
  } catch {
    return 'standard';
  }
}

export function setKeymap(id) {
  if (!isKnown(id)) throw new Error(`unknown editor keymap: ${id}`);
  try {
    localStorage.setItem(KEY, id);
  } catch {
    // Not persisted; the caller has already applied it to the open editor.
  }
}
