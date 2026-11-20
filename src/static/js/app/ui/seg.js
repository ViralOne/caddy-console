// A segmented radio group (Theme, Editor keys, Preview / Diff). Arrow keys move
// and select, as in any radio group; Tab enters and leaves it as one stop.
import { iconEl } from '../icons.js';

export function segmented({ label, options, value, onChange }) {
  const el = document.createElement('div');
  el.className = 'seg';
  el.setAttribute('role', 'radiogroup');
  el.setAttribute('aria-label', label);
  const buttons = options.map((o) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.setAttribute('role', 'radio');
    b.dataset.v = o.id;
    if (o.icon) b.append(iconEl(o.icon, { size: 14 }));
    b.append(document.createTextNode(o.label));
    return b;
  });
  const set = (v) => buttons.forEach((b) => {
    const on = b.dataset.v === v;
    b.setAttribute('aria-checked', String(on));
    b.tabIndex = on ? 0 : -1;
  });
  const pick = (b) => {
    if (b.getAttribute('aria-checked') === 'true') return;
    set(b.dataset.v);
    onChange(b.dataset.v);
  };
  el.addEventListener('click', (e) => { const b = e.target.closest('[role="radio"]'); if (b) pick(b); });
  el.addEventListener('keydown', (e) => {
    if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(e.key)) return;
    e.preventDefault();
    const i = buttons.findIndex((b) => b.getAttribute('aria-checked') === 'true');
    const step = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? 1 : -1;
    const next = buttons[(i + step + buttons.length) % buttons.length];
    pick(next);
    next.focus();
  });
  el.append(...buttons);
  set(value);
  return { el, set };
}
