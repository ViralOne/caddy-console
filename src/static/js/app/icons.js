// Icons, as <use> references into the sprite inlined by templates/_icons.html.
//
// Two entry points for the app's two rendering styles: `Icon` for the Preact
// views, `iconEl` for the plain-DOM chrome. Names are validated because a typo
// otherwise renders an invisible empty box.
import { h, htm } from '../explore-vendor.js';

const html = htm.bind(h);

export const ICONS = [
  'dashboard', 'editor', 'explore',
  'box', 'box-check', 'box-x',
  'more', 'chevron-down', 'close', 'copy', 'clock', 'filter', 'live',
  'check', 'warning', 'external', 'logout',
];

function idFor(name) {
  if (!ICONS.includes(name)) throw new Error(`unknown icon: ${name}`);
  return `#i-${name}`;
}

/** An icon for the Preact views. With no `title` it is decoration, and hidden
 *  from assistive tech. */
export function Icon({ name, size, title, class: cls }) {
  const px = size || 16;
  return html`
    <svg class=${'icon' + (cls ? ' ' + cls : '')} width=${px} height=${px}
         role=${title ? 'img' : 'presentation'} aria-hidden=${title ? null : 'true'}
         aria-label=${title || null} focusable="false">
      ${title && html`<title>${title}</title>`}
      <use href=${idFor(name)} />
    </svg>`;
}

/** The same icon as a DOM node, for the modules that build elements by hand. */
export function iconEl(name, { size = 16, title = '', cls = '' } = {}) {
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('class', 'icon' + (cls ? ' ' + cls : ''));
  svg.setAttribute('width', String(size));
  svg.setAttribute('height', String(size));
  svg.setAttribute('focusable', 'false');
  if (title) {
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', title);
  } else {
    svg.setAttribute('aria-hidden', 'true');
  }
  const use = document.createElementNS(NS, 'use');
  use.setAttribute('href', idFor(name));
  svg.appendChild(use);
  return svg;
}
