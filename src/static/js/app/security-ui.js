// Small building blocks shared by the Security view's sections, so every part
// of the page uses the same section header, status marker (icon shape + word,
// never colour alone), key/value list, form fields, copyable line and empty
// state. Every string passed in is rendered as a text child (a text node).
import { h, htm } from '../explore-vendor.js';
import { Icon } from './icons.js';

const html = htm.bind(h);

// Model tones (security-model.js) to the marker's icon and colour class.
const MARK = {
  ok: ['status-ok', 'mk-ok'],
  warn: ['warning', 'mk-warn'],
  crit: ['status-down', 'mk-crit'],
  none: ['status-none', 'mk-none'],
};
export const markOf = (tone) => MARK[tone] || MARK.none;

/** Icon + word. `size` follows the text it sits in. */
export function Mark({ tone, label, size = 14 }) {
  const [icon, cls] = markOf(tone);
  return html`<span class=${'mk ' + cls}><${Icon} name=${icon} size=${size} />${label}</span>`;
}

/** A section's state line: marker with the title, the detail beside it. Alerts for critical. */
export function StateLine({ st }) {
  return html`
    <p class=${'sec-state-line tone-' + st.tone} role=${st.tone === 'crit' ? 'alert' : 'status'}>
      <${Mark} tone=${st.tone} label=${st.title} size=${16} />
      ${st.detail && html`<span class="sec-detail">${st.detail}</span>`}
    </p>`;
}

/** The same header every section of the app uses: title and a one-line description. */
export function SectionHead({ id, title, desc, children }) {
  return html`
    <div class="h-sec sec-h"><h2 id=${id}>${title}</h2>${desc && html`<p>${desc}</p>`}${children}</div>`;
}

/** Hairline key/value rows. `rows` = [{ k, v, mono, title }]; falsy rows are skipped. */
export function KV({ rows, label }) {
  const shown = rows.filter(Boolean);
  if (!shown.length) return null;
  return html`
    <dl class="kv" aria-label=${label || null}>${shown.map(r => html`
      <div key=${r.k}><dt>${r.k}</dt><dd class=${r.mono ? 'mono' : null} title=${r.title || null}>${r.v}</dd></div>`)}
    </dl>`;
}

/** Tinted alert block (background + thin border), as the Dashboard's notice. */
export function Alert({ tone = 'warn', children, role }) {
  const icon = tone === 'crit' ? 'status-down' : tone === 'info' ? 'info' : 'warning';
  return html`
    <div class=${'alert alert-' + tone} role=${role || (tone === 'crit' ? 'alert' : 'status')}>
      <${Icon} name=${icon} size=${16} /><div>${children}</div>
    </div>`;
}

/** A line of config to paste somewhere, with its copy button always visible. */
export function CodeLine({ label, code, onCopy, what = 'Import line' }) {
  return html`
    <div class="codeline">
      ${label && html`<span class="codeline-k">${label}</span>`}
      <code class="mono">${code}</code>
      <button class="btn sm btn-quiet" type="button" onClick=${() => onCopy(code, what)}
              aria-label=${`Copy ${label || what}`}><${Icon} name="copy" size=${14} />Copy</button>
    </div>`;
}

/** The empty state every list on the page uses. */
export function Empty({ children, icon = 'status-none' }) {
  return html`<p class="empty"><${Icon} name=${icon} size=${16} /><span>${children}</span></p>`;
}

/** A labelled field: label above, the app's input below. */
export function Field({ label, grow, narrow, children, hint }) {
  return html`
    <label class=${'field' + (grow ? ' grow' : '') + (narrow ? ' narrow' : '')}>
      <span class="field-l">${label}</span>
      ${children}
      ${hint && html`<span class="field-hint">${hint}</span>`}
    </label>`;
}

/** The app's select: a native <select> (keyboard and screen readers as usual) with the shared chevron. */
export function Select({ value, onChange, options, disabled }) {
  return html`
    <span class="sel-wrap">
      <select class="inp" value=${value} disabled=${disabled} onChange=${onChange}>
        ${options.map(o => html`<option key=${o.id} value=${o.id}>${o.label}</option>`)}
      </select>
      <${Icon} name="chevron-down" size=${14} />
    </span>`;
}

/** A checkbox with its label to the right. */
export function Check({ checked, disabled, onChange, children }) {
  return html`
    <label class="check">
      <input type="checkbox" checked=${checked} disabled=${disabled} onChange=${onChange} />
      <span>${children}</span>
    </label>`;
}
