// "Never ban": the operator's own never-ban entries (an add form and a table)
// above the built-in protected ranges. Every value from the API is a text child.
import { h, htm, useState } from '../explore-vendor.js';
import { Icon } from './icons.js';
import { confirmDialog } from './ui/dialog.js';
import { toast } from './ui/toast.js';
import { requestJson as call } from './security-api.js';
import { Alert, Empty, Field } from './security-ui.js';
import { ALLOWLIST_NOTE_MAX, allowlistPayload, allowlistRows, errorMessage } from './security-model.js';

const html = htm.bind(h);

/** POST one entry; returns true when it was stored. Shared with the IP popover. */
export async function neverBan(value, note = '') {
  let payload;
  try { payload = allowlistPayload({ value, note }); } catch (err) { toast(err.message, { kind: 'error' }); return false; }
  const r = await call('/api/security/allowlist', 'POST', payload);
  toast(r.ok ? `${payload.value} will never be banned.` : errorMessage(r.body, r.status), { kind: r.ok ? 'ok' : 'error' });
  return r.ok;
}

function AddEntry({ onDone }) {
  const [value, setValue] = useState('');
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const submit = async (e) => {
    e.preventDefault();
    let payload;
    try { payload = allowlistPayload({ value, note }); } catch (err) { setError(err.message); return; }
    setBusy(true); setError('');
    const r = await call('/api/security/allowlist', 'POST', payload);
    setBusy(false);
    if (!r.ok) { setError(errorMessage(r.body, r.status)); return; }
    toast(`${r.body.entry?.value || payload.value} will never be banned.`, { kind: 'ok' });
    setValue(''); setNote('');
    onDone();
  };
  return html`
    <form class="sec-form" onSubmit=${submit} aria-label="Add a never-ban address">
      <${Field} label="IP address or CIDR range">
        <input class="inp mono" type="text" spellcheck="false" autocomplete="off" placeholder="198.51.100.7"
               value=${value} onInput=${e => setValue(e.currentTarget.value)} /></${Field}>
      <${Field} label="Note (optional)" grow>
        <input class="inp" type="text" maxlength=${ALLOWLIST_NOTE_MAX} value=${note} onInput=${e => setNote(e.currentTarget.value)} /></${Field}>
      <button class="btn btn-primary" type="submit" disabled=${busy}><${Icon} name="check" size=${16} />Add</button>
      ${error && html`<p class="form-error" role="alert">${error}</p>`}
    </form>`;
}

export function AllowlistSection({ info, writable, onDone, children }) {
  const rows = allowlistRows(info?.entries);
  const remove = async (r) => {
    const ok = await confirmDialog({ title: `Remove ${r.value} from the never-ban list?`, body: 'Bans covering it are enforced again and Caddy reloads.', confirmLabel: 'Remove', danger: true });
    if (!ok) return;
    const res = await call(`/api/security/allowlist/${encodeURIComponent(r.id)}`, 'DELETE');
    toast(res.ok ? `${r.value} removed from the never-ban list.` : errorMessage(res.body, res.status), { kind: res.ok ? 'ok' : 'error' });
    onDone();
  };
  return html`
    ${info?.corrupt && html`<${Alert} tone="crit">${info.corrupt}.</${Alert}>`}
    ${writable && !info?.corrupt && html`<${AddEntry} onDone=${onDone} />`}
    ${!rows.length ? html`<${Empty}>No addresses added. Built-in ranges below are always protected.</${Empty}>` : html`
    <div class="tbl-wrap">
      <table class="tbl sec-tbl">
        <thead><tr><th>Address</th><th>Note</th><th>Added by</th><th>When</th><th class="c-act"><span class="sr">Actions</span></th></tr></thead>
        <tbody>${rows.map(r => html`
          <tr key=${r.id}>
            <td class="c-addr"><span class="mono">${r.value}</span></td>
            <td class=${'c-reason' + (r.note ? '' : ' is-empty')} data-label="Note">${r.note || html`<span class="muted">—</span>`}</td>
            <td data-label="Added by">${r.by}</td>
            <td data-label="When"><time title=${r.created.title}>${r.created.text}</time></td>
            <td class="c-act">${writable && !info?.corrupt
              ? html`<button class="btn sm" type="button" onClick=${() => remove(r)} aria-label=${'Remove ' + r.value}>Remove</button>`
              : html`<span class="muted">—</span>`}</td>
          </tr>`)}</tbody>
      </table>
    </div>`}
    ${children}`;
}
