// Ban and Unban flows shared by the IP popover and the Security view. Confirmation
// and input use the app's own dialogs; results are toasts with plain-text messages.
import { confirmDialog, formDialog } from './ui/dialog.js';
import { toast } from './ui/toast.js';
import { requestJson } from './security-api.js';
import { DURATIONS, banPayload, errorMessage, outcomeText } from './security-model.js';

async function send(url, method, payload) {
  const res = await requestJson(url, method, payload);
  if (!res.ok) { toast(errorMessage(res.body, res.status), { kind: 'error' }); return null; }
  return res.body;
}

export async function banAddress(value) {
  const values = await formDialog({
    title: `Ban ${value}`,
    body: 'Caddy answers 403 to this address on every site that imports the ban list.',
    confirmLabel: 'Ban',
    danger: true,
    fields: [
      { name: 'value', label: 'IP address or CIDR range', type: 'text', value },
      { name: 'duration', label: 'Duration', type: 'select', value: '24h', options: DURATIONS.map(d => ({ value: d.id, label: d.label })) },
      { name: 'reason', label: 'Reason (optional)', type: 'textarea' },
    ],
    validate: (v) => { try { banPayload(v); return null; } catch (e) { return e.message; } },
  });
  if (!values) return null;
  const body = await send('/api/bans', 'POST', banPayload(values));
  if (body) { const t = outcomeText(body, 'ban'); toast(t.text, { kind: t.kind }); }
  return body;
}

export async function unbanRecords(ids, label) {
  const ok = await confirmDialog({ title: `Unban ${label}?`, body: 'New requests from this address are allowed again once Caddy reloads.', confirmLabel: 'Unban', danger: true });
  if (!ok) return null;
  let body = null;
  for (const id of ids) {
    body = await send(`/api/bans/${encodeURIComponent(id)}`, 'DELETE');
    if (!body) return null;
  }
  const t = outcomeText(body, 'unban');
  toast(t.text, { kind: t.kind });
  return body;
}
