// Security view at /security: manual IP bans, where they are enforced, and
// recovery. Wording lives in security-model.js. Every string that came from a
// record or the API is a text child, which Preact writes as a text node.
import { h, htm, render, useEffect, useState } from '../explore-vendor.js';
import { Icon } from './icons.js';
import { absoluteTime } from './format.js';
import { confirmDialog } from './ui/dialog.js';
import { toast } from './ui/toast.js';
import { requestJson as call } from './security-api.js';
import {
  DURATIONS, banPayload, errorMessage, expiryLabel, outcomeText, overallState,
  protectedLabel, recoveryActionLabel, siteActions, siteStatus,
} from './security-model.js';

const html = htm.bind(h);
const REFRESH_MS = 30000;
const SEV = { crit: 'critical', warn: 'warn', ok: 'ok', none: 'ok' };

function copy(text, what) {
  navigator.clipboard.writeText(text).then(
    () => toast(`${what} copied`, { kind: 'ok' }),
    () => toast('Could not copy to the clipboard', { kind: 'error' }));
}

function Verdict({ status, records }) {
  const v = overallState(status, records);
  return html`
    <section class=${'verdict sev-' + SEV[v.tone]} role=${v.tone === 'crit' ? 'alert' : 'status'} aria-labelledby="sec-h">
      <h1 id="sec-h">${v.title}</h1>
      ${v.body && html`<p>${v.body}</p>`}
    </section>`;
}

function AddBan({ onDone }) {
  const [value, setValue] = useState('');
  const [duration, setDuration] = useState('24h');
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const submit = async (e) => {
    e.preventDefault();
    let payload;
    try { payload = banPayload({ value, duration, reason }); } catch (err) { setError(err.message); return; }
    setBusy(true); setError('');
    const r = await call('/api/bans', 'POST', payload);
    setBusy(false);
    if (!r.ok) { setError(errorMessage(r.body, r.status)); return; }
    const t = outcomeText(r.body, 'ban');
    toast(t.text, { kind: t.kind });
    setValue(''); setReason('');
    onDone();
  };
  return html`
    <form class="sec-add" onSubmit=${submit}>
      <label>IP address or CIDR range
        <input type="text" spellcheck="false" autocomplete="off" value=${value} onInput=${e => setValue(e.currentTarget.value)} /></label>
      <label>Duration
        <select value=${duration} onChange=${e => setDuration(e.currentTarget.value)}>
          ${DURATIONS.map(d => html`<option key=${d.id} value=${d.id}>${d.label}</option>`)}
        </select></label>
      <label class="grow">Reason (optional)
        <input type="text" value=${reason} onInput=${e => setReason(e.currentTarget.value)} /></label>
      <button class="btn btn-primary" type="submit" disabled=${busy}><${Icon} name="shield" size=${16} />Ban</button>
      ${error && html`<p class="sec-error" role="alert">${error}</p>`}
    </form>`;
}

function BanList({ records, onDone }) {
  if (!records.length) return html`<p class="metrics-hint">No manual bans.</p>`;
  const unban = async (r) => {
    const ok = await confirmDialog({ title: `Unban ${r.value}?`, body: 'New requests from this address are allowed again once Caddy reloads.', confirmLabel: 'Unban', danger: true });
    if (!ok) return;
    const res = await call(`/api/bans/${encodeURIComponent(r.id)}`, 'DELETE');
    if (!res.ok) { toast(errorMessage(res.body, res.status), { kind: 'error' }); return; }
    const t = outcomeText(res.body, 'unban');
    toast(t.text, { kind: t.kind });
    onDone();
  };
  return html`
    <table class="sec-table">
      <thead><tr><th>Address</th><th>Location</th><th>Reason</th><th>By</th><th>Created</th><th>Expiry</th><th><span class="sr">Actions</span></th></tr></thead>
      <tbody>${records.map(r => html`
        <tr key=${r.id} class=${r.expired ? 'expired' : ''}>
          <td class="mono">${r.value}${r.protected && html` <span class="sec-tag" title=${'Protected: ' + protectedLabel(r.protected)}>ignored, protected</span>`}</td>
          <td>${r.geo ? [r.geo.country_code, r.geo.asn_org].filter(Boolean).join(' · ') : ''}</td>
          <td class="sec-reason">${r.reason}</td>
          <td>${r.actor}</td>
          <td>${absoluteTime(r.created_at)}</td>
          <td>${r.expired ? 'Expired, removed at the next cleanup' : expiryLabel(r.expires_at)}</td>
          <td>${r.source === 'manual'
            ? html`<button class="btn sm" type="button" onClick=${() => unban(r)}>Unban</button>`
            : html`<span class="muted">Read-only</span>`}</td>
        </tr>`)}</tbody>
    </table>`;
}

function Sites({ sites, importLine }) {
  if (!sites.length) return html`<p class="metrics-hint">No sites in the running configuration.</p>`;
  return html`
    <ul class="sec-sites">${sites.map(s => {
      const st = siteStatus(s);
      const acts = siteActions(s);
      return html`
        <li key=${s.label + ':' + (s.line || '')} class=${'tone-' + st.tone}>
          <span class="mono">${s.label}</span>
          <span class="sec-state">${st.label}</span>
          ${st.detail && html`<span class="muted small">${st.detail}</span>`}
          <span class="acts">
            ${acts.includes('insert') && html`<button class="btn sm" type="button"
                onClick=${() => document.dispatchEvent(new CustomEvent('app:insert-ban-import', { detail: { line: s.line } }))}>Add import in editor</button>`}
            ${acts.includes('copy') && html`<button class="btn sm btn-quiet" type="button" onClick=${() => copy(importLine, 'Import line')}><${Icon} name="copy" size=${14} />Copy import</button>`}
          </span>
        </li>`;
    })}</ul>`;
}

function Protected({ groups }) {
  return html`
    <dl class="sec-protected">${groups.map(g => html`
      <div key=${g.category}><dt>${g.label}</dt><dd class="mono">${g.values.join(' ')}</dd></div>`)}
    </dl>`;
}

function Recovery({ info, onDone }) {
  if (!info?.required) return null;
  const finish = (r, okText) => {
    toast(r.ok ? okText : errorMessage(r.body, r.status), { kind: r.ok ? 'ok' : 'error' });
    onDone();
  };
  const run = async (action, backupId) => {
    const ok = await confirmDialog({ title: recoveryActionLabel(action), body: 'The console rewrites the managed files and reloads Caddy.', confirmLabel: 'Continue', danger: action !== 'use_candidate' });
    if (ok) finish(await call('/api/security/recovery', 'POST', { recovery_id: info.recovery_id, action, backup_id: backupId }), 'Recovered.');
  };
  const reapply = async () => finish(await call('/api/security/reapply', 'POST', { source: 'manual' }), 'Re-applied; Caddy reloaded.');
  const reset = async () => {
    const ok = await confirmDialog({ title: 'Delete every manual ban?', body: 'The list is emptied and Caddy reloads. This cannot be undone.', confirmLabel: 'Reset manual bans', danger: true });
    if (ok) finish(await call('/api/security/reset', 'POST', { source: 'manual', version: info.state_version, confirm: true }), 'Manual bans reset.');
  };
  return html`
    <section class="sec-recovery" aria-labelledby="sec-rec-h">
      <h2 id="sec-rec-h"><${Icon} name="warning" size=${16} />Recovery</h2>
      <p>${info.summary}</p>
      ${info.files.length > 0 && html`<p class="muted small">Files: ${info.files.join(', ')}</p>`}
      <div class="acts">
        ${info.actions.filter(a => a !== 'restore_backup').map(a => html`<button class="btn" type="button" key=${a} onClick=${() => run(a)}>${recoveryActionLabel(a)}</button>`)}
        ${info.reapply && html`<button class="btn btn-primary" type="button" onClick=${reapply}>Re-apply</button>`}
        ${info.reset && html`<button class="btn btn-danger" type="button" onClick=${reset}>Reset manual bans</button>`}
      </div>
      ${info.actions.includes('restore_backup') && html`
        <ul class="sec-backups">${info.backups.map(b => html`
          <li key=${b.id}>${absoluteTime(b.created_at)}, ${b.records} ${b.records === 1 ? 'record' : 'records'}
            <button class="btn sm" type="button" onClick=${() => run('restore_backup', b.id)}>${recoveryActionLabel('restore_backup')}</button></li>`)}
        </ul>`}
      <p class="muted small">If the console itself is unreachable, use the host recovery commands in docs/security.md.</p>
    </section>`;
}

function App() {
  const [status, setStatus] = useState(null);
  const [bans, setBans] = useState(null);
  const [error, setError] = useState(null);
  const load = async () => {
    const [s, b] = await Promise.all([call('/api/security'), call('/api/bans')]);
    if (!s.ok) { setError(errorMessage(s.body, s.status)); return; }
    setError(null);
    setStatus(s.body);
    setBans(b.ok ? b.body : { records: [], error: errorMessage(b.body, b.status) });
  };
  useEffect(() => {
    load();
    const t = setInterval(() => {
      if (document.getElementById('tab-security')?.classList.contains('active')) load();
    }, REFRESH_MS);
    return () => clearInterval(t);
  }, []);

  if (error && !status) return html`<div class="page"><p class="metrics-hint error">Could not load Security: ${error}</p></div>`;
  if (!status) return html`<div class="page"><p class="metrics-hint">Loading…</p></div>`;
  const records = bans?.records || [];
  const manual = status.sources.manual;
  const writable = status.available && !status.degraded;
  return html`
    <div class="page sec">
      <${Verdict} status=${status} records=${records.length} />
      <${Recovery} info=${status.recovery} onDone=${load} />
      <section aria-labelledby="sec-bans-h">
        <div class="h-sec"><h2 id="sec-bans-h">Manual bans</h2>
          <p>${manual.active_records} active, ${manual.rendered_prefixes} of ${status.limits.max_prefixes} prefixes rendered.</p></div>
        ${writable ? html`<${AddBan} onDone=${load} />` : html`<p class="metrics-hint">Changes are paused until the problem above is resolved.</p>`}
        ${bans?.error ? html`<p class="metrics-hint error">${bans.error}</p>` : html`<${BanList} records=${records} onDone=${load} />`}
      </section>
      <section aria-labelledby="sec-sites-h">
        <div class="h-sec"><h2 id="sec-sites-h">Sites</h2><p>Proven from Caddy's running configuration.</p></div>
        <p class="sec-import">Import line: <code>${manual.import_line}</code></p>
        <${Sites} sites=${status.sites} importLine=${manual.import_line} />
      </section>
      <section aria-labelledby="sec-prot-h">
        <div class="h-sec"><h2 id="sec-prot-h">Never banned</h2><p>Refused at input and excluded again by the generated policy.</p></div>
        <${Protected} groups=${status.protected} />
      </section>
      ${status.last_apply && html`<div class="foot">Last applied ${absoluteTime(status.last_apply.time)} by ${status.last_apply.user}.</div>`}
    </div>`;
}

let mounted = false;

export function mountSecurity() {
  const root = document.getElementById('security-root');
  if (!root || mounted) return;
  render(html`<${App} />`, root);
  mounted = true;
}
