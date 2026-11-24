// Security view at /security: manual IP bans, where they are enforced, and
// recovery. Wording lives in security-model.js. Every string that came from a
// record or the API is a text child, which Preact writes as a text node.
import { h, htm, render, useEffect, useState } from '../explore-vendor.js';
import { Icon } from './icons.js';
import { absoluteTime } from './format.js';
import { unbanRecords } from './ban-dialog.js';
import { confirmDialog } from './ui/dialog.js';
import { toast } from './ui/toast.js';
import { requestJson as call } from './security-api.js';
import { CrowdSecSection } from './security-crowdsec.js';
import { PluginSection } from './security-plugin.js';
import { ClientIpSection } from './security-client-ip.js';
import { CountrySection } from './security-country.js';
import {
  DURATIONS, SOURCE_LABELS, banPayload, capacityText, createdCell, crowdsecPath, errorMessage, expiryLabel, outcomeText, overallState, staleNotice,
  HOST_RECOVERY_URL, pluginSiteActions, protectedLabel, recoveryActionLabel, siteActions, siteStatus,
} from './security-model.js';

const html = htm.bind(h);
const REFRESH_MS = 30000;
const SEV = { crit: 'critical', warn: 'warn', ok: 'ok', none: 'ok' };

function copy(text, what) {
  navigator.clipboard.writeText(text).then(
    () => toast(`${what} copied`, { kind: 'ok' }),
    () => toast('Could not copy to the clipboard', { kind: 'error' }));
}

function Verdict({ status, records, stale, recoveryShown }) {
  const v = overallState(status, records, { stale });
  return html`
    <section class=${'verdict sev-' + SEV[v.tone]} role=${v.tone === 'crit' ? 'alert' : 'status'} aria-labelledby="sec-h">
      <h1 id="sec-h">${v.title}</h1>
      ${v.body && html`<p>${v.body}</p>`}
      ${stale && html`<p class="sec-stale" role="alert">${staleNotice(stale, absoluteTime)}</p>`}
      ${v.recoveryHint && (recoveryShown
        ? html`<p><a href="#sec-recovery">Recovery options</a></p>`
        : html`<p><a href=${HOST_RECOVERY_URL} target="_blank" rel="noopener noreferrer">Host recovery steps</a></p>`)}
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
  const unban = async (r) => { if (await unbanRecords([r.id], r.value)) onDone(); };
  return html`
    <table class="sec-table">
      <thead><tr><th>Address</th><th>Location</th><th>Reason</th><th>By</th><th>Created</th><th>Expiry</th><th><span class="sr">Actions</span></th></tr></thead>
      <tbody>${records.map(r => html`
        <tr key=${r.id} class=${r.expired ? 'expired' : ''}>
          <td class="mono">${r.value}${r.protected && html` <span class="sec-tag" title=${'Protected: ' + protectedLabel(r.protected)}>ignored, protected</span>`}</td>
          <td>${r.geo ? [r.geo.country_code, r.geo.asn_org].filter(Boolean).join(' · ') : ''}</td>
          <td class="sec-reason">${r.reason}</td>
          <td>${r.actor}</td>
          <td title=${createdCell(r.created_at).title}>${createdCell(r.created_at).text}</td>
          <td>${r.expired ? 'Expired, removed at the next cleanup' : expiryLabel(r.expires_at)}</td>
          <td>${r.source === 'manual'
            ? html`<button class="btn sm" type="button" onClick=${() => unban(r)}>Unban</button>`
            : html`<span class="muted">Read-only</span>`}</td>
        </tr>`)}</tbody>
    </table>`;
}

function Sites({ sites, sources, plugin }) {
  if (!sites.length) return html`<p class="metrics-hint">No sites in the running configuration.</p>`;
  const names = Object.keys(sources);
  return html`
    <ul class="sec-sites">${sites.map(s => html`
      <li key=${s.label + ':' + (s.line || '')}>
        <span class="mono">${s.label}</span>
        ${(() => { const cp = crowdsecPath(s); return cp && html`<span class=${'sec-path tone-' + cp.tone}>${cp.text}</span>`; })()}
        ${names.map(name => {
          const p = s.policies?.[name] || (name === 'plugin' || name === 'country' ? null : s);
          if (!p) return null;
          const st = siteStatus(p, name);
          const acts = name === 'plugin' ? pluginSiteActions(p, s, plugin) : siteActions({ ...p, source: s.source });
          return html`
            <div class=${'sec-policy tone-' + st.tone} key=${name}>
              ${names.length > 1 && html`<span class="sec-src">${SOURCE_LABELS[name] || name}</span>`}
              <span class="sec-state">${st.label}</span>
              ${st.detail && html`<span class="muted small">${st.detail}</span>`}
              <span class="acts">
                ${acts.includes('insert') && html`<button class="btn sm" type="button"
                    onClick=${() => document.dispatchEvent(new CustomEvent('app:insert-ban-import', { detail: { line: s.line, source: name } }))}>Add import in editor</button>`}
                ${acts.includes('copy') && html`<button class="btn sm btn-quiet" type="button" onClick=${() => copy(sources[name].import_line, 'Import line')}><${Icon} name="copy" size=${14} />Copy import</button>`}
              </span>
            </div>`;
        })}
      </li>`)}</ul>`;
}

function Protected({ groups }) {
  return html`
    <dl class="sec-protected">${groups.map(g => html`
      <div key=${g.category}><dt>${g.label}</dt><dd class="mono">${g.values.join(' ')}</dd></div>`)}
    </dl>`;
}

function Recovery({ info, onDone, sources }) {
  if (!info?.required) return null;
  const finish = (r, okText) => {
    toast(r.ok ? okText : errorMessage(r.body, r.status), { kind: r.ok ? 'ok' : 'error' });
    onDone();
  };
  const run = async (action, backupId) => {
    const ok = await confirmDialog({ title: recoveryActionLabel(action), body: 'The console rewrites the managed files and reloads Caddy.', confirmLabel: 'Continue', danger: action !== 'use_candidate' });
    if (ok) finish(await call('/api/security/recovery', 'POST', { recovery_id: info.recovery_id, action, backup_id: backupId }), 'Recovered.');
  };
  const reapply = async (source) => finish(await call('/api/security/reapply', 'POST', { source }), 'Re-applied; Caddy reloaded.');
  const resetCrowdsec = async () => {
    const ok = await confirmDialog({ title: 'Delete every stored CrowdSec decision?', body: 'Caddy reloads without them. CrowdSec decisions that are still active return within the sync interval unless you also delete them in CrowdSec.', confirmLabel: 'Reset CrowdSec decisions', danger: true });
    if (ok) finish(await call('/api/security/reset', 'POST', { source: 'crowdsec', version: info.state_version, confirm: true }), 'CrowdSec decisions reset.');
  };
  const held = info.held_sources?.length ? info.held_sources : ['manual'];
  const reset = async () => {
    const ok = await confirmDialog({ title: 'Delete every manual ban?', body: 'The list is emptied and Caddy reloads. This cannot be undone.', confirmLabel: 'Reset manual bans', danger: true });
    if (ok) finish(await call('/api/security/reset', 'POST', { source: 'manual', version: info.state_version, confirm: true }), 'Manual bans reset.');
  };
  return html`
    <section class="sec-recovery" id="sec-recovery" aria-labelledby="sec-rec-h">
      <h2 id="sec-rec-h"><${Icon} name="warning" size=${16} />Recovery</h2>
      <p>${info.summary}</p>
      ${info.files.length > 0 && html`<p class="muted small">Files: ${info.files.join(', ')}</p>`}
      <div class="acts">
        ${info.actions.filter(a => a !== 'restore_backup').map(a => html`<button class="btn" type="button" key=${a} onClick=${() => run(a)}>${recoveryActionLabel(a)}</button>`)}
        ${info.reapply && held.map(n => html`<button class="btn btn-primary" type="button" key=${'re-' + n} onClick=${() => reapply(n)}>${n === 'manual' && held.length === 1 ? 'Re-apply' : `Re-apply ${SOURCE_LABELS[n] || n}`}</button>`)}
        ${info.reset && html`<button class="btn btn-danger" type="button" onClick=${reset}>Reset manual bans</button>`}
        ${info.reset && sources?.crowdsec && html`<button class="btn btn-danger" type="button" onClick=${resetCrowdsec}>Reset CrowdSec decisions</button>`}
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
  const [loadedAt, setLoadedAt] = useState(null);
  const load = async () => {
    const [s, b] = await Promise.all([call('/api/security'), call('/api/bans')]);
    if (!s.ok) { setError(errorMessage(s.body, s.status)); return; }
    setError(null);
    setLoadedAt(Date.now());
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
  const manualRecords = records.filter(r => r.source === 'manual');
  const crowdsecRecords = records.filter(r => r.source === 'crowdsec');
  const manual = status.sources.manual;
  const cs = status.sources.crowdsec;
  // A source that is not enabled has no policy file to show (CrowdSec off).
  const active = Object.fromEntries(Object.entries(status.sources).filter(([, s]) => s.enabled !== false));
  const writable = status.available && !status.degraded;
  const plug = status.plugin?.enabled ? status.plugin : null;
  const ip = status.client_ip_profile;
  const cp = status.country_policy;
  const withPlugin = plug ? { ...active, plugin: { import_line: plug.definition.site_import } } : active;
  const siteSources = (status.sites || []).some(s => s.policies?.country) ? { ...withPlugin, country: { import_line: cp.import_line } } : withPlugin;
  const reapplyPlugin = async () => {
    const r = await call('/api/security/reapply', 'POST', { source: 'plugin' });
    toast(r.ok ? 'Plugin route re-applied.' : errorMessage(r.body, r.status), { kind: r.ok ? 'ok' : 'error' });
    load();
  };
  return html`
    <div class="page sec">
      <${Verdict} status=${status} records=${manualRecords.length} stale=${error ? loadedAt : null} recoveryShown=${!!status.recovery?.required} />
      <${Recovery} info=${status.recovery} onDone=${load} sources=${status.sources} />
      <section aria-labelledby="sec-bans-h">
        <div class="h-sec"><h2 id="sec-bans-h">Manual bans</h2>
          <p>${manual.active_records} active. ${capacityText(status.limits)}</p></div>
        ${writable ? html`<${AddBan} onDone=${load} />` : html`<p class="metrics-hint">Changes are paused until the problem above is resolved.</p>`}
        ${bans?.error ? html`<p class="metrics-hint error">${bans.error}</p>` : html`<${BanList} records=${manualRecords} onDone=${load} />`}
      </section>
      ${cs?.enabled && html`<${CrowdSecSection} src=${cs} records=${crowdsecRecords} onCopy=${copy} />`}
      ${ip && html`<${ClientIpSection} key=${ip.mode + ':' + (ip.tunnel_peers || []).join()} info=${ip} onDone=${load} onCopy=${copy} />`}
      ${cp && html`<${CountrySection} key=${cp.updated_at || 'none'} info=${cp} onDone=${load} onCopy=${copy} />`}
      ${plug && html`<${PluginSection} plugin=${plug} onCopy=${copy} onReapply=${reapplyPlugin} />`}
      <section aria-labelledby="sec-sites-h">
        <div class="h-sec"><h2 id="sec-sites-h">Sites</h2><p>Proven from Caddy's running configuration.</p></div>
        ${Object.entries(active).map(([n, s]) => html`<p class="sec-import" key=${n}>${SOURCE_LABELS[n] || n} import line: <code>${s.import_line}</code></p>`)}
        <${Sites} sites=${status.sites} sources=${siteSources} plugin=${plug} />
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
