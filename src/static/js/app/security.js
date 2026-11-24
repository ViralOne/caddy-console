// Security view at /security: manual IP bans, where they are enforced, and
// recovery. Laid out like the Dashboard: a verdict, a row of figures, then
// sections separated by whitespace and hairlines. Wording lives in
// security-model.js, the shared pieces in security-ui.js. Every string that
// came from a record or the API is a text child, which Preact writes as a text node.
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
import { Alert, CodeLine, Empty, Field, KV, Mark, SectionHead, Select } from './security-ui.js';
import {
  DURATIONS, SOURCE_LABELS, banPayload, capacityText, clientIpState, createdCell, crowdsecPath, crowdsecState, errorMessage, expiryLabel,
  outcomeText, overallState, staleNotice, HOST_RECOVERY_URL, pluginSiteActions, protectedLabel, recoveryActionLabel, siteActions, siteStatus,
} from './security-model.js';

const html = htm.bind(h);
const REFRESH_MS = 30000;
const SEV = { crit: 'critical', warn: 'warn', ok: 'ok', none: 'ok' };
const SEV_WORD = { crit: 'Critical', warn: 'Needs attention' };
const ENFORCING = ['enforced', 'enforced_pre_handler', 'imported_empty'];

function copy(text, what) {
  navigator.clipboard.writeText(text).then(
    () => toast(`${what} copied`, { kind: 'ok' }),
    () => toast('Could not copy to the clipboard', { kind: 'error' }));
}

function Verdict({ status, records, stale, recoveryShown }) {
  const v = overallState(status, records, { stale });
  const calm = v.tone === 'ok' || v.tone === 'none';
  return html`
    <section class=${'verdict sev-' + SEV[v.tone]} role=${v.tone === 'crit' ? 'alert' : 'status'} aria-labelledby="sec-h">
      ${!calm && html`<span class="sev"><${Icon} name=${v.tone === 'crit' ? 'status-down' : 'warning'} />${SEV_WORD[v.tone]}</span>`}
      <h1 id="sec-h">${calm && html`<${Icon} name=${v.tone === 'ok' ? 'status-ok' : 'status-none'} size=${20} class=${v.tone === 'ok' ? 'verdict-ok' : 'verdict-none'} />`}${v.title}</h1>
      ${v.body && html`<p>${v.body}</p>`}
      ${stale && html`<p class="sec-stale" role="alert">${staleNotice(stale, absoluteTime)}</p>`}
      ${v.recoveryHint && html`
        <div class="acts">${recoveryShown
          ? html`<a class="btn btn-primary" href="#sec-recovery">Recovery options</a>`
          : html`<a class="btn" href=${HOST_RECOVERY_URL} target="_blank" rel="noopener noreferrer"><${Icon} name="external" size=${14} />Host recovery steps</a>`}
        </div>`}
    </section>`;
}

// Figures under the verdict, as on the Dashboard; each one jumps to its section.
function Figures({ status, manualCount, crowdsecCount }) {
  const sites = status.sites || [];
  const enforcing = sites.filter(s => Object.entries(s.policies || { manual: s })
    .some(([n, p]) => n !== 'country' && ENFORCING.includes(p.status))).length;
  const lim = status.limits || {};
  const share = lim.max_prefixes ? (lim.used || 0) / lim.max_prefixes : 0;
  const cs = status.sources?.crowdsec;
  const ip = status.client_ip_profile;
  const ipState = ip ? clientIpState(ip) : null;
  const csState = cs?.enabled ? crowdsecState(cs) : null;
  const items = [
    { key: 'bans', href: '#sec-bans-h', label: 'Manual bans', value: String(manualCount), sub: manualCount === 1 ? 'active ban' : 'active bans' },
    csState && { key: 'cs', href: '#sec-cs-h', label: 'CrowdSec decisions', value: String(crowdsecCount), tone: csState.tone, sub: csState.title },
    { key: 'sites', href: '#sec-sites-h', label: 'Sites enforcing bans', value: String(enforcing), of: `of ${sites.length}`, sub: enforcing < sites.length ? `${sites.length - enforcing} not enforced` : 'All sites' },
    { key: 'cap', href: '#sec-bans-h', label: 'Prefixes rendered', value: (lim.used ?? 0).toLocaleString('en-US'), of: `of ${(lim.max_prefixes ?? 0).toLocaleString('en-US')}`, share },
    ipState && { key: 'ip', href: '#sec-ip-h', label: 'Client IP', value: ipState.tone === 'ok' ? ipState.title : null, text: true, tone: ipState.tone, sub: ipState.tone === 'ok' ? '' : ipState.title },
  ].filter(Boolean);
  return html`
    <div class="figs sec-figs" aria-label="Summary">${items.map(f => html`
      <a class="fig" key=${f.key} href=${f.href}>
        <span class="lbl">${f.label}</span>
        ${f.value != null && html`<span class=${'fv-n' + (f.text ? ' fv-t' : '')}>${f.value}${f.of && html` <span class="fv-of">${f.of}</span>`}</span>`}
        ${f.share != null && html`<span class="bar" aria-hidden="true"><i style=${{ width: `${Math.min(1, f.share) * 100}%` }}></i></span>`}
        ${f.tone && f.tone !== 'ok'
          ? html`<span class="sub"><${Mark} tone=${f.tone} label=${f.sub} size=${13} /></span>`
          : f.sub && html`<span class="sub">${f.sub}</span>`}
      </a>`)}
    </div>`;
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
    <form class="sec-form" onSubmit=${submit} aria-label="Ban an address">
      <${Field} label="IP address or CIDR range">
        <input class="inp mono" type="text" spellcheck="false" autocomplete="off" placeholder="203.0.113.7"
               value=${value} onInput=${e => setValue(e.currentTarget.value)} /></${Field}>
      <${Field} label="Duration" narrow>
        <${Select} value=${duration} options=${DURATIONS} onChange=${e => setDuration(e.currentTarget.value)} /></${Field}>
      <${Field} label="Reason (optional)" grow>
        <input class="inp" type="text" value=${reason} onInput=${e => setReason(e.currentTarget.value)} /></${Field}>
      <button class="btn btn-primary" type="submit" disabled=${busy}><${Icon} name="shield" size=${16} />Ban</button>
      ${error && html`<p class="form-error" role="alert">${error}</p>`}
    </form>`;
}

/** "ignored, protected" on an address that the policy will never render. */
export const ProtectedTag = ({ category }) => html`
  <span class="tag tag-warn" title=${'Protected: ' + protectedLabel(category)}><${Icon} name="warning" size=${12} />ignored, protected</span>`;

function BanList({ records, onDone }) {
  if (!records.length) return html`<${Empty}>No manual bans. Ban an address above, or from an IP in Explore.</${Empty}>`;
  const unban = async (r) => { if (await unbanRecords([r.id], r.value)) onDone(); };
  return html`
    <div class="tbl-wrap">
      <table class="tbl sec-tbl">
        <thead><tr><th>Address</th><th>Location</th><th>Reason</th><th>By</th><th>Created</th><th>Expiry</th><th class="c-act"><span class="sr">Actions</span></th></tr></thead>
        <tbody>${records.map(r => {
          const created = createdCell(r.created_at);
          const geo = r.geo ? [r.geo.country_code, r.geo.asn_org].filter(Boolean).join(' · ') : '';
          return html`
            <tr key=${r.id} class=${r.expired ? 'is-expired' : ''}>
              <td class="c-addr"><span class="mono">${r.value}</span>${r.protected && html` <${ProtectedTag} category=${r.protected} />`}</td>
              <td data-label="Location" class=${geo ? '' : 'is-empty'}>${geo || html`<span class="muted">—</span>`}</td>
              <td class=${'c-reason' + (r.reason ? '' : ' is-empty')} data-label="Reason">${r.reason || html`<span class="muted">—</span>`}</td>
              <td data-label="By">${r.actor}</td>
              <td data-label="Created"><time title=${created.title}>${created.text}</time></td>
              <td data-label="Expiry">${r.expired ? html`<${Mark} tone="none" label="Expired, removed at the next cleanup" />` : expiryLabel(r.expires_at)}</td>
              <td class="c-act">${r.source === 'manual'
                ? html`<button class="btn sm" type="button" onClick=${() => unban(r)} aria-label=${'Unban ' + r.value}>Unban</button>`
                : html`<span class="muted">Read-only</span>`}</td>
            </tr>`;
        })}</tbody>
      </table>
    </div>`;
}

// "CrowdSec decisions: file sync" -> "File sync"; the row's label already says CrowdSec.
function pathLabel(text) {
  const t = text.replace(/^CrowdSec decisions: /, '');
  return t.charAt(0).toUpperCase() + t.slice(1);
}

function insertImport(line, source) {
  document.dispatchEvent(new CustomEvent('app:insert-ban-import', { detail: { line, source } }));
}

// One site: its host, then one compact line per source with a status marker.
function SiteRow({ s, sources, plugin }) {
  const names = Object.keys(sources);
  const many = names.length > 1;
  const cp = crowdsecPath(s);
  const lines = names.map(name => {
    const p = s.policies?.[name] || (name === 'plugin' || name === 'country' ? null : s);
    if (!p) return null;
    const st = siteStatus(p, name);
    const acts = name === 'plugin' ? pluginSiteActions(p, s, plugin) : siteActions({ ...p, source: s.source });
    return { name, st, acts };
  }).filter(Boolean);
  const crit = lines.some(l => l.st.tone === 'crit') || cp?.tone === 'crit';
  return html`
    <li class=${'ss' + (crit ? ' is-crit' : '')}>
      <div class="ss-host"><span class="mono">${s.label}</span>${s.line && html`<span class="ss-line">line ${s.line}</span>`}</div>
      <ul class=${'ss-pols' + (many ? '' : ' single')}>
        ${cp && html`
          <li class="ss-pol" key="path">
            ${many && html`<span class="ss-src">CrowdSec path</span>`}
            <${Mark} tone=${cp.tone} label=${pathLabel(cp.text)} />
            <span class="sec-detail"></span><span class="acts"></span>
          </li>`}
        ${lines.map(({ name, st, acts }) => html`
          <li class="ss-pol" key=${name}>
            ${many && html`<span class="ss-src">${SOURCE_LABELS[name] || name}</span>`}
            <${Mark} tone=${st.tone} label=${st.label} />
            <span class="sec-detail">${st.detail}</span>
            ${html`
              <span class="acts">
                ${acts.includes('insert') && html`<button class="btn sm" type="button" onClick=${() => insertImport(s.line, name)}>Add import in editor</button>`}
                ${acts.includes('copy') && html`<button class="btn sm btn-quiet" type="button" onClick=${() => copy(sources[name].import_line, 'Import line')}><${Icon} name="copy" size=${14} />Copy import</button>`}
              </span>`}
          </li>`)}
      </ul>
    </li>`;
}

function Sites({ sites, sources, plugin }) {
  if (!sites.length) return html`<${Empty}>No sites in the running configuration.</${Empty}>`;
  return html`
    <div class="ss-hd" aria-hidden="true"><span>Site</span><span>Enforcement</span></div>
    <ul class="ss-list">${sites.map(s => html`<${SiteRow} key=${s.label + ':' + (s.line || '')} s=${s} sources=${sources} plugin=${plugin} />`)}</ul>`;
}

// Long and rarely needed: a one-line summary that opens into the full list.
function Protected({ groups }) {
  if (!groups?.length) return html`<${Empty}>No protected ranges reported.</${Empty}>`;
  const ranges = groups.reduce((n, g) => n + g.values.length, 0);
  return html`
    <details class="disclose sec-never">
      <summary>
        <${Icon} name="chevron-right" size=${14} />
        <span class="disclose-t">${ranges} ${ranges === 1 ? 'range' : 'ranges'} in ${groups.length} ${groups.length === 1 ? 'group' : 'groups'}</span>
        <span class="disclose-s">${groups.map(g => g.label).join(', ')}</span>
      </summary>
      <${KV} label="Never banned" rows=${groups.map(g => ({ k: g.label, v: g.values.join('  '), mono: true }))} />
    </details>`;
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
    <section class="sec-recovery alert alert-crit" id="sec-recovery" aria-labelledby="sec-rec-h">
      <${Icon} name="status-down" size=${16} />
      <div>
        <h2 id="sec-rec-h">Recovery</h2>
        <p>${info.summary}</p>
        ${info.files.length > 0 && html`<p class="sec-detail">Files: <span class="mono">${info.files.join(', ')}</span></p>`}
        <div class="acts">
          ${info.reapply && held.map(n => html`<button class="btn btn-primary" type="button" key=${'re-' + n} onClick=${() => reapply(n)}>${n === 'manual' && held.length === 1 ? 'Re-apply' : `Re-apply ${SOURCE_LABELS[n] || n}`}</button>`)}
          ${info.actions.filter(a => a !== 'restore_backup').map(a => html`<button class="btn" type="button" key=${a} onClick=${() => run(a)}>${recoveryActionLabel(a)}</button>`)}
          ${info.reset && html`<button class="btn btn-danger" type="button" onClick=${reset}>Reset manual bans</button>`}
          ${info.reset && sources?.crowdsec && html`<button class="btn btn-danger" type="button" onClick=${resetCrowdsec}>Reset CrowdSec decisions</button>`}
        </div>
        ${info.actions.includes('restore_backup') && html`
          <ul class="rows sec-backups" aria-label="Backups">${info.backups.map(b => html`
            <li key=${b.id}><span>${absoluteTime(b.created_at)}</span><span class="muted">${b.records} ${b.records === 1 ? 'record' : 'records'}</span>
              <button class="btn sm" type="button" onClick=${() => run('restore_backup', b.id)}>${recoveryActionLabel('restore_backup')}</button></li>`)}
          </ul>`}
      </div>
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
  const recoveryShown = !!status.recovery?.required;
  return html`
    <div class="page sec">
      <${Verdict} status=${status} records=${manualRecords.length} stale=${error ? loadedAt : null} recoveryShown=${recoveryShown} />
      <${Recovery} info=${status.recovery} onDone=${load} sources=${status.sources} />
      <${Figures} status=${status} manualCount=${manual.active_records ?? manualRecords.length} crowdsecCount=${cs?.active_records ?? crowdsecRecords.length} />

      <section class="sec-s" aria-labelledby="sec-bans-h">
        <${SectionHead} id="sec-bans-h" title="Manual bans" desc=${`${manual.active_records} active. ${capacityText(status.limits)}`} />
        ${writable ? html`<${AddBan} onDone=${load} />` : html`<${Alert} tone="warn">Changes are paused until the problem above is resolved.</${Alert}>`}
        ${bans?.error ? html`<${Alert} tone="crit">${bans.error}</${Alert}>` : html`<${BanList} records=${manualRecords} onDone=${load} />`}
      </section>
      ${cs?.enabled && html`<${CrowdSecSection} src=${cs} records=${crowdsecRecords} onCopy=${copy} />`}
      ${plug && html`<${PluginSection} plugin=${plug} onCopy=${copy} onReapply=${reapplyPlugin} />`}
      ${ip && html`<${ClientIpSection} key=${ip.mode + ':' + (ip.tunnel_peers || []).join()} info=${ip} onDone=${load} onCopy=${copy} />`}
      ${cp && html`<${CountrySection} key=${cp.updated_at || 'none'} info=${cp} onDone=${load} onCopy=${copy} />`}

      <section class="sec-s" aria-labelledby="sec-sites-h">
        <${SectionHead} id="sec-sites-h" title="Sites" desc="Where each policy is enforced, proven from Caddy's running configuration." />
        <div class="codelines">
          ${Object.entries(active).map(([n, s]) => html`<${CodeLine} key=${n} label=${`${SOURCE_LABELS[n] || n} import line`} code=${s.import_line} onCopy=${copy} />`)}
        </div>
        <${Sites} sites=${status.sites || []} sources=${siteSources} plugin=${plug} />
      </section>

      <section class="sec-s" aria-labelledby="sec-prot-h">
        <${SectionHead} id="sec-prot-h" title="Never banned" desc="Refused at input and excluded again by the generated policy." />
        <${Protected} groups=${status.protected} />
      </section>

      <section class="sec-s" aria-labelledby="sec-rec2-h">
        <${SectionHead} id="sec-rec2-h" title="Recovery" desc="For when a policy file or a reload goes wrong." />
        ${recoveryShown
          ? html`<p class="sec-p"><${Mark} tone="crit" label="Recovery needed" /> <a href="#sec-recovery">See the recovery options at the top of the page</a>.</p>`
          : html`<${Empty} icon="status-ok">No recovery is needed right now.</${Empty}>`}
        <p class="sec-p sec-detail">If the console itself is unreachable, use the <a href=${HOST_RECOVERY_URL} target="_blank" rel="noopener noreferrer">host recovery commands</a> in docs/security.md.</p>
      </section>

      <div class="foot">${status.last_apply && html`<span>Last applied <time title=${absoluteTime(status.last_apply.time)}>${absoluteTime(status.last_apply.time)}</time> by ${status.last_apply.user}.</span>`}<span>Refreshes every ${REFRESH_MS / 1000} s.</span></div>
    </div>`;
}

let mounted = false;

export function mountSecurity() {
  const root = document.getElementById('security-root');
  if (!root || mounted) return;
  render(html`<${App} />`, root);
  mounted = true;
}
