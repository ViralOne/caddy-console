// CrowdSec part of the Security view (spec 2.7): sync health and times,
// read-only decisions with scenario and origin, ignored counts, protected
// samples and a copyable cscli command (text only, never executed). Wording
// lives in security-model.js; every string from LAPI or the API is a text
// child (a text node). `onCopy(text, what)` is the view's clipboard helper.
import { h, htm } from '../explore-vendor.js';
import { Icon } from './icons.js';
import {
  LIST_ORIGIN_WARNING, createdCell, crowdsecState, cscliDeleteCommand, expiryLabel, ignoredRows, originCountsText,
  protectedLabel, syncTimes,
} from './security-model.js';

const html = htm.bind(h);
const SEV = { crit: 'critical', warn: 'warn', ok: 'ok', none: 'ok' };

function Decisions({ records, onCopy }) {
  if (!records.length) return html`<p class="metrics-hint">No active CrowdSec decisions.</p>`;
  return html`
    <table class="sec-table">
      <thead><tr><th>Address</th><th>Scenario</th><th>Origin</th><th>Fetched</th><th>Expiry</th><th><span class="sr">Actions</span></th></tr></thead>
      <tbody>${records.map(r => {
        const fetched = createdCell(r.created_at);
        const cmd = cscliDeleteCommand(r);
        return html`
          <tr key=${r.id} class=${r.expired ? 'expired' : ''}>
            <td class="mono">${r.value}${r.protected && html` <span class="sec-tag" title=${'Protected: ' + protectedLabel(r.protected)}>ignored, protected</span>`}</td>
            <td>${r.scenario || ''}</td>
            <td>${r.origin || ''}</td>
            <td title=${fetched.title}>${fetched.text}</td>
            <td>${expiryLabel(r.expires_at)}</td>
            <td>${cmd && html`<button class="btn sm btn-quiet" type="button" title=${cmd} onClick=${() => onCopy(cmd, 'cscli command')}><${Icon} name="copy" size=${14} />Copy cscli command</button>`}</td>
          </tr>`;
      })}</tbody>
    </table>`;
}

export function CrowdSecSection({ src, records, onCopy }) {
  const st = crowdsecState(src);
  const sync = src.sync || {};
  const ignored = ignoredRows(sync.ignored);
  const sample = sync.protected_sample || [];
  const byOrigin = originCountsText(sync);
  return html`
    <section aria-labelledby="sec-cs-h">
      <div class="h-sec"><h2 id="sec-cs-h">CrowdSec decisions</h2>
        <p>Read-only, synced from CrowdSec's Local API. To remove one, delete it in CrowdSec (run the copied command inside the crowdsec container).</p></div>
      <p class=${'sec-cs-state sev-' + SEV[st.tone]} role=${st.tone === 'crit' ? 'alert' : 'status'}>
        <strong>${st.title}</strong>${st.detail && html` <span class="muted small">${st.detail}</span>`}</p>
      <dl class="sec-protected">
        ${syncTimes(sync).map(t => html`<div key=${t.label}><dt>${t.label}</dt><dd title=${t.title}>${t.text}</dd></div>`)}
        <div><dt>Origins</dt><dd class="mono">${(src.origins || []).join(', ')}</dd></div>
        ${byOrigin && html`<div><dt>Synced by origin</dt><dd class="mono">${byOrigin}</dd></div>`}
      </dl>
      ${(src.list_origins || []).length > 0 && html`<p class="metrics-hint">${LIST_ORIGIN_WARNING}</p>`}
      ${ignored.length > 0 && html`
        <div class="sec-ignored"><span class="k">Ignored decisions</span>
          <ul>${ignored.map(r => html`<li key=${r.reason}>${r.label}: ${r.count}</li>`)}</ul></div>`}
      ${sample.length > 0 && html`<p class="muted small">Protected, never rendered: ${sample.map(p => `${p.value} (${protectedLabel(p.category)})`).join(', ')}</p>`}
      <${Decisions} records=${records} onCopy=${onCopy} />
    </section>`;
}
