// CrowdSec part of the Security view (spec 2.7): sync health and times,
// read-only decisions with scenario and origin, ignored counts, protected
// samples and a copyable cscli command (text only, never executed). Wording
// lives in security-model.js; every string from LAPI or the API is a text
// child (a text node). `onCopy(text, what)` is the view's clipboard helper.
import { h, htm } from '../explore-vendor.js';
import { Icon } from './icons.js';
import { Alert, Empty, KV, SectionHead, StateLine } from './security-ui.js';
import {
  LIST_ORIGIN_WARNING, createdCell, crowdsecState, cscliDeleteCommand, expiryLabel, ignoredRows, originCountsText,
  protectedLabel, syncTimes,
} from './security-model.js';

const html = htm.bind(h);

function Decisions({ records, onCopy }) {
  if (!records.length) return html`<${Empty}>No active CrowdSec decisions.</${Empty}>`;
  return html`
    <div class="tbl-wrap">
      <table class="tbl sec-tbl">
        <thead><tr><th>Address</th><th>Scenario</th><th>Origin</th><th>Fetched</th><th>Expiry</th><th class="c-act"><span class="sr">Actions</span></th></tr></thead>
        <tbody>${records.map(r => {
          const fetched = createdCell(r.created_at);
          const cmd = cscliDeleteCommand(r);
          return html`
            <tr key=${r.id} class=${r.expired ? 'is-expired' : ''}>
              <td class="c-addr"><span class="mono">${r.value}</span>${r.protected && html` <span class="tag tag-warn" title=${'Protected: ' + protectedLabel(r.protected)}><${Icon} name="warning" size=${12} />ignored, protected</span>`}</td>
              <td data-label="Scenario" class=${r.scenario ? '' : 'is-empty'}>${r.scenario || html`<span class="muted">—</span>`}</td>
              <td data-label="Origin" class=${r.origin ? '' : 'is-empty'}>${r.origin || html`<span class="muted">—</span>`}</td>
              <td data-label="Fetched"><time title=${fetched.title}>${fetched.text}</time></td>
              <td data-label="Expiry">${expiryLabel(r.expires_at)}</td>
              <td class="c-act">${cmd && html`<button class="btn sm btn-quiet" type="button" title=${cmd} onClick=${() => onCopy(cmd, 'cscli command')}><${Icon} name="copy" size=${14} />Copy cscli command</button>`}</td>
            </tr>`;
        })}</tbody>
      </table>
    </div>`;
}

export function CrowdSecSection({ src, records, onCopy }) {
  const st = crowdsecState(src);
  const sync = src.sync || {};
  const ignored = ignoredRows(sync.ignored);
  const sample = sync.protected_sample || [];
  const byOrigin = originCountsText(sync);
  return html`
    <section class="sec-s" aria-labelledby="sec-cs-h">
      <${SectionHead} id="sec-cs-h" title="CrowdSec" desc="Read-only decisions, synced from CrowdSec's Local API." />
      <${StateLine} st=${st} />
      <${KV} label="CrowdSec sync" rows=${[
        ...syncTimes(sync).map(t => ({ k: t.label, v: t.text, title: t.title })),
        { k: 'Origins', v: (src.origins || []).join(', ') || '—', mono: true },
        byOrigin && { k: 'Synced by origin', v: byOrigin, mono: true },
        ignored.length > 0 && { k: 'Ignored decisions', v: ignored.map(r => `${r.label}: ${r.count}`).join('; ') },
      ]} />
      ${(src.list_origins || []).length > 0 && html`<${Alert} tone="warn">${LIST_ORIGIN_WARNING}</${Alert}>`}
      ${sample.length > 0 && html`<p class="sec-p sec-detail">Protected, never rendered: <span class="mono">${sample.map(p => `${p.value} (${protectedLabel(p.category)})`).join(', ')}</span></p>`}
      <h3 class="sec-h3">Active decisions</h3>
      <p class="sec-p sec-detail">To remove one, delete it in CrowdSec: run the copied command inside the crowdsec container.</p>
      <${Decisions} records=${records} onCopy=${onCopy} />
    </section>`;
}
