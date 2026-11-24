// CrowdSec part of the Security view (spec 2.7): sync health and times,
// origins, ignored counts and protected samples. The decisions themselves are
// rows of the shared IP bans list in security.js. Wording
// lives in security-model.js; every string from LAPI or the API is a text
// child (a text node).
import { h, htm } from '../explore-vendor.js';
import { Alert, KV, SectionHead, StateLine } from './security-ui.js';
import { LIST_ORIGIN_WARNING, crowdsecState, ignoredRows, originCountsText, protectedLabel, syncTimes } from './security-model.js';

const html = htm.bind(h);

export function CrowdSecSection({ src }) {
  const st = crowdsecState(src);
  const sync = src.sync || {};
  const ignored = ignoredRows(sync.ignored);
  const sample = sync.protected_sample || [];
  const byOrigin = originCountsText(sync);
  return html`
    <section class="sec-s" aria-labelledby="sec-cs-h">
      <${SectionHead} id="sec-cs-h" title="CrowdSec" desc="Sync health. Decisions are listed under IP bans." />
      <${StateLine} st=${st} />
      <${KV} label="CrowdSec sync" rows=${[
        ...syncTimes(sync).map(t => ({ k: t.label, v: t.text, title: t.title })),
        { k: 'Origins', v: (src.origins || []).join(', ') || '—', mono: true },
        byOrigin && { k: 'Synced by origin', v: byOrigin, mono: true },
        ignored.length > 0 && { k: 'Ignored decisions', v: ignored.map(r => `${r.label}: ${r.count}`).join('; ') },
      ]} />
      ${(src.list_origins || []).length > 0 && html`<${Alert} tone="warn">${LIST_ORIGIN_WARNING}</${Alert}>`}
      ${sample.length > 0 && html`<p class="sec-p sec-detail">Protected, never rendered: <span class="mono">${sample.map(p => `${p.value} (${protectedLabel(p.category)})`).join(', ')}</span></p>`}
    </section>`;
}
