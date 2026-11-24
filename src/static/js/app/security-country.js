// Country policy part of the Security view (spec 4.3): an allowlist of
// countries answered with 403 for everyone else. Wording and validation live
// in security-model.js; country names come from Intl.DisplayNames with the
// code as the fallback. Every string from the API is a text child.
import { h, htm, useState } from '../explore-vendor.js';
import { Icon } from './icons.js';
import { toast } from './ui/toast.js';
import { requestJson as call } from './security-api.js';
import { Alert, Check, Field, KV, SectionHead, StateLine } from './security-ui.js';
import {
  SPECIAL_WARNING, countryOptions, countryPayload, countryPrefixText, countryState, errorMessage, specialSelected, toggleCode,
  saveNotice,
} from './security-model.js';

const html = htm.bind(h);

function displayNames() {
  try { return new Intl.DisplayNames(navigator.languages?.length ? [...navigator.languages] : undefined, { type: 'region' }); } catch (e) { return null; }
}

export function CountrySection({ info, onDone, onCopy }) {
  const [enabled, setEnabled] = useState(!!info.enabled);
  const [codes, setCodes] = useState(info.countries || []);
  const [confirmed, setConfirmed] = useState(!!info.cloudflare_geolocation_confirmed);
  const [filter, setFilter] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [names] = useState(displayNames);
  const options = countryOptions(info, names);
  const shown = options.filter(o => !filter || o.name.toLowerCase().includes(filter.toLowerCase()) || o.code.toLowerCase() === filter.toLowerCase());
  const st = countryState(info);
  const special = specialSelected(codes, info);
  const cloudflare = info.client_ip_mode !== 'direct';
  const prefix = countryPrefixText(info.summary);
  const save = async (e) => {
    e.preventDefault();
    let payload;
    try { payload = countryPayload({ enabled, countries: codes, confirmed, shape: cloudflare ? 'cloudflare' : 'direct' }); } catch (err) { setError(err.message); return; }
    setBusy(true); setError('');
    const r = await call('/api/security/country-policy', 'PUT', payload);
    setBusy(false);
    if (!r.ok) { setError(errorMessage(r.body, r.status)); return; }
    { const n = saveNotice('Country policy', r.body); toast(n.text, { kind: n.kind }); }
    onDone();
  };
  const selectedNames = options.filter(o => codes.includes(o.code)).map(o => o.name);
  return html`
    <section class="sec-s" aria-labelledby="sec-country-h">
      <${SectionHead} id="sec-country-h" title="Country policy" desc="Only the selected countries reach a site that imports the policy; everyone else gets 403." />
      <${StateLine} st=${st} />
      <${KV} label="Country policy" rows=${[
        { k: 'Source', v: info.shape === 'cloudflare' ? 'Cloudflare CF-IPCountry header, trusted only from the profile’s peers' : info.shape === 'direct' ? `DB-IP Country Lite dataset${info.dataset?.used_month ? ` (${info.dataset.used_month})` : ''}` : 'Off' },
        prefix && { k: 'Prefixes', v: prefix },
        { k: 'Never blocked', v: 'Private and protected addresses' },
      ]} />
      ${(info.warnings || []).map(w => html`<${Alert} tone="warn" key=${w}>${w}</${Alert}>`)}
      <form class="sec-country-form" onSubmit=${save} aria-label="Country policy">
        <div class="form-row">
          <${Check} checked=${enabled} disabled=${!info.env_enabled} onChange=${e => setEnabled(e.currentTarget.checked)}>Enable country policy</${Check}>
          ${cloudflare && html`
            <${Check} checked=${confirmed} onChange=${e => setConfirmed(e.currentTarget.checked)}>I confirmed that IP geolocation is on for this Cloudflare zone (it sends CF-IPCountry)</${Check}>`}
        </div>
        <div class="cty-bar">
          <${Field} label="Find a country">
            <span class="inp-icon"><${Icon} name="filter" size=${14} />
              <input class="inp" type="text" spellcheck="false" autocomplete="off" placeholder="Name or code" value=${filter} onInput=${e => setFilter(e.currentTarget.value)} /></span></${Field}>
          <p class="cty-count" aria-live="polite"><b>${codes.length}</b> selected${selectedNames.length > 0 && html`<span class="cty-names" title=${selectedNames.join(', ')}>: ${selectedNames.join(', ')}</span>`}</p>
        </div>
        <div class="cty-grid" role="group" aria-label="Allowed countries">
          ${shown.length ? shown.map(o => html`
            <${Check} key=${o.code} checked=${codes.includes(o.code)} onChange=${e => setCodes(toggleCode(codes, o.code, e.currentTarget.checked))}>
              ${o.name}${o.special && html` <span class="tag tag-warn">not a country</span>`}</${Check}>`)
            : html`<p class="cty-none">No country matches “${filter}”.</p>`}
        </div>
        ${special.length > 0 && html`<${Alert} tone="warn" role="alert">${SPECIAL_WARNING}</${Alert}>`}
        ${error && html`<p class="form-error" role="alert">${error}</p>`}
        <div class="acts">
          <button class="btn btn-primary" type="submit" disabled=${busy}>Save country policy</button>
          <button class="btn btn-quiet" type="button" onClick=${() => onCopy(info.import_line, 'Import line')}><${Icon} name="copy" size=${14} />Copy import line</button>
        </div>
      </form>
    </section>`;
}
