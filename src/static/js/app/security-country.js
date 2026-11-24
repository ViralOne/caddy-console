// Country policy part of the Security view (spec 4.3): an allowlist of
// countries answered with 403 for everyone else. Wording and validation live
// in security-model.js; country names come from Intl.DisplayNames with the
// code as the fallback. Every string from the API is a text child.
import { h, htm, useState } from '../explore-vendor.js';
import { Icon } from './icons.js';
import { toast } from './ui/toast.js';
import { requestJson as call } from './security-api.js';
import {
  SPECIAL_WARNING, countryOptions, countryPayload, countryPrefixText, countryState, errorMessage, specialSelected, toggleCode,
} from './security-model.js';

const html = htm.bind(h);
const SEV = { crit: 'critical', warn: 'warn', ok: 'ok', none: 'ok' };

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
    toast('Country policy saved; Caddy reloaded.', { kind: 'ok' });
    onDone();
  };
  return html`
    <section aria-labelledby="sec-country-h">
      <div class="h-sec"><h2 id="sec-country-h">Country policy</h2>
        <p>Only clients from the selected countries reach a site that imports the policy; everyone else gets 403. Private and protected addresses are never blocked.</p></div>
      <p class=${'sec-cs-state sev-' + SEV[st.tone]} role=${st.tone === 'crit' ? 'alert' : 'status'}>
        <strong>${st.title}</strong>${st.detail && html` <span class="muted small">${st.detail}</span>`}</p>
      <dl class="sec-protected">
        <div><dt>Source</dt><dd>${info.shape === 'cloudflare' ? 'Cloudflare CF-IPCountry header, trusted only from the profile’s peers' : info.shape === 'direct' ? `DB-IP Country Lite dataset${info.dataset?.used_month ? ` (${info.dataset.used_month})` : ''}` : 'Off'}</dd></div>
        ${prefix && html`<div><dt>Prefixes</dt><dd>${prefix}</dd></div>`}
      </dl>
      ${(info.warnings || []).map(w => html`<p class="metrics-hint" key=${w}>${w}</p>`)}
      <form onSubmit=${save}>
        <label class="inline"><input type="checkbox" checked=${enabled} disabled=${!info.env_enabled} onChange=${e => setEnabled(e.currentTarget.checked)} />
          Enable country policy</label>
        ${cloudflare && html`
          <label class="inline"><input type="checkbox" checked=${confirmed} onChange=${e => setConfirmed(e.currentTarget.checked)} />
            I confirmed that IP geolocation is on for this Cloudflare zone (it sends CF-IPCountry)</label>`}
        <label class="sec-filter">Find a country
          <input type="text" spellcheck="false" autocomplete="off" value=${filter} onInput=${e => setFilter(e.currentTarget.value)} /></label>
        <div class="sec-countries" role="group" aria-label="Allowed countries">
          ${shown.map(o => html`
            <label class=${'inline' + (o.special ? ' sec-special' : '')} key=${o.code}>
              <input type="checkbox" checked=${codes.includes(o.code)} onChange=${e => setCodes(toggleCode(codes, o.code, e.currentTarget.checked))} />
              ${o.name}${o.special ? ' (not a country)' : ''}</label>`)}
        </div>
        <p class="muted small">${codes.length} selected.</p>
        ${special.length > 0 && html`<p class="sec-error" role="alert">${SPECIAL_WARNING}</p>`}
        <div class="acts">
          <button class="btn btn-primary" type="submit" disabled=${busy}>Save country policy</button>
          <button class="btn btn-quiet" type="button" onClick=${() => onCopy(info.import_line, 'Import line')}><${Icon} name="copy" size=${14} />Copy import line</button>
        </div>
        ${error && html`<p class="sec-error" role="alert">${error}</p>`}
      </form>
    </section>`;
}
