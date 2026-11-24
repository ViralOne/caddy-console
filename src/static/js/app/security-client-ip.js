// Client IP part of the Security view (spec 4.1): which headers Caddy trusts
// to name the visitor, the tunnel peer, and the Cloudflare edge range list.
// Wording and validation live in security-model.js; every string from the API
// is a text child. Changing the mode asks for confirmation first.
import { h, htm, useState } from '../explore-vendor.js';
import { Icon } from './icons.js';
import { confirmDialog } from './ui/dialog.js';
import { toast } from './ui/toast.js';
import { requestJson as call } from './security-api.js';
import {
  CLIENT_IP_MODES, clientIpConfirm, clientIpMode, clientIpPayload, clientIpState, errorMessage, rangesAgeText, rangesNotice,
} from './security-model.js';

const html = htm.bind(h);
const SEV = { crit: 'critical', warn: 'warn', ok: 'ok', none: 'ok' };

export function ClientIpSection({ info, onDone, onCopy }) {
  const [mode, setMode] = useState(info.mode);
  const [peers, setPeers] = useState((info.tunnel_peers || []).join(' '));
  const [tunnelOnly, setTunnelOnly] = useState(!!info.tunnel_only);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const st = clientIpState(info);
  const notice = rangesNotice(info.ranges, info.mode);
  const dirty = mode !== info.mode || (mode === 'cloudflare-tunnel' && (peers.trim().split(/[\s,]+/).join(' ') !== (info.tunnel_peers || []).join(' ') || tunnelOnly !== !!info.tunnel_only));
  const save = async (e) => {
    e.preventDefault();
    let payload;
    try { payload = clientIpPayload({ mode, peersText: peers, tunnelOnly }); } catch (err) { setError(err.message); return; }
    setError('');
    if (!(await confirmDialog(clientIpConfirm(payload)))) return;
    setBusy(true);
    const r = await call('/api/security/client-ip-profile', 'PUT', payload);
    setBusy(false);
    if (!r.ok) { setError(errorMessage(r.body, r.status)); return; }
    toast('Client-IP profile saved; Caddy reloaded.', { kind: 'ok' });
    onDone();
  };
  const refresh = async () => {
    setBusy(true);
    const r = await call('/api/security/cloudflare-ranges/refresh', 'POST', {});
    setBusy(false);
    toast(r.ok ? 'Cloudflare ranges refreshed.' : errorMessage(r.body, r.status), { kind: r.ok ? 'ok' : 'error' });
    onDone();
  };
  const ranges = info.ranges || {};
  return html`
    <section aria-labelledby="sec-ip-h">
      <div class="h-sec"><h2 id="sec-ip-h">Client IP</h2>
        <p>How Caddy decides who a visitor is. Bans, country policy and logs all use this address.</p></div>
      <p class=${'sec-cs-state sev-' + SEV[st.tone]} role=${st.tone === 'crit' ? 'alert' : 'status'}>
        <strong>${st.title}</strong>${st.detail && html` <span class="muted small">${st.detail}</span>`}</p>
      <p class="muted small">${clientIpMode(info.mode).explain}</p>
      <form class="sec-add" onSubmit=${save}>
        <label>Mode
          <select value=${mode} onChange=${e => { setMode(e.currentTarget.value); setError(''); }}>
            ${CLIENT_IP_MODES.map(m => html`<option key=${m.id} value=${m.id}>${m.label}</option>`)}
          </select></label>
        ${mode === 'cloudflare-tunnel' && html`
          <label class="grow">cloudflared address or subnet
            <input type="text" spellcheck="false" autocomplete="off" placeholder="172.18.0.5" value=${peers} onInput=${e => setPeers(e.currentTarget.value)} /></label>
          <label class="inline"><input type="checkbox" checked=${tunnelOnly} onChange=${e => setTunnelOnly(e.currentTarget.checked)} />
            Caddy is reachable only through the tunnel</label>`}
        <button class="btn btn-primary" type="submit" disabled=${busy || !dirty}>Save client IP mode</button>
        ${error && html`<p class="sec-error" role="alert">${error}</p>`}
      </form>
      <p class="muted small">${clientIpMode(mode).id !== info.mode ? clientIpMode(mode).explain : ''}</p>
      ${info.mode === 'cloudflare-proxied' && html`
        <dl class="sec-protected">
          <div><dt>Cloudflare edge ranges</dt><dd>${(ranges.v4 || []).length} IPv4 and ${(ranges.v6 || []).length} IPv6. ${rangesAgeText(ranges)}.</dd></div>
          ${ranges.checked_at && html`<div><dt>Last check</dt><dd>${ranges.checked_at}</dd></div>`}
          <div><dt>Automatic refresh</dt><dd>${ranges.auto_update ? 'Daily' : 'Off'}</dd></div>
        </dl>
        ${notice && html`<p class="sec-error" role="alert">${notice}</p>`}
        <div class="acts">
          <button class="btn" type="button" disabled=${busy} onClick=${refresh}><${Icon} name="restore" size=${14} />Refresh ranges</button>
        </div>`}
      <p class="muted small">Import line for the global servers block: <code>${info.import_line}</code>
        <button class="btn sm btn-quiet" type="button" onClick=${() => onCopy(info.import_line, 'Import line')}><${Icon} name="copy" size=${14} />Copy</button></p>
      ${(info.dependencies || []).length > 0 && html`<p class="muted small">Generated files: ${info.dependencies.map(d => `${d.file} (${d.hash})`).join(', ')}</p>`}
    </section>`;
}
