// Client IP part of the Security view (spec 4.1): which headers Caddy trusts
// to name the visitor, the tunnel peer, and the Cloudflare edge range list.
// Wording and validation live in security-model.js; every string from the API
// is a text child. Changing the mode asks for confirmation first.
import { h, htm, useState } from '../explore-vendor.js';
import { Icon } from './icons.js';
import { confirmDialog } from './ui/dialog.js';
import { toast } from './ui/toast.js';
import { requestJson as call } from './security-api.js';
import { Alert, Check, CodeLine, Field, KV, SectionHead, Select, StateLine } from './security-ui.js';
import {
  CLIENT_IP_MODES, clientIpConfirm, clientIpMode, clientIpPayload, clientIpState, errorMessage, rangesAgeText, rangesNotice,
  saveNotice,
} from './security-model.js';

const html = htm.bind(h);

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
    { const n = saveNotice('Client-IP profile', r.body); toast(n.text, { kind: n.kind }); }
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
  const chosen = clientIpMode(mode);
  return html`
    <section class="sec-s" aria-labelledby="sec-ip-h">
      <${SectionHead} id="sec-ip-h" title="Client IP" desc="How Caddy decides who a visitor is. Bans, country policy and logs all use this address." />
      <${StateLine} st=${st} />
      <p class="sec-p sec-detail">${clientIpMode(info.mode).explain}</p>
      <form class="sec-form" onSubmit=${save} aria-label="Client IP mode">
        <${Field} label="Mode" narrow>
          <${Select} value=${mode} options=${CLIENT_IP_MODES} onChange=${e => { setMode(e.currentTarget.value); setError(''); }} /></${Field}>
        ${mode === 'cloudflare-tunnel' && html`
          <${Field} label="cloudflared address or subnet" grow>
            <input class="inp mono" type="text" spellcheck="false" autocomplete="off" placeholder="172.18.0.5" value=${peers} onInput=${e => setPeers(e.currentTarget.value)} /></${Field}>`}
        <button class="btn btn-primary" type="submit" disabled=${busy || !dirty}>Save client IP mode</button>
        ${mode === 'cloudflare-tunnel' && html`
          <div class="form-row"><${Check} checked=${tunnelOnly} onChange=${e => setTunnelOnly(e.currentTarget.checked)}>Caddy is reachable only through the tunnel</${Check}></div>`}
        ${chosen.id !== info.mode && html`<p class="form-note">${chosen.explain}</p>`}
        ${error && html`<p class="form-error" role="alert">${error}</p>`}
      </form>
      ${info.mode === 'cloudflare-proxied' && html`
        <h3 class="sec-h3">Cloudflare edge ranges</h3>
        <${KV} label="Cloudflare edge ranges" rows=${[
          { k: 'Ranges', v: `${(ranges.v4 || []).length} IPv4 and ${(ranges.v6 || []).length} IPv6. ${rangesAgeText(ranges)}.` },
          ranges.checked_at && { k: 'Last check', v: ranges.checked_at },
          { k: 'Automatic refresh', v: ranges.auto_update ? 'Daily' : 'Off' },
        ]} />
        ${notice && html`<${Alert} tone="warn" role="alert">${notice}</${Alert}>`}
        <div class="acts">
          <button class="btn" type="button" disabled=${busy} onClick=${refresh}><${Icon} name="restore" size=${14} />Refresh ranges</button>
        </div>`}
      <div class="codelines">
        <${CodeLine} label="Import line for the global servers block" code=${info.import_line} onCopy=${onCopy} />
      </div>
      ${(info.dependencies || []).length > 0 && html`<p class="sec-p sec-detail">Generated files: <span class="mono">${info.dependencies.map(d => `${d.file} (${d.hash})`).join(', ')}</span></p>`}
    </section>`;
}
