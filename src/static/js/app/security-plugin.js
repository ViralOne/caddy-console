// CrowdSec plugin part of the Security view (spec 3.6): health, admin bind,
// key mode, polling interval, the protected route definition and copy-only
// commands. Wording lives in security-model.js; every string from the API is
// a text child. `onCopy(text, what)` is the view's clipboard helper.
import { h, htm } from '../explore-vendor.js';
import { Icon } from './icons.js';
import { pluginState } from './security-model.js';

const html = htm.bind(h);
const SEV = { crit: 'critical', warn: 'warn', ok: 'ok', none: 'ok' };

export function PluginSection({ plugin, onCopy, onReapply }) {
  const st = pluginState(plugin);
  if (!st) return null;
  const d = plugin.definition || {};
  const key = plugin.key_mode === 'file' ? `File secret ${plugin.key_file} (${plugin.placeholder})` : `Environment (${plugin.placeholder})`;
  return html`
    <section aria-labelledby="sec-plugin-h">
      <div class="h-sec"><h2 id="sec-plugin-h">CrowdSec plugin</h2>
        <p>Caddy asks CrowdSec directly. Protected addresses never reach the plugin; manual bans still use the ban file.</p></div>
      <p class=${'sec-cs-state sev-' + SEV[st.tone]} role=${st.tone === 'crit' ? 'alert' : 'status'}>
        <strong>${st.title}</strong>${st.detail && html` <span class="muted small">${st.detail}</span>`}</p>
      <dl class="sec-protected">
        <div><dt>Module</dt><dd>${plugin.module === true ? 'Present in the running Caddy' : plugin.module === false ? 'Missing' : 'Unknown (Caddy did not answer)'}</dd></div>
        <div><dt>Admin API</dt><dd>${plugin.refused ? plugin.admin?.message || 'Exposed' : 'Fixed caddy-admin address only'}</dd></div>
        <div><dt>Bouncer key</dt><dd class="mono">${key}</dd></div>
        <div><dt>Polling</dt><dd>Every ${plugin.ticker_interval}, near-real-time without reload</dd></div>
        <div><dt>Protected route</dt><dd class="mono">${d.import_line}${d.hash ? ` (protected ranges ${d.hash}${d.current ? '' : ', out of date'})` : ' (not generated yet)'}</dd></div>
      </dl>
      <div class="acts">
        <button class="btn" type="button" onClick=${onReapply}>Re-apply plugin route</button>
        <button class="btn btn-quiet" type="button" title=${plugin.allowlist} onClick=${() => onCopy(plugin.allowlist, 'cscli allowlist commands')}><${Icon} name="copy" size=${14} />Copy LAPI allowlist commands</button>
        <button class="btn btn-quiet" type="button" title=${plugin.check_command} onClick=${() => onCopy(plugin.check_command, 'Isolation check command')}><${Icon} name="copy" size=${14} />Copy isolation check</button>
      </div>
      <p class="muted small">Run the isolation check on the host after every start: Caddy port 2019 must refuse connections from the CrowdSec and cloudflared containers.</p>
    </section>`;
}
