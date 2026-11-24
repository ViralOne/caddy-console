// CrowdSec plugin part of the Security view (spec 3.6): health, admin bind,
// key mode, polling interval, the protected route definition and copy-only
// commands. Wording lives in security-model.js; every string from the API is
// a text child. `onCopy(text, what)` is the view's clipboard helper.
import { h, htm } from '../explore-vendor.js';
import { Icon } from './icons.js';
import { KV, Mark, SectionHead, StateLine } from './security-ui.js';
import { pluginState } from './security-model.js';

const html = htm.bind(h);

export function PluginSection({ plugin, onCopy, onReapply }) {
  const st = pluginState(plugin);
  if (!st) return null;
  const d = plugin.definition || {};
  const key = plugin.key_mode === 'file' ? `File secret ${plugin.key_file} (${plugin.placeholder})` : `Environment (${plugin.placeholder})`;
  const module = plugin.module === true
    ? html`<${Mark} tone="ok" label="Present in the running Caddy" />`
    : plugin.module === false ? html`<${Mark} tone="warn" label="Missing" />` : html`<${Mark} tone="none" label="Unknown (Caddy did not answer)" />`;
  const admin = plugin.refused
    ? html`<${Mark} tone="crit" label=${plugin.admin?.message || 'Exposed'} />`
    : html`<${Mark} tone="ok" label="Fixed caddy-admin address only" />`;
  return html`
    <section class="sec-s" aria-labelledby="sec-plugin-h">
      <${SectionHead} id="sec-plugin-h" title="CrowdSec plugin" desc="Caddy asks CrowdSec directly; manual bans still use the ban file." />
      <${StateLine} st=${st} />
      <${KV} label="CrowdSec plugin" rows=${[
        { k: 'Module', v: module },
        { k: 'Admin API', v: admin },
        { k: 'Bouncer key', v: key, mono: true },
        { k: 'Polling', v: `Every ${plugin.ticker_interval}, near-real-time without reload` },
        { k: 'Protected route', v: `${d.import_line}${d.hash ? ` (protected ranges ${d.hash}${d.current ? '' : ', out of date'})` : ' (not generated yet)'}`, mono: true },
      ]} />
      <p class="sec-p sec-detail">Protected addresses never reach the plugin. Run the isolation check on the host after every start: Caddy port 2019 must refuse connections from the CrowdSec and cloudflared containers.</p>
      <div class="acts">
        <button class="btn" type="button" onClick=${onReapply}><${Icon} name="restore" size=${14} />Re-apply plugin route</button>
        <button class="btn btn-quiet" type="button" title=${plugin.allowlist} onClick=${() => onCopy(plugin.allowlist, 'cscli allowlist commands')}><${Icon} name="copy" size=${14} />Copy LAPI allowlist commands</button>
        <button class="btn btn-quiet" type="button" title=${plugin.check_command} onClick=${() => onCopy(plugin.check_command, 'Isolation check command')}><${Icon} name="copy" size=${14} />Copy isolation check</button>
      </div>
    </section>`;
}
