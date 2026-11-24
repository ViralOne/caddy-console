// The popover behind a client IP in an expanded event: where the address is
// from, and what else it did in the range on screen.
//
// Every correlation row is a filter, so "this IP hit 3 hosts" is one click from
// seeing those requests — the popover never becomes a dead end beside the stream.
import { h, htm, useEffect, useState } from '../explore-vendor.js';
import { setTermState } from './explore-query.js';
import { Icon } from './icons.js';
import { banAddress, unbanRecords } from './ban-dialog.js';
import { requestJson } from './security-api.js';
import { banState, errorMessage } from './security-model.js';
import { asnLine, kindLabel, kindNote, placeLine, placement, sourceLine } from './ip-info.js';

const html = htm.bind(h);

const pad = (n) => String(n).padStart(2, '0');
function stamp(ts) {
  const d = new Date(ts * 1000);
  return `${d.getMonth() + 1}/${d.getDate()} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

const chipClass = (v) => ({ '2xx': 's2', '3xx': 's3', '4xx': 's4', '5xx': 's5' }[v] || 'so');

const bansOn = () => typeof document !== 'undefined' && document.body?.dataset.bans === 'on';

function BanSection({ ip }) {
  const [look, setLook] = useState(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let live = true;
    requestJson('/api/bans?covering=' + encodeURIComponent(ip)).then(res => {
      if (live) setLook(res.ok ? res.body : { error: errorMessage(res.body, res.status) });
    });
    return () => { live = false; };
  }, [ip, tick]);
  if (!look) return null;
  if (look.error) return html`<div class="sect muted small">${look.error}</div>`;
  const s = banState(look);
  const refresh = (body) => { if (body) setTick(t => t + 1); };
  return html`
    <div class="sect ban-sect">
      ${s.banned && html`<span class="ban-badge"><${Icon} name="shield" size=${12} />Banned</span>`}
      ${s.coveredText && html`<span class="muted small">${s.coveredText}</span>`}
      ${s.protectedText && html`<span class="muted small">${s.protectedText}</span>`}
      ${s.canBan && html`<button class="btn sm" type="button" onClick=${async () => refresh(await banAddress(ip))}><${Icon} name="shield" size=${14} />Ban…</button>`}
      ${s.canUnban && html`<button class="btn sm" type="button" onClick=${async () => refresh(await unbanRecords(s.exact, ip))}>Unban</button>`}
    </div>`;
}

export function IpPopover({ ip, anchor, from, to, query, onQuery, onCopy, onClose }) {
  const [info, setInfo] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let live = true;
    setInfo(null); setError(null);
    const params = new URLSearchParams({ ip });
    if (from != null && to != null) {
      params.set('from', String(Math.floor(from)));
      params.set('to', String(Math.ceil(to)));
    }
    fetch('/api/explore/ip?' + params)
      .then(r => r.json().then(body => ({ ok: r.ok, body })))
      .then(({ ok, body }) => {
        if (!live) return;
        if (!ok || body.error) setError(body.error || 'Lookup failed');
        else setInfo(body);
      })
      .catch(e => live && setError(e.message));
    return () => { live = false; };
  }, [ip, from, to]);

  const only = (extra) => {
    let q = setTermState(query, 'client', ip, 'include');
    if (extra) q = setTermState(q, extra.key, extra.value, 'include');
    onQuery(q);
  };

  const seen = info?.seen;
  const place = placeLine(info?.location);
  const network = asnLine(info?.asn);

  const pos = anchor ? placement(anchor, { width: window.innerWidth, height: window.innerHeight }) : null;
  const style = pos ? Object.fromEntries(Object.entries(pos).map(([k, v]) => [k, v + 'px'])) : null;

  return html`
    <div class="pop ippop ip-pop" role="dialog" aria-label=${'About ' + ip} style=${style}>
      <div class="sect">
        <div class="k">${info ? kindLabel(info.kind) : 'IP address'}</div>
        <div class="ip"><span>${ip}</span>
          <button class="ibtn sm" type="button" title="Copy IP" aria-label="Copy IP" onClick=${() => onCopy(ip)}><${Icon} name="copy" size=${14} /></button></div>
      </div>
      ${error && html`<div class="sect ip-pop-error" role="alert">${error}</div>`}
      ${!info && !error && html`<div class="sect muted">Looking up…</div>`}
      ${info && info.kind !== 'public' && html`<div class="sect muted">${kindNote(info.kind)}</div>`}
      ${info && info.kind === 'public' && html`
        <div class="sect">
          <dl class="kv">
            <dt>Location</dt>
            <dd>${place ? html`<span class="cc">${info.location.country_code}</span> ${place}`
                        : html`<span class="muted">${info.source?.available ? 'Not in the database' : 'Unknown'}</span>`}</dd>
            <dt>Network</dt>
            <dd>${network || html`<span class="muted">${info.source?.available ? 'Not in the database' : 'Unknown'}</span>`}</dd>
          </dl>
        </div>`}
      ${seen && html`
        <div class="sect">
          <div class="k">In this range</div>
          ${seen.requests === 0
            ? html`<div class="muted">No requests from this IP in the range on screen.</div>`
            : html`
              <div><b>${seen.requests.toLocaleString()} ${seen.requests === 1 ? 'request' : 'requests'}</b>${seen.errors > 0 && html`, <span class="s5">${seen.errors.toLocaleString()} ${seen.errors === 1 ? 'is' : 'are'} 5xx</span>`}</div>
              <div class="muted small">First ${stamp(seen.first_ts)}, last ${stamp(seen.last_ts)}</div>
              <div class="chips">
                ${seen.status_classes.map(c => html`
                  <button class=${'schip ' + chipClass(c.value)} type="button" key=${c.value} title=${`Show ${c.value} from ${ip}`}
                          onClick=${() => only({ key: 'status', value: c.value })}>${c.value} ${c.count.toLocaleString()}</button>`)}
              </div>`}
        </div>
        ${seen.requests > 0 && (seen.hosts.length > 0 || seen.paths.length > 0) && html`
          <div class="sect toplist">
            ${[['host', 'Top hosts', seen.hosts, seen.host_count], ['path', 'Top paths', seen.paths, seen.path_count]]
              .filter(([, , list]) => list.length)
              .map(([key, title, list, count]) => html`
                <div key=${key}>
                  <span class="k">${title}${count > list.length ? `, ${list.length} of ${count}` : ''}</span>
                  <ol>${list.map(r => html`
                    <li key=${r.value}><button class="ip-row" type="button" title=${`Show ${key}:${r.value} from ${ip}`}
                        onClick=${() => only({ key, value: r.value })}><span>${r.value}</span><span>${r.count.toLocaleString()}</span></button></li>`)}</ol>
                </div>`)}
          </div>`}`}
      ${bansOn() && info && info.kind === 'public' && html`<${BanSection} ip=${ip} />`}
      <div class="sect acts">
        <button class="btn btn-primary sm" type="button" onClick=${() => only(null)}><${Icon} name="filter" size=${14} />Only this IP</button>
        <button class="btn sm" type="button" onClick=${() => onQuery(setTermState(query, 'client', ip, 'exclude'))}><${Icon} name="minus-circle" size=${14} />Exclude</button>
        <button class="btn sm btn-quiet ip-close" type="button" onClick=${() => onClose && onClose()}>Close</button>
      </div>
      ${info?.source && info.kind === 'public' && html`
        <div class="src">${info.source.available
          ? html`<a href=${info.source.url} target="_blank" rel="noopener noreferrer">${sourceLine(info.source)}</a>`
          : sourceLine(info.source)}</div>`}
    </div>`;
}
