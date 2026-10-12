// The popover behind a client IP in an expanded event: where the address is
// from, and what else it did in the range on screen.
//
// Every correlation row is a filter, so "this IP hit 3 hosts" is one click from
// seeing those requests — the popover never becomes a dead end beside the stream.
import { h, htm, useEffect, useState } from '../explore-vendor.js';
import { setTermState } from './explore-query.js';
import { Icon } from './icons.js';
import { asnLine, flagOf, kindLabel, kindNote, placeLine, placement, sourceLine } from './ip-info.js';

const html = htm.bind(h);

const pad = (n) => String(n).padStart(2, '0');
function stamp(ts) {
  const d = new Date(ts * 1000);
  return `${d.getMonth() + 1}/${d.getDate()} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function IpPopover({ ip, anchor, from, to, query, onQuery, onCopy }) {
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
    <div class="ip-pop" role="dialog" aria-label=${'About ' + ip} style=${style}>
      <div class="ip-pop-head">
        <div class="ip-pop-kind">${info ? kindLabel(info.kind) : 'IP address'}</div>
        <div class="ip-pop-ip">
          <span>${ip}</span>
          <button class="ip-pop-icon" title="Copy IP" aria-label="Copy IP"
                  onClick=${() => onCopy(ip)}><${Icon} name="copy" size=${14} /></button>
        </div>
      </div>

      ${error && html`<div class="ip-pop-section ip-pop-error">${error}</div>`}
      ${!info && !error && html`<div class="ip-pop-section ip-pop-muted">Looking up…</div>`}

      ${info && html`
        ${info.kind !== 'public' && html`
          <div class="ip-pop-section ip-pop-muted">${kindNote(info.kind)}</div>`}
        ${info.kind === 'public' && html`
          <div class="ip-pop-section">
            <div class="ip-pop-label">Location</div>
            <div class="ip-pop-value">
              ${place ? html`<span class="ip-pop-flag" aria-hidden="true">${flagOf(info.location.country_code)}</span>${place}`
                      : html`<span class="ip-pop-muted">${info.source?.available ? 'Not in the database' : 'Unknown'}</span>`}
            </div>
            <div class="ip-pop-label">Network</div>
            <div class="ip-pop-value">
              ${network || html`<span class="ip-pop-muted">${info.source?.available ? 'Not in the database' : 'Unknown'}</span>`}
            </div>
          </div>`}

        ${seen && html`
          <div class="ip-pop-section">
            <div class="ip-pop-label">In this range</div>
            ${seen.requests === 0
              ? html`<div class="ip-pop-muted">No requests from this IP in the range on screen.</div>`
              : html`
                <div class="ip-pop-value">
                  <b>${seen.requests.toLocaleString()}</b> request${seen.requests === 1 ? '' : 's'}
                  ${seen.errors > 0 && html` · <span class="tone-critical">${seen.errors.toLocaleString()} 5xx</span>`}
                </div>
                <div class="ip-pop-muted ip-pop-small">${stamp(seen.first_ts)} → ${stamp(seen.last_ts)}</div>
                <div class="ip-pop-chips">
                  ${seen.status_classes.map(c => html`
                    <button class=${'ip-pop-chip tone-' + (c.value === '5xx' ? 'critical' : c.value === '4xx' ? 'warn' : c.value === '2xx' ? 'good' : 'accent')}
                            title=${`Show ${c.value} from ${ip}`}
                            onClick=${() => only({ key: 'status', value: c.value })}>
                      ${c.value} <span>${c.count.toLocaleString()}</span>
                    </button>`)}
                </div>`}
          </div>
          ${[['host', 'Hosts', seen.hosts, seen.host_count], ['path', 'Paths', seen.paths, seen.path_count]]
            .filter(([, , rows]) => rows.length)
            .map(([key, title, rows, count]) => html`
              <div class="ip-pop-section ip-pop-list" key=${key}>
                <div class="ip-pop-label">${title}${count > rows.length ? ` · top ${rows.length} of ${count}` : ''}</div>
                ${rows.map(r => html`
                  <button class="ip-pop-row" key=${r.value} title=${`Show ${key}:${r.value} from ${ip}`}
                          onClick=${() => only({ key, value: r.value })}>
                    <span class="ip-pop-row-value">${r.value}</span>
                    <span class="ip-pop-row-count">${r.count.toLocaleString()}</span>
                  </button>`)}
              </div>`)}`}
      `}

      <div class="ip-pop-actions">
        <button class="btn btn-primary btn-sm" onClick=${() => only(null)}>
          <${Icon} name="filter" size=${14} />Only this IP
        </button>
        <button class="btn btn-secondary btn-sm"
                onClick=${() => onQuery(setTermState(query, 'client', ip, 'exclude'))}>
          <${Icon} name="box-x" size=${14} />Exclude
        </button>
      </div>
      ${info?.source && info.kind === 'public' && html`
        <div class="ip-pop-foot">
          ${info.source.available
            ? html`<a href=${info.source.url} target="_blank" rel="noopener noreferrer">${sourceLine(info.source)}</a>`
            : sourceLine(info.source)}
        </div>`}
    </div>`;
}
