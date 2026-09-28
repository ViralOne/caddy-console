// Stacked events-over-time histogram, hand-rolled SVG, no chart dependency.
//
// Colour comes only from the reserved status tokens, and the legend is always
// present, so status is never communicated by colour alone. The event stream
// below the chart is its table view.
import { h, htm, useRef, useState } from '../explore-vendor.js';

const html = htm.bind(h);

// Bottom to top: healthy at the base, failures on top, so a growing error band
// is visible against the flat edge of the chart rather than lost in the middle.
export const CLASSES = [
  { key: '2xx', label: '2xx', token: 'var(--status-good)' },
  { key: '3xx', label: '3xx', token: 'var(--accent)' },
  { key: '4xx', label: '4xx', token: 'var(--status-warn)' },
  { key: '5xx', label: '5xx', token: 'var(--status-critical)' },
  { key: 'other', label: 'other', token: 'var(--status-none)' },
];

const HEIGHT = 96;
const GAP = 2;  // surface gap between stacked segments

function formatTick(ts, bucketSeconds) {
  const d = new Date(ts * 1000);
  const pad = (n) => String(n).padStart(2, '0');
  if (bucketSeconds >= 86400) return `${d.getMonth() + 1}/${pad(d.getDate())}`;
  if (bucketSeconds >= 3600) return `${pad(d.getHours())}:00`;
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function formatSpan(seconds) {
  if (seconds >= 86400) return Math.round(seconds / 86400) + 'd';
  if (seconds >= 3600) return Math.round(seconds / 3600) + 'h';
  if (seconds >= 60) return Math.round(seconds / 60) + 'm';
  return Math.round(seconds) + 's';
}

export function Histogram({ histogram, total, onRange, loading, from, to }) {
  // Hover and drag live in state so the brush and highlight actually re-render;
  // a plain local variable would be reset on every render and paint nothing.
  const [hover, setHover] = useState(null);      // bucket index under the cursor
  const [drag, setDrag] = useState(null);         // {from, to}, for painting the brush
  const svgRef = useRef(null);
  // The drag is also tracked in a ref because state updates are asynchronous:
  // a pointerup arriving before the re-render would read a stale null from the
  // closure and silently discard the selection.
  const dragRef = useRef(null);

  const buckets = (histogram && histogram.buckets) || [];
  const width = histogram ? (histogram.bucket_seconds || 60) : 60;

  if (!buckets.length) {
    return html`
      <div class=${'hist' + (loading ? ' loading' : '')}>
        <div class="hist-empty">${loading ? 'Loading…' : 'No events in this range.'}</div>
      </div>`;
  }

  const peak = Math.max(...buckets.map(b => CLASSES.reduce((n, c) => n + (b[c.key] || 0), 0)));

  // Bars are placed by time, not by array index. Only buckets containing events
  // are sent, so indexing would stretch a single busy minute across a whole
  // 24h chart and hide when it actually happened.
  const spanFrom = from != null ? from : buckets[0].t;
  const spanTo = to != null ? to : buckets[buckets.length - 1].t + width;
  const span = Math.max(width, spanTo - spanFrom);
  const slotW = Math.max(0.35, (width / span) * 100);
  const xOf = (t) => ((t - spanFrom) / span) * 100;

  const tsAt = (ev) => {
    const box = (svgRef.current || ev.currentTarget).getBoundingClientRect();
    const frac = Math.min(1, Math.max(0, (ev.clientX - box.left) / box.width));
    return spanFrom + frac * span;
  };
  const bucketAt = (ts) => {
    let best = null;
    let bestGap = Infinity;
    for (let i = 0; i < buckets.length; i++) {
      const gap = Math.abs(buckets[i].t + width / 2 - ts);
      if (gap < bestGap) { bestGap = gap; best = i; }
    }
    // Only count as a hover if the cursor is actually near a bar, so empty
    // stretches of the chart don't latch onto a distant bucket.
    return bestGap <= Math.max(width, span / 100) ? best : null;
  };

  const onDown = (ev) => {
    const t = tsAt(ev);
    dragRef.current = { from: t, to: t };
    setDrag(dragRef.current);
    if (ev.currentTarget.setPointerCapture) ev.currentTarget.setPointerCapture(ev.pointerId);
  };
  const onMove = (ev) => {
    const t = tsAt(ev);
    if (dragRef.current) {
      dragRef.current = { from: dragRef.current.from, to: t };
      setDrag(dragRef.current);
    } else {
      setHover(bucketAt(t));
    }
  };
  const onUp = (ev) => {
    const started = dragRef.current;
    dragRef.current = null;
    if (!started) return;
    const end = tsAt(ev);
    let [a, b] = started.from <= end ? [started.from, end] : [end, started.from];
    setDrag(null);
    if (!onRange) return;
    // A click rather than a drag would be a zero-width range; widen it to one
    // bucket so a single click still selects something meaningful.
    if (b - a < width) b = a + width;
    onRange(Math.floor(a), Math.ceil(b));
  };
  const onLeave = () => { setHover(null); if (!dragRef.current) setDrag(null); };

  const ticks = [0, 0.5, 1].map(f => ({
    pct: f * 100,
    label: formatTick(spanFrom + f * span, width),
  }));

  const brush = drag && Math.abs(drag.to - drag.from) > 0
    ? { x: xOf(Math.min(drag.from, drag.to)), w: Math.abs(drag.to - drag.from) / span * 100 }
    : null;

  const hovered = hover != null ? buckets[hover] : null;
  const hoveredTotal = hovered ? CLASSES.reduce((n, c) => n + (hovered[c.key] || 0), 0) : 0;

  return html`
    <div class=${'hist' + (loading ? ' loading' : '')}>
      <div class="hist-head">
        <span class="hist-total">${(total || 0).toLocaleString()} events</span>
        ${loading && html`<span class="hist-loading">updating…</span>`}
        <span class="hist-legend">
          ${CLASSES.map(c => html`
            <span class="hist-legend-item">
              <span class="hist-swatch" style=${{ background: c.token }}></span>${c.label}
            </span>`)}
        </span>
      </div>

      <div class="hist-plot">
        <svg class=${'hist-svg' + (drag ? ' dragging' : '')} ref=${svgRef}
             viewBox=${`0 0 100 ${HEIGHT}`} preserveAspectRatio="none"
             onPointerDown=${onDown} onPointerMove=${onMove} onPointerUp=${onUp}
             onPointerLeave=${onLeave}>
          ${buckets.map((b, i) => {
            let y = HEIGHT;
            const dim = hover != null && hover !== i;
            return CLASSES.map(c => {
              const n = b[c.key] || 0;
              if (!n) return null;
              const hPx = (n / peak) * (HEIGHT - 4);
              y -= hPx;
              return html`<rect class=${'hist-bar' + (dim ? ' dim' : '')}
                x=${xOf(b.t) + slotW * 0.1} y=${y}
                width=${slotW * 0.8} height=${Math.max(0.5, hPx - GAP / 2)}
                fill=${c.token} />`;
            });
          })}
          ${hovered && html`<rect class="hist-hover-band"
            x=${xOf(hovered.t) - slotW * 0.35} y="0"
            width=${slotW * 1.7} height=${HEIGHT} />`}
          ${brush && html`<rect class="hist-brush" x=${brush.x} y="0"
            width=${Math.max(0.3, brush.w)} height=${HEIGHT} />`}
        </svg>

        ${hovered && !drag && html`
          <div class="hist-tip" style=${{ left: Math.min(88, Math.max(2, xOf(hovered.t))) + '%' }}>
            <div class="hist-tip-time">${formatTick(hovered.t, width)} · ${formatSpan(width)} bucket</div>
            ${CLASSES.filter(c => hovered[c.key]).map(c => html`
              <div class="hist-tip-row">
                <span class="hist-swatch" style=${{ background: c.token }}></span>
                <span class="hist-tip-label">${c.label}</span>
                <span class="hist-tip-count">${hovered[c.key].toLocaleString()}</span>
              </div>`)}
            <div class="hist-tip-row hist-tip-total">
              <span class="hist-tip-label">total</span>
              <span class="hist-tip-count">${hoveredTotal.toLocaleString()}</span>
            </div>
          </div>`}

        ${drag && html`
          <div class="hist-brush-label"
               style=${{ left: Math.min(80, Math.max(2, xOf(Math.min(drag.from, drag.to)))) + '%' }}>
            ${formatSpan(Math.abs(drag.to - drag.from))} selected — release to zoom
          </div>`}
      </div>

      <div class="hist-axis">
        ${ticks.map(t => html`<span class="hist-tick" style=${{ left: t.pct + '%' }}>${t.label}</span>`)}
      </div>
      <div class="hist-help">Drag across the chart to zoom into a range.</div>
    </div>`;
}
