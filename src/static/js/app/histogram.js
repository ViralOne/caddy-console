// Stacked events-over-time histogram, hand-rolled SVG, no chart dependency.
//
// Colour comes only from the reserved status tokens, and the legend is always
// present, so status is never communicated by colour alone. The event stream
// below the chart is its table view.
import { h, htm } from '../explore-vendor.js';

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

export function Histogram({ histogram, total, onRange, loading, from, to }) {
  const buckets = (histogram && histogram.buckets) || [];
  const width = histogram ? (histogram.bucket_seconds || 60) : 60;

  if (!buckets.length) {
    return html`<div class="hist-empty">${loading ? 'Loading…' : 'No events in this range.'}</div>`;
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

  // Drag across the chart to narrow the range. Pointer events rather than mouse
  // so it works on a trackpad and a touchscreen alike.
  let dragFrom = null;
  const tsAt = (ev) => {
    const box = ev.currentTarget.getBoundingClientRect();
    const frac = Math.min(1, Math.max(0, (ev.clientX - box.left) / box.width));
    return spanFrom + frac * span;
  };
  const onDown = (ev) => { dragFrom = tsAt(ev); ev.currentTarget.setPointerCapture(ev.pointerId); };
  const onUp = (ev) => {
    if (dragFrom === null || !onRange) return;
    const end = tsAt(ev);
    let [a, b] = dragFrom <= end ? [dragFrom, end] : [end, dragFrom];
    dragFrom = null;
    // A click rather than a drag would be a zero-width range; widen it to one
    // bucket so a single click still selects something meaningful.
    if (b - a < width) b = a + width;
    onRange(Math.floor(a), Math.ceil(b));
  };

  const ticks = [0, 0.5, 1].map(f => ({
    pct: f * 100,
    label: formatTick(spanFrom + f * span, width),
  }));

  return html`
    <div class="hist">
      <div class="hist-head">
        <span class="hist-total">${(total || 0).toLocaleString()} events</span>
        <span class="hist-legend">
          ${CLASSES.map(c => html`
            <span class="hist-legend-item">
              <span class="hist-swatch" style=${{ background: c.token }}></span>${c.label}
            </span>`)}
        </span>
      </div>
      <svg class="hist-svg" viewBox=${`0 0 100 ${HEIGHT}`} preserveAspectRatio="none"
           onPointerDown=${onDown} onPointerUp=${onUp}>
        ${buckets.map((b, i) => {
          const totalHere = CLASSES.reduce((n, c) => n + (b[c.key] || 0), 0);
          let y = HEIGHT;
          return CLASSES.map(c => {
            const n = b[c.key] || 0;
            if (!n) return null;
            const hPx = (n / peak) * (HEIGHT - 4);
            y -= hPx;
            const rect = html`<rect x=${xOf(b.t) + slotW * 0.1} y=${y}
              width=${slotW * 0.8} height=${Math.max(0.5, hPx - GAP / 2)}
              fill=${c.token}><title>${formatTick(b.t, width)} · ${c.label} ${n.toLocaleString()} of ${totalHere.toLocaleString()}</title></rect>`;
            return rect;
          });
        })}
      </svg>
      <div class="hist-axis">
        ${ticks.map(t => html`<span class="hist-tick" style=${{ left: t.pct + '%' }}>${t.label}</span>`)}
      </div>
    </div>`;
}
