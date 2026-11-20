// Where the histogram's time labels go, and how the keyboard moves its readout.
// Pure, so the placement that used to clip at the edges is pinned by tests.
const pad = (n) => String(n).padStart(2, '0');

export function formatTick(ts, bucketSeconds) {
  const d = new Date(ts * 1000);
  if (bucketSeconds >= 86400) return `${d.getMonth() + 1}/${pad(d.getDate())}`;
  if (bucketSeconds >= 3600) return `${pad(d.getHours())}:00`;
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function formatSpan(seconds) {
  if (seconds >= 86400) return Math.round(seconds / 86400) + 'd';
  if (seconds >= 3600) return Math.round(seconds / 3600) + 'h';
  if (seconds >= 60) return Math.round(seconds / 60) + 'm';
  return Math.round(seconds) + 's';
}

/** Evenly spaced labels inside the plot: first left-aligned, last right-aligned. */
export function axisTicks({ from, to, bucketSeconds, now = Date.now() / 1000, count = 5 }) {
  const span = Math.max(1, to - from);
  const live = Math.abs(now - to) <= Math.max(60, bucketSeconds);
  return Array.from({ length: count }, (_, i) => {
    const f = count === 1 ? 1 : i / (count - 1);
    let label = formatTick(from + f * span, bucketSeconds);
    if (i === count - 1 && live) label = `now, ${label}`;
    return { pct: f * 100, label, align: i === 0 ? 'start' : i === count - 1 ? 'end' : 'middle' };
  });
}

/** Arrow-key stepping over buckets; from nothing, start at the newest. */
export function stepIndex(current, delta, length) {
  if (!length) return null;
  if (current == null) return length - 1;
  return Math.min(length - 1, Math.max(0, current + delta));
}
