// Formatting for the IP popover. Pure functions, so tests import them directly.

const KIND_LABELS = {
  public: 'Public IP',
  private: 'Private network',
  loopback: 'Loopback',
  'link-local': 'Link-local',
  cgnat: 'Carrier-grade NAT',
  multicast: 'Multicast',
  reserved: 'Reserved range',
};

export function kindLabel(kind) {
  return KIND_LABELS[kind] || 'IP address';
}

/** Why a non-public address has no location, in words a reader can act on. */
export function kindNote(kind) {
  if (kind === 'private') return 'A LAN or container address — the request came from inside your network, or a proxy in front of Caddy is not passing the real client IP.';
  if (kind === 'loopback') return 'This machine. Usually a health check or a local proxy.';
  if (kind === 'cgnat') return 'Shared carrier address (100.64/10), e.g. Tailscale or a mobile ISP — not locatable.';
  if (kind === 'link-local' || kind === 'multicast' || kind === 'reserved') return 'Not routable on the internet, so it has no location.';
  return '';
}

/** Regional-indicator flag for an ISO 3166 alpha-2 code; '' for anything else. */
export function flagOf(code) {
  if (!/^[A-Za-z]{2}$/.test(code || '')) return '';
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1f1a5 + c.charCodeAt(0)));
}

/** "Oakland, California, United States", skipping parts that are missing or repeated. */
export function placeLine(location) {
  if (!location) return '';
  const parts = [];
  for (const p of [location.city, location.region, location.country]) {
    if (p && !parts.includes(p)) parts.push(p);
  }
  return parts.join(', ');
}

export function asnLine(asn) {
  if (!asn || (!asn.number && !asn.org)) return '';
  return [asn.number ? `AS${asn.number}` : '', asn.org || ''].filter(Boolean).join(' · ');
}

/** The footer line about where the data came from, or why there is none. */
export function sourceLine(source) {
  if (!source) return '';
  if (source.available) return `IP data by ${source.name}${source.version ? ' · ' + source.version : ''}`;
  if (source.downloading) return 'Downloading the IP database…';
  if (source.last_error) return `IP database download failed: ${source.last_error}`;
  return 'No IP database yet — see "IP location" in docs/setup.md';
}

// Fixed to the viewport rather than absolute in the row: the stream is a scroll
// container, and would clip a 400px popover opened near either edge.
const WIDTH = 340;
const GAP = 4;
const MARGIN = 8;

/** Below the anchor if it fits, else whichever side has more room. */
export function placement(anchor, viewport) {
  const below = viewport.height - anchor.bottom - GAP - MARGIN;
  const above = anchor.top - GAP - MARGIN;
  const left = Math.max(MARGIN, Math.min(anchor.left, viewport.width - WIDTH - MARGIN));
  if (below >= 420 || below >= above) return { left, top: anchor.bottom + GAP, maxHeight: below };
  return { left, bottom: viewport.height - anchor.top + GAP, maxHeight: above };
}
