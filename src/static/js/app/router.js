// Path-based views, so each one is linkable and the back button works.
//
//   /          dashboard (site health)
//   /editor    the Caddyfile editor
//   /explore   log explorer — its full state lives in the query string
//
// Flask serves the same document for all three; this decides what to show.
// Explore keeps its state in the URL rather than in component state alone, so a
// pasted link reproduces exactly what the sender was looking at, timestamps
// included.

const VIEWS = ['dashboard', 'editor', 'explore'];
const PATHS = { dashboard: '/', editor: '/editor', explore: '/explore' };

export function viewFromPath(pathname = location.pathname) {
  const clean = (pathname || '/').replace(/\/+$/, '') || '/';
  if (clean === '/editor') return 'editor';
  if (clean === '/explore') return 'explore';
  return 'dashboard';
}

export function pathFor(view) {
  return PATHS[VIEWS.includes(view) ? view : 'dashboard'];
}

/** Navigate without reloading. `search` replaces the query string wholesale. */
export function navigate(view, search = '', { replace = false } = {}) {
  const url = pathFor(view) + (search ? (search.startsWith('?') ? search : '?' + search) : '');
  if (url === location.pathname + location.search) return;
  history[replace ? 'replaceState' : 'pushState']({ view }, '', url);
}

/** Update only the query string of the current view, without a history entry.
 *
 * Used while typing in Explore: every keystroke would otherwise add a back-button
 * step, making Back feel broken.
 */
export function replaceSearch(search) {
  const url = location.pathname + (search ? '?' + search : '');
  if (url === location.pathname + location.search) return;
  history.replaceState(history.state, '', url);
}

export function onNavigate(handler) {
  window.addEventListener('popstate', () => handler(viewFromPath()));
}

/** Intercept in-app links so they route instead of reloading the page. */
export function interceptLinks(handler) {
  document.addEventListener('click', (e) => {
    const a = e.target.closest('a[data-view]');
    if (!a || e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
    e.preventDefault();
    const url = new URL(a.getAttribute('href'), location.origin);
    history.pushState({}, '', url.pathname + url.search);
    handler(viewFromPath(url.pathname));
  });
}

// --- Explore state <-> query string ---------------------------------------
//
// Only non-default values are written, so a plain /explore stays clean and a
// shared link carries just what differs.

const DEFAULTS = { q: '', range: '24h', windowMb: 10, from: null, to: null, live: false };

export function exploreStateFromSearch(search = location.search) {
  const p = new URLSearchParams(search);
  const num = (key) => {
    const v = parseFloat(p.get(key));
    return Number.isFinite(v) ? v : null;
  };
  const windowMb = parseInt(p.get('window'), 10);
  const from = num('from');
  const to = num('to');
  return {
    q: p.get('q') || DEFAULTS.q,
    range: p.get('range') || DEFAULTS.range,
    windowMb: [10, 25, 50, 100].includes(windowMb) ? windowMb : DEFAULTS.windowMb,
    // A pinned absolute range needs both ends to be meaningful.
    custom: from !== null && to !== null ? { from, to } : null,
    live: p.get('live') === '1',
  };
}

export function exploreStateToSearch({ q, range, windowMb, custom, live }) {
  const p = new URLSearchParams();
  if (q) p.set('q', q);
  if (custom) {
    // An absolute range is what makes a link reproducible; `range` would drift.
    p.set('from', String(Math.floor(custom.from)));
    p.set('to', String(Math.ceil(custom.to)));
  } else if (range && range !== DEFAULTS.range) {
    p.set('range', range);
  }
  if (windowMb && windowMb !== DEFAULTS.windowMb) p.set('window', String(windowMb));
  if (live) p.set('live', '1');
  return p.toString();
}
