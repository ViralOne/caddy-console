// Fetch wrapper: attach the session CSRF token to every state-changing request
// and handle an expired session in one place.
// Must load before any other script that issues a fetch.
const CSRF_TOKEN = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
const _origFetch = window.fetch.bind(window);
let _sessionExpired = false;

window.fetch = async (url, opts = {}) => {
  const method = (opts.method || 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD') {
    // Normalise through Headers so a caller passing a Headers instance (whose
    // entries Object.assign would silently drop) keeps its headers.
    const headers = new Headers(opts.headers || {});
    headers.set('X-CSRF-Token', CSRF_TOKEN);
    opts = { ...opts, headers };
  }
  const res = await _origFetch(url, opts);
  if (res.status === 401 && typeof url === 'string' && url.startsWith('/api/') && !_sessionExpired) {
    // Every API call would otherwise fail in its own confusing way ("config is
    // invalid: undefined"). Stop background polling, tell the user, go sign in.
    _sessionExpired = true;
    if (typeof stopLogs === 'function') stopLogs();
    if (typeof setStatus === 'function') { setStatus('Session expired — sign in again', 'err'); setDot('red'); }
    alert('Your session has expired. Sign in again to continue.\n\nIf you have unsaved changes, copy them somewhere first.');
    window.location.href = '/welcome';
  }
  return res;
};
