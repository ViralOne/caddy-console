// The one JSON request helper for everything the Security view sends.
//
// CSRF: csrf.js wraps window.fetch and adds the session token to every
// non-GET request (main.js imports it before anything runs), so this helper only
// has to be the single place requests go through. It stays DOM-free so node can
// test it with a stubbed fetch.

/** Resolves to { ok, status, body } and never throws: a network failure resolves to status 0 with a null body. `ok` is
 * false for a non-2xx status and for a 2xx body that says `ok: false`. `body`
 * is null when the response was not JSON (a proxy error page, for example). */
export async function requestJson(url, method = 'GET', payload) {
  const opts = { method };
  if (payload !== undefined) {
    opts.headers = { 'Content-Type': 'application/json' };
    opts.body = JSON.stringify(payload);
  }
  let r;
  try { r = await fetch(url, opts); } catch (e) { return { ok: false, status: 0, body: null }; }
  const body = await r.json().catch(() => null);
  return { ok: r.ok && body?.ok !== false, status: r.status, body };
}
