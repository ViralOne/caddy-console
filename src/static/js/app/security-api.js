// The one JSON request helper for everything the Security view sends.
//
// CSRF: csrf.js wraps window.fetch and adds the session token to every
// non-GET request, so this helper only has to be the single place requests go
// through. Importing csrf.js here makes that dependency explicit and keeps it
// true for any module that imports this one.
import './csrf.js';

/** Resolves to { ok, status, body } and never throws on an HTTP error. `ok` is
 * false for a non-2xx status and for a 2xx body that says `ok: false`. `body`
 * is null when the response was not JSON (a proxy error page, for example). */
export async function requestJson(url, method = 'GET', payload) {
  const opts = { method };
  if (payload !== undefined) {
    opts.headers = { 'Content-Type': 'application/json' };
    opts.body = JSON.stringify(payload);
  }
  const r = await fetch(url, opts);
  const body = await r.json().catch(() => null);
  return { ok: r.ok && body?.ok !== false, status: r.status, body };
}
