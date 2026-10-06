// The query string is the single source of truth for the Explore view: clicking
// a facet edits the query rather than holding separate state, so what you see in
// the search box always explains what you are looking at.
//
// Pure functions only — no DOM, no fetch — so they are unit-testable directly.

const KEYS = ['host', 'status', 'method', 'path'];

/** Split on whitespace, keeping "quoted values" together. Mirrors the server. */
export function tokenize(query) {
  const out = [];
  let buf = '';
  let quoted = false;
  for (const ch of query || '') {
    if (ch === '"') quoted = !quoted;
    else if (/\s/.test(ch) && !quoted) { if (buf) { out.push(buf); buf = ''; } }
    else buf += ch;
  }
  if (buf) out.push(buf);
  return out;
}

/** A token needs quoting when it would otherwise split or be misread. */
function quoteValue(value) {
  return /[\s"]/.test(value) ? `"${value.replace(/"/g, '')}"` : value;
}

export function term(key, value, negated = false) {
  return `${negated ? '-' : ''}${key}:${quoteValue(value)}`;
}

/** A token as the server reads it: a known `key:value`, or free text.
 *
 * Compares parsed values, not rendered strings: tokenising strips the quotes, so
 * `path:"/a b"` would never match the `/a b` it was built from.
 */
function parseToken(token) {
  const negated = token.startsWith('-') && token.length > 1;
  const bare = negated ? token.slice(1) : token;
  const colon = bare.indexOf(':');
  if (colon <= 0) return { key: '', value: token, negated: false };
  const key = bare.slice(0, colon).toLowerCase();
  if (!KEYS.includes(key)) return { key: '', value: token, negated: false };
  return { key, value: bare.slice(colon + 1), negated };
}

function isSameTerm(token, key, value) {
  const p = parseToken(token);
  return p.key === key.toLowerCase() && p.value.toLowerCase() === value.toLowerCase();
}

/** How the query treats `key:value`: 'off', 'include' or 'exclude'. */
export function termState(query, key, value) {
  for (const token of tokenize(query)) {
    if (isSameTerm(token, key, value)) return parseToken(token).negated ? 'exclude' : 'include';
  }
  return 'off';
}

/** Is `key:value` an active positive filter? */
export function hasTerm(query, key, value) {
  return termState(query, key, value) === 'include';
}

/** Put `key:value` into `state`, replacing whichever polarity is there now.
 *
 * Rewritten in place rather than stacked: `host:a -host:a` would match nothing.
 */
export function setTermState(query, key, value, state) {
  const next = state === 'include' ? term(key, value)
    : state === 'exclude' ? term(key, value, true)
      : null;
  const out = [];
  let placed = false;
  for (const token of tokenize(query)) {
    if (isSameTerm(token, key, value)) {
      // In place, so cycling a facet does not shuffle the query under the cursor.
      if (next && !placed) { out.push(next); placed = true; }
      continue;
    }
    out.push(requote(token));
  }
  if (next && !placed) out.push(next);
  return out.join(' ');
}

const NEXT_STATE = { off: 'include', include: 'off', exclude: 'off' };

/** One click on a facet row: a plain include toggle, and clear from excluded.
 *
 * Deliberately not a three-way cycle. Clearing a filter is far more common than
 * inverting one, and routing it through `exclude` meant a wasted fetch showing
 * the inverse of what you were reading. Exclude has its own control instead.
 */
export function cycleTerm(query, key, value) {
  return setTermState(query, key, value, NEXT_STATE[termState(query, key, value)]);
}

/** Drop every term for a key, e.g. when clearing a whole facet group. */
export function removeKey(query, key) {
  const wanted = key.toLowerCase();
  return tokenize(query)
    .filter(t => parseToken(t).key !== wanted)
    .map(requote)
    .join(' ');
}

// Tokenising strips quotes, so anything with whitespace needs them back before
// the query is reassembled.
function requote(token) {
  const p = parseToken(token);
  if (!p.key) return /\s/.test(token) ? `"${token}"` : token;
  return term(p.key, p.value, p.negated);
}

/** The example query for an empty search box, built from the window on screen.
 *
 * Derived rather than fixed so the example would actually return rows, and so no
 * real hostname is baked into a public repo.
 */
export function placeholderFor(data) {
  const hosts = (data && data.facets && data.facets.host) || [];
  const busiest = hosts.find(v => v && v.value);
  const host = busiest ? term('host', busiest.value) : 'host:…';
  return `${host} -status:2xx  —  or any text`;
}

/** Which keys the query constrains — lets the UI show what is narrowing it. */
export function activeKeys(query) {
  const keys = new Set();
  for (const token of tokenize(query)) {
    const { key } = parseToken(token);
    if (key) keys.add(key);
  }
  return keys;
}
