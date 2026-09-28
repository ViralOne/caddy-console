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

/** Is `key:value` already in the query? Used to render facet checkboxes. */
export function hasTerm(query, key, value) {
  const wanted = term(key, value).toLowerCase();
  return tokenize(query).some(t => t.toLowerCase() === wanted);
}

/** Add the term if absent, remove it if present. */
export function toggleTerm(query, key, value) {
  const wanted = term(key, value).toLowerCase();
  const tokens = tokenize(query);
  const kept = tokens.filter(t => t.toLowerCase() !== wanted);
  if (kept.length !== tokens.length) return kept.map(requote).join(' ');
  return [...tokens.map(requote), term(key, value)].join(' ');
}

/** Drop every term for a key, e.g. when clearing a whole facet group. */
export function removeKey(query, key) {
  const prefix = key.toLowerCase() + ':';
  return tokenize(query)
    .filter(t => {
      const bare = t.startsWith('-') ? t.slice(1) : t;
      return !bare.toLowerCase().startsWith(prefix);
    })
    .map(requote)
    .join(' ');
}

// Tokenising strips quotes, so anything with whitespace needs them back before
// the query is reassembled.
function requote(token) {
  const negated = token.startsWith('-');
  const bare = negated ? token.slice(1) : token;
  const colon = bare.indexOf(':');
  const key = colon > 0 ? bare.slice(0, colon).toLowerCase() : '';
  if (!KEYS.includes(key)) return /\s/.test(token) ? `"${token}"` : token;
  return term(key, bare.slice(colon + 1), negated);
}

/** Which keys the query constrains — lets the UI show what is narrowing it. */
export function activeKeys(query) {
  const keys = new Set();
  for (const token of tokenize(query)) {
    const bare = token.startsWith('-') ? token.slice(1) : token;
    const colon = bare.indexOf(':');
    if (colon <= 0) continue;
    const key = bare.slice(0, colon).toLowerCase();
    if (KEYS.includes(key)) keys.add(key);
  }
  return keys;
}
