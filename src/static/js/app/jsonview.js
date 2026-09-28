// Pretty-printed, coloured JSON for the raw log line.
//
// A Caddy access entry on one line is ~350 characters of unbroken text, which is
// technically complete and practically unreadable. Indenting it and colouring the
// parts is the difference between "the data is there" and being able to read it.
//
// Colours come from tokens, and nodes are built as real text nodes rather than
// injected markup, so a log line can never smuggle HTML into the page.
import { h, htm } from '../explore-vendor.js';

const html = htm.bind(h);

// One pass over the formatted text: strings (a key if followed by a colon),
// numbers, and the three literals. Everything else is punctuation or whitespace.
const TOKEN = /"(?:[^"\\]|\\.)*"(\s*:)?|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|\b(?:true|false|null)\b/g;

function classOf(match, keyColon) {
  if (match.startsWith('"')) return keyColon ? 'jv-key' : 'jv-string';
  if (match === 'true' || match === 'false') return 'jv-bool';
  if (match === 'null') return 'jv-null';
  return 'jv-number';
}

function colourise(text) {
  const out = [];
  let last = 0;
  let m;
  TOKEN.lastIndex = 0;
  while ((m = TOKEN.exec(text)) !== null) {
    if (m.index > last) out.push(text.slice(last, m.index));
    out.push(html`<span class=${classOf(m[0], m[1])}>${m[0]}</span>`);
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

/** Format `text` as JSON if it is JSON, and show it as-is if it is not. */
export function JsonView({ text }) {
  if (!text) return null;
  let formatted = null;
  try {
    // Re-serialising preserves key order from the original document, so the
    // entry reads in the order Caddy wrote it.
    formatted = JSON.stringify(JSON.parse(text), null, 2);
  } catch (e) {
    // Not JSON — a truncated line, or a different log format. Show exactly what
    // is on disk rather than an error: the point of this view is the real bytes.
    return html`<pre class="stream-raw">${text}</pre>`;
  }
  return html`<pre class="stream-raw jv">${colourise(formatted)}</pre>`;
}
