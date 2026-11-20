// Top-level site blocks of a Caddyfile, by line: for "Open <site> block" on the
// dashboard and for naming the sites a diff touches. A brace counter, not a
// parser. Site addresses are always the first thing on a depth-0 line that opens
// a block, which is all this needs.

const count = (s, ch) => s.split(ch).length - 1;

/** "http://a.example.com:8443/x" -> "a.example.com"; ":8080" -> "". */
export function hostOf(address) {
  return String(address).toLowerCase()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
}

export function siteBlocks(text) {
  const blocks = [];
  let depth = 0;
  let current = null;
  String(text).split('\n').forEach((raw, i) => {
    const line = raw.replace(/(^|\s)#.*$/, '').trim();
    if (!line) return;
    // `{` alone opens the global options; `(name) {` opens a snippet.
    if (depth === 0 && line.endsWith('{') && line !== '{' && !line.startsWith('(')) {
      const addresses = line.slice(0, -1).split(/[\s,]+/).filter(Boolean);
      current = { addresses, hosts: addresses.map(hostOf).filter(Boolean), start: i + 1, end: i + 1 };
      blocks.push(current);
    }
    const bare = line.replace(/\{[^{}\s]*\}/g, '');   // placeholders are not blocks
    depth = Math.max(0, depth + count(bare, '{') - count(bare, '}'));
    if (current) current.end = i + 1;
    if (depth === 0) current = null;
  });
  return blocks;
}

export function findSiteBlockLine(text, host) {
  const want = String(host || '').toLowerCase();
  if (!want) return null;
  const blocks = siteBlocks(text);
  const exact = blocks.find(b => b.hosts.includes(want));
  if (exact) return exact.start;
  const wild = blocks.find(b => b.hosts.some((h) => {
    if (!h.startsWith('*.')) return false;
    const suffix = h.slice(1);
    const prefix = want.slice(0, want.length - suffix.length);
    return want.endsWith(suffix) && prefix !== '' && !prefix.includes('.');
  }));
  return wild ? wild.start : null;
}

export function sitesForLines(text, lineNumbers) {
  const blocks = siteBlocks(text);
  const out = [];
  for (const n of lineNumbers) {
    const b = blocks.find(x => n >= x.start && n <= x.end);
    const label = b && (b.hosts[0] || b.addresses[0]);
    if (label && !out.includes(label)) out.push(label);
  }
  return out;
}
