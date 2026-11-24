// Where a site-scoped snippet goes: first inside the site block under the
// cursor, never twice, never into the console's own site. Pure, so node can
// test it; panels.js applies the plan to the editor buffer only.
import { siteBlocks } from './caddyfile-sites.js';

/** Caddy/Go glob semantics: `*` and `?` never cross a `/`. */
export function globToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') re += '[^/]*';
    else if (c === '?') re += '[^/]';
    else if (c === '[' && glob.indexOf(']', i + 1) > i) { const end = glob.indexOf(']', i + 1); re += glob.slice(i, end + 1); i = end; }
    else re += c.replace(/[.+^${}()|\\\]]/g, '\\$&');
  }
  return new RegExp('^' + re + '$');
}

export function importMatches(token, target) {
  if (!token) return false;
  if (token.startsWith('/')) return globToRegExp(token).test(target);
  if (!token.includes('/') && !token.includes('.')) return false;   // a snippet or named-route name
  const base = (p) => p.slice(p.lastIndexOf('/') + 1);
  return globToRegExp(base(token)).test(base(target));             // relative: Caddy's cwd is unknown
}

/** Mirrors render.AFTER in src/bans/render.py: the CrowdSec import may follow the manual one. */
export const IMPORT_AFTER = { crowdsec: ['manual'] };
export const SOURCE_FILES = { manual: 'bans-manual.caddy', crowdsec: 'bans-crowdsec.caddy' };

const stripComment = (raw) => String(raw ?? '').replace(/(^|\s)#.*$/, '').trim();

export function planSiteInsertion(text, cursorLine, code, { target, managementHosts = [], after = [] } = {}) {
  const lines = String(text).split('\n');
  const block = siteBlocks(text).find(b => cursorLine >= b.start && cursorLine <= b.end);
  if (!block) return { ok: false, reason: 'outside-site' };
  const mgmt = managementHosts.map(h => String(h).toLowerCase());
  if (block.hosts.some(h => mgmt.includes(h))) return { ok: false, reason: 'management-site', block };
  // Interior lines are block.start + 1 .. block.end - 1 (1-based); lines[] is 0-based.
  for (let n = block.start + 1; n <= block.end - 1; n++) {
    const m = stripComment(lines[n - 1]).match(/^import\s+(\S+)/);
    if (m && importMatches(m[1], target)) return { ok: false, reason: 'duplicate', block, line: n };
  }
  // `after`: managed imports that may lead the block (the CrowdSec import goes
  // directly after the manual one). Skip a leading run of them, if any.
  const kids = [];
  for (let n = block.start + 1; n <= block.end - 1; n++) if (stripComment(lines[n - 1])) kids.push(n);
  const leadsAfter = (n) => {
    const m = stripComment(lines[n - 1]).match(/^import\s+(\S+)/);
    return !!m && after.some(t => importMatches(m[1], t));
  };
  let lead = 0;
  while (lead < kids.length && leadsAfter(kids[lead])) lead++;
  if (lead > 0) {
    const prev = kids[lead - 1];
    const indent = lines[prev - 1].match(/^\s*/)[0];
    return { ok: true, block, line: prev + 1, text: indent + String(code).trim() + '\n' };
  }
  const firstChild = lines.slice(block.start, block.end - 1).find(l => stripComment(l));
  const indent = (firstChild && firstChild.match(/^\s*/)[0]) || '\t';
  const body = indent + String(code).trim();
  // The opening line is the last line of the buffer: there is no line below to insert before.
  if (block.start >= lines.length) return { ok: true, block, line: block.start + 1, text: '\n' + body, atEnd: true };
  return { ok: true, block, line: block.start + 1, text: body + '\n' };
}
