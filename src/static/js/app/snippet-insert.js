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

export function planSiteInsertion(text, cursorLine, code, { target, managementHosts = [], after = [], snippetName = null } = {}) {
  const lines = String(text).split('\n');
  const block = siteBlocks(text).find(b => cursorLine >= b.start && cursorLine <= b.end);
  if (!block) return { ok: false, reason: 'outside-site' };
  const mgmt = managementHosts.map(h => String(h).toLowerCase());
  if (block.hosts.some(h => mgmt.includes(h))) return { ok: false, reason: 'management-site', block };
  // Interior lines are block.start + 1 .. block.end - 1 (1-based); lines[] is 0-based.
  for (let n = block.start + 1; n <= block.end - 1; n++) {
    const m = stripComment(lines[n - 1]).match(/^import\s+(\S+)/);
    if (m && (snippetName ? m[1] === snippetName : importMatches(m[1], target))) return { ok: false, reason: 'duplicate', block, line: n };
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

/** The CrowdSec plugin's site import (spec 3.6): `import protect_crowdsec`, after any ban imports. */
export const PLUGIN_SNIPPET = 'protect_crowdsec';
export const PLUGIN_IMPORT_AFTER = ['manual', 'crowdsec'];

const count = (s, ch) => s.split(ch).length - 1;

/** Non-empty lines with the brace depth before each (placeholders are not blocks). */
function depthLines(text) {
  const out = [];
  let depth = 0;
  String(text).split('\n').forEach((raw, i) => {
    const line = stripComment(raw);
    if (!line) return;
    out.push({ n: i + 1, line, depth });
    const bare = line.replace(/\{[^{}\s]*\}/g, '');
    depth = Math.max(0, depth + count(bare, '{') - count(bare, '}'));
  });
  return out;
}

/** The global options block: the first top-level line when it is a bare `{`. */
export function globalOptionsBlock(text) {
  const lines = depthLines(text);
  if (!lines.length || lines[0].line !== '{') return null;
  // The block ends on the last line before the next top-level line (or at the end of the file).
  for (let i = 1; i < lines.length; i++) if (lines[i].depth === 0) return { start: lines[0].n, end: lines[i - 1].n };
  return { start: lines[0].n, end: lines[lines.length - 1].n };
}

/** Insert lines inside the global options, before its closing brace; create the block if there is none. */
export function planGlobalOptionInsertion(text, code) {
  const body = String(code).replace(/\n$/, '').split('\n');
  const g = globalOptionsBlock(text);
  if (!g) return { ok: true, line: 1, text: '{\n' + body.map(l => '\t' + l).join('\n') + '\n}\n\n' };
  const inner = depthLines(text).filter(l => l.n > g.start && l.n < g.end);
  const dup = inner.find(l => l.depth === 1 && /^crowdsec(\s|\{|$)/.test(l.line));
  if (dup) return { ok: false, reason: 'duplicate-global', line: dup.n };
  const lines = String(text).split('\n');
  const first = inner.find(l => l.depth === 1);
  const indent = (first && lines[first.n - 1].match(/^\s*/)[0]) || '\t';
  return { ok: true, line: g.end, text: body.map(l => indent + l).join('\n') + '\n' };
}

/** A top-level import, directly below the global options (or first in the file); never twice at top level. */
export function planTopLevelInsertion(text, code, { target } = {}) {
  const dup = depthLines(text).find((l) => {
    const m = l.depth === 0 && l.line.match(/^import\s+(\S+)/);
    return m && importMatches(m[1], target);
  });
  if (dup) return { ok: false, reason: 'duplicate', line: dup.n };
  const body = String(code).trim();
  const g = globalOptionsBlock(text);
  if (!g) return { ok: true, line: 1, text: body + '\n\n' };
  const lines = String(text).split('\n');
  if (g.end >= lines.length) return { ok: true, line: g.end + 1, text: '\n\n' + body, atEnd: true };
  return { ok: true, line: g.end + 1, text: '\n' + body + '\n' };
}

/** Why a plugin snippet cannot be inserted now, or null (spec 3.6 prerequisites). */
export function pluginGate(snippet, ctx) {
  if (!ctx) return 'plugin-unavailable';
  if (ctx.module === false) return 'plugin-module-missing';
  if (ctx.blocked) return 'plugin-blocked';
  if (snippet.insert === 'top-level' && !ctx.definition_current) return 'plugin-definition-stale';
  if (snippet.id === 'crowdsec-plugin-site') {
    if (!ctx.app_live) return 'plugin-app-missing';
    if (!ctx.definition_import || !ctx.definition_current) return 'plugin-definition-missing';
  }
  return null;
}
