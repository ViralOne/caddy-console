// Validation warnings arrive as plain strings, many as "Line N: …". Parsed here
// so the strip can link the line, and so Save can tell a cosmetic warning
// ("not formatted", fixed by the save itself) from one worth confirming.

const LINE_RE = /^Line (\d+):\s*/;

export function parseWarning(text) {
  const m = LINE_RE.exec(text);
  const rest = m ? text.slice(m[0].length) : text;
  const kind = /^not formatted\b/.test(rest) ? 'fmt'
    : /could not be resolved from the console container/.test(rest) ? 'dns' : 'other';
  return { line: m ? Number(m[1]) : null, text: rest.charAt(0).toUpperCase() + rest.slice(1), kind };
}

/** The warnings that should make Save ask first: everything but "not formatted". */
export function withoutFormat(list) {
  return (list || []).filter(w => parseWarning(w).kind !== 'fmt');
}
