// In-design replacements for alert() and confirm(), on the native <dialog>.
//
// showModal() gives focus containment, an inert page behind and Esc-to-cancel
// for free. Each call builds its own dialog and removes it when done, so two
// flows can never fight over one shared element.

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text) e.textContent = text;
  return e;
}

function build({ title, body, detail }) {
  const d = el('dialog');
  const id = 'dlg-' + Math.random().toString(36).slice(2, 9);
  d.setAttribute('aria-labelledby', id + '-h');
  const hd = el('div', 'dlg-hd');
  const h = el('h2', '', title);
  h.id = id + '-h';
  hd.append(h);
  if (body) hd.append(el('p', '', body));
  d.append(hd);
  if (detail) {
    const bd = el('div', 'dlg-bd');
    bd.append(el('pre', 'dlg-detail', detail));
    d.append(bd);
  }
  const ft = el('div', 'dlg-ft');
  d.append(ft);
  return { d, ft };
}

function button(label, cls) {
  const b = el('button', 'btn ' + cls, label);
  b.type = 'button';
  return b;
}

function show(d, focusEl, wire, cancelValue) {
  const opener = document.activeElement;
  document.body.append(d);
  return new Promise((resolve) => {
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      if (d.open) d.close();
      d.remove();
      if (opener && typeof opener.focus === 'function' && opener.isConnected) opener.focus();
      resolve(value);
    };
    wire(finish);
    d.addEventListener('cancel', (e) => { e.preventDefault(); finish(cancelValue); });
    // Any other close path (form method=dialog, d.close() elsewhere) must not leave the promise pending.
    d.addEventListener('close', () => finish(cancelValue));
    d.showModal();
    focusEl.focus();
  });
}

export function confirmDialog({ title, body = '', detail = null, confirmLabel = 'OK', cancelLabel = 'Cancel', danger = false }) {
  const { d, ft } = build({ title, body, detail });
  const cancel = button(cancelLabel, 'btn-quiet');
  const ok = button(confirmLabel, danger ? 'btn-danger-solid' : 'btn-primary');
  ft.append(cancel, ok);
  // A destructive default would turn a stray Enter into data loss.
  return show(d, danger ? cancel : ok, (finish) => {
    ok.addEventListener('click', () => finish(true));
    cancel.addEventListener('click', () => finish(false));
  }, false);
}

export function alertDialog({ title, body = '', detail = null, okLabel = 'OK' }) {
  const { d, ft } = build({ title, body, detail });
  const ok = button(okLabel, 'btn-primary');
  ft.append(ok);
  return show(d, ok, (finish) => { ok.addEventListener('click', () => finish(undefined)); }, undefined);
}

/** A small form in a dialog. Resolves to {name: value} on confirm, or null.
 *  `validate(values)` returns an error message to show, or null to accept. */
export function formDialog({ title, body = '', fields, confirmLabel = 'OK', cancelLabel = 'Cancel', danger = false, validate = null }) {
  const { d, ft } = build({ title, body });
  const bd = el('div', 'dlg-bd dlg-form');
  const inputs = {};
  for (const f of fields) {
    const id = 'fld-' + Math.random().toString(36).slice(2, 9);
    const label = el('label', 'dlg-label', f.label);
    label.htmlFor = id;
    let input;
    if (f.type === 'select') {
      input = el('select');
      for (const o of f.options) {
        const opt = el('option', '', o.label);
        opt.value = o.value;
        input.append(opt);
      }
    } else if (f.type === 'textarea') {
      input = el('textarea');
      input.rows = 3;
    } else {
      input = el('input');
      input.type = 'text';
      input.spellcheck = false;
      input.autocomplete = 'off';
    }
    input.id = id;
    input.name = f.name;
    if (f.value != null) input.value = f.value;
    inputs[f.name] = input;
    bd.append(label, input);
    if (f.hint) bd.append(el('p', 'dlg-hint', f.hint));
  }
  const error = el('p', 'dlg-error');
  error.setAttribute('role', 'alert');
  error.hidden = true;
  bd.append(error);
  d.insertBefore(bd, ft);
  const cancel = button(cancelLabel, 'btn-quiet');
  const ok = button(confirmLabel, danger ? 'btn-danger-solid' : 'btn-primary');
  ft.append(cancel, ok);
  return show(d, inputs[fields[0].name], (finish) => {
    const submit = () => {
      const values = Object.fromEntries(Object.entries(inputs).map(([k, v]) => [k, v.value]));
      const problem = validate ? validate(values) : null;
      if (problem) { error.textContent = problem; error.hidden = false; return; }
      finish(values);
    };
    ok.addEventListener('click', submit);
    cancel.addEventListener('click', () => finish(null));
    d.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && e.target.tagName === 'INPUT') { e.preventDefault(); submit(); }
    });
  }, null);
}
