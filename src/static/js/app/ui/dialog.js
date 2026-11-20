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
