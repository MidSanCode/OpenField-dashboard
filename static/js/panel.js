// Confirmation for destructive forms, loaded as an external file so the panel
// needs no inline-script exemption in its Content-Security-Policy.
//
// This used to be an inline onsubmit="return confirm('... {{ value }} ...')" per
// form. Jinja escapes a quote in that context as &#39;, but the browser decodes
// attribute character references BEFORE compiling the handler as JavaScript, so
// the quote came back and closed the string literal. Any value that reached such
// a handler unvalidated — users.username is written from an identity provider's
// display name — became script running in the panel origin with access to the
// page's CSRF token.
//
// The message now travels in a data- attribute, where escaping happens in the
// HTML context and the value is never parsed as code. The text is read back with
// dataset, which yields the original characters with no entity decoding step
// that can reintroduce a quote.
document.addEventListener('submit', function (event) {
  var form = event.target;
  if (!form || !form.dataset || !form.dataset.confirm) {
    return;
  }
  if (!window.confirm(form.dataset.confirm)) {
    event.preventDefault();
  }
}, true);

// Submit a form when a select inside it changes, replacing the former inline
// onchange="this.form.submit()" so no inline handler is needed.
document.addEventListener('change', function (event) {
  var el = event.target;
  if (!el || !el.dataset || el.dataset.autosubmit === undefined) {
    return;
  }
  if (el.form) {
    el.form.submit();
  }
}, true);
