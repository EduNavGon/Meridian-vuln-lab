'use strict';

// Renders a user-supplied receipt/e-mail template. Placeholders written as
// ${ ... } are interpolated against the provided data object. The template is
// compiled into a JS template literal and evaluated, so any expression inside
// ${ ... } is executed server-side (SSTI sink).
function renderTemplate(template, data) {
  const fn = new Function('data', 'with (data) { return `' + template + '`; }');
  return fn(data || {});
}

module.exports = { renderTemplate };
