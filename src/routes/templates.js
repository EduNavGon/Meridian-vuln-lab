'use strict';

const express = require('express');
const router = express.Router();
const { requireAuth } = require('../session');
const { renderTemplate } = require('../lib/template');

// POST /api/templates/preview  { template }
// Preview a custom receipt/e-mail template. Placeholders ${ ... } are rendered
// against the caller's data. The template is evaluated server-side (SSTI sink).
router.post('/preview', requireAuth, (req, res) => {
  const template = req.body && req.body.template;
  if (typeof template !== 'string') return res.status(400).json({ error: 'template (string) required' });

  const data = {
    user: req.user.name,
    company: 'Meridian Ledger',
    amount: 4200.0,
    date: new Date().toISOString().slice(0, 10)
  };

  try {
    const rendered = renderTemplate(template, data);
    res.json({ ok: true, rendered: String(rendered) });
  } catch (e) {
    res.status(400).json({ error: 'template render error', detail: e.message });
  }
});

module.exports = router;
