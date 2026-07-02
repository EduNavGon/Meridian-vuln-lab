'use strict';

const express = require('express');
const router = express.Router();
const { requireAuth } = require('../session');
const { deepMerge } = require('../lib/deepmerge');

// Per-user preference blobs, kept in memory.
const store = new Map();

function defaults() {
  return {
    theme: 'light',
    notifications: { email: true, sms: false },
    dashboard: { density: 'comfortable', widgets: ['balance', 'activity'] }
  };
}

router.get('/', requireAuth, (req, res) => {
  const s = store.get(req.user.email) || defaults();
  res.json({ settings: s });
});

// POST /api/settings — apply a partial preferences patch on top of the current
// settings using a recursive merge.
router.post('/', requireAuth, (req, res) => {
  const current = store.get(req.user.email) || defaults();
  const merged = deepMerge(current, req.body || {});
  store.set(req.user.email, merged);
  res.json({ ok: true, settings: merged });
});

module.exports = router;
