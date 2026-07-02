'use strict';

const express = require('express');
const router = express.Router();
const { requireAuth } = require('../session');
const { serialize, unserialize } = require('../lib/unserialize');

// GET /api/session/export — export the caller's current workspace state as a
// portable, base64-encoded blob (used by "move workspace between environments").
router.get('/export', requireAuth, (req, res) => {
  const snapshot = {
    email: req.user.email,
    context: req.session.context || null,
    exportedAt: new Date().toISOString()
  };
  const blob = Buffer.from(serialize(snapshot), 'utf8').toString('base64');
  res.json({ ok: true, state: blob });
});

// POST /api/session/restore — restore workspace state from a previously
// exported blob. The blob is base64-decoded and rehydrated.
router.post('/restore', requireAuth, (req, res) => {
  const { state } = req.body || {};
  if (!state) return res.status(400).json({ error: 'state blob required' });

  let decoded;
  try {
    decoded = Buffer.from(state, 'base64').toString('utf8');
  } catch (e) {
    return res.status(400).json({ error: 'invalid base64' });
  }

  let obj;
  try {
    obj = unserialize(decoded);
  } catch (e) {
    return res.status(400).json({ error: 'could not restore state' });
  }

  if (obj && obj.context) req.session.context = obj.context;
  res.json({ ok: true, restored: { email: obj && obj.email, context: req.session.context } });
});

module.exports = router;
