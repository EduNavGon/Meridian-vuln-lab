'use strict';

const express = require('express');
const router = express.Router();
const { db } = require('../db');
const { requireAuth } = require('../session');
const { fetchUrl } = require('../lib/fetchUrl');

router.get('/', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT id, target_url, last_status, created_at FROM webhooks WHERE owner_email = ?')
    .all(req.user.email);
  res.json({ webhooks: rows });
});

// POST /api/webhooks — register an outbound webhook. Before saving, the server
// makes a validation request to the supplied URL to confirm it is reachable.
// Only a coarse status is returned to the caller.
router.post('/', requireAuth, async (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'url required' });

  const result = await fetchUrl(url);

  db.prepare('INSERT INTO webhooks (owner_email, target_url, last_status, created_at) VALUES (?,?,?,?)')
    .run(req.user.email, url, result.status, new Date().toISOString());

  res.json({ ok: true, validation: result.status });
});

// POST /api/webhooks/test — re-run the reachability validation for an ad-hoc URL
// without saving it. Same server-side fetch, same blind response.
router.post('/test', requireAuth, async (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'url required' });
  const result = await fetchUrl(url);
  res.json({ reachable: result.ok, status: result.status });
});

module.exports = router;
