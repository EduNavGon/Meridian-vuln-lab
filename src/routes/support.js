'use strict';

const express = require('express');
const router = express.Router();
const { db } = require('../db');
const { requireAuth } = require('../session');

// POST /api/support  { subject, body }
// Any authenticated member can open a support ticket. Subject/body are stored
// verbatim and later rendered in the admin console without escaping
// (stored/blind XSS: the payload executes when an admin opens the console).
router.post('/', requireAuth, (req, res) => {
  const subject = String((req.body && req.body.subject) || '').slice(0, 200);
  const body = String((req.body && req.body.body) || '').slice(0, 5000);
  if (!subject || !body) return res.status(400).json({ error: 'subject and body required' });

  db.prepare('INSERT INTO support_tickets (author_email, subject, body, created_at) VALUES (?,?,?,?)')
    .run(req.user.email, subject, body, new Date().toISOString());

  res.json({ ok: true, message: 'ticket submitted' });
});

// GET /api/support/mine — the caller's own tickets.
router.get('/mine', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT id, subject, body, created_at FROM support_tickets WHERE author_email = ? ORDER BY id DESC')
    .all(req.user.email);
  res.json({ tickets: rows });
});

module.exports = router;
