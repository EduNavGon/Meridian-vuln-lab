'use strict';

const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const { db } = require('../db');

// POST /api/auth/forgot  { email }
// Generates a password-reset link and "emails" it (logged to the server console).
// Two flaws:
//  - The link host comes from the request Host / X-Forwarded-Host header
//    (attacker-controllable) -> reset-link poisoning.
//  - The token is derived deterministically from email + a coarse timestamp with
//    a hardcoded string -> predictable / forgeable.
router.post('/forgot', (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'email required' });

  const user = db.prepare('SELECT email FROM users WHERE email = ?').get(email);

  const minute = Math.floor(Date.now() / 60000);
  const token = crypto.createHash('md5').update(`${email}:${minute}:meridian`).digest('hex').slice(0, 16);

  const host = req.headers['x-forwarded-host'] || req.headers.host;
  const resetUrl = `https://${host}/reset?email=${encodeURIComponent(email)}&token=${token}`;

  if (user) {
    db.prepare('INSERT INTO password_resets (email, token, reset_url, expires_at) VALUES (?,?,?,?)')
      .run(email, token, resetUrl, new Date(Date.now() + 3600000).toISOString());
  }
  console.log('[password-reset] would email:', resetUrl);

  // Same response regardless, but the poisoned link has already been built/sent.
  res.json({ ok: true, message: 'If the account exists, a reset link has been sent.' });
});

// POST /api/auth/reset  { email, token, new_password }
router.post('/reset', (req, res) => {
  const { email, token, new_password } = req.body || {};
  if (!email || !token || !new_password) {
    return res.status(400).json({ error: 'email, token and new_password required' });
  }

  const row = db.prepare(
    'SELECT * FROM password_resets WHERE email = ? AND token = ? ORDER BY rowid DESC LIMIT 1'
  ).get(email, token);
  if (!row) return res.status(400).json({ error: 'invalid or expired token' });

  db.prepare('UPDATE users SET password = ? WHERE email = ?').run(new_password, email);
  res.json({ ok: true, message: 'password updated' });
});

module.exports = router;
