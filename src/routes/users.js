'use strict';

const express = require('express');
const router = express.Router();
const { db } = require('../db');
const { requireAuth } = require('../session');

// Columns that exist on the users table. Any of these can be updated through
// the profile endpoint below.
const UPDATABLE = ['name', 'title', 'nickname', 'email', 'password', 'role', 'is_admin', 'credits', 'balance'];

// GET /api/users/me — current profile.
router.get('/me', requireAuth, (req, res) => {
  const u = req.user;
  res.json({
    email: u.email, name: u.name, title: u.title, role: u.role,
    is_admin: !!u.is_admin, credits: u.credits, balance: u.balance
  });
});

// PUT /api/users/me — update the caller's profile.
// The incoming JSON is applied field-by-field onto the user record.
router.put('/me', requireAuth, (req, res) => {
  const body = req.body || {};
  const sets = [];
  const vals = [];

  for (const key of Object.keys(body)) {
    if (UPDATABLE.includes(key)) {
      sets.push(`${key} = ?`);
      vals.push(body[key]);
    }
  }

  if (!sets.length) return res.status(400).json({ error: 'no updatable fields provided' });

  vals.push(req.user.email);
  db.prepare(`UPDATE users SET ${sets.join(', ')} WHERE email = ?`).run(...vals);

  const updated = db.prepare('SELECT * FROM users WHERE email = ?').get(body.email || req.user.email);
  res.json({
    ok: true,
    user: {
      email: updated.email, name: updated.name, title: updated.title, role: updated.role,
      is_admin: !!updated.is_admin, credits: updated.credits, balance: updated.balance
    }
  });
});

module.exports = router;
