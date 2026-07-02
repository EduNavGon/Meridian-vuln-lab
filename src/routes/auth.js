'use strict';

const express = require('express');
const router = express.Router();
const { db } = require('../db');
const { createSession, destroySession, requireAuth } = require('../session');

// Parameterised login — the login form is intentionally NOT the vulnerable path.
router.post('/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'invalid credentials' });
  }

  const existing = req.cookies && req.cookies.sid;
  const token = createSession(user.email, existing);
  res.cookie('sid', token, { httpOnly: true, sameSite: 'lax', path: '/' });
  res.json({
    ok: true,
    user: { email: user.email, name: user.name, title: user.title, role: user.role }
  });
});

router.post('/logout', (req, res) => {
  destroySession(req.cookies && req.cookies.sid);
  res.clearCookie('sid');
  res.json({ ok: true });
});

router.get('/me', requireAuth, (req, res) => {
  const u = req.user;
  res.json({
    email: u.email, name: u.name, title: u.title, role: u.role,
    is_admin: !!u.is_admin, credits: u.credits, balance: u.balance
  });
});

module.exports = router;
