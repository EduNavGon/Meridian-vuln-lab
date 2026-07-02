'use strict';

const express = require('express');
const router = express.Router();
const { db } = require('../db');
const jwt = require('../lib/jwt');

// Bearer-token auth for the v2 API. Uses the flawed JWT verifier.
function requireJwt(req, res, next) {
  const auth = req.headers.authorization || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ error: 'bearer token required' });
  const payload = jwt.verify(m[1]);
  if (!payload) return res.status(401).json({ error: 'invalid token' });
  req.jwt = payload;
  next();
}

// GET /api/v2/admin — privileged console, authorized purely by the JWT `role` claim.
router.get('/admin', requireJwt, (req, res) => {
  if (req.jwt.role !== 'admin') {
    return res.status(403).json({ error: 'admin role required' });
  }
  const users = db.prepare('SELECT email, name, role, is_admin, credits, balance FROM users').all();
  res.json({
    ok: true,
    console: 'v2-admin',
    caller: req.jwt.sub,
    users: users.map((u) => ({ ...u, is_admin: !!u.is_admin }))
  });
});

// GET /api/v2/me — echo the token claims (handy for debugging tokens).
router.get('/me', requireJwt, (req, res) => res.json({ claims: req.jwt }));

module.exports = router;
