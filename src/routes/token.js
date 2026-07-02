'use strict';

const express = require('express');
const router = express.Router();
const { requireAuth } = require('../session');
const jwt = require('../lib/jwt');

// POST /api/auth/token — issue an API JWT for the current (cookie-authenticated) user.
router.post('/token', requireAuth, (req, res) => {
  const now = Math.floor(Date.now() / 1000);
  const token = jwt.sign({
    sub: req.user.email,
    name: req.user.name,
    role: req.user.role,
    iat: now,
    exp: now + 3600
  });
  res.json({ ok: true, token_type: 'Bearer', access_token: token });
});

// GET /api/auth/jwks — publish the RSA public key used to verify RS256 tokens.
router.get('/jwks', (req, res) => {
  res.type('text/plain').send(jwt.PUBLIC_PEM);
});

module.exports = router;
