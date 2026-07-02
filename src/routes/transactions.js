'use strict';

const express = require('express');
const router = express.Router();
const { db } = require('../db');
const { requireAuth } = require('../session');

// GET /api/transactions?sort=created_at&dir=desc
// Returns the caller's transaction history. The result ordering is caller
// controlled via sort/dir, which are composed into the ORDER BY clause.
router.get('/', requireAuth, (req, res) => {
  const sort = (req.query.sort || 'created_at').toString();
  const dir = (req.query.dir || 'DESC').toString();

  const sql =
    'SELECT id, kind, amount, memo, created_at FROM transactions ' +
    'WHERE owner_email = ? ORDER BY ' + sort + ' ' + dir;

  try {
    const rows = db.prepare(sql).all(req.user.email);
    res.json({ transactions: rows });
  } catch (e) {
    // Generic error — no SQL detail is surfaced to the caller.
    res.status(400).json({ error: 'could not list transactions' });
  }
});

module.exports = router;
