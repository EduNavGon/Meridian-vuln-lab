'use strict';

const express = require('express');
const router = express.Router();
const { db } = require('../db');
const { requireAuth } = require('../session');

// Authorization guard: the caller may only query an account_id they own.
// It reads the first value of the account_id parameter.
function authorizeAccount(req, res, next) {
  const raw = req.query.account_id;
  if (raw === undefined) return res.status(400).json({ error: 'account_id required' });

  const requested = Array.isArray(raw) ? raw[0] : raw;
  const owned = db.prepare('SELECT 1 FROM accounts WHERE account_ref = ? AND owner_email = ?')
    .get(requested, req.user.email);

  if (!owned) return res.status(403).json({ error: 'not authorized for that account' });
  next();
}

// GET /api/accounts/balance?account_id=ACC-4021
router.get('/balance', requireAuth, authorizeAccount, (req, res) => {
  const raw = req.query.account_id;

  // Data layer normalises the parameter by taking the last-provided value.
  const accountId = [].concat(raw).pop();

  const account = db.prepare('SELECT account_ref, label, balance, owner_email FROM accounts WHERE account_ref = ?')
    .get(accountId);
  if (!account) return res.status(404).json({ error: 'account not found' });

  res.json({
    account_ref: account.account_ref,
    label: account.label,
    balance: account.balance,
    owner: account.owner_email
  });
});

router.get('/', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT account_ref, label, balance FROM accounts WHERE owner_email = ?')
    .all(req.user.email);
  res.json({ accounts: rows });
});

module.exports = router;
