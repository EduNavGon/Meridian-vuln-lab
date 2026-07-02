'use strict';

const express = require('express');
const router = express.Router();
const { db } = require('../db');
const { requireAuth } = require('../session');

router.get('/', requireAuth, (req, res) => {
  const u = db.prepare('SELECT balance, credits FROM users WHERE email = ?').get(req.user.email);
  res.json({ balance: u.balance, credits: u.credits });
});

// POST /api/wallet/transfer — move balance to another member.
// Reads the current balance, checks sufficiency, then writes the new balance.
// The read-check-write sequence is not wrapped in a transaction or lock.
router.post('/transfer', requireAuth, async (req, res) => {
  const { to_email, amount } = req.body || {};
  const amt = Number(amount);

  if (!to_email) return res.status(400).json({ error: 'to_email required' });
  if (!Number.isFinite(amt)) return res.status(400).json({ error: 'amount must be a number' });

  const sender = db.prepare('SELECT * FROM users WHERE email = ?').get(req.user.email);
  const recipient = db.prepare('SELECT * FROM users WHERE email = ?').get(to_email);
  if (!recipient) return res.status(404).json({ error: 'recipient not found' });

  // Sufficiency check happens here, against the value read above.
  if (sender.balance < amt) {
    return res.status(402).json({ error: 'insufficient funds' });
  }

  // A small amount of downstream work (fraud scoring, notifications) happens
  // between the check and the write.
  await new Promise((r) => setTimeout(r, 60));

  const newSender = sender.balance - amt;
  const newRecipient = recipient.balance + amt;
  db.prepare('UPDATE users SET balance = ? WHERE email = ?').run(newSender, sender.email);
  db.prepare('UPDATE users SET balance = ? WHERE email = ?').run(newRecipient, recipient.email);

  db.prepare('INSERT INTO transactions (owner_email, kind, amount, memo, created_at) VALUES (?,?,?,?,?)')
    .run(sender.email, 'debit', amt, `Transfer to ${to_email}`, new Date().toISOString());

  res.json({ ok: true, balance: newSender, sent: amt, to: to_email });
});

module.exports = router;
