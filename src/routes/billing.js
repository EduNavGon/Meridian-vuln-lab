'use strict';

const express = require('express');
const router = express.Router();
const { db } = require('../db');
const { requireAuth } = require('../session');

// Refund flow for a disputed charge:
//   POST /api/billing/charge  { amount }   -> record a pending charge
//   POST /api/billing/refund               -> refund the pending charge to balance
//   GET  /api/billing/charge               -> inspect current pending charge
//
// Two intentional flaws that compound:
//
//  1. Business logic — the refund credits `balance` by the charge amount, but a
//     "charge" is only a client-declared intent: no money is ever actually
//     debited by /charge. So refunding provisions real balance for a charge that
//     never happened (refund > 0 net gain), and the amount is caller-controlled.
//
//  2. Fine-grained race (TOCTOU) — /refund reads the charge status, then does an
//     async "refund-provider" round-trip, and only marks the charge `refunded`
//     AFTER the await. N concurrent /refund calls all pass the pending check
//     before any of them flips the status, so the same charge is paid out N
//     times. The economic invariant (a charge is refunded at most once) breaks.

router.post('/charge', requireAuth, (req, res) => {
  const amount = Number((req.body && req.body.amount) || 0);
  if (!Number.isFinite(amount) || amount <= 0) {
    return res.status(400).json({ error: 'positive amount required' });
  }
  // Declared intent only — nothing is debited here.
  req.session.pendingCharge = { amount, status: 'pending', created_at: Date.now() };
  res.json({ ok: true, charge: req.session.pendingCharge });
});

router.get('/charge', requireAuth, (req, res) => {
  res.json({ charge: req.session.pendingCharge || null });
});

router.post('/refund', requireAuth, async (req, res) => {
  const charge = req.session.pendingCharge;

  // TOCTOU check — evaluated before the async gap below.
  if (!charge || charge.status !== 'pending') {
    return res.status(409).json({ error: 'no refundable charge' });
  }

  // Refund-provider round-trip. Concurrent requests interleave here, all having
  // already passed the pending check above.
  await new Promise((r) => setTimeout(r, 60));

  db.prepare('UPDATE users SET balance = balance + ? WHERE email = ?')
    .run(charge.amount, req.user.email);

  // Status flipped only now, after the payout — too late to stop concurrent calls.
  charge.status = 'refunded';

  const after = db.prepare('SELECT balance FROM users WHERE email = ?').get(req.user.email);
  res.json({ ok: true, refunded: charge.amount, balance: after.balance });
});

module.exports = router;
