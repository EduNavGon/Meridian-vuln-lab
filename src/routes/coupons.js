'use strict';

const express = require('express');
const router = express.Router();
const { db } = require('../db');
const { requireAuth } = require('../session');

router.get('/', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT code, discount, remaining_uses FROM coupons').all();
  res.json({ coupons: rows });
});

// POST /api/coupons/redeem — redeem a promo code for account credits.
// Checks remaining_uses, applies the credit, then decrements the counter.
// No row lock / transaction guards the read-modify-write.
router.post('/redeem', requireAuth, async (req, res) => {
  const { code } = req.body || {};
  if (!code) return res.status(400).json({ error: 'code required' });

  const coupon = db.prepare('SELECT * FROM coupons WHERE code = ?').get(code);
  if (!coupon) return res.status(404).json({ error: 'unknown code' });

  if (coupon.remaining_uses <= 0) {
    return res.status(409).json({ error: 'coupon fully redeemed' });
  }

  // Payment-provider round-trip simulated here, between check and decrement.
  await new Promise((r) => setTimeout(r, 50));

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(req.user.email);
  const creditsAwarded = coupon.discount;
  db.prepare('UPDATE users SET credits = credits + ? WHERE email = ?').run(creditsAwarded, user.email);
  db.prepare('UPDATE coupons SET remaining_uses = remaining_uses - 1, redeemed_log = redeemed_log || ? WHERE code = ?')
    .run(`${user.email};`, code);

  const after = db.prepare('SELECT credits FROM users WHERE email = ?').get(user.email);
  res.json({ ok: true, code, credits_awarded: creditsAwarded, credits_balance: after.credits });
});

module.exports = router;
