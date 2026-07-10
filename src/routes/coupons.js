'use strict';

const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const { db } = require('../db');
const { requireAuth } = require('../session');

function couponReseedToken(minute) {
  return crypto.createHash('md5').update(`coupons:${minute}:meridian`).digest('hex').slice(0, 16);
}

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

// POST /api/coupons/reseed  { token }
// Benchmark heal for shared persistent DBs (Railway). Predictable token mirrors #15.
router.post('/reseed', (req, res) => {
  if (process.env.LAB_MODE === '0') {
    return res.status(404).json({ error: 'not found' });
  }
  const { token } = req.body || {};
  // Accept a small window around the current minute so scanner/Railway clock
  // skew (either direction) doesn't reject a valid predictable token. Mirrors
  // the minute offsets the Vex Raptor benchmark heal tries (benchmark_coupon_heal).
  const minute = Math.floor(Date.now() / 60000);
  const accepted = [-2, -1, 0, 1, 2].map((off) => couponReseedToken(minute + off));
  if (!token || !accepted.includes(token)) {
    return res.status(403).json({ error: 'invalid token' });
  }
  db.prepare("UPDATE coupons SET remaining_uses = 1 WHERE code = 'WELCOME50'").run();
  db.prepare("UPDATE coupons SET remaining_uses = 3 WHERE code = 'LOYALTY25'").run();
  const rows = db.prepare('SELECT code, remaining_uses FROM coupons').all();
  res.json({ ok: true, reseeded: rows });
});

module.exports = router;
