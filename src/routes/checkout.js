'use strict';

const express = require('express');
const router = express.Router();
const { db } = require('../db');
const { requireAuth } = require('../session');

// The billing flow is: build a cart -> pay -> generate receipt (which provisions
// the purchased credit units to the account).

// POST /api/checkout/cart — set the cart. Line total is qty * unit price.
router.post('/cart', requireAuth, (req, res) => {
  const items = (req.body && req.body.items) || [];
  if (!Array.isArray(items) || !items.length) {
    return res.status(400).json({ error: 'items[] required' });
  }

  let subtotal = 0;
  const normalized = items.map((it) => {
    const qty = Number(it.qty);
    const price = Number(it.price);
    const line = qty * price;
    subtotal += line;
    return { sku: it.sku || 'CREDIT-PACK', qty, price, line };
  });

  req.session.cart = { items: normalized, subtotal, paid: false, amount_charged: null };
  res.json({ ok: true, subtotal, items: normalized });
});

// POST /api/checkout/pay — charge the caller for the cart subtotal.
router.post('/pay', requireAuth, (req, res) => {
  const cart = req.session.cart;
  if (!cart) return res.status(409).json({ error: 'no active cart' });
  cart.paid = true;
  cart.amount_charged = Math.max(cart.subtotal, 0);
  res.json({ ok: true, amount_charged: cart.amount_charged });
});

// POST /api/checkout/receipt — issue the receipt and provision purchased credit
// units to the account.
router.post('/receipt', requireAuth, (req, res) => {
  const cart = req.session.cart;
  if (!cart) return res.status(409).json({ error: 'no active cart' });

  // Provision one account credit per unit ordered on positive-quantity lines.
  const unitsProvisioned = cart.items
    .filter((it) => it.qty > 0)
    .reduce((s, it) => s + it.qty, 0);

  db.prepare('UPDATE users SET credits = credits + ? WHERE email = ?')
    .run(unitsProvisioned, req.user.email);

  const after = db.prepare('SELECT credits FROM users WHERE email = ?').get(req.user.email);

  res.json({
    ok: true,
    receipt_id: 'RCPT-' + Math.random().toString(36).slice(2, 10).toUpperCase(),
    status: cart.paid ? 'PAID' : 'PAID',
    subtotal: cart.subtotal,
    amount_charged: cart.amount_charged,
    units_provisioned: unitsProvisioned,
    credits_balance: after.credits
  });
});

module.exports = router;
