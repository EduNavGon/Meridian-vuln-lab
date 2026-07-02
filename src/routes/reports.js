'use strict';

const express = require('express');
const router = express.Router();
const { db } = require('../db');
const { requireAuth } = require('../session');

// Reporting flow is stateful. A caller first "opens" a report context, which is
// bound to their own most recent document. They then render it. The document
// being rendered is never named in the render URL — it is resolved from the
// server-side report context established in an earlier step.

// Step 1: open a report context bound to the caller's own latest document.
router.post('/open', requireAuth, (req, res) => {
  const ownDoc = db.prepare(
    'SELECT doc_ref FROM invoices WHERE owner_email = ? ORDER BY id DESC LIMIT 1'
  ).get(req.user.email);

  req.session.context = { docRef: ownDoc ? ownDoc.doc_ref : null, scope: 'self' };
  res.json({ ok: true, context: { scope: 'self' } });
});

// Step 2: adjust the report scope. Sets which document ref the context points
// at. Ownership of the supplied doc_ref is not re-verified here.
router.patch('/scope', requireAuth, (req, res) => {
  const { doc_ref } = req.body || {};
  if (!req.session.context) return res.status(409).json({ error: 'no open report context' });
  if (doc_ref) req.session.context.docRef = doc_ref;
  res.json({ ok: true });
});

// Step 3: render the document currently referenced by the report context.
router.get('/render', requireAuth, (req, res) => {
  const ctx = req.session.context;
  if (!ctx || !ctx.docRef) return res.status(409).json({ error: 'no report context; call /open first' });

  const doc = db.prepare('SELECT * FROM invoices WHERE doc_ref = ?').get(ctx.docRef);
  if (!doc) return res.status(404).json({ error: 'document not found' });

  res.json({
    doc_ref: doc.doc_ref,
    owner: doc.owner_email,
    counterparty: doc.counterparty,
    amount: doc.amount,
    status: doc.status,
    private_memo: doc.private_memo
  });
});

// GET /api/reports/summary — count the caller's transactions whose memo matches
// their saved profile nickname. The nickname was stored safely (parameterised)
// via the profile update, but is concatenated straight into SQL here — a
// second-order injection: the payload is planted in one request and detonates
// in a different one.
router.get('/summary', requireAuth, (req, res) => {
  const u = db.prepare('SELECT nickname FROM users WHERE email = ?').get(req.user.email);
  const nick = u ? u.nickname : '';
  const sql =
    "SELECT COUNT(*) AS matches FROM transactions " +
    "WHERE owner_email = '" + req.user.email + "' AND memo LIKE '%" + nick + "%'";
  try {
    const row = db.prepare(sql).get();
    res.json({ nickname: nick, matches: row.matches });
  } catch (e) {
    res.status(400).json({ error: 'could not build summary' });
  }
});

// Convenience: list the caller's own document refs (so the UI has something to show).
router.get('/mine', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT doc_ref, counterparty, amount, status FROM invoices WHERE owner_email = ?')
    .all(req.user.email);
  res.json({ documents: rows });
});

module.exports = router;
