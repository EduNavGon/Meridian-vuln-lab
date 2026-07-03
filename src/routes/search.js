'use strict';

const express = require('express');
const router = express.Router();
const { db } = require('../db');
const { requireAuth } = require('../session');

// POST /api/search/invoices  { filter: { ... } }
//
// "Flexible" invoice search. The client sends a Mongo-style filter object and
// the server translates it into a SQL WHERE clause. Supported operators:
//   { "field": "value" }                 -> field = value
//   { "field": { "$ne":  x } }           -> field <> x
//   { "field": { "$gt":  x } }           -> field >  x
//   { "field": { "$lt":  x } }           -> field <  x
//   { "field": { "$like": x } }          -> field LIKE x
//   { "$or": [ {...}, {...} ] }           -> ( ... OR ... )
//
// Intentional flaw (NoSQL-style operator injection):
//  - The endpoint scopes results to the caller by ANDing owner_email, but the
//    caller-supplied operators are trusted. Passing {"owner_email":{"$ne":"__"}}
//    or a {"$or":[...]} that re-opens the scope returns OTHER tenants' invoices.
//  - Values are concatenated straight into the SQL text (no binding), so the
//    operator layer is also a classic string-concat SQLi sink. A single-quote in
//    a value breaks out of the literal.
//
// This mirrors how a NoSQL operator-injection bug behaves on top of a SQL store:
// the attacker controls the *shape* of the query, not just a value.

function sqlLiteral(v) {
  if (v === null || v === undefined) return 'NULL';
  if (typeof v === 'number') return String(v);
  // NOTE: no escaping — value is embedded verbatim inside single quotes.
  return "'" + String(v) + "'";
}

function clauseFor(field, cond) {
  if (cond && typeof cond === 'object' && !Array.isArray(cond)) {
    const op = Object.keys(cond)[0];
    const val = cond[op];
    switch (op) {
      case '$ne':   return `${field} <> ${sqlLiteral(val)}`;
      case '$gt':   return `${field} > ${sqlLiteral(val)}`;
      case '$lt':   return `${field} < ${sqlLiteral(val)}`;
      case '$like': return `${field} LIKE ${sqlLiteral(val)}`;
      default:      return `${field} = ${sqlLiteral(val)}`;
    }
  }
  return `${field} = ${sqlLiteral(cond)}`;
}

function buildWhere(filter) {
  const parts = [];
  for (const key of Object.keys(filter || {})) {
    if (key === '$or' && Array.isArray(filter.$or)) {
      const ors = filter.$or.map((sub) => '(' + buildWhere(sub) + ')').filter(Boolean);
      if (ors.length) parts.push('(' + ors.join(' OR ') + ')');
      continue;
    }
    parts.push(clauseFor(key, filter[key]));
  }
  return parts.join(' AND ');
}

router.post('/invoices', requireAuth, (req, res) => {
  const filter = (req.body && req.body.filter) || {};

  // The intent: always scope to the caller. The caller's own operators are
  // appended and trusted, which is exactly where the scope gets subverted.
  const scoped = { owner_email: req.user.email, ...filter };
  const where = buildWhere(scoped) || '1=1';

  const sql =
    'SELECT doc_ref, owner_email, counterparty, amount, status, private_memo ' +
    'FROM invoices WHERE ' + where;

  try {
    const rows = db.prepare(sql).all();
    res.json({ ok: true, count: rows.length, results: rows });
  } catch (e) {
    res.status(400).json({ error: 'could not run search' });
  }
});

module.exports = router;
