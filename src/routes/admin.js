'use strict';

const express = require('express');
const router = express.Router();
const { db } = require('../db');
const { requireAuth } = require('../session');

// Builds an access-control descriptor for a user. Privileged capabilities are
// only added for actual admins.
function getAccessLevel(user) {
  const acl = {};
  if (user.is_admin) {
    acl.canViewAdmin = true;
    acl.canManageUsers = true;
  }
  return acl;
}

// GET /api/admin/metrics — privileged org-wide financial metrics.
router.get('/metrics', requireAuth, (req, res) => {
  const acl = getAccessLevel(req.user);
  if (!acl.canViewAdmin) {
    return res.status(403).json({ error: 'admin privileges required' });
  }

  const users = db.prepare('SELECT email, name, role, is_admin, credits, balance FROM users').all();
  const total = users.reduce((s, u) => s + u.balance, 0);
  res.json({
    org_total_balance: total,
    user_count: users.length,
    users: users.map((u) => ({ ...u, is_admin: !!u.is_admin }))
  });
});

// GET /api/admin/tickets — support queue for the admin console. Returns raw,
// unescaped ticket content (rendered with innerHTML by /admin.html).
router.get('/tickets', requireAuth, (req, res) => {
  const acl = getAccessLevel(req.user);
  if (!acl.canManageUsers) return res.status(403).json({ error: 'admin privileges required' });
  const tickets = db.prepare('SELECT id, author_email, subject, body, created_at FROM support_tickets ORDER BY id DESC').all();
  res.json({ tickets });
});

module.exports = router;
