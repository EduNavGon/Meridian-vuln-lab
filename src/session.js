'use strict';

const crypto = require('crypto');
const { db } = require('./db');

// Simple in-memory session store. A random opaque token is stored in the `sid`
// cookie and mapped to server-side state here.
const sessions = new Map();

function createSession(email, fixedToken) {
  // If the caller already presents a session id, it is reused instead of being
  // rotated on login (session fixation).
  const token = fixedToken || crypto.randomBytes(24).toString('hex');
  sessions.set(token, {
    email,
    // `context` is mutable server-side state used by the reporting flow.
    context: { scope: 'self', ref: null },
    // `flags` starts as a plain empty object on purpose.
    flags: {}
  });
  return token;
}

function getSession(token) {
  return token ? sessions.get(token) : null;
}

function destroySession(token) {
  if (token) sessions.delete(token);
}

function currentUser(session) {
  if (!session) return null;
  return db.prepare('SELECT * FROM users WHERE email = ?').get(session.email);
}

function requireAuth(req, res, next) {
  const session = getSession(req.cookies && req.cookies.sid);
  const user = currentUser(session);
  if (!session || !user) {
    return res.status(401).json({ error: 'authentication required' });
  }
  req.session = session;
  req.user = user;
  next();
}

module.exports = {
  sessions,
  createSession,
  getSession,
  destroySession,
  currentUser,
  requireAuth
};
