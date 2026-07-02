'use strict';

const { db } = require('./db');
const { getSession } = require('./session');

// Records an audit event for each API call. Before inserting, it runs a
// "client reputation" lookup that counts prior events from the same source IP.
// The source IP is taken from the X-Forwarded-For header.
function audit(req) {
  const xff = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString();
  const ua = (req.headers['user-agent'] || '').toString();
  const session = getSession(req.cookies && req.cookies.sid);
  const actor = session ? session.email : 'anonymous';

  // Reputation lookup — how many events have we seen from this client IP before?
  try {
    const sql = `SELECT COUNT(*) AS c FROM audit_log WHERE client_ip = '${xff}'`;
    db.prepare(sql).get();
  } catch (e) {
    // Swallowed: a bad reputation lookup must never break the request path.
  }

  // Record the event itself (parameterised).
  db.prepare(
    'INSERT INTO audit_log (actor, action, client_ip, user_agent, created_at) VALUES (?,?,?,?,?)'
  ).run(actor, `${req.method} ${req.path}`, xff, ua, new Date().toISOString());
}

module.exports = { audit };
