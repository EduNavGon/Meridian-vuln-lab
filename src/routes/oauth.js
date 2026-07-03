'use strict';

const express = require('express');
const router = express.Router();
const { requireAuth } = require('../session');

// Minimal OAuth-style authorization endpoint for "Connect an app" integrations.
//
// GET /api/auth/authorize?client_id=...&redirect_uri=...&state=...
//
// Intentional flaw (open redirect / redirect_uri not validated):
//  - `redirect_uri` is NOT checked against a registered allow-list for the
//    client_id. Any absolute URL is accepted and the browser is 302'd to it
//    with the authorization `code` appended.
//  - Combined with the JWT issuance flow, this is a token-leak primitive: an
//    attacker crafts an authorize link with their own redirect_uri and harvests
//    the code/token when the victim approves.
//
// A correct implementation would look up the client_id and only redirect to a
// pre-registered URI (exact match, no open scheme/host).

const CLIENTS = {
  'meridian-mobile': { name: 'Meridian Mobile' },
  'meridian-cli': { name: 'Meridian CLI' }
};

router.get('/authorize', requireAuth, (req, res) => {
  const { client_id, redirect_uri, state } = req.query;
  if (!client_id || !redirect_uri) {
    return res.status(400).json({ error: 'client_id and redirect_uri required' });
  }

  const client = CLIENTS[String(client_id)];
  // client_id is looked up only to label the consent screen — the redirect_uri
  // is trusted regardless of whether it belongs to this client.
  const clientName = client ? client.name : String(client_id);

  const code = 'ac_' + Buffer.from(`${req.user.email}:${Date.now()}`).toString('base64url');

  // No allow-list check: the caller-supplied redirect_uri is used verbatim.
  const sep = String(redirect_uri).includes('?') ? '&' : '?';
  let location = `${redirect_uri}${sep}code=${encodeURIComponent(code)}`;
  if (state) location += `&state=${encodeURIComponent(String(state))}`;

  res.setHeader('X-Authorized-Client', clientName);
  res.redirect(302, location);
});

module.exports = router;
