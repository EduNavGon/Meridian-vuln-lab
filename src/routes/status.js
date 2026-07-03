'use strict';

const express = require('express');
const router = express.Router();
const { requireAuth } = require('../session');

// Lightweight in-memory response cache for the "status summary" widget. The
// summary is expensive to build, so the first caller's rendered payload is
// cached and served to everyone for a short TTL.
//
// Intentional flaw (web cache poisoning via unkeyed input):
//  - The cache KEY is the request path only.
//  - The cached BODY embeds a `portal_url` / `assets_base` built from the
//    X-Forwarded-Host header, which is UNKEYED. Whoever populates the cache
//    first controls the host baked into the response that every later victim
//    (including the admin dashboard, which fetches this) receives.
//  - An attacker sends one request with a hostile X-Forwarded-Host; the poisoned
//    links (used by the frontend to load scripts / build absolute URLs) are then
//    served to other users from cache -> redirect / client-side script inclusion.

const cache = new Map(); // path -> { body, expires }
const TTL_MS = 30000;

router.get('/summary', requireAuth, (req, res) => {
  const key = req.path;
  const hit = cache.get(key);
  if (hit && hit.expires > Date.now()) {
    res.setHeader('X-Cache', 'HIT');
    return res.json(hit.body);
  }

  // Host is taken from the (unkeyed, attacker-controllable) forwarded header.
  const host = req.headers['x-forwarded-host'] || req.headers.host || 'meridian.io';

  const body = {
    ok: true,
    service: 'meridian-ledger',
    generated_at: new Date().toISOString(),
    // These absolute URLs are consumed by the frontend to load assets and build
    // links. They are cached and reused across users.
    portal_url: `https://${host}/`,
    assets_base: `https://${host}/static`,
    support_url: `https://${host}/support`
  };

  cache.set(key, { body, expires: Date.now() + TTL_MS });
  res.setHeader('X-Cache', 'MISS');
  res.json(body);
});

module.exports = router;
