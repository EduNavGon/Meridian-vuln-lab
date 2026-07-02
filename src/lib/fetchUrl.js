'use strict';

const http = require('http');
const https = require('https');

// Server-side URL fetcher used to validate that a webhook / document endpoint
// is reachable before saving it. It follows the URL exactly as provided and
// only reports a coarse reachability status back to the caller — the response
// body is never returned to the client (blind by design).
function fetchUrl(rawUrl, { timeoutMs = 4000 } = {}) {
  return new Promise((resolve) => {
    let parsed;
    try {
      parsed = new URL(rawUrl);
    } catch (e) {
      return resolve({ ok: false, status: 'invalid-url' });
    }
    const client = parsed.protocol === 'https:' ? https : http;
    const started = Date.now();
    const req = client.get(
      parsed,
      { timeout: timeoutMs, headers: { 'User-Agent': 'Meridian-Webhook-Validator/1.0' } },
      (res) => {
        // Drain and discard the body — nothing is echoed to the caller.
        res.on('data', () => {});
        res.on('end', () => {
          resolve({ ok: true, status: 'validated', httpStatus: res.statusCode, ms: Date.now() - started });
        });
      }
    );
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, status: 'timeout', ms: Date.now() - started }); });
    req.on('error', () => resolve({ ok: false, status: 'unreachable', ms: Date.now() - started }));
  });
}

module.exports = { fetchUrl };
