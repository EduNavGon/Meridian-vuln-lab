'use strict';

const http = require('http');
const https = require('https');

// "Hardened" fetch used by the document-import feature. It rejects a small set
// of known-sensitive hostnames before making the request.
//
// Weaknesses (intentional):
//  - Only the INITIAL URL's hostname is validated. Redirects (3xx) are followed
//    without re-validating the new location -> redirect-based bypass.
//  - The blocklist matches literal hostnames only. Alternate IP encodings
//    (decimal/octal/hex, IPv6-mapped, 0.0.0.0, [::]) and RFC1918 private ranges
//    are not normalised or blocked.
const BLOCKLIST = new Set([
  '169.254.169.254',
  'localhost',
  '127.0.0.1',
  'metadata.google.internal'
]);

function hostnameBlocked(hostname) {
  return BLOCKLIST.has(String(hostname || '').toLowerCase());
}

function guardedFetch(rawUrl, opts = {}) {
  const { timeoutMs = 4000, maxRedirects = 5, _depth = 0 } = opts;
  return new Promise((resolve) => {
    let parsed;
    try { parsed = new URL(rawUrl); } catch (e) { return resolve({ ok: false, status: 'invalid-url' }); }

    // Validation happens ONLY here, and only on the first hop.
    if (_depth === 0 && hostnameBlocked(parsed.hostname)) {
      return resolve({ ok: false, status: 'blocked-by-policy', host: parsed.hostname });
    }

    const client = parsed.protocol === 'https:' ? https : http;
    const started = Date.now();
    const req = client.get(
      parsed,
      { timeout: timeoutMs, headers: { 'User-Agent': 'Meridian-DocImport/1.0' } },
      (res) => {
        const loc = res.headers.location;
        if (res.statusCode >= 300 && res.statusCode < 400 && loc && _depth < maxRedirects) {
          res.resume(); // discard body
          const next = new URL(loc, parsed).toString();
          // NOTE: the redirect target is fetched without re-checking the blocklist.
          return resolve(guardedFetch(next, { timeoutMs, maxRedirects, _depth: _depth + 1 }));
        }
        res.on('data', () => {}); // drain, never returned to caller (blind)
        res.on('end', () => resolve({ ok: true, status: 'imported', httpStatus: res.statusCode, ms: Date.now() - started, hops: _depth }));
      }
    );
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, status: 'timeout' }); });
    req.on('error', () => resolve({ ok: false, status: 'unreachable' }));
  });
}

module.exports = { guardedFetch, hostnameBlocked };
