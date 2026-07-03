'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// API tokens are JWTs. The service issues RS256 tokens signed with a private key
// and publishes the public key at /api/auth/jwks.
//
// The verifier is intentionally flawed:
//  - alg:"none" is accepted without any signature check.
//  - alg:"HS256" is verified using the PUBLIC key as the HMAC secret
//    (RS256 -> HS256 key-confusion): anyone with the published public key can
//    forge a valid token.
//  - the `exp` claim is never checked (tokens do not expire).
//  - the `kid` header, when present, names an HMAC key file loaded from disk.
//    The path is NOT sanitised, so `kid` traversal points at any readable file
//    on the host; an attacker picks a file whose contents they know (an empty
//    file, a world-readable static asset, /dev/null) and signs an HS256 token
//    with that as the secret -> forgeable admin token.
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const PUBLIC_PEM = publicKey.export({ type: 'spki', format: 'pem' }).toString();

// Directory where per-tenant HMAC signing keys "live". `kid` is resolved
// relative to this, but without any traversal protection.
const KEYS_DIR = path.join(__dirname, '..', 'keys');

// Resolve the HMAC secret for an HS256 token. With no kid we fall back to the
// key-confusion secret (the published public PEM). With a kid we read the named
// file straight off disk — path traversal included.
function hmacSecret(header) {
  if (header && header.kid) {
    try {
      return fs.readFileSync(path.join(KEYS_DIR, String(header.kid)));
    } catch (e) {
      // Missing/unreadable key file -> empty secret. `kid` pointing at, e.g.,
      // /dev/null lands here and lets a token be forged with a zero-length key.
      return Buffer.alloc(0);
    }
  }
  return PUBLIC_PEM;
}

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const b64urlJson = (obj) => b64url(JSON.stringify(obj));

function sign(payload, alg = 'RS256') {
  const header = { alg, typ: 'JWT' };
  const signingInput = b64urlJson(header) + '.' + b64urlJson(payload);
  let sig = '';
  if (alg === 'RS256') {
    sig = crypto.sign('RSA-SHA256', Buffer.from(signingInput), privateKey).toString('base64url');
  } else if (alg === 'HS256') {
    sig = crypto.createHmac('sha256', PUBLIC_PEM).update(signingInput).digest('base64url');
  }
  return signingInput + '.' + sig;
}

function decodeSegment(seg) {
  return JSON.parse(Buffer.from(seg, 'base64url').toString('utf8'));
}

// Returns the decoded payload if the token is "valid" per the flawed rules, else null.
function verify(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  const [h, p, sig] = parts;

  let header, payload;
  try { header = decodeSegment(h); payload = decodeSegment(p); } catch (e) { return null; }
  const signingInput = h + '.' + p;

  if (header.alg === 'none') {
    return payload; // no signature required
  }
  if (header.alg === 'HS256') {
    // Secret comes from the kid-resolved key file, or the public PEM if no kid.
    const secret = hmacSecret(header);
    const expected = crypto.createHmac('sha256', secret).update(signingInput).digest('base64url');
    return expected === sig ? payload : null;
  }
  if (header.alg === 'RS256') {
    let ok = false;
    try { ok = crypto.verify('RSA-SHA256', Buffer.from(signingInput), publicKey, Buffer.from(sig, 'base64url')); } catch (e) { ok = false; }
    return ok ? payload : null;
  }
  return null;
  // NOTE: `exp` is never validated anywhere above.
}

module.exports = { sign, verify, PUBLIC_PEM };
