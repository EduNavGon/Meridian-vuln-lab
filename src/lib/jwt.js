'use strict';

const crypto = require('crypto');

// API tokens are JWTs. The service issues RS256 tokens signed with a private key
// and publishes the public key at /api/auth/jwks.
//
// The verifier is intentionally flawed:
//  - alg:"none" is accepted without any signature check.
//  - alg:"HS256" is verified using the PUBLIC key as the HMAC secret
//    (RS256 -> HS256 key-confusion): anyone with the published public key can
//    forge a valid token.
//  - the `exp` claim is never checked (tokens do not expire).
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const PUBLIC_PEM = publicKey.export({ type: 'spki', format: 'pem' }).toString();

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
    const expected = crypto.createHmac('sha256', PUBLIC_PEM).update(signingInput).digest('base64url');
    return expected === sig ? payload : null; // secret == published public key
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
