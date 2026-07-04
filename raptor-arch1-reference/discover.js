'use strict';

/*
 * ARCH-1 — API surface discovery (reference implementation for Vex Raptor).
 * ---------------------------------------------------------------------------
 * The bottleneck that keeps Raptor at 1/23: against a SPA, its HTML crawler
 * sees "1 page, 0 forms, API=not found", so the attack modules have nothing to
 * aim at. This module builds the missing endpoint inventory.
 *
 * It combines TWO sources, because neither is enough on its own:
 *   (A) Bundle parsing — pull `/api/...` literals (+ method + body field names)
 *       straight out of the served JS. Gets the UI-driven routes for free.
 *   (B) Active probing — a generic API wordlist + verb/sibling expansion,
 *       CONFIRMED against the live target with the authenticated session.
 *       This is what finds the *hidden* attack routes (admin, documents,
 *       exports, templates, v2, search, billing, oauth, ...) that the bundle
 *       never references.
 *
 * Detection trick for this style of Express SPA: unknown GET paths fall through
 * to the catch-all and return the SPA HTML (200 text/html); unknown POST/PUT/
 * PATCH return 404. So a path is REAL when a probe returns JSON, or an
 * application status (400/401/402/403/405/409) — anything but "200 html" or 404.
 *
 * Output: a normalized endpoint inventory (method, path, source, status,
 * contentType, bodyFields) written to endpoints.json and printed as a table.
 * In Raptor this array is what you publish into the shared [MEMORY]/OODA store
 * for every attack module to consume.
 *
 * Usage:
 *   node discover.js <baseUrl> <email> <password>
 *   node discover.js http://localhost:3000 alice@meridian.io 'M3ridian!Alice2026'
 *
 * No dependencies (Node built-in http/https only) so it ports cleanly.
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');
const fs = require('fs');

const BASE = process.argv[2] || 'http://localhost:3000';
const EMAIL = process.argv[3] || 'alice@meridian.io';
const PASSWORD = process.argv[4] || 'M3ridian!Alice2026';
const CONCURRENCY = Number(process.env.CONCURRENCY || 40);
const METHODS = ['GET', 'POST', 'PUT', 'PATCH'];

// --------------------------------------------------------------------------
// Minimal HTTP client (no redirects, captures status + content-type + body).
// --------------------------------------------------------------------------
function httpReq(method, path, { cookie, body } = {}) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(path, BASE); } catch (e) { return resolve({ status: 0 }); }
    const lib = u.protocol === 'https:' ? https : http;
    const headers = { 'User-Agent': 'raptor-arch1/1.0' };
    if (cookie) headers['Cookie'] = cookie;
    let data = body;
    if (data != null) { headers['Content-Type'] = 'application/json'; headers['Content-Length'] = Buffer.byteLength(data); }
    const req = lib.request({
      method, hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search, headers, timeout: 8000
    }, (res) => {
      let chunks = '';
      res.on('data', (c) => { if (chunks.length < 4096) chunks += c; });
      res.on('end', () => {
        const jar = {};
        (res.headers['set-cookie'] || []).forEach((sc) => { const m = sc.match(/^([^=]+)=([^;]+)/); if (m) jar[m[1]] = m[2]; });
        resolve({ status: res.statusCode, contentType: res.headers['content-type'] || '', body: chunks, jar });
      });
    });
    req.on('error', () => resolve({ status: 0 }));
    req.on('timeout', () => { req.destroy(); resolve({ status: 0 }); });
    if (data != null) req.write(data);
    req.end();
  });
}

async function login() {
  const r = await httpReq('POST', '/api/auth/login', { body: JSON.stringify({ email: EMAIL, password: PASSWORD }) });
  const sid = r.jar && r.jar.sid;
  return sid ? `sid=${sid}` : '';
}

// --------------------------------------------------------------------------
// (A) Bundle parsing — pull routes, methods, body field names from served JS.
// --------------------------------------------------------------------------
async function fetchBundles() {
  const texts = [];
  const index = await httpReq('GET', '/', {});
  const scripts = new Set(['/app.js']);
  const re = /<script[^>]+src=["']([^"']+\.js)["']/gi;
  let m; while ((m = re.exec(index.body || '')) !== null) scripts.add(m[1]);
  for (const s of scripts) {
    const r = await httpReq('GET', s, {});
    if (r.status === 200 && /javascript|text/.test(r.contentType || '') && r.body) texts.push(r.body);
    // source map, if any
    const map = await httpReq('GET', s + '.map', {});
    if (map.status === 200 && map.body) texts.push(map.body);
  }
  return texts.join('\n');
}

function parseBundle(js) {
  const found = new Map(); // path -> { methods:Set, bodyFields:Set }
  // Every /api/... string literal.
  const pathRe = /['"`](\/api\/[\w\/.:-]+)(\?[^'"`]*)?['"`]/g;
  let m;
  while ((m = pathRe.exec(js)) !== null) {
    const p = m[1].replace(/\/$/, '');
    if (!found.has(p)) found.set(p, { methods: new Set(), bodyFields: new Set(), source: 'bundle' });
    // query-string params seen inline
    if (m[2]) for (const kv of m[2].slice(1).split('&')) { const k = kv.split('=')[0]; if (k) found.get(p).bodyFields.add(k + ' (query)'); }
  }
  // Method + body hints from api('/path', { method:'X', body: JSON.stringify({ a, b }) }) call sites.
  const callRe = /\(\s*['"`](\/api\/[\w\/.:-]+)[^'"`]*['"`]\s*,\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}/g;
  while ((m = callRe.exec(js)) !== null) {
    const p = m[1].replace(/\/$/, '');
    const opts = m[2];
    const rec = found.get(p) || { methods: new Set(), bodyFields: new Set(), source: 'bundle' };
    const mm = opts.match(/method\s*:\s*['"`](\w+)['"`]/i);
    if (mm) rec.methods.add(mm[1].toUpperCase());
    const bm = opts.match(/JSON\.stringify\(\s*\{([^}]*)\}/);
    if (bm) for (const part of bm[1].split(',')) { const k = part.split(':')[0].trim().replace(/['"]/g, ''); if (/^[\w$]+$/.test(k)) rec.bodyFields.add(k); }
    found.set(p, rec);
  }
  return found;
}

// --------------------------------------------------------------------------
// (B) Active probing — generic API wordlist + expansion, confirmed live.
// --------------------------------------------------------------------------
// Generic REST resource/verb wordlist (NOT lab-specific — the kind of list any
// content-discovery tool ships with). Kept compact for a fast run.
const WORDS = [
  'admin', 'metrics', 'tickets', 'users', 'user', 'me', 'token', 'tokens', 'jwks', 'keys',
  'login', 'logout', 'register', 'forgot', 'reset', 'password', 'refresh', 'verify', 'authorize',
  'session', 'sessions', 'export', 'exports', 'import', 'import-xml', 'restore', 'backup', 'run',
  'preview', 'render', 'template', 'templates', 'report', 'reports', 'summary', 'mine', 'scope',
  'open', 'transfer', 'redeem', 'coupon', 'coupons', 'cart', 'pay', 'checkout', 'receipt',
  'invoice', 'invoices', 'order', 'orders', 'search', 'query', 'find', 'status', 'health',
  'healthz', 'ping', 'version', 'info', 'config', 'settings', 'preferences', 'webhook', 'webhooks',
  'test', 'callback', 'document', 'documents', 'fetch', 'upload', 'download', 'file', 'files',
  'billing', 'charge', 'refund', 'payment', 'payments', 'wallet', 'balance', 'account', 'accounts',
  'transaction', 'transactions', 'oauth', 'connect', 'v1', 'v2', 'support', 'contact', 'feedback'
];
// Resource prefixes to expand with the wordlist (discovered + generic).
const BASE_PREFIXES = [
  'auth', 'admin', 'users', 'reports', 'accounts', 'wallet', 'checkout', 'billing', 'coupons',
  'session', 'webhooks', 'settings', 'documents', 'exports', 'templates', 'support', 'search',
  'status', 'transactions', 'v2', 'oauth', 'integrations', 'payments'
];

function buildCandidates(bundleMap) {
  const set = new Set();
  for (const p of bundleMap.keys()) set.add(p);
  // prefixes = generic list + first segment of every bundle route
  const prefixes = new Set(BASE_PREFIXES);
  for (const p of bundleMap.keys()) { const seg = p.split('/')[2]; if (seg) prefixes.add(seg); }
  for (const w of WORDS) set.add('/api/' + w);                 // top-level resources
  for (const pre of prefixes) { set.add('/api/' + pre); for (const w of WORDS) set.add('/api/' + pre + '/' + w); }
  return [...set];
}

// A response proves a path exists if it is NOT the SPA HTML fallback and NOT a
// hard 404. JSON or an application status (4xx business codes) => real handler.
function isReal(res) {
  if (!res || res.status === 0) return false;
  const ct = res.contentType || '';
  if (/html/.test(ct)) return false;                                   // SPA fallback (200 html) => not real
  if (/json/.test(ct)) return true;
  if ([400, 401, 402, 403, 405, 409, 415, 422].includes(res.status)) return true;
  if (res.status === 200) return true;    // 200 non-html handler (e.g. jwks text/plain, csv, xml)
  return false;                            // 404 or other => not a real endpoint
}

async function probePath(cookie, path) {
  const hits = [];
  for (const method of METHODS) {
    const res = await httpReq(method, path, { cookie, body: method === 'GET' ? undefined : '{}' });
    if (isReal(res)) hits.push({ method, status: res.status, contentType: res.contentType });
  }
  return hits;
}

async function runPool(items, worker) {
  const out = []; let i = 0;
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, items.length) }, async () => {
    while (i < items.length) { const idx = i++; out[idx] = await worker(items[idx]); }
  }));
  return out;
}

// --------------------------------------------------------------------------
// Main
// --------------------------------------------------------------------------
async function main() {
  const cookie = await login();
  if (!cookie) { console.error('Login failed — check creds/URL.'); process.exit(2); }
  console.log(`\nARCH-1 discovery vs ${BASE}  (session: ${cookie ? 'OK' : 'none'})\n`);

  const js = await fetchBundles();
  const bundleMap = parseBundle(js);
  console.log(`(A) bundle parse: ${bundleMap.size} routes referenced in JS`);

  const candidates = buildCandidates(bundleMap);
  console.log(`(B) probing ${candidates.length} candidates x ${METHODS.length} methods ...\n`);

  const results = await runPool(candidates, async (p) => ({ path: p, hits: await probePath(cookie, p) }));

  // Assemble inventory: one row per (path) with the methods that responded.
  const inv = [];
  for (const { path, hits } of results) {
    if (!hits.length) continue;
    const b = bundleMap.get(path);
    const methods = [...new Set(hits.map((h) => h.method))];
    inv.push({
      path,
      methods,
      source: b ? 'bundle+probe' : 'probe',
      status: hits.map((h) => `${h.method}:${h.status}`).join(' '),
      bodyFields: b ? [...b.bodyFields] : []
    });
  }
  inv.sort((a, b) => a.path.localeCompare(b.path));

  for (const r of inv) {
    console.log(`  ${r.methods.join(',').padEnd(16)} ${r.path.padEnd(34)} [${r.source}]${r.bodyFields.length ? '  fields: ' + r.bodyFields.join(', ') : ''}`);
  }
  console.log(`\n──────────────────────────────────────────────`);
  console.log(`  ENDPOINTS DISCOVERED: ${inv.length}`);
  console.log(`──────────────────────────────────────────────\n`);

  fs.writeFileSync(__dirname + '/endpoints.json', JSON.stringify({ base: BASE, at: new Date().toISOString(), count: inv.length, endpoints: inv }, null, 2));
}

main().catch((e) => { console.error(e); process.exit(1); });
