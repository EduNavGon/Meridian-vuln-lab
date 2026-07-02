'use strict';

const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');

const { db } = require('./src/db');

const app = express();

// Trust proxy so X-Forwarded-For is read from the header (typical behind Railway's edge).
app.set('trust proxy', true);
// Default query parser (qs) so duplicated query keys become arrays (needed for HPP demo).
app.set('query parser', 'extended');

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CORS: reflect whatever Origin the caller sends and allow credentials. This
// lets any origin make authenticated cross-site requests and read the response.
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
    return res.sendStatus(204);
  }
  next();
});

// ---------------------------------------------------------------------------
// Audit middleware. Records every API call for the "client reputation" feature.
// ---------------------------------------------------------------------------
const { audit } = require('./src/audit');
app.use('/api', (req, res, next) => {
  try { audit(req); } catch (e) { /* audit failures never block a request */ }
  next();
});

// ---------------------------------------------------------------------------
// API routes
// ---------------------------------------------------------------------------
app.use('/api/auth', require('./src/routes/auth'));
app.use('/api/users', require('./src/routes/users'));
app.use('/api/wallet', require('./src/routes/wallet'));
app.use('/api/coupons', require('./src/routes/coupons'));
app.use('/api/reports', require('./src/routes/reports'));
app.use('/api/webhooks', require('./src/routes/webhooks'));
app.use('/api/settings', require('./src/routes/settings'));
app.use('/api/admin', require('./src/routes/admin'));
app.use('/api/session', require('./src/routes/restore'));
app.use('/api/accounts', require('./src/routes/accounts'));
app.use('/api/checkout', require('./src/routes/checkout'));
app.use('/api/transactions', require('./src/routes/transactions'));

// Additional API surface (advanced vulnerability set)
app.use('/api/documents', require('./src/routes/documents'));   // SSRF bypass + XXE
app.use('/api/exports', require('./src/routes/exports'));       // prototype pollution -> RCE
app.use('/api/templates', require('./src/routes/templates'));   // SSTI -> RCE
app.use('/api/auth', require('./src/routes/token'));            // JWT issue + JWKS
app.use('/api/auth', require('./src/routes/password'));         // reset poisoning + weak token
app.use('/api/v2', require('./src/routes/v2'));                 // JWT-protected admin
app.use('/api/support', require('./src/routes/support'));       // stored XSS source

// Health check for Railway.
app.get('/healthz', (req, res) => res.json({ status: 'ok', service: 'meridian-ledger' }));

// Static frontend.
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[meridian] listening on 0.0.0.0:${PORT}`);
  if (process.env.LAB_MODE !== '0') {
    console.log('[meridian] LAB MODE — intentionally vulnerable target. Do not expose to untrusted networks.');
  }
});
