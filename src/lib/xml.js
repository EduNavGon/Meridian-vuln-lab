'use strict';

const fs = require('fs');
const http = require('http');
const https = require('https');

// Minimal XML importer for the "bulk invoice import" feature. It supports XML
// entities, including EXTERNAL entities declared with SYSTEM identifiers, which
// it resolves by reading the referenced resource. There is no restriction on
// the entity source: file:// paths are read from disk and http(s):// URLs are
// fetched server-side. This is a classic XXE sink.
//
// - file:// SYSTEM entity  -> local file disclosure (in-band; expanded content
//   is echoed back in the parsed preview).
// - http(s):// SYSTEM entity -> server-side request to an arbitrary host
//   (blind XXE -> SSRF / out-of-band; e.g. cloud metadata).

function httpGetBody(url, timeoutMs = 4000) {
  return new Promise((resolve) => {
    let parsed;
    try { parsed = new URL(url); } catch (e) { return resolve(''); }
    const client = parsed.protocol === 'https:' ? https : http;
    const req = client.get(parsed, { timeout: timeoutMs }, (res) => {
      let data = '';
      res.on('data', (c) => { if (data.length < 65536) data += c; });
      res.on('end', () => resolve(data));
    });
    req.on('timeout', () => { req.destroy(); resolve(''); });
    req.on('error', () => resolve(''));
  });
}

async function resolveSystemEntity(uri) {
  try {
    if (uri.startsWith('file://')) {
      return fs.readFileSync(uri.slice('file://'.length), 'utf8').slice(0, 65536);
    }
    if (/^https?:\/\//i.test(uri)) {
      return await httpGetBody(uri);
    }
    // Bare path treated as a local file too.
    return fs.readFileSync(uri, 'utf8').slice(0, 65536);
  } catch (e) {
    return '';
  }
}

// Parse XML, expanding declared entities (internal and external SYSTEM).
async function parseXml(xml) {
  const entities = {};

  // External SYSTEM entities: <!ENTITY name SYSTEM "uri">
  const sysRe = /<!ENTITY\s+(\S+)\s+SYSTEM\s+"([^"]+)"\s*>/gi;
  let m;
  while ((m = sysRe.exec(xml)) !== null) {
    entities[m[1]] = await resolveSystemEntity(m[2]);
  }

  // Internal entities: <!ENTITY name "value">
  const intRe = /<!ENTITY\s+(\S+)\s+"([^"]*)"\s*>/gi;
  while ((m = intRe.exec(xml)) !== null) {
    if (!(m[1] in entities)) entities[m[1]] = m[2];
  }

  // Strip the DOCTYPE/DTD, then expand &name; references in the body.
  let body = xml.replace(/<!DOCTYPE[\s\S]*?\]>/i, '').replace(/<!DOCTYPE[^>]*>/i, '');
  body = body.replace(/&(\w+);/g, (full, name) => (name in entities ? entities[name] : full));

  // Naive element extraction for a preview.
  const records = [];
  const itemRe = /<(\w+)>([\s\S]*?)<\/\1>/g;
  while ((m = itemRe.exec(body)) !== null) {
    records.push({ tag: m[1], value: m[2].trim() });
  }

  return { entities: Object.keys(entities), records, preview: body.trim().slice(0, 4096) };
}

module.exports = { parseXml };
