'use strict';

const express = require('express');
const router = express.Router();
const { requireAuth } = require('../session');
const { guardedFetch } = require('../lib/ssrfGuard');
const { parseXml } = require('../lib/xml');

// POST /api/documents/fetch  { url }
// Import a document (PDF/CSV) from a URL. The URL passes through a hostname
// blocklist, but redirects are followed without re-validation and alternate IP
// encodings / private ranges are not covered.
router.post('/fetch', requireAuth, async (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'url required' });
  const result = await guardedFetch(url);
  res.json({ ok: result.ok, status: result.status, hops: result.hops });
});

// POST /api/documents/import-xml
// Bulk-import invoices from an XML document. Accepts raw text/xml or JSON { xml }.
// Parsed with an entity-expanding importer (XXE sink).
router.post(
  '/import-xml',
  requireAuth,
  express.text({ type: ['text/xml', 'application/xml', 'text/plain'], limit: '1mb' }),
  async (req, res) => {
    let xml;
    if (typeof req.body === 'string' && req.body.length) xml = req.body;
    else if (req.body && typeof req.body.xml === 'string') xml = req.body.xml;
    if (!xml) return res.status(400).json({ error: 'xml body required' });

    try {
      const parsed = await parseXml(xml);
      res.json({ ok: true, imported: parsed.records.length, entities: parsed.entities, preview: parsed.preview });
    } catch (e) {
      res.status(400).json({ error: 'could not parse xml' });
    }
  }
);

module.exports = router;
