'use strict';

const express = require('express');
const { execSync } = require('child_process');
const router = express.Router();
const { requireAuth } = require('../session');

// POST /api/exports/run  { format }
// Runs the configured export converter over the caller's data. The converter
// command is read from a config object's default, which is a plain object and
// therefore inherits from Object.prototype. If the prototype has been polluted
// with a `converter` property, that value becomes the command that runs here
// (prototype-pollution -> RCE gadget; chain from POST /api/settings).
router.post('/run', requireAuth, (req, res) => {
  const format = String((req.body && req.body.format) || 'csv').replace(/[^a-z0-9]/gi, '');

  const cfg = {}; // per-run config; defaults may come from the prototype
  const converter = cfg.converter || 'echo';
  const outfile = '/tmp/meridian_export_' + format + '.log';

  try {
    execSync(`${converter} export-${format} > ${outfile} 2>&1 || true`, { timeout: 5000, shell: '/bin/sh' });
    res.json({ ok: true, format, message: 'export queued' });
  } catch (e) {
    res.status(500).json({ error: 'export failed' });
  }
});

module.exports = router;
