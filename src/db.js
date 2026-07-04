'use strict';

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');

// File-based SQLite so the ORDER BY / string-concat query paths behave like a
// real deployment. Recreated and seeded on every boot for deterministic scans.
const DATA_DIR = path.join(__dirname, '..', 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_PATH = path.join(DATA_DIR, 'meridian.db');

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

function ref(prefix) {
  return prefix + '_' + crypto.randomBytes(9).toString('hex');
}

function seed() {
  db.exec(`
    DROP TABLE IF EXISTS users;
    DROP TABLE IF EXISTS accounts;
    DROP TABLE IF EXISTS invoices;
    DROP TABLE IF EXISTS coupons;
    DROP TABLE IF EXISTS transactions;
    DROP TABLE IF EXISTS webhooks;
    DROP TABLE IF EXISTS audit_log;
    DROP TABLE IF EXISTS support_tickets;
    DROP TABLE IF EXISTS password_resets;

    CREATE TABLE users (
      id           TEXT PRIMARY KEY,
      email        TEXT UNIQUE NOT NULL,
      password     TEXT NOT NULL,
      name         TEXT NOT NULL,
      title        TEXT,
      nickname     TEXT NOT NULL DEFAULT '',
      role         TEXT NOT NULL DEFAULT 'member',
      is_admin     INTEGER NOT NULL DEFAULT 0,
      credits      REAL NOT NULL DEFAULT 0,
      balance      REAL NOT NULL DEFAULT 0,
      api_key      TEXT
    );

    CREATE TABLE accounts (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      account_ref  TEXT UNIQUE NOT NULL,
      owner_email  TEXT NOT NULL,
      label        TEXT NOT NULL,
      balance      REAL NOT NULL DEFAULT 0
    );

    CREATE TABLE invoices (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      doc_ref      TEXT UNIQUE NOT NULL,
      owner_email  TEXT NOT NULL,
      counterparty TEXT NOT NULL,
      amount       REAL NOT NULL,
      status       TEXT NOT NULL,
      private_memo TEXT
    );

    CREATE TABLE coupons (
      code           TEXT PRIMARY KEY,
      discount       REAL NOT NULL,
      remaining_uses INTEGER NOT NULL,
      redeemed_log   TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE transactions (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_email  TEXT NOT NULL,
      kind         TEXT NOT NULL,
      amount       REAL NOT NULL,
      memo         TEXT,
      created_at   TEXT NOT NULL
    );

    CREATE TABLE webhooks (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_email  TEXT NOT NULL,
      target_url   TEXT NOT NULL,
      last_status  TEXT,
      created_at   TEXT NOT NULL
    );

    CREATE TABLE audit_log (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      actor        TEXT,
      action       TEXT,
      client_ip    TEXT,
      user_agent   TEXT,
      created_at   TEXT NOT NULL
    );

    CREATE TABLE support_tickets (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      author_email TEXT NOT NULL,
      subject      TEXT NOT NULL,
      body         TEXT NOT NULL,
      created_at   TEXT NOT NULL
    );

    CREATE TABLE password_resets (
      email        TEXT NOT NULL,
      token        TEXT NOT NULL,
      reset_url    TEXT,
      expires_at   TEXT NOT NULL
    );
  `);

  const insUser = db.prepare(`INSERT INTO users
    (id, email, password, name, title, nickname, role, is_admin, credits, balance, api_key)
    VALUES (@id,@email,@password,@name,@title,@nickname,@role,@is_admin,@credits,@balance,@api_key)`);

  insUser.run({
    id: ref('usr'), email: 'admin@meridian.io', password: 'M3ridian!Admin',
    name: 'Dana Whitfield', title: 'Platform Administrator', nickname: 'dana', role: 'admin',
    is_admin: 1, credits: 100000, balance: 4820500.75, api_key: ref('sk_live')
  });
  insUser.run({
    id: ref('usr'), email: 'alice@meridian.io', password: 'Password123!',
    name: 'Alice Moreno', title: 'Finance Analyst', nickname: 'alice', role: 'member',
    is_admin: 0, credits: 250, balance: 1200.00, api_key: ref('sk_live')
  });
  insUser.run({
    id: ref('usr'), email: 'bob@meridian.io', password: 'M3ridian!Bob2026',
    name: 'Bob Tanaka', title: 'Treasury Lead', nickname: 'bob', role: 'member',
    is_admin: 0, credits: 500, balance: 88450.10, api_key: ref('sk_live')
  });

  const insAcct = db.prepare(`INSERT INTO accounts (account_ref, owner_email, label, balance)
    VALUES (?,?,?,?)`);
  insAcct.run('ACC-4021', 'alice@meridian.io', 'Operating — Alice', 1200.00);
  insAcct.run('ACC-4022', 'bob@meridian.io', 'Treasury — Bob', 88450.10);
  insAcct.run('ACC-0001', 'admin@meridian.io', 'Corporate Reserve', 4820500.75);

  const insInv = db.prepare(`INSERT INTO invoices
    (doc_ref, owner_email, counterparty, amount, status, private_memo)
    VALUES (?,?,?,?,?,?)`);
  insInv.run(ref('doc'), 'alice@meridian.io', 'Cloudstrand LLC', 4200.00, 'paid',
    'Standard vendor invoice.');
  insInv.run(ref('doc'), 'bob@meridian.io', 'Project Halcyon (confidential)', 950000.00, 'pending',
    'CONFIDENTIAL: acquisition escrow, do not disclose. Wire ref 88-XY-2231.');
  insInv.run(ref('doc'), 'admin@meridian.io', 'Board settlement', 2750000.00, 'pending',
    'CONFIDENTIAL: exec bonus pool + settlement terms.');

  const insCoupon = db.prepare(`INSERT INTO coupons (code, discount, remaining_uses)
    VALUES (?,?,?)`);
  insCoupon.run('WELCOME50', 50, 1);
  insCoupon.run('LOYALTY25', 25, 3);

  const insTx = db.prepare(`INSERT INTO transactions
    (owner_email, kind, amount, memo, created_at) VALUES (?,?,?,?,?)`);
  const now = Date.now();
  const rows = [
    ['alice@meridian.io', 'credit', 1200.00, 'Opening balance'],
    ['alice@meridian.io', 'debit', 42.50, 'SaaS subscription'],
    ['alice@meridian.io', 'debit', 130.00, 'Travel reimbursement'],
    ['bob@meridian.io', 'credit', 88450.10, 'Treasury sweep'],
    ['bob@meridian.io', 'debit', 12000.00, 'Vendor payout']
  ];
  rows.forEach((r, i) => {
    insTx.run(r[0], r[1], r[2], r[3], new Date(now - (i + 1) * 3600_000).toISOString());
  });

  db.prepare('INSERT INTO support_tickets (author_email, subject, body, created_at) VALUES (?,?,?,?)')
    .run('bob@meridian.io', 'Export not working', 'The CSV export button does nothing on Safari.',
      new Date(now - 7200_000).toISOString());

  return db.prepare('SELECT email FROM users').all().length;
}

const count = seed();
console.log(`[db] initialized SQLite at ${DB_PATH} (${count} users seeded)`);

module.exports = { db, ref };
