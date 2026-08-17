/**
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║   CLOUD BANK & MERCHANT STORE — BUG HUNTING MASTERY PLATFORM v4.0            ║
 * ║   ⚠ FOR AUTHORIZED SECURITY ASSESSMENTS & BURP SUITE TRAINING ONLY ⚠        ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║  Complete Enterprise Real-World Vulnerability Target Application             ║
 * ║  Covers 18+ Vulnerability Classes across 40 Weeks of Bug Hunting Roadmap.     ║
 * ║  Features: REST APIs, GraphQL, OAuth 2.0 Server, XML XXE Engine,           ║
 * ║  Race Condition Handler, JWT Exploitation, SQLi, XSS, SSRF, CORS, IDOR.     ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 */

'use strict';

const express = require('express');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const { URL } = require('url');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Secrets & Keys
const JWT_SECRET = 'banking123';
const JWT_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu...'; // HMAC vs RSA key confusion target
const VALID_API_KEYS = ['sk_live_abcdef1234567890', 'sk_test_0000000000000000', 'sk_live_BankAdmin2024Key!'];

// State Management
let globalDifficulty = 'EASY'; // EASY, MEDIUM, HARD
const csrfTokens = new Map();
const rateLimitStore = new Map();
const oauthCodes = new Map();
const httpLog = [];

// ──────────────────────────────────────────────
//  REAL-TIME HTTP TRAFFIC CAPTURE (Burp-Style)
//  Every request/response is captured raw so the
//  UI console can replay it exactly like Burp Proxy.
// ──────────────────────────────────────────────

app.use((req, res, next) => {
  const reqId = crypto.randomBytes(8).toString('hex');
  const started = Date.now();
  res.setHeader('X-Request-Id', reqId);
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');

  const entry = {
    id: reqId,
    timestamp: new Date().toISOString(),
    source_ip: req.headers['x-forwarded-for'] || req.headers['client-ip'] || req.socket.remoteAddress || 'unknown',
    method: req.method,
    url: req.originalUrl,
    http_version: 'HTTP/' + req.httpVersion,
    request_headers: req.rawHeaders,
    request_body: '',
    response: null
  };

  const inChunks = [];
  req.on('data', c => inChunks.push(c));
  req.on('end', () => { entry.request_body = Buffer.concat(inChunks).toString('utf8'); });

  const origWrite = res.write;
  const origEnd = res.end;
  const outChunks = [];
  res.write = function (chunk) {
    if (chunk !== undefined && chunk !== null) outChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    return origWrite.apply(this, arguments);
  };
  res.end = function (chunk) {
    if (chunk !== undefined && chunk !== null) outChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    return origEnd.apply(this, arguments);
  };

  res.on('finish', () => {
    entry.duration_ms = Date.now() - started;
    entry.response = {
      status: res.statusCode,
      status_text: res.statusMessage || '',
      http_version: 'HTTP/' + res.httpVersion,
      headers: res.getHeaders(),
      body: Buffer.concat(outChunks).toString('utf8')
    };
    httpLog.unshift(entry);
    if (httpLog.length > 40) httpLog.length = 40;
  });

  next();
});

// ──────────────────────────────────────────────────────────────
//  MIDDLEWARE
// ──────────────────────────────────────────────────────────────

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Raw Text Middleware for XXE XML Parsing
app.use('/api/v1/invoice/xml', express.text({ type: ['application/xml', 'text/xml', '*/*'] }));

// Dynamic Difficulty & Custom Header Handler
app.use((req, res, next) => {
  const diffHeader = req.headers['x-difficulty-level'] || req.query.difficulty;
  if (diffHeader && ['EASY', 'MEDIUM', 'HARD'].includes(diffHeader.toUpperCase())) {
    req.difficulty = diffHeader.toUpperCase();
  } else {
    req.difficulty = globalDifficulty;
  }

  // Dynamic CORS Handling (CORS Misconfiguration Target)
  const origin = req.headers['origin'];
  if (origin) {
    if (req.difficulty === 'EASY') {
      // Arbitrary origin trust + credentials
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    } else if (req.difficulty === 'MEDIUM') {
      // Trust null origin or subdomains
      if (origin === 'null' || origin.includes('cloudbank')) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
      } else {
        res.setHeader('Access-Control-Allow-Origin', '*');
      }
    } else {
      res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');
    }
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }

  res.setHeader('X-Powered-By', 'CloudBank-Enterprise/4.0');
  res.setHeader('Server', 'nginx/1.24.0');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=(), payment=()');
  res.setHeader('X-Difficulty-Level', req.difficulty);
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key, X-CSRF-Token, X-Forwarded-For, Client-IP, X-Difficulty-Level');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  next();
});

app.options('*', (req, res) => res.sendStatus(204));

// CSRF Protection — enforced ONLY in HARD mode.
// In EASY/MEDIUM the bank trusts any state-changing request (CSRF vulnerability).
// In HARD mode a valid X-CSRF-Token header is required (fetch via GET /api/v1/csrf-token).
function enforceCsrf(req, res, next) {
  if (req.difficulty === 'HARD' && !['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    const exempt = ['/api/v1/auth/login', '/api/v1/difficulty', '/oauth/token'];
    if (!exempt.some(p => req.path.startsWith(p))) {
      const token = req.headers['x-csrf-token'];
      if (!token || !csrfTokens.has(token)) {
        return res.status(403).json({
          status: 'error',
          code: 'CSRF_TOKEN_MISSING',
          message: 'A valid X-CSRF-Token header is required for this request.',
          hint: 'Fetch a token from GET /api/v1/csrf-token and include it as X-CSRF-Token.'
        });
      }
    }
  }
  next();
}
app.use(enforceCsrf);

// ──────────────────────────────────────────────────────────────
//  IN-MEMORY SQLITE DATABASE SETUP & SEEDING
// ──────────────────────────────────────────────────────────────

let db;
try {
  db = new Database(':memory:');
} catch (e) {
  db = new Database(path.join(__dirname, 'cloudbank.db'));
}

db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password      TEXT NOT NULL,
    email         TEXT,
    role          TEXT DEFAULT 'customer',
    account_no    TEXT UNIQUE,
    balance       REAL DEFAULT 0.0,
    pin_2fa       TEXT,
    bio           TEXT,
    avatar        TEXT DEFAULT 'default.png',
    created_at    TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE cards (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER,
    card_number   TEXT NOT NULL,
    cvv           TEXT NOT NULL,
    exp_month     TEXT NOT NULL,
    exp_year      TEXT NOT NULL,
    card_type     TEXT DEFAULT 'VISA',
    status        TEXT DEFAULT 'active',
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE transfer_routes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    account_no    TEXT NOT NULL,
    routing_code  TEXT NOT NULL,
    bank_name     TEXT,
    status        TEXT DEFAULT 'verified'
  );

  CREATE TABLE documents (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER,
    doc_type      TEXT NOT NULL,
    filename      TEXT NOT NULL,
    content       TEXT,
    classification TEXT DEFAULT 'confidential',
    created_at    TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE support_tickets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER,
    subject       TEXT NOT NULL,
    message       TEXT NOT NULL,
    status        TEXT DEFAULT 'open',
    created_at    TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE products (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    price         REAL NOT NULL,
    stock         INTEGER DEFAULT 100
  );

  CREATE TABLE merchants (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    merchant_id   TEXT UNIQUE NOT NULL,
    name          TEXT NOT NULL,
    api_key       TEXT NOT NULL,
    webhook_url   TEXT,
    status        TEXT DEFAULT 'active'
  );

  CREATE TABLE audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    action        TEXT,
    details       TEXT,
    ip_address    TEXT,
    timestamp     TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE transactions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    from_account  TEXT,
    to_account    TEXT,
    amount        REAL NOT NULL,
    description   TEXT,
    status        TEXT DEFAULT 'completed',
    reference     TEXT,
    created_at    TEXT DEFAULT (datetime('now'))
  );
`);

function seedDB() {
  // Users
  const insertUser = db.prepare(`INSERT INTO users (username, password, email, role, account_no, balance, pin_2fa, bio) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
  [
    ['admin',        'admin123',       'admin@cloudbank.io',     'admin',    'ACC_1001', 999999.99, '1337', 'System Admin'],
    ['john.doe',     'password123',    'john@example.com',       'customer', 'ACC_2001', 1000.00,   '4829', 'Regular Customer'],
    ['jane.smith',   'qwerty',         'jane@example.com',       'customer', 'ACC_2002', 87230.00,  '1234', 'VIP Member'],
    ['bob.merchant', 'merchant2024',   'bob@merchant.io',        'merchant', 'ACC_3001', 250000.00, '0000', 'Shop Operator'],
    ['alice.vip',    'letmein',        'alice@vipbank.com',      'vip',      'ACC_4001', 1500000.00,'7777', 'Investor'],
    ['test.user',    'test',           'test@cloudbank.io',      'customer', 'ACC_5001', 500.00,    '9999', 'Tester'],
  ].forEach(u => insertUser.run(...u));

  // Cards
  const insertCard = db.prepare(`INSERT INTO cards (user_id, card_number, cvv, exp_month, exp_year, card_type, status) VALUES (?, ?, ?, ?, ?, ?, ?)`);
  [
    [2, '4111111111111111', '737', '09', '2027', 'VISA',       'active'],
    [2, '4111111111112222', '123', '03', '2026', 'VISA',       'expired'],
    [3, '5500000000000004', '456', '12', '2028', 'MASTERCARD', 'active'],
    [4, '378282246310005',  '9012','06', '2027', 'AMEX',       'active'],
    [5, '4222222222222',    '321', '11', '2026', 'VISA',       'active'],
  ].forEach(c => insertCard.run(...c));

  // Transfer Routes
  const insertRoute = db.prepare(`INSERT INTO transfer_routes (account_no, routing_code, bank_name, status) VALUES (?, ?, ?, ?)`);
  [
    ['ACC_2001', 'ROUTE_7001', 'First National Bank',      'verified'],
    ['ACC_2002', 'ROUTE_7002', 'Metro Credit Union',       'verified'],
    ['ACC_3001', 'ROUTE_7003', 'Commerce Trust',           'verified'],
    ['ACC_4001', 'ROUTE_7004', 'Elite Private Banking',    'verified'],
    ['ACC_5001', 'ROUTE_7005', 'Community Savings',        'verified'],
    ['ACC_1001', 'ROUTE_9999', 'CloudBank Internal',       'restricted'],
  ].forEach(r => insertRoute.run(...r));

  // Documents
  const insertDoc = db.prepare(`INSERT INTO documents (user_id, doc_type, filename, content, classification) VALUES (?, ?, ?, ?, ?)`);
  [
    [1, 'system',    'admin_credentials.txt',    'Master DB Secret: Sup3rS3cretDB!2024\nSSH Key Passphrase: cl0udb4nk_ssh', 'top-secret'],
    [1, 'config',    'api_keys_internal.json',   '{"stripe_sk":"sk_live_realkey123","aws_access":"AKIA1234567890ABCDEF"}', 'top-secret'],
    [2, 'statement', 'john_statement_2024.pdf',  'Account: ACC_2001 | Balance: $1,000.00 | SSN: 123-45-6789', 'confidential'],
    [3, 'statement', 'jane_statement_2024.pdf',  'Account: ACC_2002 | Balance: $87,230.00 | SSN: 987-65-4321', 'confidential'],
    [4, 'contract',  'merchant_agreement.pdf',   'Merchant ID: MERCH_001 | Fee Rate: 2.9% + $0.30', 'restricted'],
    [5, 'kyc',       'alice_passport_scan.jpg',  '[PASSPORT_BINARY_DATA] DOB: 1985-03-15 | Passport: X12345678', 'top-secret'],
  ].forEach(d => insertDoc.run(...d));

  // Products
  const insertProd = db.prepare(`INSERT INTO products (name, price, stock) VALUES (?, ?, ?)`);
  [
    ['Hardware Crypto Wallet', 199.99, 50],
    ['Premium Security Key', 45.00, 200],
    ['CloudBank Gold Subscription', 9.99, 999]
  ].forEach(p => insertProd.run(...p));

  // Merchants
  const insertMerchant = db.prepare(`INSERT INTO merchants (merchant_id, name, api_key, webhook_url, status) VALUES (?, ?, ?, ?, ?)`);
  [
    ['MERCH_001', 'ShopMax Global',     'sk_live_abcdef1234567890', 'https://shopmax.io/webhook',  'active'],
    ['MERCH_002', 'PayQuick Services',  'sk_test_0000000000000000', 'https://payquick.io/webhook', 'active'],
    ['MERCH_003', 'BankAdmin Internal', 'sk_live_BankAdmin2024Key!','http://127.0.0.1:3000/api/v1/admin/panel', 'active'],
  ].forEach(m => insertMerchant.run(...m));

  // Transactions (realistic ledger history)
  const insertTxn = db.prepare(`INSERT INTO transactions (from_account, to_account, amount, description, status, reference, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`);
  [
    ['ACC_2001', 'ACC_3001', 249.99, 'Crypto Wallet Purchase',           'completed', 'TXN_9F3K2Q7X', '2026-08-16 14:22:10'],
    ['ACC_2002', 'ACC_2001', 320.00, 'Split Lunch Reimbursement',        'completed', 'TXN_1B8D4M2L', '2026-08-16 09:05:41'],
    ['ACC_1001', 'ACC_2001', 1500.00,'Monthly Payroll Deposit',          'completed', 'TXN_4C2Z9P7N', '2026-08-15 10:00:00'],
    ['ACC_2001', 'ACC_2002', 85.50,  'Utility Bill - Metro Power',       'completed', 'TXN_7H1X5W3R', '2026-08-14 18:47:33'],
    ['ACC_3001', 'ACC_2001', 612.00, 'Store Settlement - ShopMax',      'completed', 'TXN_2J9V3K8B', '2026-08-13 23:59:59'],
    ['ACC_2001', 'ACC_4001', 40.00,  'Investment Contribution',         'completed', 'TXN_5Q6E1T8N', '2026-08-12 16:30:22'],
    ['ACC_2002', 'ACC_5001', 12.99,  'Streaming Subscription Renewal',  'completed', 'TXN_8M3A7C2D', '2026-08-11 07:12:08'],
    ['ACC_2001', 'ACC_3001', 199.99, 'Hardware Crypto Wallet',          'completed', 'TXN_6W4Y2U9P', '2026-08-10 20:15:45'],
    ['ACC_4001', 'ACC_2001', 2500.00,'Dividend Payout - Q2',            'completed', 'TXN_3E9R5T1H', '2026-08-09 11:00:00'],
    ['ACC_2001', 'ACC_2002', 75.00,  'Family Dinner Transfer',          'completed', 'TXN_0B6V4C8X', '2026-08-08 19:22:17'],
  ].forEach(t => insertTxn.run(...t));
}

seedDB();

// ──────────────────────────────────────────────────────────────
//  HELPER FUNCTIONS & PRNG
// ──────────────────────────────────────────────────────────────

class WeakPRNG {
  constructor(seed) { this.state = seed || 123456789; }
  next() { this.state = (this.state * 1103515245 + 12345) & 0x7fffffff; return this.state; }
  nextHex(bytes) {
    let result = '';
    for (let i = 0; i < bytes; i++) { result += (this.next() & 0xff).toString(16).padStart(2, '0'); }
    return result;
  }
}
const weakPrng = new WeakPRNG(123456789);

function generateCsrfToken(sessionId) {
  const token = Buffer.from(`csrf_${Date.now()}_${sessionId}`).toString('base64');
  csrfTokens.set(token, { sessionId, createdAt: Date.now() });
  return token;
}

function rateLimit(maxRequests, windowMs) {
  return (req, res, next) => {
    const clientIP = req.headers['x-forwarded-for']
      || req.headers['client-ip']
      || req.headers['x-real-ip']
      || req.socket.remoteAddress;

    const now = Date.now();
    let entry = rateLimitStore.get(clientIP);
    if (!entry || now > entry.resetAt) {
      entry = { count: 0, resetAt: now + windowMs };
      rateLimitStore.set(clientIP, entry);
    }
    entry.count++;
    res.setHeader('X-RateLimit-Limit', maxRequests);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, maxRequests - entry.count));
    res.setHeader('X-RateLimit-Reset', new Date(entry.resetAt).toISOString());
    res.setHeader('X-RateLimit-ClientIP', clientIP);

    if (entry.count > maxRequests) {
      return res.status(429).json({
        status: 'error',
        code: 'RATE_LIMIT_EXCEEDED',
        message: `Too many requests from ${clientIP}. Rotate X-Forwarded-For header to bypass limit.`,
        detected_ip: clientIP
      });
    }
    next();
  };
}

function authenticateJWT(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ status: 'error', code: 'AUTH_REQUIRED', message: 'Missing Authorization header.' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const parts = token.split('.');
    if (parts.length >= 2) {
      try {
        const headerDecoded = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
        // JWT 'none' Algorithm Vulnerability
        if (headerDecoded.alg && headerDecoded.alg.toLowerCase() === 'none') {
          const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
          req.user = payload;
          return next();
        }
      } catch (e) {}
    }

    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'HS384', 'HS512'] });
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ status: 'error', code: 'INVALID_TOKEN', message: 'JWT verification failed.', details: err.message });
  }
}

// ──────────────────────────────────────────────────────────────
//  DIFFICULTY CONTROL & UTILITY ENDPOINTS
// ──────────────────────────────────────────────────────────────

app.get('/api/v1/difficulty', (req, res) => res.json({ status: 'success', difficulty: globalDifficulty }));

app.post('/api/v1/difficulty', (req, res) => {
  const { level } = req.body;
  if (['EASY', 'MEDIUM', 'HARD'].includes(level)) {
    globalDifficulty = level;
    return res.json({ status: 'success', message: `Difficulty set to ${globalDifficulty}`, difficulty: globalDifficulty });
  }
  res.status(400).json({ status: 'error', message: 'Invalid level.' });
});

app.get('/api/v1/csrf-token', (req, res) => {
  const token = generateCsrfToken('sess_' + (req.cookies.session_id || 'anon'));
  res.json({ status: 'success', csrf_token: token });
});

// Open Redirect Endpoint (Week 15 Roadmap Target)
app.get('/api/v1/redirect', (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).send('url parameter required.');
  
  // Vulnerable redirect
  if (req.difficulty === 'EASY') {
    return res.redirect(url);
  } else if (req.difficulty === 'MEDIUM') {
    // Naive bypass check
    if (url.startsWith('/') || url.includes('cloudbank')) {
      return res.redirect(url);
    }
    return res.redirect(url); // Bypassed with //evil.com or https://cloudbank.com.evil.com
  }
  res.redirect(url);
});

// ──────────────────────────────────────────────────────────────
//  1. AUTHENTICATION & ENUMERATION (Sniper / Battering Ram Target)
// ──────────────────────────────────────────────────────────────

app.post('/api/v1/auth/login', (req, res) => {
  let { username, password } = req.body;
  const level = req.difficulty;

  if (!username || !password) {
    return res.status(400).json({ status: 'error', message: 'Username and password required.' });
  }

  if (level === 'MEDIUM') {
    username = username.replace(/\s+/g, '');
  } else if (level === 'HARD') {
    if (/'\s*(OR|AND|UNION|SELECT)/i.test(username) && !/\/\*.*\*\//.test(username)) {
      return res.status(403).json({ status: 'error', code: 'WAF_BLOCKED', message: 'WAF Rule #8042 Blocked Request.' });
    }
  }

  let user;
  try {
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    user = db.prepare(query).get();
  } catch (err) {
    return res.status(500).json({ status: 'error', code: 'SQL_ERROR', message: err.message, query_attempted: `SELECT * FROM users WHERE username = '${username}'` });
  }

  if (!user) {
    const exists = db.prepare(`SELECT id FROM users WHERE username = ?`).get(username);
    if (exists) {
      return res.status(401).json({ status: 'error', code: 'INVALID_PASSWORD', message: `Incorrect password for user '${username}'.` });
    }
    return res.status(401).json({ status: 'error', code: 'USER_NOT_FOUND', message: `User account '${username}' does not exist.` });
  }

  const token = jwt.sign(
    { user_id: user.id, username: user.username, email: user.email, role: user.role, account_no: user.account_no },
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: '24h' }
  );

  const csrfToken = generateCsrfToken(user.username);

  const cardCount = db.prepare('SELECT COUNT(*) AS c FROM cards WHERE user_id = ?').get(user.id).c;
  const txnCount = db.prepare('SELECT COUNT(*) AS c FROM transactions WHERE from_account = ? OR to_account = ?').get(user.account_no, user.account_no).c;
  const docCount = db.prepare('SELECT COUNT(*) AS c FROM documents WHERE user_id = ?').get(user.id).c;

  res.json({
    status: 'success',
    message: `Logged in as ${user.username}`,
    data: {
      token,
      csrf_token: csrfToken,
      session_id: crypto.randomBytes(16).toString('hex'),
      server_time: new Date().toISOString(),
      user: { id: user.id, username: user.username, email: user.email, role: user.role, account_no: user.account_no, balance: user.balance },
      account_summary: { cards: cardCount, transactions: txnCount, documents: docCount }
    }
  });
});

// Logout — invalidate the current session (realistic session termination)
app.post('/api/v1/auth/logout', authenticateJWT, (req, res) => {
  const token = req.headers['authorization'].split(' ')[1];
  res.clearCookie('cb_session');
  res.json({
    status: 'success',
    message: 'Logged out successfully.',
    data: { session_terminated: true, token_revoked: token.substring(0, 12) + '...' }
  });
});

// 2FA Reset (Sniper Mode & X-Forwarded-For Rate Limit Bypass)
app.post('/api/v1/auth/2fa-reset', rateLimit(5, 60000), (req, res) => {
  const { username, pin } = req.body;
  if (!username || !pin) return res.status(400).json({ status: 'error', message: 'Username and 4-digit PIN required.' });

  const user = db.prepare('SELECT id, pin_2fa FROM users WHERE username = ?').get(username);
  if (!user) return res.status(404).json({ status: 'error', message: 'User not found.' });

  if (pin === user.pin_2fa) {
    return res.json({ status: 'success', message: '2FA PIN reset successful.', recovery_code: crypto.randomBytes(8).toString('hex') });
  }
  res.status(401).json({ status: 'error', code: 'INVALID_PIN', message: 'Incorrect PIN.' });
});

// ──────────────────────────────────────────────────────────────
//  2. INTRUDER MODES (Pitchfork, Cluster Bomb, Battering Ram)
// ──────────────────────────────────────────────────────────────

// Transfer Verify (Pitchfork Mode: target_account x routing_code)
app.post('/api/v1/transfer/verify', authenticateJWT, (req, res) => {
  const { target_account, routing_code } = req.body;
  if (!target_account || !routing_code) return res.status(400).json({ status: 'error', message: 'target_account and routing_code required.' });

  const route = db.prepare(`SELECT * FROM transfer_routes WHERE account_no = ? AND routing_code = ? AND status = 'verified'`).get(target_account, routing_code);
  if (route) {
    return res.json({ status: 'success', message: 'Transfer route verified.', data: { account: route.account_no, routing: route.routing_code, bank: route.bank_name, status: 'CONFIRMED' } });
  }

  const accExists = !!db.prepare('SELECT id FROM transfer_routes WHERE account_no = ?').get(target_account);
  const routeExists = !!db.prepare('SELECT id FROM transfer_routes WHERE routing_code = ?').get(routing_code);
  res.status(404).json({ status: 'error', code: 'INVALID_PAIR', debug: { account_found: accExists, routing_found: routeExists } });
});

// Card Validate (Cluster Bomb Mode: card_number x cvv x exp_month)
app.post('/api/v1/card/validate', authenticateJWT, (req, res) => {
  const { card_number, cvv, exp_month } = req.body;
  if (!card_number || !cvv || !exp_month) return res.status(400).json({ status: 'error', message: 'card_number, cvv, and exp_month required.' });

  const card = db.prepare(`SELECT c.*, u.username FROM cards c JOIN users u ON c.user_id = u.id WHERE c.card_number = ? AND c.cvv = ? AND c.exp_month = ? AND c.status = 'active'`).get(card_number, cvv, exp_month);
  if (card) return res.json({ status: 'success', message: 'Card valid.', data: { type: card.card_type, last_four: card.card_number.slice(-4), cardholder: card.username } });

  const cardExists = db.prepare('SELECT id, status FROM cards WHERE card_number = ?').get(card_number);
  const cvvMatch = db.prepare('SELECT id FROM cards WHERE card_number = ? AND cvv = ?').get(card_number, cvv);

  let code = 'CARD_NOT_FOUND';
  if (cardExists) {
    if (cardExists.status !== 'active') code = 'CARD_INACTIVE';
    else if (!cvvMatch) code = 'CVV_MISMATCH';
    else code = 'EXP_MISMATCH';
  }
  res.status(403).json({ status: 'error', code });
});

// Merchant Pay (Battering Ram Mode & API Key Timing Side-Channel)
app.post('/api/v1/merchant/pay', (req, res) => {
  const apiKey = req.headers['x-api-key'];
  const { merchant_id, amount } = req.body;
  if (!apiKey || !merchant_id || !amount) return res.status(400).json({ status: 'error', message: 'X-API-Key header, merchant_id, and amount required.' });

  let valid = VALID_API_KEYS.includes(apiKey);
  if (!valid) {
    let maxMatch = 0;
    VALID_API_KEYS.forEach(k => {
      let m = 0;
      for (let i = 0; i < Math.min(apiKey.length, k.length); i++) { if (apiKey[i] === k[i]) m++; else break; }
      maxMatch = Math.max(maxMatch, m);
    });
    return res.status(403).json({ status: 'error', code: 'INVALID_API_KEY', prefix_match_length: maxMatch });
  }

  const merchant = db.prepare('SELECT * FROM merchants WHERE merchant_id = ? AND api_key = ?').get(merchant_id, apiKey);
  if (!merchant) return res.status(404).json({ status: 'error', message: 'Merchant ID mismatch.' });
  res.json({ status: 'success', message: 'Payment processed.', transaction_id: 'TXN_' + Date.now() });
});

// ──────────────────────────────────────────────────────────────
//  3. SQL INJECTION (Union, Blind Time-Based & Second-Order)
// ──────────────────────────────────────────────────────────────

// Union SQLi & Search
app.get('/api/v1/user/search', (req, res) => {
  const { q } = req.query;
  if (!q) return res.status(400).json({ status: 'error', message: 'q parameter required.' });

  try {
    const query = `SELECT id, username, email, role FROM users WHERE username LIKE '%${q}%' OR email LIKE '%${q}%'`;
    const results = db.prepare(query).all();
    res.json({ status: 'success', query_executed: query, results });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message, attempted: q });
  }
});

// Blind Time-Based SQLi (Merchant Search Target)
app.get('/api/v1/merchant/search', (req, res) => {
  const { name } = req.query;
  if (!name) return res.status(400).json({ status: 'error', message: 'name parameter required.' });

  // Simulate SQL SLEEP payload detection
  if (name.includes('SLEEP(') || name.includes('WAITFOR DELAY')) {
    const match = name.match(/SLEEP\((\d+)\)/i);
    const sleepTime = match ? parseInt(match[1]) * 1000 : 3000;
    setTimeout(() => {
      res.json({ status: 'success', message: 'Merchant search complete (delayed).', results: [] });
    }, Math.min(sleepTime, 10000));
    return;
  }

  try {
    const results = db.prepare(`SELECT * FROM merchants WHERE name LIKE '%${name}%'`).all();
    res.json({ status: 'success', results });
  } catch (err) {
    res.status(500).json({ status: 'error', message: 'Search execution error.' });
  }
});

// Second-Order SQLi (Update Profile Bio -> Triggered in Admin Audit Log)
app.put('/api/v1/user/bio', authenticateJWT, (req, res) => {
  const { bio } = req.body;
  if (!bio) return res.status(400).json({ status: 'error', message: 'bio required.' });

  db.prepare('UPDATE users SET bio = ? WHERE id = ?').run(bio, req.user.user_id);
  // Log entry with second order payload stored in DB
  db.prepare('INSERT INTO audit_log (action, details, ip_address) VALUES (?, ?, ?)').run('UPDATE_BIO', `Bio payload stored: ${bio}`, req.ip);

  res.json({ status: 'success', message: 'Profile bio updated.', bio });
});

// ──────────────────────────────────────────────────────────────
//  4. XSS (Reflected, Stored, DOM-based)
// ──────────────────────────────────────────────────────────────

app.get('/api/v1/search/reflect', (req, res) => {
  const { query } = req.query;
  const level = req.difficulty;
  let term = query || '';

  if (level === 'MEDIUM') {
    term = term.replace(/<script>/gi, ''); // Naive XSS filter
  } else if (level === 'HARD') {
    // CSP hardening — inline script injection blocked, requires a CSP bypass
    res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; font-src 'none'");
  }

  res.send(`
    <html>
      <head><meta charset="utf-8"><title>Apex Global Bank — Search</title></head>
      <body style="background:#0f172a; color:#f8fafc; font-family:sans-serif; padding:2rem;">
        <h3>Search Results for: ${term}</h3>
        <p>No records found matching your term.</p>
        <a href="/" style="color:#38bdf8;">Return to Dashboard</a>
      </body>
    </html>
  `);
});

// Stored XSS — Support Ticket System
app.post('/api/v1/ticket/create', authenticateJWT, (req, res) => {
  const { subject, message } = req.body;
  if (!subject || !message) return res.status(400).json({ status: 'error', message: 'subject and message required.' });

  db.prepare('INSERT INTO support_tickets (user_id, subject, message) VALUES (?, ?, ?)').run(req.user.user_id, subject, message);
  res.json({ status: 'success', message: 'Support ticket submitted.', ticket: { subject, message } });
});

app.get('/api/v1/ticket/list', authenticateJWT, (req, res) => {
  const tickets = db.prepare('SELECT * FROM support_tickets WHERE user_id = ?').all(req.user.user_id);
  res.json({ status: 'success', tickets });
});

// ──────────────────────────────────────────────────────────────
//  5. BUSINESS LOGIC, RACE CONDITION & PRICE TAMPERING
// ──────────────────────────────────────────────────────────────

// Race Condition Endpoint (Parallel Transfer / Double Withdrawal)
app.post('/api/v1/transfer/race', authenticateJWT, async (req, res) => {
  const { to_account, amount } = req.body;
  const userId = req.user.user_id;

  if (!to_account || !amount || amount <= 0) {
    return res.status(400).json({ status: 'error', message: 'Invalid to_account or amount.' });
  }

  const user = db.prepare('SELECT id, balance, account_no FROM users WHERE id = ?').get(userId);
  
  if (user.balance >= amount) {
    // Artificial Async Delay to expose Race Condition window
    await new Promise(r => setTimeout(r, 250));

    // Deduct balance & transfer
    db.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').run(amount, userId);
    db.prepare('UPDATE users SET balance = balance + ? WHERE account_no = ?').run(amount, to_account);

    const updated = db.prepare('SELECT balance FROM users WHERE id = ?').get(userId);
    const reference = 'TXN_' + Date.now().toString(36).toUpperCase() + crypto.randomBytes(2).toString('hex').toUpperCase();
    db.prepare('INSERT INTO transactions (from_account, to_account, amount, description, status, reference) VALUES (?, ?, ?, ?, ?, ?)')
      .run(user.account_no, to_account, amount, 'Online Wire Transfer', 'completed', reference);
    return res.json({
      status: 'success',
      message: 'Transfer completed.',
      data: {
        reference,
        timestamp: new Date().toISOString(),
        amount,
        to_account,
        remaining_balance: updated.balance
      }
    });
  }

  res.status(400).json({ status: 'error', message: 'Insufficient funds.', current_balance: user.balance });
});

// Price Tampering & Negative Balance Checkout
app.post('/api/v1/store/checkout', authenticateJWT, (req, res) => {
  const { product_id, quantity, unit_price } = req.body;
  const userId = req.user.user_id;

  if (!product_id || !quantity) return res.status(400).json({ status: 'error', message: 'product_id and quantity required.' });

  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(product_id);
  if (!product) return res.status(404).json({ status: 'error', message: 'Product not found.' });

  // Vulnerability: Accepts client-supplied price or negative quantity
  const finalPrice = unit_price !== undefined ? parseFloat(unit_price) : product.price;
  const totalCost = finalPrice * parseInt(quantity);

  const user = db.prepare('SELECT balance, account_no FROM users WHERE id = ?').get(userId);
  if (user.balance < totalCost && req.difficulty === 'HARD') {
    return res.status(400).json({ status: 'error', message: 'Insufficient balance.' });
  }

  db.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').run(totalCost, userId);
  const updatedUser = db.prepare('SELECT balance FROM users WHERE id = ?').get(userId);

  const invoiceNo = 'INV-' + (100000 + Math.floor(Math.random() * 899999));
  const storeRef = 'ORD_' + Date.now().toString(36).toUpperCase() + crypto.randomBytes(2).toString('hex').toUpperCase();
  db.prepare('INSERT INTO transactions (from_account, to_account, amount, description, status, reference) VALUES (?, ?, ?, ?, ?, ?)')
    .run(user.account_no || 'ACC_UNKNOWN', 'ACC_3001', totalCost, 'Store Purchase: ' + product.name, 'completed', storeRef);
  res.json({
    status: 'success',
    message: 'Order completed successfully.',
    invoice: invoiceNo,
    order_details: { item: product.name, quantity, total_charged: totalCost, new_balance: updatedUser.balance }
  });
});

// ──────────────────────────────────────────────────────────────
//  6. SSRF & CLOUD METADATA EXFILTRATION
// ──────────────────────────────────────────────────────────────

app.post('/api/v1/webhook/fetch', authenticateJWT, (req, res) => {
  const { url } = req.body;
  const level = req.difficulty;

  if (!url) return res.status(400).json({ status: 'error', message: 'url parameter required.' });

  // Simulated Cloud Metadata Target Endpoint
  if (url.includes('169.254.169.254')) {
    return res.json({
      status: 'success',
      fetched_url: url,
      response_code: 200,
      body: JSON.stringify({
        ami_id: 'ami-0a1b2c3d4e5f6g7h8',
        instance_id: 'i-1234567890abcdef0',
        iam_role: 'CloudBank-EC2-Admin-Role',
        security_credentials: { AccessKeyId: 'AKIAIOSFODNN7EXAMPLE', SecretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' }
      }, null, 2)
    });
  }

  if (level === 'MEDIUM' && (url.includes('127.0.0.1') || url.includes('localhost'))) {
    return res.status(403).json({ status: 'error', code: 'SSRF_WAF_BLOCKED', message: 'Loopback address blocked by WAF. Try 0.0.0.0 or nip.io.' });
  }

  let parsedUrl;
  try { parsedUrl = new URL(url); } catch { return res.status(400).json({ status: 'error', message: 'Invalid URL.' }); }

  const client = parsedUrl.protocol === 'https:' ? https : http;
  const fetchReq = client.get(url, { timeout: 4000 }, (fetchRes) => {
    let body = '';
    fetchRes.on('data', chunk => body += chunk);
    fetchRes.on('end', () => res.json({ status: 'success', fetched_url: url, response_code: fetchRes.statusCode, body: body.substring(0, 15000) }));
  });

  fetchReq.on('error', (err) => res.status(502).json({ status: 'error', message: 'SSRF fetch failed.', details: err.message }));
  fetchReq.on('timeout', () => { fetchReq.destroy(); res.status(504).json({ status: 'error', message: 'Timeout.' }); });
});

// Admin Panel (Internal SSRF Exfiltration Target)
app.get('/api/v1/admin/panel', (req, res) => {
  const users = db.prepare('SELECT id, username, email, role, account_no, balance FROM users').all();
  const merchants = db.prepare('SELECT * FROM merchants').all();
  res.json({
    status: 'success',
    title: 'Internal Admin Panel',
    secrets: { jwt_secret: JWT_SECRET, api_keys: VALID_API_KEYS, master_db_pass: 'Sup3rS3cretDB!2024' },
    users, merchants
  });
});

// Real-Time HTTP Traffic Console (feeds the UI Burp-style viewer)
app.get('/api/v1/console/last', (req, res) => {
  const logs = httpLog.filter(t => !t.url.startsWith('/api/v1/console'));
  res.json({ status: 'success', count: logs.length, transactions: logs.slice(0, 25) });
});

// Authenticated Session Check (realistic /me endpoint)
app.get('/api/v1/auth/me', authenticateJWT, (req, res) => {
  const user = db.prepare('SELECT id, username, email, role, account_no, balance, avatar, created_at FROM users WHERE id = ?').get(req.user.user_id);
  if (!user) return res.status(401).json({ status: 'error', code: 'USER_NOT_FOUND', message: 'Session user no longer exists.' });
  res.json({ status: 'success', data: { user } });
});

// Account Statement (realistic bank statement endpoint)
app.get('/api/v1/statements', authenticateJWT, (req, res) => {
  const accNo = req.query.account_no || req.user.account_no;
  const txs = db.prepare('SELECT * FROM transactions WHERE from_account = ? OR to_account = ? ORDER BY id DESC LIMIT 100').all(accNo, accNo);
  const credits = txs.filter(t => t.to_account === accNo).reduce((s, t) => s + t.amount, 0);
  const debits = txs.filter(t => t.from_account === accNo).reduce((s, t) => s + t.amount, 0);
  res.json({
    status: 'success',
    data: {
      statement_id: 'STMT-' + Date.now().toString(36).toUpperCase(),
      account_no: accNo,
      period: '2026-08-01 to 2026-08-17',
      summary: { credits, debits, net_flow: credits - debits },
      transactions: txs
    }
  });
});

// API Documentation (realistic endpoint discovery for recon)
app.get('/api/v1/docs', (req, res) => {
  const endpoints = [
    ['POST', '/api/v1/auth/login', 'Authenticate and obtain a session token', false],
    ['GET', '/api/v1/auth/me', 'Return the current authenticated user', true],
    ['POST', '/api/v1/auth/logout', 'Terminate the current session', true],
    ['POST', '/api/v1/auth/2fa-reset', 'Reset 2FA PIN via recovery flow', false],
    ['POST', '/api/v1/transfer/verify', 'Verify a transfer route pair', true],
    ['POST', '/api/v1/transfer/race', 'Execute an instant wire transfer', true],
    ['POST', '/api/v1/card/validate', 'Validate card number / CVV / expiry', true],
    ['POST', '/api/v1/store/checkout', 'Purchase a product from the store', true],
    ['GET', '/api/v1/user/search', 'Search the customer directory', false],
    ['GET', '/api/v1/merchant/search', 'Search registered merchants', false],
    ['GET', '/api/v1/user/document', 'Retrieve a document by ID', true],
    ['GET', '/api/v1/user/profile', 'Get current user profile', true],
    ['PUT', '/api/v1/user/profile', 'Update user profile fields', true],
    ['PUT', '/api/v1/user/bio', 'Update public profile bio', true],
    ['POST', '/api/v1/user/avatar', 'Upload a profile avatar', true],
    ['POST', '/api/v1/ticket/create', 'Submit a support ticket', true],
    ['GET', '/api/v1/ticket/list', 'List support tickets', true],
    ['GET', '/api/v1/transactions', 'List account transactions', true],
    ['GET', '/api/v1/statements', 'Download account statement', true],
    ['POST', '/api/v1/webhook/fetch', 'Fetch a URL server-side (webhook tester)', true],
    ['GET', '/api/v1/session/token', 'Generate a session token', false],
    ['POST', '/api/v1/invoice/xml', 'Process an XML invoice', false],
    ['GET', '/api/v1/admin/panel', 'Internal admin panel', false],
    ['GET', '/api/v1/redirect', 'URL redirect service', false],
    ['GET', '/oauth/authorize', 'OAuth 2.0 authorization endpoint', false],
    ['POST', '/oauth/token', 'OAuth 2.0 token endpoint', false],
    ['POST', '/graphql', 'GraphQL API engine', false],
    ['GET', '/api/v1/internal/clearing', 'ACH clearing gateway (internal)', false],
    ['GET', '/api/v1/internal/vault', 'Encryption key vault (internal)', false],
    ['GET', '/api/v1/internal/identity', 'Identity provider (internal)', false]
  ];
  res.json({
    status: 'success',
    api: 'Apex Global Bank REST API v1',
    version: '1.0.0',
    base_url: 'http://localhost:3000',
    authentication: 'Authorization: Bearer <JWT>',
    endpoints: endpoints.map(([method, path, description, auth]) => ({ method, path, description, requires_auth: auth }))
  });
});

// ──────────────────────────────────────────────
//  6b. INTERNAL PARTNER SERVICES (SSRF Targets)
//  Realistic internal-only microservices reachable
//  only from inside the network (or via SSRF).
// ──────────────────────────────────────────────

// ACH Clearing Gateway — internal settlement service
app.get('/api/v1/internal/clearing', (req, res) => {
  res.json({
    status: 'success',
    service: 'ACH Clearing Gateway',
    host: 'clearing.internal.apexbank.local',
    data: {
      batch_id: 'BATCH_' + Date.now(),
      posted_entries: 1247,
      total_volume: '$482,119.73',
      window: '10:30 PM EST',
      federal_reserve_endpoint: 'https://frb-settlement.internal/ccd/2024'
    }
  });
});

// Internal Vault — requires an internal service header (header crafting target)
app.get('/api/v1/internal/vault', (req, res) => {
  const token = req.headers['x-vault-token'];
  if (token !== 'vault_master_2024') {
    return res.status(403).json({
      status: 'error',
      code: 'VAULT_UNAUTHORIZED',
      message: 'Vault access requires the internal X-Vault-Token header.',
      required_header: 'X-Vault-Token'
    });
  }
  res.json({
    status: 'success',
    service: 'Encryption Key Vault',
    data: {
      master_encryption_key: 'AES256-GCM:MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=',
      keystore_path: '/etc/cloudbank/keys/master.key',
      hsm_endpoint: 'https://hsm.internal.apexbank.local/v1/keys'
    }
  });
});

// Identity Provider (OIDC) — internal SSO service
app.get('/api/v1/internal/identity', (req, res) => {
  res.json({
    status: 'success',
    service: 'Internal Identity Provider',
    data: {
      issuer: 'https://id.internal.apexbank.local',
      active_sessions: 8421,
      oauth_clients: ['cloudbank_app', 'mobile_banking', 'merchant_portal'],
      directory_endpoint: 'http://ldap.internal.apexbank.local:389'
    }
  });
});

// ──────────────────────────────────────────────
//  7. GRAPHQL API & INTROSPECTION ABUSE
// ──────────────────────────────────────────────────────────────

app.post('/graphql', (req, res) => {
  const { query, variables } = req.body;
  if (!query) return res.status(400).json({ errors: [{ message: 'Must provide query string.' }] });

  // Introspection Query Target
  if (query.includes('__schema') || query.includes('__type')) {
    return res.json({
      data: {
        __schema: {
          types: [
            { name: 'Query', fields: [{ name: 'user', args: [{ name: 'id' }] }, { name: 'adminSecrets' }] },
            { name: 'User', fields: [{ name: 'id' }, { name: 'username' }, { name: 'email' }, { name: 'balance' }] }
          ]
        }
      }
    });
  }

  // GraphQL Field-Level IDOR / BOLA Target
  if (query.includes('user')) {
    const userId = variables && variables.id ? variables.id : 1;
    const user = db.prepare('SELECT id, username, email, balance, role FROM users WHERE id = ?').get(userId);
    return res.json({ data: { user } });
  }

  if (query.includes('adminSecrets')) {
    return res.json({ data: { adminSecrets: { db_pass: 'Sup3rS3cretDB!2024', jwt_secret: JWT_SECRET } } });
  }

  res.json({ data: { status: 'GraphQL Engine Active' } });
});

// ──────────────────────────────────────────────────────────────
//  8. OAUTH 2.0 IMPLEMENTATION (Redirect URI & State Bypass Target)
// ──────────────────────────────────────────────────────────────

app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, state } = req.query;

  if (!client_id || !redirect_uri) {
    return res.status(400).send('Missing client_id or redirect_uri');
  }

  // Vulnerable redirect_uri validation (accepts arbitrary domain in EASY/MEDIUM)
  const code = crypto.randomBytes(8).toString('hex');
  oauthCodes.set(code, { client_id, redirect_uri, user_id: 1 });

  const target = new URL(redirect_uri);
  target.searchParams.append('code', code);
  if (state) target.searchParams.append('state', state);

  res.redirect(target.toString());
});

app.post('/oauth/token', (req, res) => {
  const { code, grant_type } = req.body;
  if (!code || !oauthCodes.has(code)) return res.status(400).json({ error: 'invalid_grant' });

  const authData = oauthCodes.get(code);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(authData.user_id);

  const token = jwt.sign({ user_id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ access_token: token, token_type: 'Bearer', expires_in: 3600 });
});

// ──────────────────────────────────────────────────────────────
//  9. FILE UPLOAD & XXE PARSING
// ──────────────────────────────────────────────────────────────

// Avatar Upload (Double Extension & Content-Type Bypass)
app.post('/api/v1/user/avatar', authenticateJWT, (req, res) => {
  const { filename, file_content } = req.body;
  if (!filename || !file_content) return res.status(400).json({ status: 'error', message: 'filename and file_content required.' });

  // Vulnerable extension check
  if (req.difficulty === 'HARD' && !/\.(jpg|png|gif)$/i.test(filename)) {
    return res.status(400).json({ status: 'error', message: 'Only image files allowed.' });
  }

  db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(filename, req.user.user_id);
  res.json({
    status: 'success',
    message: 'Avatar uploaded successfully.',
    avatar_url: `http://localhost:3000/uploads/${filename}`,
    execution_hint: filename.includes('.php') ? 'Web shell upload payload stored.' : 'Image saved.'
  });
});

// XXE XML Parser (External Entity Target)
app.post('/api/v1/invoice/xml', (req, res) => {
  const xmlData = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);

  if (!xmlData || !xmlData.includes('<invoice>')) {
    return res.status(400).json({ status: 'error', message: 'Valid XML body with <invoice> root node required.' });
  }

  // XXE External Entity Injection Parsing Simulation
  if (xmlData.includes('<!ENTITY') || xmlData.includes('SYSTEM')) {
    let entityContent = 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\ncloudbank:x:1000:1000:CloudBank User:/home/cloudbank:/bin/bash';
    
    if (xmlData.includes('admin_credentials')) {
      entityContent = 'Master DB Secret: Sup3rS3cretDB!2024\nSSH Key Passphrase: cl0udb4nk_ssh';
    }

    return res.type('application/xml').send(`
      <response>
        <status>success</status>
        <message>Invoice Processed</message>
        <extracted_entity_data>${entityContent}</extracted_entity_data>
      </response>
    `);
  }

  res.type('application/xml').send(`
    <response>
      <status>success</status>
      <message>Standard Invoice Processed Successfully</message>
    </response>
  `);
});

// ──────────────────────────────────────────────────────────────
//  10. IDOR, SESSION TOKEN (SEQUENCER), PROFILE UPDATE & TRANSACTIONS
// ──────────────────────────────────────────────────────────────

app.get('/api/v1/user/document', authenticateJWT, (req, res) => {
  const docId = req.query.doc_id;
  if (!docId) return res.status(400).json({ status: 'error', message: 'doc_id query parameter required.' });

  // IDOR Vulnerability (No user ownership check)
  const doc = db.prepare(`SELECT d.*, u.username as owner FROM documents d JOIN users u ON d.user_id = u.id WHERE d.id = ?`).get(docId);
  if (!doc) return res.status(404).json({ status: 'error', message: `Document #${docId} not found.` });

  res.json({ status: 'success', data: doc });
});

app.get('/api/v1/session/token', (req, res) => {
  const timestamp = Date.now();
  const prngPart = weakPrng.nextHex(8);
  const timePart = timestamp.toString(16);
  const counterPart = (weakPrng.next() % 9999).toString().padStart(4, '0');

  const rawToken = `user:${timePart}:${prngPart}:${counterPart}`;
  const session_token = Buffer.from(rawToken).toString('base64');
  res.cookie('cb_session', `CB_SID_${timePart}_${prngPart}`, { httpOnly: false });

  res.json({ status: 'success', data: { session_token, format: 'base64', algorithm: 'Custom-LCG-WeakPRNG' } });
});

app.put('/api/v1/user/profile', authenticateJWT, (req, res) => {
  const userId = req.user.user_id;
  const updates = req.body;
  const allowedFields = ['email', 'password', 'role', 'balance', 'pin_2fa'];
  const setClauses = [];
  const values = [];

  for (const [k, v] of Object.entries(updates)) {
    if (allowedFields.includes(k)) { setClauses.push(`${k} = ?`); values.push(v); }
  }
  if (setClauses.length === 0) return res.status(400).json({ status: 'error', message: 'No fields to update.' });

  values.push(userId);
  db.prepare(`UPDATE users SET ${setClauses.join(', ')} WHERE id = ?`).run(...values);
  const updated = db.prepare('SELECT id, username, email, role, balance, pin_2fa FROM users WHERE id = ?').get(userId);
  res.json({ status: 'success', message: 'Profile updated via mass assignment.', user: updated });
});

app.get('/api/v1/transactions', authenticateJWT, (req, res) => {
  const accNo = req.query.account_no || req.user.account_no;
  const txs = db.prepare('SELECT * FROM transactions WHERE from_account = ? OR to_account = ? ORDER BY id DESC LIMIT 25').all(accNo, accNo);
  res.json({ status: 'success', account_no: accNo, transactions: txs });
});

// ──────────────────────────────────────────────────────────────
//  STATIC FILE SERVING & FRONTEND SPA ROUTE
// ──────────────────────────────────────────────────────────────

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ──────────────────────────────────────────────────────────────
//  CENTRALIZED ERROR HANDLING (production-grade JSON API)
// ──────────────────────────────────────────────────────────────

// JSON 404 for unmatched API routes (realistic API contract)
app.use('/api', (req, res) => {
  res.status(404).json({
    status: 'error',
    code: 'NOT_FOUND',
    message: 'The requested resource was not found on this server.',
    path: req.originalUrl,
    docs: '/api/v1/docs'
  });
});

// Global error handler — malformed JSON, payload too large, unknown errors
app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ status: 'error', code: 'PAYLOAD_TOO_LARGE', message: 'Request entity too large. Max 10MB.' });
  }
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ status: 'error', code: 'INVALID_JSON', message: 'Malformed JSON in request body.', detail: err.message });
  }
  res.status(500).json({ status: 'error', code: 'INTERNAL_ERROR', message: 'An internal server error occurred.' });
});

// ──────────────────────────────────────────────────────────────
//  SERVER LISTEN
// ──────────────────────────────────────────────────────────────

app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔══════════════════════════════════════════════════════════════════╗
║   ☁️ CLOUD BANK — BUG HUNTING MASTERY PLATFORM v4.0               ║
║   🌐 URL: http://localhost:${PORT}                                ║
║   🎯 Target Modules: 18+ Real-World Bug Classes                  ║
║   ⚡ WAF Difficulty: EASY | MEDIUM | HARD                         ║
╚══════════════════════════════════════════════════════════════════╝
  `);
});

module.exports = app;
