# OpenVulnBank — Deliberately Vulnerable Banking Platform

> **⚠️ WARNING: This application is INTENTIONALLY VULNERABLE.** Built exclusively for **authorized** security assessments, penetration testing practice, and Burp Suite training in isolated lab environments. **NEVER deploy to production or expose to untrusted networks.**

---

## 📋 Overview

**OpenVulnBank** is a production-grade, deliberately vulnerable online banking platform engineered to mirror a real-world fintech attack surface. It is a complete SPA + REST API security lab designed for practicing every major **Burp Suite** capability against realistic HTTP traffic:

- **Intruder Modes**: Sniper, Battering Ram, Pitchfork, Cluster Bomb
- **Repeater**: SQLi, SSRF, IDOR, JWT exploitation, Privilege Escalation, Mass Assignment
- **Sequencer**: Weak PRNG token entropy analysis
- **Decoder**: Base64, Hex, XOR, JWT `alg:none` decoding
- **Burp Proxy-style HTTP Console**: every request/response captured raw, viewable in the UI exactly like Burp
- **Dynamic Difficulty Engine**: switch between **EASY**, **MEDIUM**, and **HARD** security levels on the fly

It intentionally ships with **18+ real-world vulnerability classes** across a realistic bank architecture — customers, cards, transfers, a merchant store, a document vault, support tickets, webhooks, GraphQL, OAuth 2.0, XML processing, and internal microservices.

---

## ⚡ Dynamic Difficulty Engine

Toggle the security level from the **HTTP Console (WAF selector)** or **Settings → Security Environment**, or send the `X-Difficulty-Level` header / `?difficulty=` parameter directly from Burp:

| Level | Protection Mechanisms | Required Bypass Strategy in Burp |
|-------|----------------------|----------------------------------|
| **EASY** | Raw vulnerabilities, zero sanitization, descriptive SQL & system error leaks. | Direct payload execution. |
| **MEDIUM** | Common WAF rules: strips spaces, strips basic `<script>` tags, loopback IP filtering for SSRF. | Burp Decoder: URL encoding, comment injection `/**/`, alternative loopback IPs (`0.0.0.0`, `127.0.0.1.nip.io`). |
| **HARD** | Strict WAF keyword filters, **CSRF token enforcement** on state-changing requests, **Content-Security-Policy** on reflected output, rate-limiting. | IP rotation via `X-Forwarded-For`, CSRF token harvesting (`GET /api/v1/csrf-token`), header crafting, comment-obfuscated SQLi, CSP bypass. |

---

## 🚀 Quick Start

### 1. Install & Run

```bash
cd OpenVulnBank
npm install
node server.js
```

### 2. Access the Application

- **Online Banking SPA**: `http://localhost:3000`
- **API Documentation**: `GET /api/v1/docs` (30 documented endpoints)
- **Dynamic Difficulty API**: `GET/POST /api/v1/difficulty`

---

## 🏗️ Architecture & Production Realism

Unlike a traditional lab, OpenVulnBank behaves like a real production target:

- **Realistic HTTP traffic** — every request carries `X-Request-Id`, `Cache-Control: no-store`, `Server`, `Referrer-Policy`, `Permissions-Policy`, and a JSON API contract (JSON 404s, `400 INVALID_JSON`, `413 PAYLOAD_TOO_LARGE`).
- **HTTP Request/Response Console** — server-side raw capture of every transaction, rendered in the UI with **Request / Response / Response (JSON)** tabs and **Copy Raw**, exactly like Burp Proxy history.
- **Live transaction ledger** — transfers and store purchases post real ledger entries; dashboards and statements update in real time.
- **Realistic session lifecycle** — `POST /api/v1/auth/login`, `GET /api/v1/auth/me`, `POST /api/v1/auth/logout`.
- **Internal microservices** — ACH clearing gateway, encryption key vault, identity provider, admin panel, and simulated AWS metadata — all reachable only via SSRF.
- **Realistic secrets** — JWT `alg:none` support, weak JWT secret, hardcoded API keys, leaked cloud credentials.

---

## 🎯 Vulnerability Modules & Attack Guide

### 1. Authentication & Enumeration — `POST /api/v1/auth/login`
- **Burp**: Intruder (Sniper / Battering Ram) & Repeater
- **Bugs**: SQLi auth bypass (`admin' OR 1=1--`), user enumeration via differential errors (`INVALID_PASSWORD` vs `USER_NOT_FOUND`).

### 2. 2FA PIN Reset — `POST /api/v1/auth/2fa-reset`
- **Burp**: Intruder (Sniper, 4-digit PIN) + header rotation
- **Bugs**: Per-IP rate limiting bypassed via `X-Forwarded-For` / `Client-IP` rotation.

### 3. Wire Transfer Route Verification — `POST /api/v1/transfer/verify`
- **Burp**: Intruder (Pitchfork)
- **Bugs**: Lockstep matching of `target_account` (`ACC_XXXX`) × `routing_code` (`ROUTE_YYYY`); verbose debug responses.

### 4. Credit Card Validation — `POST /api/v1/card/validate`
- **Burp**: Intruder (Cluster Bomb)
- **Bugs**: Card Number × CVV × Exp Month iteration with distinct codes (`CARD_NOT_FOUND`, `CVV_MISMATCH`, `EXP_MISMATCH`).

### 5. Weak Session Token — `GET /api/v1/session/token`
- **Burp**: Sequencer & Decoder
- **Bugs**: Low-entropy LCG PRNG. Base64-decoded structure: `<role>:<timestamp_hex>:<prng_hex>:<counter>`.

### 6. Webhook Tester (SSRF) — `POST /api/v1/webhook/fetch`
- **Burp**: Repeater
- **Bugs**: SSRF to internal targets — admin panel (`/api/v1/admin/panel`), ACH clearing, key vault, identity provider, AWS metadata (`169.254.169.254`).

### 7. Document Vault (IDOR + JWT) — `GET /api/v1/user/document?doc_id=<id>`
- **Burp**: Repeater
- **Bugs**: IDOR on `doc_id` (no ownership check); accepts forged `{"alg":"none"}` JWTs.

### 8. Merchant Payment — `POST /api/v1/merchant/pay`
- **Burp**: Intruder (Battering Ram)
- **Bugs**: Payload accepted in both `X-API-Key` header and `merchant_id` body; timing side-channel leaks `prefix_match_length`.

### 9. User Directory — `GET /api/v1/user/search?q=<query>`
- **Burp**: Repeater
- **Bugs**: UNION-based SQLi (`' UNION SELECT 1,username,password,role FROM users--`); reflected output.

### 10. Business Logic & Race Conditions — `POST /api/v1/transfer/race`, `POST /api/v1/store/checkout`
- **Burp**: Turbo Intruder
- **Bugs**: Race-condition double-spend; client-supplied `unit_price` (negative pricing) tampering.

### 11. SQL Injection (Blind & Second-Order) — `GET /api/v1/merchant/search`, `PUT /api/v1/user/bio`
- **Bugs**: Time-based blind SQLi (`SLEEP(n)`); stored bio payload interpolated into admin audit queries.

### 12. XSS — `GET /api/v1/search/reflect`, `POST /api/v1/ticket/create`
- **Bugs**: Reflected XSS; stored XSS via support tickets (CSP-hardened in HARD mode for bypass practice).

### 13. Broken Access Control — `PUT /api/v1/user/profile`, `GET /api/v1/admin/panel`
- **Bugs**: Mass assignment (`role`, `balance`); publicly accessible internal admin panel.

### 14. XXE — `POST /api/v1/invoice/xml`
- **Bugs**: External entity expansion to read server files (`file:///etc/passwd`, admin credentials).

### 15. GraphQL Abuse — `POST /graphql`
- **Bugs**: Introspection (`__schema`), field-level BOLA/IDOR (`user(id:1)`), secret dump (`adminSecrets`).

### 16. OAuth 2.0 & Open Redirect — `/oauth/authorize`, `GET /api/v1/redirect`
- **Bugs**: `redirect_uri` manipulation; unvalidated redirects.

### 17. CORS Misconfiguration
- **Bugs**: Arbitrary origin + credentials trust (EASY/MEDIUM); `null` origin trust.

### 18. Weak File Upload — `POST /api/v1/user/avatar`
- **Bugs**: Missing/inadequate extension validation (webshell filenames).

### 19. API Key Timing Attack — `POST /api/v1/merchant/pay`
- **Bugs**: `prefix_match_length` oracle enables character-by-character key recovery.

### 20. CSRF — state-changing endpoints
- **Bugs**: No CSRF protection in EASY/MEDIUM; HARD requires `X-CSRF-Token`.

---

## 🔑 Test Credentials

| Role | Username | Password | Account No | Balance | 2FA PIN |
|------|----------|----------|------------|---------|---------|
| Admin | `admin` | `admin123` | ACC_1001 | $999,999.99 | 1337 |
| Customer | `john.doe` | `password123` | ACC_2001 | $15,420.50 | 4829 |
| Customer | `jane.smith` | `qwerty` | ACC_2002 | $87,230.00 | 1234 |
| Merchant | `bob.merchant` | `merchant2024` | ACC_3001 | $250,000.00 | 0000 |
| VIP | `alice.vip` | `letmein` | ACC_4001 | $1,500,000.00 | 7777 |

> ⚠️ **Responsible use only.** This project is for authorized security education. You are responsible for using it legally and ethically.
