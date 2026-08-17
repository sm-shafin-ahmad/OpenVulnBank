# ☁️ CloudBank Enterprise Security Lab v3.0

> **⚠️ WARNING: This application is INTENTIONALLY VULNERABLE. Built exclusively for authorized security assessments, penetration testing practice, and Burp Suite labs. NEVER deploy to production or expose to untrusted networks.**

---

## 📋 Overview

CloudBank Enterprise Security Lab v3.0 is a complete Single-Page Application (SPA) & REST API Security Lab designed specifically for practicing **Burp Suite** capabilities:

- **Intruder Modes**: Sniper, Battering Ram, Pitchfork, Cluster Bomb
- **Repeater**: SSRF, IDOR, SQL Injection (Authentication & UNION-based), Privilege Escalation, Mass Assignment
- **Sequencer**: Weak PRNG Token Entropy Analysis
- **Decoder**: Base64, Hex, XOR, and JWT 'none' Algorithm Decoding
- **Dynamic Difficulty Engine**: Switch between **EASY**, **MEDIUM**, and **HARD** WAF/filtering levels on the fly.

---

## ⚡ Dynamic Difficulty Engine

You can toggle the security level dynamically using the UI header dropdown or by sending the `X-Difficulty-Level` header / `?difficulty=` parameter in Burp:

| Level | WAF & Protection Mechanisms | Required Bypass Strategy in Burp |
|-------|----------------------------|----------------------------------|
| **EASY** | Raw vulnerabilities, zero input sanitization, descriptive SQL & system error leaks. | Direct payload execution. |
| **MEDIUM** | Common WAF rules (stripping spaces, stripping basic `<script>` tags, loopback IP filtering for SSRF). | Burp Decoder (URL encoding, comment injection `/**/`, alternative loopback IPs like `0.0.0.0` or `127.0.0.1.nip.io`). |
| **HARD** | Strict WAF keyword filters, rate-limiting on sensitive operations, structural header validation. | IP rotation via `X-Forwarded-For`, custom header crafting, comment-obfuscated SQLi, JWT algorithm manipulation. |

---

## 🚀 Quick Start

### 1. Install & Run
```bash
cd ~/Desktop/Burp-Test
npm install
node server.js
```

### 2. Access the Application
- **Interactive SPA Lab Dashboard**: `http://localhost:3000`
- **Dynamic Difficulty API**: `GET /api/v1/difficulty` / `POST /api/v1/difficulty`

---

## 🎯 Lab Modules & Burp Suite Attack Guide

### 1. Auth & Login (`POST /api/v1/auth/login`)
- **Burp Attack**: Intruder (Sniper / Battering Ram) & Repeater
- **Vulnerabilities**: SQL Injection (`admin' OR 1=1--`), User Enumeration via differential error responses (`INVALID_PASSWORD` vs `USER_NOT_FOUND`).

### 2. 2FA PIN Reset (`POST /api/v1/auth/2fa-reset`)
- **Burp Attack**: Intruder (Sniper Mode on 4-digit PIN) + Match & Replace Header Spoofing
- **Vulnerabilities**: Rate-limiting enforced per IP, easily bypassed by rotating `X-Forwarded-For` or `Client-IP` headers.

### 3. Wire Transfer Route Verification (`POST /api/v1/transfer/verify`)
- **Burp Attack**: Intruder (Pitchfork Mode)
- **Vulnerabilities**: Synchronized dual-list attack matching valid `target_account` (ACC_XXXX) and `routing_code` (ROUTE_YYYY) pairs in lockstep.

### 4. Credit Card Validation (`POST /api/v1/card/validate`)
- **Burp Attack**: Intruder (Cluster Bomb Mode)
- **Vulnerabilities**: Combinatorial iteration across Card Number × CVV × Exp Month. Returns distinct status codes (200, 403, 404) for `CARD_NOT_FOUND`, `CVV_MISMATCH`, and `EXP_MISMATCH`.

### 5. Session Token Generator (`GET /api/v1/session/token`)
- **Burp Attack**: Burp Sequencer & Burp Decoder
- **Vulnerabilities**: Low-entropy Linear Congruential Generator (LCG) token generation. Base64 decoded structure reveals `<role>:<timestamp_hex>:<prng_hex>:<counter>`.

### 6. Webhook Diagnostic Tester (`POST /api/v1/webhook/fetch`)
- **Burp Attack**: Repeater (SSRF)
- **Vulnerabilities**: Server-Side Request Forgery allowing internal network probing and access to internal endpoints like `http://127.0.0.1:3000/api/v1/admin/panel` to leak master database passwords and JWT secrets.

### 7. Document Vault (`GET /api/v1/user/document?doc_id=<id>`)
- **Burp Attack**: Repeater (IDOR & JWT 'none' Algorithm)
- **Vulnerabilities**: Insecure Direct Object Reference on `doc_id`. Accepts forged JWT tokens using `{"alg":"none"}` header with no signature.

### 8. Merchant Payment System (`POST /api/v1/merchant/pay`)
- **Burp Attack**: Intruder (Battering Ram)
- **Vulnerabilities**: Accepts payload simultaneously in `X-API-Key` header and `merchant_id` body. Leaks timing side-channel match statistics (`prefix_match_length`).

### 9. User Directory Search (`GET /api/v1/user/search?q=<query>`)
- **Burp Attack**: Repeater (UNION SQLi)
- **Vulnerabilities**: Reflected search string + UNION-based SQL Injection (`' UNION SELECT 1,username,password,role FROM users--`).

---

## 🔑 Test Credentials & Test Data

| Role | Username | Password | Account No | Balance | 2FA PIN |
|------|----------|----------|------------|---------|---------|
| Admin | `admin` | `admin123` | ACC_1001 | $999,999.99 | 1337 |
| Customer | `john.doe` | `password123` | ACC_2001 | $15,420.50 | 4829 |
| Customer | `jane.smith` | `qwerty` | ACC_2002 | $87,230.00 | 1234 |
| Merchant | `bob.merchant` | `merchant2024` | ACC_3001 | $250,000.00 | 0000 |
| VIP | `alice.vip` | `letmein` | ACC_4001 | $1,500,000.00 | 7777 |
