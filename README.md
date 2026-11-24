# OrbitPay — Cross-Border Liquidity Mesh & Multi-Tenant AML Engine

![OrbitPay CI](https://img.shields.io/badge/Tests-node%3Atest%20(Unit%20%2B%20API%20%2B%20Smoke)-22c55e)
![Container](https://img.shields.io/badge/Docker-Non--Root%20Node%2022%20Alpine%20%2B%20Healthcheck-38bdf8)
![Security](https://img.shields.io/badge/Ledger-Full%20256--Bit%20SHA--256%20JSONL-818cf8)
![Accessibility](https://img.shields.io/badge/A11y-WCAG%202.1%20AA-f59e0b)

**Track:** PromptWars x Sudarshan (Open Innovation / OrbitPay Challenge)  
**Author:** Ravindra Prajapat (`ravijan2006-create`)

## Problem Statement
Traditional cross-border remittances rely on correspondent banking (SWIFT), causing 3–5 day settlement delays, hidden ~6.5% FX spreads, and fragmented compliance checks. **OrbitPay** replaces slow point-to-point wires with bidirectional regional liquidity pools (`USD`, `INR`, `EUR`, `GBP`) that settle locally with measured API latency while enforcing multi-tenant anti-money laundering (AML), server-side binary document forensics, and durable 256-bit hash-chained audit logging.

## Architecture & Key Engineering Controls
1. **Durable Append-Only JSONL Ledger & Atomic State Persistence (`store.js`):**
   - Persists every settlement and treasury rebalance to `data/ledger.jsonl` with a **full 256-bit (64-char) SHA-256 hash chain** over every canonical settlement/rebalance field (`amount`, `payout`, `recipient`, `rate`, `purpose`, `corridor`, `ts`) and streaming `readline` tamper verification (`verifyLedgerChain()`).
   - Crash recovery (`loadFromDisk()`) strips truncated trailing JSONL lines cleanly so subsequent appends never corrupt the ledger; failed ledger writes roll back `prevChainHash`, `recentLedger`, pools, and tenant balances.
   - `resetDemo()` appends a cryptographic `LEDGER_RESET` block rather than wiping audit history.
2. **Strict Multi-Tenant Isolation & Bidirectional AML (`compliance.js`, `store.js`, `server.js`):**
   - Public `GET /api/state` is strictly read-only (never creates ghost tenants or triggers eviction) and returns only the requested tenant's scoped ledger — zero `opsEvents` or cross-tenant data leakage.
   - Symmetric bidirectional corridor pairs (`EUR<->INR`, `USD<->INR`, `GBP<->INR`, `USD<->EUR`, `GBP<->USD`) with 24-hour time-windowed circular round-trip detection, multi-sender fan-in smurfing detection, NFKC identity normalization, self-remittance blocking (`extractBeneficiaryBaseName`), and integer minor-unit (`toMinor`/`fromMinor`) arithmetic.
3. **Zero-Trust Security & Server-Side Forensics (`compliance.js`, `server.js`, `store.js`):**
   - **Runtime Scrypt-Hashed Ops PIN:** Server generates a cryptographic random runtime PIN on boot (or reads `ORBITPAY_OPS_PIN`) hashed via `crypto.scryptSync` — zero hardcoded PINs in source code or docs.
   - **Hashed Secrets at Rest:** OTPs and single-use unlock tokens are stored in `state.json` only as salted `scrypt` hashes (`unlockTokenHash` + `unlockTokenSalt`) and never written into `opsEvents`.
   - **Mandatory `txId` Replay Binding:** `/api/confirm` requires both matching `txId` and valid 6-digit OTP, and resets `wrongOtpCount` to `0` on successful verification.
   - **Deep Binary Forensics:** Validates magic bytes (`PDF`, `PNG`, `JPEG`), Shannon entropy (`>= 1.5` bits/byte), and format-specific structural markers (`obj`/`endobj`/`%%EOF` for PDF, `IHDR`/`IEND` for PNG, `0xFFD9` EOI for JPEG) plus O(1) `Set` SHA-256 deduplication persisted across restarts.
   - **CSRF, Rate Limiting & Clean 413 Handling:** Same-origin `Origin` check, `application/json` enforcement (`415`), per-IP rate limiting across auth and transfer routes (`429`), and clean `413 Payload too large` JSON responses prior to socket teardown.
4. **WCAG 2.1 Level AA Accessibility (`public/index.html`, `public/styles.css`, `public/app.js`):**
   - Top-level `<h1>OrbitPay</h1>`, high-contrast AA palette (`>= 7:1` text contrast), `28x28px` `.orb-btn` touch target, inline amount validation (`aria-describedby="amtErr"`), silent timer/list updates without screen-reader spam, `Alt+Shift+O` shortcut, and `inert` background modal isolation.

## Quick Start & Automated Tests
```bash
# Run syntax lint + node:test unit, API integration, and smoke suites
npm run lint && npm test

# Start server on port 8080 (prints runtime Ops PIN to stdout)
npm start

# Build & run hardened non-root Docker container with healthcheck
docker build -t orbitpay-mesh .
docker run -p 8080:8080 -e ORBITPAY_OPS_PIN=YOUR_SECRET_PIN orbitpay-mesh
```
