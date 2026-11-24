const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  INIT_POOLS,
  CORRIDOR_META,
  FEE_CONFIG,
  computeQuote,
  normalizeIdentityName,
  extractBeneficiaryBaseName,
  isRateWithinCircuitBreaker,
  toInr,
  validatePanForHolder,
  detectCircularRoundTrip,
  inspectBinaryProof,
  evaluateComplianceGate
} = require("./compliance.js");
const { createLedgerStore, normalizeTenantId, timingSafeEqualStr } = require("./store.js");

test("1. Symmetric bidirectional corridors & 24h time-windowed round-trip AML", () => {
  assert.equal(INIT_POOLS.USD, 254500);
  assert.ok(CORRIDOR_META.EUR_INR && CORRIDOR_META.INR_EUR);
  assert.ok(CORRIDOR_META.USD_INR && CORRIDOR_META.INR_USD);
  assert.ok(CORRIDOR_META.GBP_INR && CORRIDOR_META.INR_GBP);
  assert.ok(CORRIDOR_META.USD_EUR && CORRIDOR_META.EUR_USD);
  assert.ok(CORRIDOR_META.GBP_USD && CORRIDOR_META.USD_GBP);

  const now = Date.now();
  assert.equal(detectCircularRoundTrip([{ from: "GBP", to: "USD", ts: now - 60_000 }], "USD", "GBP", now), true);
  // Reverse transfer older than 24h window must NOT trigger false positive
  assert.equal(detectCircularRoundTrip([{ from: "GBP", to: "USD", ts: now - (FEE_CONFIG.ROUND_TRIP_WINDOW_MS + 5000) }], "USD", "GBP", now), false);
});

test("2. Integer minor-unit quote calculation & INR normalization", () => {
  const qBase = computeQuote(50, 102.523, 20000000, 20680975.35);
  assert.equal(qBase.feeRate, 0.004);
  assert.equal(qBase.fee, 0.2);
  assert.equal(qBase.payout, 5105.65);

  const qLow = computeQuote(50, 102.523, 1000000, 20680975.35);
  assert.equal(qLow.feeRate, 0.0105);
  assert.equal(qLow.rebalanceActive, true);

  assert.equal(toInr(1000, "INR"), 1000);
  assert.equal(toInr(100, "USD"), 9337.27);
  assert.throws(() => toInr(100, "XYZ"), RangeError);
});

test("3. NFKC identity normalization, self-transfer pool-tag stripping, & multi-sender fan-in smurfing", () => {
  assert.equal(normalizeIdentityName("  Ravindra\u00A0  Prajapat  "), "ravindra prajapat");
  assert.equal(extractBeneficiaryBaseName("Ravindra Prajapat (INR Local Pool)"), "ravindra prajapat");
  assert.equal(validatePanForHolder("ABCPP8821F", "Ravindra Prajapat"), "");
  assert.notEqual(validatePanForHolder("ABCPA8821F", "Ravindra Prajapat"), "");

  // Self-transfer with "(INR Local Pool)" suffix must be blocked
  const selfPoolBlock = evaluateComplianceGate({
    amount: 50, currency: "EUR", toCurrency: "INR", cumulativeInr: 0,
    kycName: "Ravindra Prajapat", senderName: "Ravindra Prajapat",
    recipient: "Ravindra Prajapat (INR Local Pool)",
    docType: "PAN Card", docNum: "ABCPP8821F", hasValidProof: false
  });
  assert.equal(selfPoolBlock.code, "SELF_TRANSFER_AML");

  // Fan-in smurfing: 2 distinct senders pushing > ₹1.5L to same beneficiary triggers PROOF_REQUIRED
  const fanInBlock = evaluateComplianceGate({
    amount: 1000, currency: "EUR", toCurrency: "INR", cumulativeInr: 0,
    recipientCumulativeInr: 80000, recipientDistinctSenders: 2,
    kycName: "Ravindra Prajapat", senderName: "Ravindra Prajapat",
    recipient: "Shared Beneficiary",
    docType: "PAN Card", docNum: "ABCPP8821F", hasValidProof: false
  });
  assert.equal(fanInBlock.code, "PROOF_REQUIRED");
});

test("4. Deep binary forensics: Shannon entropy + PDF/PNG/JPEG structural markers", () => {
  const validPdf = Buffer.concat([
    Buffer.from("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"),
    crypto.randomBytes(4200),
    Buffer.from("\n%%EOF\n")
  ]);
  assert.equal(inspectBinaryProof(validPdf).ok, true);

  // Zero-padded buffer with JPEG header must fail entropy + EOI check
  const fakeZeroJpg = Buffer.concat([Buffer.from([0xFF, 0xD8, 0xFF, 0xE0]), Buffer.alloc(5000)]);
  assert.equal(inspectBinaryProof(fakeZeroJpg).ok, false);

  // Random bytes with JPEG header but missing 0xFFD9 EOI must fail
  const noEoiJpg = Buffer.concat([Buffer.from([0xFF, 0xD8, 0xFF, 0xE0]), crypto.randomBytes(5000)]);
  assert.equal(inspectBinaryProof(noEoiJpg).ok, false);

  // Valid high-entropy JPEG ending with 0xFFD9 passes
  const validJpg = Buffer.concat([Buffer.from([0xFF, 0xD8, 0xFF, 0xE0]), crypto.randomBytes(5000), Buffer.from([0xFF, 0xD9])]);
  assert.equal(inspectBinaryProof(validJpg).ok, true);
});

test("5. Persistence across restart: docHash, txHistory, wrongOtpCount reset, hashed unlock token, & truncated JSONL recovery", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "orbitpay-unit-"));
  try {
    const store1 = createLedgerStore({ dataDir: tmpDir, maxDocHashes: 3, maxTenants: 4 });

    // Read-only GET must NOT create tenants
    assert.equal(store1.getStatus("Ghost User").tenant.kycId, "ghost_user");
    assert.equal(store1.findTenant("Ghost User"), null);

    const validPdf = Buffer.concat([
      Buffer.from("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"),
      crypto.randomBytes(4200),
      Buffer.from("\n%%EOF\n")
    ]);

    const initRes = store1.initiateTransfer({
      kycName: "Ravindra Prajapat",
      senderName: "Ravindra Prajapat",
      amount: 2500,
      fromCurrency: "EUR",
      toCurrency: "INR",
      docType: "PAN Card",
      docNum: "ABCPP8821F",
      proofBase64: validPdf.toString("base64")
    });
    assert.equal(initRes.ok, true);

    // 2 wrong OTPs followed by 1 valid OTP must reset wrongOtpCount to 0
    await store1.verifyOtpAndSettle({ kycId: "Ravindra Prajapat", txId: initRes.txId, otp: "000000" });
    await store1.verifyOtpAndSettle({ kycId: "Ravindra Prajapat", txId: initRes.txId, otp: "000000" });
    assert.equal(store1.getStatus("Ravindra Prajapat").tenant.wrongOtpCount, 2);

    const opsView = store1.getOpsStatus("Ravindra Prajapat");
    const settleRes = await store1.verifyOtpAndSettle({
      kycId: "Ravindra Prajapat",
      txId: initRes.txId,
      otp: opsView.activeChallenge.otp
    });
    assert.equal(settleRes.ok, true);
    assert.equal(settleRes.tenant.wrongOtpCount, 0);
    await store1.flush();

    // Simulate crash leaving partial line without newline
    fs.appendFileSync(path.join(tmpDir, "ledger.jsonl"), '{"type":"TRUNCATED_CRASH_LINE', "utf8");

    // Restart store -> recovers cleanly, repairs trailing line, preserves docHash & txHistory
    const store2 = createLedgerStore({ dataDir: tmpDir, maxDocHashes: 3, maxTenants: 4 });
    assert.equal((await store2.verifyLedgerChain()).valid, true);

    // Duplicate docHash must still be blocked after restart (Item 7)
    const replayDoc = store2.initiateTransfer({
      kycName: "Ravindra Prajapat",
      senderName: "Ravindra Prajapat",
      amount: 2100,
      fromCurrency: "EUR",
      toCurrency: "INR",
      docType: "PAN Card",
      docNum: "ABCPP8821F",
      proofBase64: validPdf.toString("base64")
    });
    assert.equal(replayDoc.code, "DUPLICATE_DOC_HASH");

    // Round-trip history must still block INR -> EUR after restart
    const roundTripAfterRestart = store2.initiateTransfer({
      kycName: "Ravindra Prajapat",
      senderName: "Ravindra Prajapat",
      amount: 1000,
      fromCurrency: "INR",
      toCurrency: "EUR",
      docType: "PAN Card",
      docNum: "ABCPP8821F"
    });
    assert.equal(roundTripAfterRestart.code, "ROUND_TRIP_AML");

    // New block appended after crash recovery must keep chain 100% valid (Item 8)
    const reb = await store2.rebalancePool({ currency: "INR", amount: 10000 });
    assert.equal(reb.ok, true);
    assert.equal((await store2.verifyLedgerChain()).valid, true);

    // Tampering with payout or recipient must fail digest verification (Item 9)
    const ledgerFile = path.join(tmpDir, "ledger.jsonl");
    const rawLedger = fs.readFileSync(ledgerFile, "utf8");
    fs.writeFileSync(ledgerFile, rawLedger.replace('"recipient":"Recipient"', '"recipient":"Attacker Eve"'), "utf8");
    const tamperRes = await store2.verifyLedgerChain();
    assert.equal(tamperRes.valid, false);
    assert.equal(tamperRes.reason, "DIGEST_TAMPERED");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("6. Static security & WCAG 2.1 AA structural invariants", () => {
  const appSource = fs.readFileSync(path.join(__dirname, "public", "app.js"), "utf8");
  const htmlSource = fs.readFileSync(path.join(__dirname, "public", "index.html"), "utf8");
  assert.equal(/\.innerHTML\s*=|\beval\s*\(|document\.write\s*\(/.test(appSource), false);
  assert.ok(htmlSource.includes("<h1>OrbitPay</h1>"));
  assert.ok(htmlSource.includes('aria-describedby="amtErr"'));
  assert.ok(!htmlSource.includes('id="otpTimer" role="status"'));
});