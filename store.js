const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const readline = require("readline");
const OrbitCompliance = require("./compliance.js");

const { INIT_POOLS, toMinor, fromMinor, computeQuote } = OrbitCompliance;
const GENESIS_HASH = "0".repeat(64);
const MAX_CACHED_LEDGER = 100;
const MAX_DOC_HASHES = 10000;
const MAX_TENANTS = 5000;
const MAX_TX_HISTORY_PER_TENANT = 100;
const MAX_INITIATIONS_PER_MIN = 15;

function normalizeTenantId(kycId) {
  const slug = String(kycId || "")
    .normalize("NFKC")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return /[a-z0-9]/.test(slug) ? slug : "";
}

function timingSafeEqualStr(a, b) {
  const bufA = Buffer.from(String(a || ""), "utf8");
  const bufB = Buffer.from(String(b || ""), "utf8");
  if (bufA.length === 0 || bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function hashSecret(secret, salt) {
  return crypto.scryptSync(String(secret), String(salt), 32).toString("hex");
}

function verifyServerProofPayload(proofBase64) {
  if (!proofBase64) {
    return { hasValidProof: false, docHash: "", error: null };
  }
  if (typeof proofBase64 !== "string") {
    return { hasValidProof: false, docHash: "", error: "Invalid proofBase64 encoding." };
  }
  const cleanB64 = proofBase64.replace(/^data:[^;]+;base64,/, "").trim();
  const fileBuf = Buffer.from(cleanB64, "base64");
  const check = OrbitCompliance.inspectBinaryProof(fileBuf);
  if (!check.ok) {
    return { hasValidProof: false, docHash: "", error: check.reason };
  }
  const docHash = crypto.createHash("sha256").update(fileBuf).digest("hex");
  return { hasValidProof: true, docHash, format: check.format, error: null };
}

// Item 9: Full cryptographic commitment over ALL settlement & rebalance fields
function computeBlockDigest(prevHash, entry) {
  const canonical = JSON.stringify({
    prevHash,
    type: entry.type || "",
    txId: entry.txId || "",
    kycId: entry.kycId || "SYSTEM",
    corridor: entry.corridor || "",
    currency: entry.currency || "",
    fromCurrency: entry.fromCurrency || "",
    toCurrency: entry.toCurrency || "",
    amount: Number(entry.amount || 0),
    payout: Number(entry.payout || 0),
    feeRate: Number(entry.feeRate || 0),
    rate: Number(entry.rate || 0),
    recipient: entry.recipient || "",
    purpose: entry.purpose || "",
    beforeBalance: Number(entry.beforeBalance || 0),
    afterBalance: Number(entry.afterBalance || 0),
    reservePct: Number(entry.reservePct || 0),
    source: entry.source || "",
    ts: entry.ts || ""
  });
  return crypto.createHash("sha256").update(canonical).digest("hex");
}

function createLedgerStore(options = {}) {
  const dataDir = options.dataDir || process.env.ORBITPAY_DATA_DIR || path.join(__dirname, "data");
  const maxDocHashes = Number(options.maxDocHashes || MAX_DOC_HASHES);
  const maxTenants = Number(options.maxTenants || MAX_TENANTS);
  const ledgerPath = path.join(dataDir, "ledger.jsonl");
  const statePath = path.join(dataDir, "state.json");

  fs.mkdirSync(dataDir, { recursive: true });

  let pools = { ...INIT_POOLS };
  let rates = { ...OrbitCompliance.DEFAULT_RATES };
  let recipientLedger = {}; // { [recKey]: { volumeInr: number, senders: string[] } }
  let usedDocHashes = new Set();
  let prevChainHash = GENESIS_HASH;
  let tenants = new Map();
  let opsEvents = [];
  let recentLedger = [];

  let ledgerWriteQueue = Promise.resolve();
  let persistScheduled = false;
  let persistInFlight = Promise.resolve();

  function trackDocHash(hash) {
    if (!hash) return;
    if (usedDocHashes.has(hash)) {
      usedDocHashes.delete(hash);
    } else if (usedDocHashes.size >= maxDocHashes) {
      const oldestHash = usedDocHashes.values().next().value;
      usedDocHashes.delete(oldestHash);
    }
    usedDocHashes.add(hash);
  }

  // Item 2: Never persist plaintext OTPs or plaintext unlock tokens to state.json
  function buildSnapshotJson() {
    const tenantsObj = {};
    for (const [id, t] of tenants.entries()) {
      tenantsObj[id] = {
        kycId: t.kycId,
        wrongOtpCount: t.wrongOtpCount,
        accountLocked: t.accountLocked,
        unlockTokenHash: t.unlockTokenHash || "",
        unlockTokenSalt: t.unlockTokenSalt || "",
        cumulativeInrVolume: t.cumulativeInrVolume,
        txHistory: t.txHistory.slice(-MAX_TX_HISTORY_PER_TENANT)
      };
    }
    return JSON.stringify({
      pools,
      rates,
      recipientLedger,
      usedDocHashes: Array.from(usedDocHashes),
      prevChainHash,
      tenants: tenantsObj,
      opsEvents: opsEvents.slice(0, 100)
    });
  }

  function schedulePersist() {
    if (persistScheduled) return persistInFlight;
    persistScheduled = true;
    persistInFlight = persistInFlight.then(
      () => new Promise(resolve => {
        queueMicrotask(async () => {
          persistScheduled = false;
          const json = buildSnapshotJson();
          const tmpFile = `${statePath}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`;
          try {
            await fs.promises.writeFile(tmpFile, json, "utf8");
            await fs.promises.rename(tmpFile, statePath);
          } catch (e) {
            try { fs.unlinkSync(tmpFile); } catch (_) {}
          }
          resolve();
        });
      })
    );
    return persistInFlight;
  }

  function persistSyncImmediate() {
    const tmpFile = `${statePath}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`;
    fs.writeFileSync(tmpFile, buildSnapshotJson(), "utf8");
    fs.renameSync(tmpFile, statePath);
  }

  function defaultTenant(kycId) {
    return {
      kycId,
      wrongOtpCount: 0,
      accountLocked: false,
      unlockTokenHash: "",
      unlockTokenSalt: "",
      activeUnlockTokenForOps: "",
      cumulativeInrVolume: 0,
      txHistory: [],
      pendingOtp: null,
      initiationTimestamps: []
    };
  }

  // Item 3: Read-only lookup (does NOT create tenants on GET)
  function findTenant(kycId) {
    const id = normalizeTenantId(kycId);
    if (!id) return null;
    return tenants.get(id) || null;
  }

  function getOrCreateTenant(kycId) {
    const id = normalizeTenantId(kycId);
    if (!id) return null;
    if (tenants.has(id)) {
      const existing = tenants.get(id);
      if (!Array.isArray(existing.initiationTimestamps)) existing.initiationTimestamps = [];
      tenants.delete(id);
      tenants.set(id, existing);
      return existing;
    }
    if (tenants.size >= maxTenants) {
      // Never evict tenants with active volume, locks, or pending OTPs before idle zero-volume tenants
      for (const [candidateId, candidate] of tenants.entries()) {
        if (!candidate.accountLocked && !candidate.pendingOtp && candidate.cumulativeInrVolume === 0) {
          tenants.delete(candidateId);
          break;
        }
      }
      if (tenants.size >= maxTenants) {
        for (const [candidateId, candidate] of tenants.entries()) {
          if (!candidate.accountLocked && !candidate.pendingOtp) {
            tenants.delete(candidateId);
            break;
          }
        }
      }
    }
    const created = defaultTenant(id);
    tenants.set(id, created);
    return created;
  }

  // Item 6: Rollback prevChainHash & recentLedger cleanly if JSONL append fails
  function appendLedgerBlock(entry) {
    const priorChainHash = prevChainHash;
    const digest = computeBlockDigest(priorChainHash, entry);
    const shortPrev = priorChainHash.slice(0, 10);
    const block = {
      ...entry,
      prevHash: shortPrev,
      fullPrevHash: priorChainHash,
      hash: digest,
      receipt: `sha256:${digest.slice(0, 32)} (prev:${shortPrev})`
    };

    prevChainHash = digest;
    recentLedger.unshift(block);
    if (recentLedger.length > MAX_CACHED_LEDGER) recentLedger.length = MAX_CACHED_LEDGER;

    const line = JSON.stringify(block) + "\n";
    const writePromise = ledgerWriteQueue.then(() => fs.promises.appendFile(ledgerPath, line, "utf8"));
    ledgerWriteQueue = writePromise.catch(err => {
      prevChainHash = priorChainHash;
      const idx = recentLedger.indexOf(block);
      if (idx !== -1) recentLedger.splice(idx, 1);
      opsEvents.unshift({
        severity: "LEDGER_IO_ERROR",
        detail: `Failed to append JSONL audit block: ${err.message}`,
        kycId: "system",
        ts: new Date().toISOString()
      });
    });

    schedulePersist();
    return { block, writePromise };
  }

  function logOpsEvent(severity, detail, kycId = "SYSTEM") {
    opsEvents.unshift({
      severity,
      detail,
      kycId: normalizeTenantId(kycId) || "system",
      ts: new Date().toISOString()
    });
    if (opsEvents.length > 100) opsEvents.length = 100;
    schedulePersist();
  }

  // Item 8: Truncate corrupt/partial trailing JSONL line on crash recovery so future appends start cleanly
  function loadFromDisk() {
    if (fs.existsSync(statePath)) {
      try {
        const saved = JSON.parse(fs.readFileSync(statePath, "utf8"));
        if (saved && saved.pools) pools = { ...INIT_POOLS, ...saved.pools };
        if (saved && saved.rates) {
          for (const [k, v] of Object.entries(saved.rates)) {
            if (OrbitCompliance.isRateWithinCircuitBreaker(k, v)) rates[k] = Number(v);
          }
        }
        if (saved && saved.recipientLedger && typeof saved.recipientLedger === "object") {
          recipientLedger = saved.recipientLedger;
        }
        if (Array.isArray(saved.usedDocHashes)) {
          usedDocHashes = new Set(saved.usedDocHashes.slice(-maxDocHashes));
        }
        if (typeof saved.prevChainHash === "string" && saved.prevChainHash.length === 64) {
          prevChainHash = saved.prevChainHash;
        }
        if (saved && saved.tenants && typeof saved.tenants === "object") {
          for (const [id, rawT] of Object.entries(saved.tenants).slice(-maxTenants)) {
            tenants.set(id, {
              ...defaultTenant(id),
              ...rawT,
              pendingOtp: null,
              initiationTimestamps: []
            });
          }
        }
        if (Array.isArray(saved.opsEvents)) opsEvents = saved.opsEvents;
      } catch (e) {}
    }

    if (fs.existsSync(ledgerPath)) {
      try {
        const raw = fs.readFileSync(ledgerPath, "utf8");
        const rawLines = raw.split("\n");
        const validLines = [];
        const validBlocks = [];
        let hadCorruptLine = false;

        for (const line of rawLines) {
          if (!line.trim()) continue;
          try {
            const parsedLine = JSON.parse(line);
            if (parsedLine && typeof parsedLine.hash === "string" && parsedLine.hash.length === 64) {
              validLines.push(JSON.stringify(parsedLine));
              validBlocks.push(parsedLine);
            } else {
              hadCorruptLine = true;
            }
          } catch (_) {
            hadCorruptLine = true;
          }
        }

        if (hadCorruptLine || (raw.length > 0 && !raw.endsWith("\n"))) {
          fs.writeFileSync(ledgerPath, validLines.length > 0 ? validLines.join("\n") + "\n" : "", "utf8");
        }

        if (validBlocks.length > 0) {
          const last = validBlocks[validBlocks.length - 1];
          prevChainHash = last.hash;
          recentLedger = validBlocks.slice(-MAX_CACHED_LEDGER).reverse();
        }
      } catch (e) {}
    } else {
      fs.writeFileSync(ledgerPath, "", "utf8");
      persistSyncImmediate();
    }
  }

  loadFromDisk();

  function readLedger(limit = 30) {
    return recentLedger.slice(0, limit);
  }

  async function verifyLedgerChain() {
    await flush();
    if (!fs.existsSync(ledgerPath)) return { valid: true, blocks: 0 };

    const stream = fs.createReadStream(ledgerPath, { encoding: "utf8" });
    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

    let expectedPrev = GENESIS_HASH;
    let index = 0;

    try {
      for await (const line of rl) {
        if (!line.trim()) continue;
        let block;
        try {
          block = JSON.parse(line);
        } catch (e) {
          rl.close();
          stream.destroy();
          return { valid: false, brokenAtIndex: index, reason: "CORRUPT_JSON" };
        }
        if (block.fullPrevHash && block.fullPrevHash !== expectedPrev) {
          rl.close();
          stream.destroy();
          return { valid: false, brokenAtIndex: index, reason: "PREV_HASH_MISMATCH" };
        }
        const recomputed = computeBlockDigest(expectedPrev, block);
        if (block.hash !== recomputed) {
          rl.close();
          stream.destroy();
          return { valid: false, brokenAtIndex: index, reason: "DIGEST_TAMPERED" };
        }
        expectedPrev = block.hash;
        index += 1;
      }
    } finally {
      rl.close();
    }

    return { valid: true, blocks: index, headHash: expectedPrev };
  }

  function updateRates(incomingRates) {
    if (!incomingRates || typeof incomingRates !== "object") {
      return { ok: false, status: 400, code: "INVALID_RATES_PAYLOAD", message: "Rates object required." };
    }
    const staged = {};
    for (const [corridor, rawVal] of Object.entries(incomingRates)) {
      if (!Object.prototype.hasOwnProperty.call(OrbitCompliance.DEFAULT_RATES, corridor)) continue;
      const val = Number(rawVal);
      if (!OrbitCompliance.isRateWithinCircuitBreaker(corridor, val)) {
        logOpsEvent("CIRCUIT_BREAKER_TRIP", `Rejected out-of-bounds FX quote ${corridor}=${rawVal}`);
        return {
          ok: false,
          status: 400,
          code: "RATE_CIRCUIT_BREAKER",
          message: `FX rate ${corridor}=${rawVal} violates circuit-breaker bounds.`
        };
      }
      staged[corridor] = +val.toFixed(6);
    }
    if (Object.keys(staged).length > 0) {
      Object.assign(rates, staged);
      schedulePersist();
    }
    return { ok: true, status: 200, rates: { ...rates } };
  }

  function generateUnlockToken() {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    const bytes = crypto.randomBytes(6);
    return Array.from(bytes, b => chars[b % chars.length]).join("");
  }

  function initiateTransfer(params) {
    const tenant = getOrCreateTenant(params.kycId || params.kycName);
    if (!tenant) {
      return {
        ok: false,
        status: 400,
        code: "KYC_ID_REQUIRED",
        message: "Valid alphanumeric kycId or kycName is required."
      };
    }

    if (tenant.accountLocked) {
      logOpsEvent("LOCKED_ATTEMPT", `Blocked transfer for frozen tenant '${tenant.kycId}'`, tenant.kycId);
      return {
        ok: false,
        status: 423,
        code: "ACCOUNT_LOCKED",
        message: `Account '${tenant.kycId}' is frozen after 3 failed OTP attempts. Requires Compliance Officer unlock.`
      };
    }

    const now = Date.now();
    tenant.initiationTimestamps = (tenant.initiationTimestamps || []).filter(ts => now - ts < 60_000);
    if (tenant.initiationTimestamps.length >= MAX_INITIATIONS_PER_MIN) {
      logOpsEvent("OTP_CHURN_BLOCKED", `[${tenant.kycId}] Exceeded ${MAX_INITIATIONS_PER_MIN} transfer initiations/min`, tenant.kycId);
      return {
        ok: false,
        status: 429,
        code: "INITIATE_RATE_LIMITED",
        message: "Too many transfer initiations for this KYC tenant. Retry in 60s."
      };
    }

    const fromCurrency = String(params.fromCurrency || "").trim().toUpperCase();
    const toCurrency = String(params.toCurrency || "").trim().toUpperCase();
    const corridor = `${fromCurrency}_${toCurrency}`;
    const serverRate = rates[corridor];
    if (!serverRate || !OrbitCompliance.isRateWithinCircuitBreaker(corridor, serverRate)) {
      return {
        ok: false,
        status: 400,
        code: "UNSUPPORTED_CORRIDOR",
        message: `Unsupported or circuit-broken corridor '${corridor}'.`
      };
    }
    if (params.rate !== undefined && !OrbitCompliance.isRateWithinCircuitBreaker(corridor, Number(params.rate))) {
      logOpsEvent("RATE_TAMPER_BLOCK", `[${tenant.kycId}] Blocked out-of-bounds client rate ${params.rate} for ${corridor}`, tenant.kycId);
      return {
        ok: false,
        status: 400,
        code: "RATE_CIRCUIT_BREAKER",
        message: `Submitted FX rate violates circuit-breaker bounds for ${corridor}.`
      };
    }

    const proofCheck = verifyServerProofPayload(params.proofBase64);
    if (proofCheck.error) {
      logOpsEvent("SPOOFED_FILE_BLOCKED", `[${tenant.kycId}] ${proofCheck.error}`, tenant.kycId);
      return {
        ok: false,
        status: 400,
        code: "DOC_FORENSICS_FAILED",
        message: proofCheck.error
      };
    }

    const cleanRecipient = String(params.recipient || "Recipient").trim();
    const cleanPurpose = String(params.purpose || "Family Support").trim();
    const cleanDocNum = String(params.docNum || "").trim();
    const recKey = OrbitCompliance.extractBeneficiaryBaseName(cleanRecipient) || "recipient";
    const recStats = recipientLedger[recKey] || { volumeInr: 0, senders: [] };
    const distinctSenders = new Set([...recStats.senders, tenant.kycId]).size;

    const gate = OrbitCompliance.evaluateComplianceGate({
      amount: Number(params.amount),
      currency: fromCurrency,
      toCurrency,
      cumulativeInr: tenant.cumulativeInrVolume,
      recipientCumulativeInr: recStats.volumeInr,
      recipientDistinctSenders: distinctSenders,
      kycName: params.kycName,
      senderName: params.senderName,
      recipient: cleanRecipient,
      purpose: cleanPurpose,
      docType: params.docType,
      docNum: cleanDocNum,
      hasValidProof: proofCheck.hasValidProof,
      docHash: proofCheck.docHash,
      usedDocHashes,
      txHistory: tenant.txHistory,
      rates,
      now
    });

    if (!gate.allowed) {
      logOpsEvent(gate.code, `[${tenant.kycId}] ${gate.message}`, tenant.kycId);
      return { ok: false, status: 400, code: gate.code, message: gate.message };
    }

    tenant.initiationTimestamps.push(now);
    const txId = "TX-" + crypto.randomBytes(6).toString("hex").toUpperCase();
    const otp = String(crypto.randomInt(100000, 1000000));
    const otpSalt = crypto.randomBytes(8).toString("hex");
    tenant.pendingOtp = {
      txId,
      otpHash: hashSecret(otp, otpSalt),
      otpSalt,
      activeOtpForOps: otp,
      expiresAt: now + 60_000,
      tx: {
        txId,
        kycId: tenant.kycId,
        kycName: String(params.kycName).trim().slice(0, 120),
        amount: fromMinor(toMinor(params.amount)),
        fromCurrency,
        toCurrency,
        corridor,
        rate: serverRate,
        recipient: cleanRecipient.slice(0, OrbitCompliance.MAX_RECIPIENT_LEN),
        recKey,
        purpose: cleanPurpose.slice(0, OrbitCompliance.MAX_PURPOSE_LEN),
        docType: String(params.docType || "").trim().slice(0, 40),
        docNum: cleanDocNum.slice(0, OrbitCompliance.MAX_DOC_ID_LEN),
        docHash: proofCheck.docHash,
        inrEq: gate.inrEq
      }
    };
    schedulePersist();

    return {
      ok: true,
      status: 200,
      txId,
      kycId: tenant.kycId,
      lockedRate: serverRate,
      expiresInSec: 60,
      requiresEnhancedDd: gate.requiresEnhancedDd
    };
  }

  // Item 4 & Item 5: txId is MANDATORY, and wrongOtpCount resets to 0 on successful settlement
  async function verifyOtpAndSettle({ kycId, kycName, txId, otp }) {
    const tenant = findTenant(kycId || kycName);
    if (!tenant) {
      return { ok: false, status: 400, code: "KYC_ID_REQUIRED", message: "Valid active kycId is required." };
    }
    if (tenant.accountLocked) {
      return { ok: false, status: 423, code: "ACCOUNT_LOCKED", message: "Account is locked." };
    }
    if (!tenant.pendingOtp) {
      return { ok: false, status: 400, code: "NO_PENDING_TX", message: "No pending OTP challenge for this user." };
    }
    const cleanTxId = String(txId || "").trim();
    if (!cleanTxId || tenant.pendingOtp.txId !== cleanTxId) {
      return {
        ok: false,
        status: 409,
        code: "TX_ID_MISMATCH",
        message: "Valid matching txId is required to confirm pending OTP challenge."
      };
    }
    if (Date.now() > tenant.pendingOtp.expiresAt) {
      tenant.pendingOtp = null;
      schedulePersist();
      return { ok: false, status: 410, code: "OTP_EXPIRED", message: "60s OTP window expired." };
    }

    const entered = String(otp || "").trim();
    if (!/^\d{6}$/.test(entered)) {
      return {
        ok: false,
        status: 400,
        code: "INVALID_OTP_FORMAT",
        message: "Enter a 6-digit numeric OTP.",
        wrongOtpCount: tenant.wrongOtpCount
      };
    }

    const enteredHash = hashSecret(entered, tenant.pendingOtp.otpSalt);
    if (!timingSafeEqualStr(enteredHash, tenant.pendingOtp.otpHash)) {
      tenant.wrongOtpCount += 1;
      logOpsEvent("OTP_FAILURE", `[${tenant.kycId}] Wrong OTP (${tenant.wrongOtpCount}/3)`, tenant.kycId);

      if (tenant.wrongOtpCount >= 3) {
        tenant.accountLocked = true;
        tenant.pendingOtp = null;
        const rawToken = generateUnlockToken();
        const tokenSalt = crypto.randomBytes(8).toString("hex");
        tenant.unlockTokenSalt = tokenSalt;
        tenant.unlockTokenHash = hashSecret(rawToken, tokenSalt);
        tenant.activeUnlockTokenForOps = rawToken;
        schedulePersist();
        // Item 2: Never write raw unlock token into opsEvents log text!
        logOpsEvent(
          "ACCOUNT_LOCKED",
          `[${tenant.kycId}] Frozen after 3 wrong OTPs. Compliance Officer override required.`,
          tenant.kycId
        );
        return {
          ok: false,
          status: 423,
          code: "ACCOUNT_LOCKED",
          message: `Account '${tenant.kycId}' locked after 3 wrong OTP attempts.`,
          wrongOtpCount: tenant.wrongOtpCount,
          accountLocked: true
        };
      }

      schedulePersist();
      return {
        ok: false,
        status: 401,
        code: "WRONG_OTP",
        message: `Incorrect OTP (${tenant.wrongOtpCount}/3).`,
        wrongOtpCount: tenant.wrongOtpCount,
        accountLocked: false
      };
    }

    const tx = tenant.pendingOtp.tx;
    tenant.pendingOtp = null;
    const quote = computeQuote(tx.amount, tx.rate, pools[tx.toCurrency], INIT_POOLS[tx.toCurrency]);
    const feeRate = quote.feeRate;
    const payout = quote.payout;

    if (toMinor(payout) > toMinor(pools[tx.toCurrency])) {
      schedulePersist();
      return {
        ok: false,
        status: 409,
        code: "INSUFFICIENT_POOL_LIQUIDITY",
        message: `Requested payout (${payout} ${tx.toCurrency}) exceeds ${tx.toCurrency} pool balance.`
      };
    }

    const prevFromPool = pools[tx.fromCurrency];
    const prevToPool = pools[tx.toCurrency];
    const prevCumVol = tenant.cumulativeInrVolume;
    const prevWrongOtp = tenant.wrongOtpCount;
    const prevRecEntry = recipientLedger[tx.recKey]
      ? { volumeInr: recipientLedger[tx.recKey].volumeInr, senders: [...recipientLedger[tx.recKey].senders] }
      : null;

    pools[tx.fromCurrency] = fromMinor(toMinor(pools[tx.fromCurrency]) + toMinor(tx.amount));
    pools[tx.toCurrency] = fromMinor(toMinor(pools[tx.toCurrency]) - toMinor(payout));
    tenant.cumulativeInrVolume = fromMinor(toMinor(tenant.cumulativeInrVolume) + toMinor(tx.inrEq));
    tenant.wrongOtpCount = 0; // Item 5: Reset strike counter on successful 2FA settlement

    const updatedSenders = new Set(prevRecEntry ? prevRecEntry.senders : []);
    updatedSenders.add(tenant.kycId);
    recipientLedger[tx.recKey] = {
      volumeInr: fromMinor(toMinor(prevRecEntry ? prevRecEntry.volumeInr : 0) + toMinor(tx.inrEq)),
      senders: Array.from(updatedSenders)
    };

    const { block, writePromise } = appendLedgerBlock({
      type: "SETTLEMENT",
      txId: tx.txId,
      kycId: tenant.kycId,
      kycName: tx.kycName,
      corridor: tx.corridor,
      fromCurrency: tx.fromCurrency,
      toCurrency: tx.toCurrency,
      amount: tx.amount,
      payout,
      feeRate,
      rate: tx.rate,
      recipient: tx.recipient,
      purpose: tx.purpose,
      docType: tx.docType,
      ts: new Date().toISOString()
    });

    try {
      await writePromise;
    } catch (ioErr) {
      pools[tx.fromCurrency] = prevFromPool;
      pools[tx.toCurrency] = prevToPool;
      tenant.cumulativeInrVolume = prevCumVol;
      tenant.wrongOtpCount = prevWrongOtp;
      if (prevRecEntry) recipientLedger[tx.recKey] = prevRecEntry;
      else delete recipientLedger[tx.recKey];
      return {
        ok: false,
        status: 500,
        code: "LEDGER_PERSISTENCE_FAILED",
        message: "Audit ledger write failed; settlement aborted cleanly."
      };
    }

    // Item 7: Track docHash & txHistory, then explicitly schedulePersist() so restarts never lose them
    if (tx.docHash) trackDocHash(tx.docHash);
    tenant.txHistory.push({ from: tx.fromCurrency, to: tx.toCurrency, amount: tx.amount, ts: Date.now() });
    if (tenant.txHistory.length > MAX_TX_HISTORY_PER_TENANT) {
      tenant.txHistory.splice(0, tenant.txHistory.length - MAX_TX_HISTORY_PER_TENANT);
    }
    schedulePersist();

    const destRatio = pools[tx.toCurrency] / INIT_POOLS[tx.toCurrency];
    if (destRatio < 0.20) {
      logOpsEvent(
        "TREASURY_REBALANCE_ALERT",
        `${tx.toCurrency} pool dropped below 20% reserve (${(destRatio * 100).toFixed(1)}%). Dynamic +0.65% spread active.`,
        tenant.kycId
      );
    }

    return {
      ok: true,
      status: 200,
      block,
      pools: { ...pools },
      tenant: getTenantPublicState(tenant.kycId)
    };
  }

  function unlockTenant({ kycId, kycName, token }) {
    const tenant = findTenant(kycId || kycName);
    if (!tenant) {
      return { ok: false, status: 400, code: "KYC_ID_REQUIRED", message: "Valid kycId is required." };
    }
    const cleanToken = String(token || "").trim().toUpperCase();
    const candidateHash = tenant.unlockTokenSalt ? hashSecret(cleanToken, tenant.unlockTokenSalt) : "";
    if (!tenant.accountLocked || !tenant.unlockTokenHash || !timingSafeEqualStr(candidateHash, tenant.unlockTokenHash)) {
      return { ok: false, status: 403, code: "INVALID_UNLOCK_TOKEN", message: "Invalid or inactive single-use unlock token." };
    }
    tenant.accountLocked = false;
    tenant.wrongOtpCount = 0;
    tenant.unlockTokenHash = "";
    tenant.unlockTokenSalt = "";
    tenant.activeUnlockTokenForOps = "";
    schedulePersist();
    logOpsEvent("ACCOUNT_UNLOCKED", `[${tenant.kycId}] Unlocked via single-use compliance token`, tenant.kycId);
    return { ok: true, status: 200, tenant: getTenantPublicState(tenant.kycId) };
  }

  async function rebalancePool({ currency, amount, source = "TREASURY_NOSTRO_TOPUP", operator = "OPS_CONSOLE" }) {
    const cur = String(currency || "").trim().toUpperCase();
    const topUp = fromMinor(toMinor(amount));
    if (!Object.prototype.hasOwnProperty.call(INIT_POOLS, cur)) {
      return { ok: false, status: 400, code: "INVALID_CURRENCY", message: `Unsupported pool currency '${cur}'.` };
    }
    if (!Number.isFinite(topUp) || topUp <= 0) {
      return { ok: false, status: 400, code: "INVALID_TOPUP_AMOUNT", message: "Top-up amount must be a positive number." };
    }

    const before = pools[cur];
    pools[cur] = fromMinor(toMinor(pools[cur]) + toMinor(topUp));
    const reservePct = +((pools[cur] / INIT_POOLS[cur]) * 100).toFixed(1);

    const { block, writePromise } = appendLedgerBlock({
      type: "TREASURY_REBALANCE",
      kycId: operator,
      currency: cur,
      amount: topUp,
      beforeBalance: before,
      afterBalance: pools[cur],
      reservePct,
      source: String(source).trim().slice(0, 60),
      ts: new Date().toISOString()
    });

    try {
      await writePromise;
    } catch (ioErr) {
      pools[cur] = before;
      return {
        ok: false,
        status: 500,
        code: "LEDGER_PERSISTENCE_FAILED",
        message: "Audit ledger write failed; treasury rebalance rolled back."
      };
    }

    logOpsEvent(
      "TREASURY_TOPUP",
      `Injected +${topUp} ${cur} via ${source} (Reserve now ${reservePct}%)`,
      operator
    );

    return {
      ok: true,
      status: 200,
      currency: cur,
      added: topUp,
      balance: pools[cur],
      reservePct,
      rebalanceFeeActive: reservePct < 20,
      block,
      pools: { ...pools }
    };
  }

  // Item 3: Pure read-only tenant state projection (zero side effects on GET)
  function getTenantPublicState(kycId) {
    const id = normalizeTenantId(kycId);
    if (!id) {
      return { kycId: "", wrongOtpCount: 0, accountLocked: false, cumulativeInrVolume: 0, txCount: 0, hasPendingOtp: false };
    }
    const t = findTenant(id);
    if (!t) {
      return { kycId: id, wrongOtpCount: 0, accountLocked: false, cumulativeInrVolume: 0, txCount: 0, hasPendingOtp: false };
    }
    const hasPending = Boolean(t.pendingOtp && Date.now() <= t.pendingOtp.expiresAt);
    return {
      kycId: t.kycId,
      wrongOtpCount: t.wrongOtpCount,
      accountLocked: t.accountLocked,
      cumulativeInrVolume: t.cumulativeInrVolume,
      txCount: t.txHistory.length,
      hasPendingOtp: hasPending
    };
  }

  // Item 1: Unauthenticated public status returns ONLY tenant-scoped ledger + pools + rates (NO opsEvents, NO other tenants' data)
  function getPublicStatus(kycId) {
    const id = normalizeTenantId(kycId);
    const tenantLedger = id
      ? recentLedger.filter(b => b.kycId === id || b.type === "TREASURY_REBALANCE").slice(0, 30)
      : [];
    return {
      pools: { ...pools },
      initPools: { ...INIT_POOLS },
      rates: { ...rates },
      feeConfig: OrbitCompliance.FEE_CONFIG,
      prevChainHash,
      tenant: getTenantPublicState(id),
      ledger: tenantLedger
    };
  }

  // Privileged Ops view (behind Ops PIN auth): includes global ledger, opsEvents, active OTP challenge, & dynamic unlock token
  function getOpsStatus(kycId) {
    const id = normalizeTenantId(kycId);
    const t = id ? findTenant(id) : null;
    const activeChallenge = t && t.pendingOtp && Date.now() <= t.pendingOtp.expiresAt
      ? {
          kycId: t.kycId,
          txId: t.pendingOtp.txId,
          otp: t.pendingOtp.activeOtpForOps,
          expiresInSec: Math.max(1, Math.ceil((t.pendingOtp.expiresAt - Date.now()) / 1000))
        }
      : null;
    return {
      pools: { ...pools },
      initPools: { ...INIT_POOLS },
      rates: { ...rates },
      prevChainHash,
      tenant: getTenantPublicState(id),
      ledger: readLedger(30),
      opsEvents: opsEvents.slice(0, 30),
      activeChallenge,
      tenantUnlockToken: t && t.accountLocked ? t.activeUnlockTokenForOps : ""
    };
  }

  // Append-only audit compliant reset: appends LEDGER_RESET genesis marker rather than truncating history
  async function resetDemo() {
    pools = { ...INIT_POOLS };
    rates = { ...OrbitCompliance.DEFAULT_RATES };
    recipientLedger = {};
    usedDocHashes = new Set();
    tenants = new Map();
    opsEvents = [];
    const { block, writePromise } = appendLedgerBlock({
      type: "LEDGER_RESET",
      kycId: "OPS_CONSOLE",
      amount: 0,
      source: "OPERATOR_SANDBOX_RESET",
      ts: new Date().toISOString()
    });
    await writePromise;
    persistSyncImmediate();
    return { ok: true, status: 200, pools: { ...pools }, rates: { ...rates }, block };
  }

  async function flush() {
    await ledgerWriteQueue;
    await persistInFlight;
  }

  return {
    INIT_POOLS,
    findTenant,
    getTenant: getOrCreateTenant,
    getTenantPublicState,
    updateRates,
    initiateTransfer,
    verifyOtpAndSettle,
    unlockTenant,
    rebalancePool,
    getStatus: getPublicStatus,
    getOpsStatus,
    readLedger,
    verifyLedgerChain,
    resetDemo,
    flush,
    _stats: () => ({ docHashesSize: usedDocHashes.size, tenantsSize: tenants.size })
  };
}

module.exports = { createLedgerStore, INIT_POOLS, normalizeTenantId, timingSafeEqualStr, verifyServerProofPayload };
