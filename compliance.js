(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.OrbitCompliance = factory();
  }
}(typeof self !== "undefined" ? self : this, function () {
  const INIT_POOLS = Object.freeze({
    USD: 254500.00,
    INR: 20680975.35,
    EUR: 180000.00,
    GBP: 140000.00
  });

  const CORRIDOR_META = Object.freeze({
    EUR_INR: { from: "EUR", to: "INR", sym: "\u20B9", defaultRec: "Ravi Sharma (INR Local Pool)" },
    INR_EUR: { from: "INR", to: "EUR", sym: "\u20AC", defaultRec: "Lukas Weber (EUR Local Pool)" },
    USD_INR: { from: "USD", to: "INR", sym: "\u20B9", defaultRec: "Ravi Sharma (INR Local Pool)" },
    INR_USD: { from: "INR", to: "USD", sym: "$", defaultRec: "Alex Morgan (USD Local Pool)" },
    GBP_INR: { from: "GBP", to: "INR", sym: "\u20B9", defaultRec: "Ravi Sharma (INR Local Pool)" },
    INR_GBP: { from: "INR", to: "GBP", sym: "\u00A3", defaultRec: "Arthur Pendelton (GBP Local Pool)" },
    USD_EUR: { from: "USD", to: "EUR", sym: "\u20AC", defaultRec: "Lukas Weber (EUR Local Pool)" },
    EUR_USD: { from: "EUR", to: "USD", sym: "$", defaultRec: "Alex Morgan (USD Local Pool)" },
    GBP_USD: { from: "GBP", to: "USD", sym: "$", defaultRec: "Alex Morgan (USD Local Pool)" },
    USD_GBP: { from: "USD", to: "GBP", sym: "\u00A3", defaultRec: "Arthur Pendelton (GBP Local Pool)" }
  });

  const DEFAULT_RATES = Object.freeze({
    EUR_INR: 102.523,
    INR_EUR: 0.009754,
    USD_INR: 93.3727,
    INR_USD: 0.01071,
    GBP_INR: 118.2,
    INR_GBP: 0.00846,
    USD_EUR: 0.9107,
    EUR_USD: 1.0981,
    GBP_USD: 1.2659,
    USD_GBP: 0.7899
  });

  const RATE_BOUNDS = Object.freeze({
    EUR_INR: [75, 140],
    INR_EUR: [0.007, 0.014],
    USD_INR: [70, 125],
    INR_USD: [0.008, 0.015],
    GBP_INR: [90, 160],
    INR_GBP: [0.006, 0.012],
    USD_EUR: [0.65, 1.25],
    EUR_USD: [0.80, 1.55],
    GBP_USD: [0.95, 1.65],
    USD_GBP: [0.55, 1.05]
  });

  const FEE_CONFIG = Object.freeze({
    BASE_FEE_RATE: 0.004,
    REBALANCE_FEE_RATE: 0.0105,
    LOW_RESERVE_THRESHOLD: 0.20,
    HIGH_VALUE_INR: 200000,
    MAX_ROLLING_INR: 500000,
    ROUND_TRIP_WINDOW_MS: 24 * 60 * 60 * 1000
  });

  const MIN_PROOF_BYTES = 4096;
  const MAX_PROOF_BYTES = 5 * 1024 * 1024;
  const MAX_DOC_ID_LEN = 32;
  const MAX_RECIPIENT_LEN = 120;
  const MAX_PURPOSE_LEN = 80;
  const MIN_TRANSFER_AMOUNT = 0.01;

  // Integer minor-unit (paise/cents) helpers to avoid IEEE-754 float drift
  function toMinor(amount) {
    return Math.round(Number(amount) * 100);
  }

  function fromMinor(minor) {
    return Math.round(minor) / 100;
  }

  function computeQuote(amount, rate, destBalance, destInitBalance) {
    const amtMinor = toMinor(amount);
    const ratio = destInitBalance > 0 ? destBalance / destInitBalance : 1;
    const feeRate = ratio < FEE_CONFIG.LOW_RESERVE_THRESHOLD
      ? FEE_CONFIG.REBALANCE_FEE_RATE
      : FEE_CONFIG.BASE_FEE_RATE;
    const feeMinor = Math.round(amtMinor * feeRate);
    const netMinor = amtMinor - feeMinor;
    const payoutMinor = Math.round(netMinor * rate);
    return {
      feeRate,
      fee: fromMinor(feeMinor),
      payout: fromMinor(payoutMinor),
      rebalanceActive: ratio < FEE_CONFIG.LOW_RESERVE_THRESHOLD
    };
  }

  function normalizeIdentityName(name) {
    return String(name || "")
      .normalize("NFKC")
      .trim()
      .replace(/\s+/g, " ")
      .toLowerCase();
  }

  function extractBeneficiaryBaseName(recipient) {
    const stripped = String(recipient || "")
      .replace(/\([^)]*\)/g, " ")
      .trim();
    return normalizeIdentityName(stripped);
  }

  function isRateWithinCircuitBreaker(corridor, rate) {
    const num = Number(rate);
    if (!Number.isFinite(num) || num <= 0) return false;
    const bounds = RATE_BOUNDS[corridor];
    if (!bounds) return false;
    return num >= bounds[0] && num <= bounds[1];
  }

  function toInr(amount, currency, rates = DEFAULT_RATES) {
    const cur = String(currency || "").trim().toUpperCase();
    if (cur === "INR") return fromMinor(toMinor(amount));
    if (cur === "USD") return fromMinor(Math.round(toMinor(amount) * rates.USD_INR));
    if (cur === "EUR") return fromMinor(Math.round(toMinor(amount) * rates.EUR_INR));
    if (cur === "GBP") return fromMinor(Math.round(toMinor(amount) * rates.GBP_INR));
    throw new RangeError("Unsupported currency for INR normalization: " + cur);
  }

  function validatePanForHolder(pan, fullName) {
    const cleanPan = String(pan || "").trim().toUpperCase();
    if (!/^[A-Z]{5}[0-9]{4}[A-Z]$/.test(cleanPan)) {
      return "PAN must follow 10-char format (e.g. ABCPP8821F).";
    }
    if (cleanPan[3] !== "P") {
      return "4th character of individual PAN must be 'P' (Personal).";
    }
    const parts = String(fullName || "").normalize("NFKC").trim().toUpperCase().split(/\s+/).filter(Boolean);
    const surnameInitial = parts.length > 0 ? parts[parts.length - 1][0] : "";
    if (surnameInitial && cleanPan[4] !== surnameInitial) {
      return "5th character of PAN must match holder surname initial ('" + surnameInitial + "').";
    }
    return "";
  }

  function detectCircularRoundTrip(history, fromCurrency, toCurrency, now = Date.now(), windowMs = FEE_CONFIG.ROUND_TRIP_WINDOW_MS) {
    if (!Array.isArray(history) || history.length === 0) return false;
    return history.some(tx => {
      if (tx.from !== toCurrency || tx.to !== fromCurrency) return false;
      if (typeof tx.ts === "number" && (now - tx.ts) > windowMs) return false;
      return true;
    });
  }

  function detectBinaryFormat(bytes) {
    if (!bytes || typeof bytes.length !== "number" || bytes.length < 4) return null;
    if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) return "PDF";
    if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) return "PNG";
    if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) return "JPEG";
    return null;
  }

  function bytesToLatin1Chunked(bytes, start, end) {
    const CHUNK = 4096;
    const parts = [];
    for (let i = start; i < end; i += CHUNK) {
      const slice = bytes.subarray ? bytes.subarray(i, Math.min(end, i + CHUNK)) : bytes.slice(i, Math.min(end, i + CHUNK));
      parts.push(String.fromCharCode.apply(null, slice));
    }
    return parts.join("");
  }

  // Deep binary structure + Shannon entropy check across PDF, PNG, and JPEG
  function inspectBinaryProof(bytes) {
    if (!bytes || bytes.length < MIN_PROOF_BYTES || bytes.length > MAX_PROOF_BYTES) {
      return { ok: false, reason: "Proof file must be between 4 KB and 5 MB (blank/tiny files rejected)." };
    }
    const format = detectBinaryFormat(bytes);
    if (!format) {
      return { ok: false, reason: "Invalid binary magic-byte header (must be authentic PDF, PNG, or JPEG)." };
    }

    // Shannon entropy check on payload body (rejects zero-padded or single-byte spoofed buffers)
    const sampleStart = 16;
    const sampleEnd = Math.min(bytes.length, 65536);
    const freq = new Uint32Array(256);
    const sampleLen = sampleEnd - sampleStart;
    for (let i = sampleStart; i < sampleEnd; i++) freq[bytes[i]]++;
    let entropy = 0;
    for (let b = 0; b < 256; b++) {
      if (freq[b] > 0) {
        const p = freq[b] / sampleLen;
        entropy -= p * Math.log2(p);
      }
    }
    if (entropy < 1.5) {
      return { ok: false, reason: "Low-entropy or blank-padded binary file rejected by document forensics." };
    }

    if (format === "PDF") {
      const headEnd = Math.min(bytes.length, 32768);
      const tailStart = Math.max(0, bytes.length - 1024);
      const head = bytesToLatin1Chunked(bytes, 0, headEnd);
      const tail = bytesToLatin1Chunked(bytes, tailStart, bytes.length);
      const hasEof = head.includes("%%EOF") || tail.includes("%%EOF");
      const hasObj = head.includes("obj") && head.includes("endobj");
      if (!hasEof || !hasObj) {
        return { ok: false, reason: "Corrupt or empty PDF structure (missing PDF object streams or %%EOF marker)." };
      }
    } else if (format === "PNG") {
      // Must contain IHDR chunk at offset 12..15 and IEND trailer marker
      const hasIhdr = bytes.length >= 24 && bytes[12] === 0x49 && bytes[13] === 0x48 && bytes[14] === 0x44 && bytes[15] === 0x52;
      const tailStr = bytesToLatin1Chunked(bytes, Math.max(0, bytes.length - 64), bytes.length);
      if (!hasIhdr || !tailStr.includes("IEND")) {
        return { ok: false, reason: "Corrupt PNG structure (missing IHDR header or IEND chunk)." };
      }
    } else if (format === "JPEG") {
      // Must end with JPEG EOI marker (0xFF 0xD9) and contain valid segment markers
      const hasEoi = bytes[bytes.length - 2] === 0xFF && bytes[bytes.length - 1] === 0xD9;
      if (!hasEoi) {
        return { ok: false, reason: "Corrupt JPEG structure (missing 0xFFD9 End-Of-Image marker)." };
      }
    }
    return { ok: true, format };
  }

  function evaluateComplianceGate({
    amount,
    currency,
    toCurrency,
    cumulativeInr,
    recipientCumulativeInr = 0,
    recipientDistinctSenders = 0,
    kycName,
    senderName,
    recipient = "Recipient",
    purpose = "Family Support",
    docType,
    docNum,
    hasValidProof,
    docHash = "",
    usedDocHashes = [],
    txHistory = [],
    rates = DEFAULT_RATES,
    now = Date.now()
  }) {
    if (!Number.isFinite(amount) || amount < MIN_TRANSFER_AMOUNT) {
      return { allowed: false, code: "INVALID_AMOUNT", message: "Enter a transfer amount of at least 0.01." };
    }
    if (String(kycName || "").trim().length > 120 || String(senderName || "").trim().length > 120) {
      return { allowed: false, code: "FIELD_TOO_LONG", message: "KYC or sender name exceeds 120 characters." };
    }
    if (String(recipient || "").trim().length > MAX_RECIPIENT_LEN) {
      return { allowed: false, code: "RECIPIENT_TOO_LONG", message: "Recipient label exceeds 120 characters." };
    }
    if (String(purpose || "").trim().length > MAX_PURPOSE_LEN) {
      return { allowed: false, code: "PURPOSE_TOO_LONG", message: "Purpose code exceeds 80 characters." };
    }

    const normKyc = normalizeIdentityName(kycName);
    const normSender = normalizeIdentityName(senderName);
    const normRecipient = extractBeneficiaryBaseName(recipient);

    if (!normKyc || !normSender || normKyc !== normSender) {
      return { allowed: false, code: "AML_MISMATCH", message: "Source bank holder does not match verified KYC holder (Third-party funding blocked)." };
    }
    if (normRecipient && normRecipient === normKyc) {
      return { allowed: false, code: "SELF_TRANSFER_AML", message: "Self-remittance to identical KYC beneficiary is blocked by AML policy." };
    }
    if (toCurrency && detectCircularRoundTrip(txHistory, currency, toCurrency, now)) {
      return { allowed: false, code: "ROUND_TRIP_AML", message: "Circular round-trip layering detected (" + currency + " \u2194 " + toCurrency + "). Transfer frozen for AML review." };
    }

    let inrEq;
    try {
      inrEq = toInr(amount, currency, rates);
    } catch (e) {
      return { allowed: false, code: "UNSUPPORTED_CURRENCY", message: e.message };
    }

    const projectedSender = fromMinor(toMinor(cumulativeInr) + toMinor(inrEq));
    const projectedRecipient = fromMinor(toMinor(recipientCumulativeInr) + toMinor(inrEq));

    if (projectedSender > FEE_CONFIG.MAX_ROLLING_INR || projectedRecipient > FEE_CONFIG.MAX_ROLLING_INR) {
      return { allowed: false, code: "ROLLING_CAP_EXCEEDED", message: "Rolling sender/recipient volume exceeds \u20B95,00,000 hard cap (Anti-structuring protection)." };
    }

    const cleanDocNum = String(docNum || "").trim();
    if (docType === "PAN Card") {
      const panErr = validatePanForHolder(cleanDocNum, kycName);
      if (panErr) return { allowed: false, code: "INVALID_PAN", message: panErr };
    } else if (!/^[A-Za-z0-9\-\/]{6,32}$/.test(cleanDocNum)) {
      return { allowed: false, code: "DOC_ID_REQUIRED", message: "Document ID must be 6-32 alphanumeric characters (letters, digits, '-', '/')." };
    }

    const isDuplicateDoc = docHash && (
      usedDocHashes instanceof Set
        ? usedDocHashes.has(docHash)
        : Array.isArray(usedDocHashes) && usedDocHashes.includes(docHash)
    );
    if (isDuplicateDoc) {
      return { allowed: false, code: "DUPLICATE_DOC_HASH", message: "Duplicate proof document detected. Reusing the same invoice/ID file across transfers is blocked." };
    }

    const fanInSmurfing = recipientDistinctSenders >= 2 && projectedRecipient > 150000;
    const requiresEnhancedDd = projectedSender > FEE_CONFIG.HIGH_VALUE_INR || projectedRecipient > FEE_CONFIG.HIGH_VALUE_INR || fanInSmurfing;
    if (requiresEnhancedDd && !hasValidProof) {
      return { allowed: false, code: "PROOF_REQUIRED", message: "Enhanced Due Diligence triggered (>\u20B92L volume or multi-sender fan-in). Upload a genuine PDF/JPG/PNG proof document." };
    }

    return {
      allowed: true,
      code: "APPROVED",
      inrEq,
      projected: projectedSender,
      projectedRecipient,
      requiresEnhancedDd
    };
  }

  return Object.freeze({
    INIT_POOLS,
    CORRIDOR_META,
    DEFAULT_RATES,
    RATE_BOUNDS,
    FEE_CONFIG,
    MIN_PROOF_BYTES,
    MAX_PROOF_BYTES,
    MAX_DOC_ID_LEN,
    MAX_RECIPIENT_LEN,
    MAX_PURPOSE_LEN,
    MIN_TRANSFER_AMOUNT,
    toMinor,
    fromMinor,
    computeQuote,
    normalizeIdentityName,
    extractBeneficiaryBaseName,
    isRateWithinCircuitBreaker,
    toInr,
    validatePanForHolder,
    detectCircularRoundTrip,
    detectBinaryFormat,
    inspectBinaryProof,
    evaluateComplianceGate
  });
}));
