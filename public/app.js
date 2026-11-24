(function () {
  "use strict";

  const OPS_SESSION_TTL_MS = 5 * 60 * 1000;
  const { INIT_POOLS, CORRIDOR_META: META, FEE_CONFIG, computeQuote } = OrbitCompliance;
  const PRESET_PANS = Object.freeze({
    "Ravindra Prajapat": "ABCPP8821F",
    "Ananya Sharma": "XYZPS4419K",
    "Vikram Rathore": "LMNPR9021D"
  });
  const MODAL_IDS = ["bioModal", "bankModal", "opsAuthModal"];

  const $ = id => document.getElementById(id);

  let pools = { ...INIT_POOLS };
  let rates = { ...OrbitCompliance.DEFAULT_RATES };
  let rateMode = "Server Locked";
  let tenantState = { kycId: "ravindra_prajapat", wrongOtpCount: 0, accountLocked: false, cumulativeInrVolume: 0 };
  let activeTxId = "";
  let verifiedOpsPin = "";
  let opsPinTimer = null;
  let pendingOpsAction = null;
  let otpCountdown = null;
  let otpSecondsLeft = 60;
  let lastTriggerEl = null;
  let syncSeq = 0;
  let lastLedgerFingerprint = "";
  let lastOpsFingerprint = "";

  function setStatus(cls, prefix, text) {
    const out = $("outBox");
    out.textContent = "";
    const badge = document.createElement("span");
    badge.className = cls;
    badge.textContent = prefix + " ";
    out.appendChild(badge);
    out.appendChild(document.createTextNode(text));
  }

  function setFieldError(inputEl, errEl, message) {
    if (message) {
      inputEl.setAttribute("aria-invalid", "true");
      errEl.textContent = message;
    } else {
      inputEl.removeAttribute("aria-invalid");
      errEl.textContent = "";
    }
  }

  function clearOpsSession() {
    verifiedOpsPin = "";
    clearTimeout(opsPinTimer);
    opsPinTimer = null;
  }

  function armOpsSession(pin) {
    verifiedOpsPin = pin;
    clearTimeout(opsPinTimer);
    opsPinTimer = setTimeout(() => {
      clearOpsSession();
      const panel = $("stealthPanel");
      if (panel.classList.contains("open")) {
        panel.classList.remove("open");
        $("orbTrigger").setAttribute("aria-expanded", "false");
        setStatus("warn", "OPS SESSION EXPIRED:", "Compliance Ops Console auto-locked after 5 minutes of inactivity.");
      }
    }, OPS_SESSION_TTL_MS);
  }

  function getFocusableElements(container) {
    return Array.from(
      container.querySelectorAll(
        'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
      )
    ).filter(el => el.offsetParent !== null);
  }

  function trapModalTab(e, modalEl) {
    if (e.key !== "Tab") return;
    const focusables = getFocusableElements(modalEl);
    if (focusables.length === 0) return;
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }

  function setBackgroundInert(isInert) {
    const appRoot = $("appRoot");
    if (!appRoot) return;
    appRoot.inert = isInert;
    if (isInert) {
      appRoot.setAttribute("aria-hidden", "true");
    } else {
      appRoot.removeAttribute("aria-hidden");
    }
  }

  function openModal(modalEl, focusEl, preserveTrigger = false) {
    if (!preserveTrigger) {
      lastTriggerEl = document.activeElement;
    }
    modalEl.querySelectorAll("[aria-invalid]").forEach(el => el.removeAttribute("aria-invalid"));
    modalEl.querySelectorAll('[role="alert"]').forEach(el => { el.textContent = ""; });
    setBackgroundInert(true);
    modalEl.classList.add("open");
    if (focusEl) focusEl.focus();
  }

  function closeModal(modalEl, restoreFocus = true) {
    if (!modalEl.classList.contains("open")) return;
    modalEl.classList.remove("open");
    if (modalEl.id === "bioModal") clearInterval(otpCountdown);
    const anyOpen = MODAL_IDS.some(id => $(id).classList.contains("open"));
    if (!anyOpen) setBackgroundInert(false);
    if (restoreFocus && lastTriggerEl && typeof lastTriggerEl.focus === "function" && lastTriggerEl.offsetParent !== null) {
      lastTriggerEl.focus();
    }
  }

  for (const id of MODAL_IDS) {
    const modal = $(id);
    modal.addEventListener("keydown", e => {
      if (e.key === "Escape") {
        e.preventDefault();
        if (id === "opsAuthModal" && pendingOpsAction === "modalOtp") {
          pendingOpsAction = null;
          closeModal(modal, false);
          openModal($("bioModal"), $("liveInput"), true);
          return;
        }
        pendingOpsAction = null;
        closeModal(modal, true);
        return;
      }
      trapModalTab(e, modal);
    });
    // Non-OTP modals allow backdrop click dismissal; bioModal prevents accidental 2FA dismissal
    if (id !== "bioModal") {
      modal.addEventListener("click", e => {
        if (e.target === modal) {
          if (id === "opsAuthModal" && pendingOpsAction === "modalOtp") {
            pendingOpsAction = null;
            closeModal(modal, false);
            openModal($("bioModal"), $("liveInput"), true);
            return;
          }
          pendingOpsAction = null;
          closeModal(modal, true);
        }
      });
    }
  }

  function activeKycName() { return $("kyc").value.trim(); }
  function currentCorridor() { return $("corridor").value; }
  function getActiveRate() { return rates[currentCorridor()]; }

  function formatNum(n, dec = 2) {
    return Number(n).toLocaleString("en-IN", { minimumFractionDigits: dec, maximumFractionDigits: dec });
  }

  function setStep(idx, label, cls) {
    const el = $("s" + idx);
    const card = $("st" + idx);
    el.textContent = label;
    el.className = cls;
    card.className = "step" + (cls === "run" ? " active" : "");
  }

  function renderPools() {
    $("usPool").textContent = "$" + pools.USD.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    $("inPool").textContent = "\u20B9" + formatNum(pools.INR, 2);
    $("euPool").textContent = "\u20AC" + pools.EUR.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    $("ukPool").textContent = "\u00A3" + pools.GBP.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });

    for (const cur of Object.keys(INIT_POOLS)) {
      const card = $("poolCard_" + cur);
      if (card) card.classList.toggle("low", (pools[cur] / INIT_POOLS[cur]) < FEE_CONFIG.LOW_RESERVE_THRESHOLD);
    }
    $("capPill").textContent = "Tenant Vol: \u20B9" + formatNum(tenantState.cumulativeInrVolume || 0, 0) + " / \u20B95L";
  }

  function syncLockUI() {
    const locked = Boolean(tenantState.accountLocked);
    $("bankApproveBtn").classList.toggle("hidden", !locked);
    const s2 = $("s2");
    if (locked) {
      s2.textContent = "LOCKED (3/3)";
      s2.className = "bad";
      setStep(1, "Tenant Frozen", "bad");
    } else {
      const cnt = tenantState.wrongOtpCount || 0;
      s2.textContent = cnt + "/3 Failed";
      s2.className = cnt > 0 ? "run" : "wait";
      setStep(1, "Ready", "wait");
    }
  }

  function renderLedger(entries) {
    const fp = JSON.stringify((entries || []).map(e => e.hash));
    if (fp === lastLedgerFingerprint) return;
    lastLedgerFingerprint = fp;

    const logList = $("logList");
    logList.textContent = "";
    if (!entries || entries.length === 0) {
      const emptyLi = document.createElement("li");
      emptyLi.textContent = "No transactions yet for this tenant.";
      logList.appendChild(emptyLi);
      return;
    }
    for (const item of entries) {
      const row = document.createElement("li");
      row.className = "log-item";

      const left = document.createElement("div");
      const badge = document.createElement("span");
      badge.className = "ok";
      badge.textContent = `[${item.type}] `;
      const summary = item.type === "TREASURY_REBALANCE"
        ? `+${formatNum(item.amount, 2)} ${item.currency} injected (${item.source}) | Reserve: ${item.reservePct}% | ${item.receipt}`
        : `[${item.kycId}] ${item.amount} ${item.fromCurrency} \u2192 ${formatNum(item.payout, 2)} ${item.toCurrency} | ${item.receipt}`;
      left.appendChild(badge);
      left.appendChild(document.createTextNode(summary));

      const right = document.createElement("div");
      right.className = "muted";
      right.textContent = new Date(item.ts).toLocaleTimeString();

      row.appendChild(left);
      row.appendChild(right);
      logList.appendChild(row);
    }
  }

  function renderOpsEvents(events) {
    const fp = JSON.stringify(events || []);
    if (fp === lastOpsFingerprint) return;
    lastOpsFingerprint = fp;

    const box = $("stealthLogs");
    box.textContent = "";
    if (!events || events.length === 0) {
      const emptyLi = document.createElement("li");
      emptyLi.textContent = "No risk or treasury events captured yet.";
      box.appendChild(emptyLi);
      return;
    }
    for (const ev of events) {
      const row = document.createElement("li");
      row.className = "log-item";
      const left = document.createElement("div");
      const badge = document.createElement("span");
      badge.className = ev.severity.includes("TOPUP") || ev.severity.includes("UNLOCK") ? "ok" : "bad";
      badge.textContent = `[${ev.severity}] `;
      left.appendChild(badge);
      left.appendChild(document.createTextNode(ev.detail));
      const right = document.createElement("div");
      right.className = "muted";
      right.textContent = new Date(ev.ts).toLocaleTimeString();
      row.appendChild(left);
      row.appendChild(right);
      box.appendChild(row);
    }
  }

  async function apiRequest(endpoint, body) {
    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      const text = await res.text();
      try {
        return JSON.parse(text);
      } catch (_) {
        return {
          ok: false,
          code: `HTTP_${res.status}`,
          message: `Server returned non-JSON response (${res.status}).`
        };
      }
    } catch (err) {
      return {
        ok: false,
        code: "NETWORK_ERROR",
        message: "Unable to reach OrbitPay server. Check connection and retry."
      };
    }
  }

  async function syncServerState() {
    const reqId = ++syncSeq;
    try {
      const res = await fetch("/api/state?kycId=" + encodeURIComponent(activeKycName()));
      const data = await res.json();
      if (reqId !== syncSeq) return; // Discard stale out-of-order response
      if (data.ok) {
        pools = { ...INIT_POOLS, ...data.pools };
        if (data.rates) rates = { ...OrbitCompliance.DEFAULT_RATES, ...data.rates };
        tenantState = data.tenant;
        renderPools();
        syncLockUI();
        refreshQuote();
        renderLedger(data.ledger);
      }
    } catch (e) {}
  }

  function onTenantChange() {
    clearInterval(otpCountdown);
    activeTxId = "";
    closeModal($("bioModal"), false);
    closeModal($("bankModal"), false);

    const name = activeKycName();
    $("dep").value = name;
    if (PRESET_PANS[name]) {
      $("docType").value = "PAN Card";
      $("docNum").value = PRESET_PANS[name];
    }
    setStep(3, "Ready", "wait");
    setStep(4, "Ready", "wait");
    setStatus("ok", "ACTIVE TENANT:", `Switched context to ${name || "(empty)"}. Synced per-tenant volume & lock state.`);
    syncServerState();
  }

  function onCorridorChange() {
    const c = currentCorridor();
    const m = META[c];
    $("ratePairText").textContent = `${m.from} to ${m.to} Rate`;
    $("rateInput").value = rates[c];
    $("rec").value = m.defaultRec;
    refreshQuote();
  }

  function validateAmountField() {
    const raw = parseFloat($("amt").value);
    if (!Number.isFinite(raw) || raw < OrbitCompliance.MIN_TRANSFER_AMOUNT) {
      setFieldError($("amt"), $("amtErr"), "Enter an amount of at least 0.01.");
      return false;
    }
    setFieldError($("amt"), $("amtErr"), "");
    return true;
  }

  function refreshQuote() {
    const c = currentCorridor();
    const m = META[c];
    const r = getActiveRate();
    const rawAmt = parseFloat($("amt").value);
    const amt = Number.isFinite(rawAmt) && rawAmt > 0 ? rawAmt : 0;
    const quote = computeQuote(amt, r, pools[m.to], INIT_POOLS[m.to]);
    const swiftEst = (amt * 0.065 + 12).toFixed(2);
    const inrEq = OrbitCompliance.toInr(amt, m.from, rates);
    const projectedCumulative = (tenantState.cumulativeInrVolume || 0) + inrEq;

    $("rateInput").value = r;
    $("rateLine").textContent = `1 ${m.from} = ${r} ${m.to}`;
    $("ratePill").textContent = `1 ${m.from} = ${r} ${m.to} (${rateMode})`;
    $("swiftLine").textContent = `${swiftEst} ${m.from} (3-5 Days)`;
    $("feeLabel").textContent = quote.rebalanceActive
      ? "OrbitPay Mesh Fee (1.05% Rebalance Active):"
      : "OrbitPay Mesh Fee (0.4% base):";
    $("feeLine").textContent = `${quote.fee.toFixed(2)} ${m.from}`;
    $("payoutLine").textContent = `${m.sym}${formatNum(quote.payout, 2)} ${m.to}`;

    const docTag = $("docReqTag");
    const requiresProof = inrEq > FEE_CONFIG.HIGH_VALUE_INR || projectedCumulative > FEE_CONFIG.HIGH_VALUE_INR;
    docTag.textContent = requiresProof ? "Mandatory (Cumulative > \u20B92L)" : "Optional (Cumulative \u2264 \u20B92L)";
    docTag.classList.toggle("warn-tag", requiresProof);
  }

  async function fetchRates(manual = false) {
    const diag = $("diag");
    if (manual) diag.textContent = "Refreshing live FX rates via server...";
    try {
      const res = await fetch("/api/rates/refresh" + (manual ? "?force=1" : ""));
      const data = await res.json();
      if (data.ok && data.rates) {
        rates = { ...OrbitCompliance.DEFAULT_RATES, ...data.rates };
        rateMode = data.source || "Server Locked";
        diag.textContent = `FX quote verified & circuit-locked on server (${rateMode}).`;
        refreshQuote();
        return;
      }
    } catch (e) {}
    rateMode = "Server Locked";
    diag.textContent = "Using server circuit-breaker FX quote.";
    refreshQuote();
  }

  async function readProofFileBase64(file) {
    if (!file) return { ok: true, proofBase64: "" };
    if (file.size < OrbitCompliance.MIN_PROOF_BYTES || file.size > OrbitCompliance.MAX_PROOF_BYTES) {
      return { ok: false, reason: "Proof file must be between 4 KB and 5 MB." };
    }
    const fullBuf = await file.arrayBuffer();
    const fullBytes = new Uint8Array(fullBuf);
    const localCheck = OrbitCompliance.inspectBinaryProof(fullBytes);
    if (!localCheck.ok) {
      return { ok: false, reason: localCheck.reason };
    }
    const dataUrl = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result || ""));
      reader.onerror = () => reject(new Error("Failed to read proof file."));
      reader.readAsDataURL(file);
    });
    const commaIdx = dataUrl.indexOf(",");
    return { ok: true, proofBase64: commaIdx >= 0 ? dataUrl.slice(commaIdx + 1) : dataUrl };
  }

  function startOtpTimer() {
    clearInterval(otpCountdown);
    otpSecondsLeft = 60;
    const el = $("otpTimer");
    el.textContent = "Expires in 60s";
    otpCountdown = setInterval(() => {
      otpSecondsLeft -= 1;
      if (otpSecondsLeft <= 0) {
        clearInterval(otpCountdown);
        closeModal($("bioModal"), true);
        setStatus("bad", "OTP EXPIRED:", "60s window closed.");
      } else {
        el.textContent = `Expires in ${otpSecondsLeft}s`;
      }
    }, 1000);
  }

  async function initiateFlow(forceMismatch) {
    if (!validateAmountField()) {
      $("amt").focus();
      return;
    }
    const t0 = performance.now();
    const kyc = activeKycName();
    if (forceMismatch) {
      $("dep").value = "Unknown Third-Party Sender";
    } else if ($("dep").value === "Unknown Third-Party Sender") {
      $("dep").value = kyc;
    }

    const dep = $("dep").value.trim();
    const amt = parseFloat($("amt").value) || 0;
    const rec = $("rec").value.trim() || "Recipient";
    const purpose = $("purpose").value;
    const docType = $("docType").value;
    const docNum = $("docNum").value.trim().toUpperCase();
    const docFile = $("docFile").files[0];
    const m = META[currentCorridor()];

    setStep(1, "Auditing...", "run");
    const encoded = await readProofFileBase64(docFile);
    if (!encoded.ok) {
      setStep(1, "Doc Forensics Failed", "bad");
      setStatus("bad", "DOCUMENT FORENSICS FAILED:", encoded.reason);
      return;
    }

    const data = await apiRequest("/api/initiate", {
      kycId: kyc,
      kycName: kyc,
      senderName: dep,
      amount: amt,
      fromCurrency: m.from,
      toCurrency: m.to,
      recipient: rec,
      purpose,
      docType,
      docNum,
      proofBase64: encoded.proofBase64
    });
    const initMs = Math.max(1, Math.round(performance.now() - t0));
    $("latencyPill").textContent = `Init Latency: ${initMs}ms`;
    await syncServerState();

    if (!data.ok) {
      setStep(1, data.code || "Blocked", "bad");
      setStatus("bad", `${data.code}:`, data.message);
      return;
    }

    activeTxId = data.txId || "";
    setStep(1, `Verified (${initMs}ms)`, "ok");
    setStep(2, "Awaiting OTP", "run");
    $("liveCode").textContent = `${data.txId} (Check Ops Console)`;
    $("liveInput").value = "";
    openModal($("bioModal"), $("liveInput"), false);
    startOtpTimer();
  }

  async function completeAfterBio() {
    const t0 = performance.now();
    const entered = $("liveInput").value.trim();
    const data = await apiRequest("/api/confirm", {
      kycId: activeKycName(),
      txId: activeTxId,
      otp: entered
    });
    const settleMs = Math.max(1, Math.round(performance.now() - t0));
    await syncServerState();

    if (!data.ok) {
      setFieldError($("liveInput"), $("modalErr"), data.message);
      if (data.accountLocked) {
        activeTxId = "";
        closeModal($("bioModal"), true);
        setStatus("bad", "TENANT LOCKED:", `${data.message} Open Ops Console to view dynamic unlock token.`);
      } else {
        $("liveInput").focus();
        $("liveInput").select();
      }
      return;
    }

    activeTxId = "";
    setFieldError($("liveInput"), $("modalErr"), "");
    closeModal($("bioModal"), true);
    $("latencyPill").textContent = `Settle Latency: ${settleMs}ms`;
    setStep(2, "OTP Verified", "ok");
    setStep(3, "JSONL Appended", "ok");
    setStep(4, `Settled (${settleMs}ms)`, "ok");
    setStatus("ok", `DURABLY SETTLED (${settleMs}ms):`, `${data.block.recipient} | Payout: ${formatNum(data.block.payout, 2)} ${data.block.toCurrency} | ${data.block.receipt}`);
  }

  async function verifyBankUnlock() {
    const token = $("bankPinInput").value.trim();
    const data = await apiRequest("/api/tenant/unlock", { kycId: activeKycName(), token });
    if (!data.ok) {
      setFieldError($("bankPinInput"), $("bankErr"), data.message);
      $("bankPinInput").focus();
      return;
    }
    setFieldError($("bankPinInput"), $("bankErr"), "");
    closeModal($("bankModal"), true);
    await syncServerState();
    setStatus("ok", "TENANT UNLOCKED:", "Single-use compliance token consumed.");
  }

  async function executePrivilegedReset(pin) {
    const data = await apiRequest("/api/demo/reset", { opsPin: pin });
    if (!data.ok) {
      setStatus("bad", "RESET BLOCKED:", data.message);
      return;
    }
    activeTxId = "";
    await syncServerState();
    setStatus("ok", "SANDBOX POOLS RESET:", "Pools & tenant limits reset with append-only LEDGER_RESET block.");
  }

  function showOpsPanel(data) {
    const panel = $("stealthPanel");
    panel.classList.add("open");
    $("orbTrigger").setAttribute("aria-expanded", "true");
    renderOpsEvents(data.opsEvents);
    if (data.activeChallenge && $("bioModal").classList.contains("open")) {
      $("liveCode").textContent = data.activeChallenge.otp;
    }
    const tokenHint = data.tenantUnlockToken ? ` | Active Unlock Token: ${data.tenantUnlockToken}` : "";
    if (!$("bioModal").classList.contains("open")) {
      setStatus("ok", "OPS CONSOLE OPEN:", `Compliance & Treasury Ops Console expanded${tokenHint}.`);
      panel.focus();
    }
  }

  function hideOpsPanel() {
    const panel = $("stealthPanel");
    panel.classList.remove("open");
    $("orbTrigger").setAttribute("aria-expanded", "false");
    clearOpsSession();
    setStatus("ok", "OPS CONSOLE CLOSED:", "Compliance Ops Console locked & session cleared.");
    $("orbTrigger").focus();
  }

  async function verifyOpsAccess() {
    const pin = $("opsPinInput").value.trim();
    const data = await apiRequest("/api/ops/auth", { pin, kycId: activeKycName() });
    if (!data.ok) {
      setFieldError($("opsPinInput"), $("opsErr"), data.message);
      $("opsPinInput").focus();
      return;
    }
    setFieldError($("opsPinInput"), $("opsErr"), "");
    armOpsSession(pin);

    if (pendingOpsAction === "reset") {
      pendingOpsAction = null;
      closeModal($("opsAuthModal"), true);
      await executePrivilegedReset(pin);
      return;
    }

    if (pendingOpsAction === "modalOtp") {
      pendingOpsAction = null;
      closeModal($("opsAuthModal"), false);
      if (data.activeChallenge) {
        $("liveCode").textContent = data.activeChallenge.otp;
      }
      openModal($("bioModal"), $("liveInput"), true);
      return;
    }

    closeModal($("opsAuthModal"), false);
    showOpsPanel(data);
  }

  async function triggerTreasuryRebalance() {
    const currency = $("rebCur").value;
    const amount = Number($("rebAmt").value);
    const data = await apiRequest("/api/treasury/rebalance", { opsPin: verifiedOpsPin, currency, amount });
    await syncServerState();
    if (!data.ok) {
      setStatus("bad", "REBALANCE FAILED:", data.message);
      return;
    }
    armOpsSession(verifiedOpsPin);
    setStatus("ok", "TREASURY REBALANCED:", `+${formatNum(data.added, 2)} ${data.currency} injected (Reserve: ${data.reservePct}%). Receipt: ${data.block.receipt}`);
  }

  async function toggleStealth() {
    const p = $("stealthPanel");
    if (p.classList.contains("open")) {
      hideOpsPanel();
      return;
    }
    if (!verifiedOpsPin) {
      pendingOpsAction = "console";
      $("opsPinInput").value = "";
      openModal($("opsAuthModal"), $("opsPinInput"), false);
      return;
    }
    const data = await apiRequest("/api/ops/auth", { pin: verifiedOpsPin, kycId: activeKycName() });
    if (data.ok) {
      armOpsSession(verifiedOpsPin);
      showOpsPanel(data);
    } else {
      clearOpsSession();
      openModal($("opsAuthModal"), $("opsPinInput"), false);
    }
  }

  let kycDebounce = null;
  let lastSyncedKyc = activeKycName();
  $("orbTrigger").addEventListener("click", toggleStealth);
  $("hideConsoleBtn").addEventListener("click", hideOpsPanel);
  $("kyc").addEventListener("input", () => {
    clearTimeout(kycDebounce);
    kycDebounce = setTimeout(() => {
      if (activeKycName() !== lastSyncedKyc) {
        lastSyncedKyc = activeKycName();
        onTenantChange();
      }
    }, 300);
  });
  $("kyc").addEventListener("change", () => {
    clearTimeout(kycDebounce);
    if (activeKycName() !== lastSyncedKyc) {
      lastSyncedKyc = activeKycName();
      onTenantChange();
    }
  });
  $("amt").addEventListener("input", () => {
    validateAmountField();
    refreshQuote();
  });
  $("corridor").addEventListener("change", onCorridorChange);
  $("refreshRateBtn").addEventListener("click", () => fetchRates(true));
  $("resetDemoBtn").addEventListener("click", async () => {
    if (!verifiedOpsPin) {
      pendingOpsAction = "reset";
      $("opsPinInput").value = "";
      openModal($("opsAuthModal"), $("opsPinInput"), false);
      return;
    }
    await executePrivilegedReset(verifiedOpsPin);
  });
  $("settleBtn").addEventListener("click", () => initiateFlow(false));
  $("amlTestBtn").addEventListener("click", () => initiateFlow(true));
  $("bankApproveBtn").addEventListener("click", () => {
    $("bankPinInput").value = "";
    openModal($("bankModal"), $("bankPinInput"), false);
  });
  $("modalInspectOpsBtn").addEventListener("click", async () => {
    if (verifiedOpsPin) {
      const data = await apiRequest("/api/ops/auth", { pin: verifiedOpsPin, kycId: activeKycName() });
      if (data.ok && data.activeChallenge) {
        armOpsSession(verifiedOpsPin);
        $("liveCode").textContent = data.activeChallenge.otp;
        $("liveInput").focus();
        return;
      }
    }
    pendingOpsAction = "modalOtp";
    closeModal($("bioModal"), false);
    $("opsPinInput").value = "";
    openModal($("opsAuthModal"), $("opsPinInput"), true);
  });
  $("verifyOtpBtn").addEventListener("click", completeAfterBio);
  $("cancelOtpBtn").addEventListener("click", () => {
    pendingOpsAction = null;
    closeModal($("bioModal"), true);
  });
  $("liveInput").addEventListener("input", () => setFieldError($("liveInput"), $("modalErr"), ""));
  $("liveInput").addEventListener("keydown", e => {
    if (e.key === "Enter") { e.preventDefault(); completeAfterBio(); }
  });
  $("authUnlockBtn").addEventListener("click", verifyBankUnlock);
  $("cancelBankBtn").addEventListener("click", () => closeModal($("bankModal"), true));
  $("bankPinInput").addEventListener("input", () => setFieldError($("bankPinInput"), $("bankErr"), ""));
  $("bankPinInput").addEventListener("keydown", e => {
    if (e.key === "Enter") { e.preventDefault(); verifyBankUnlock(); }
  });
  $("openOpsBtn").addEventListener("click", verifyOpsAccess);
  $("cancelOpsBtn").addEventListener("click", () => {
    if (pendingOpsAction === "modalOtp") {
      pendingOpsAction = null;
      closeModal($("opsAuthModal"), false);
      openModal($("bioModal"), $("liveInput"), true);
      return;
    }
    pendingOpsAction = null;
    closeModal($("opsAuthModal"), true);
  });
  $("opsPinInput").addEventListener("input", () => setFieldError($("opsPinInput"), $("opsErr"), ""));
  $("opsPinInput").addEventListener("keydown", e => {
    if (e.key === "Enter") { e.preventDefault(); verifyOpsAccess(); }
  });
  $("rebalanceBtn").addEventListener("click", triggerTreasuryRebalance);
  document.addEventListener("keydown", e => {
    if (e.altKey && e.shiftKey && e.key.toUpperCase() === "O") {
      e.preventDefault();
      toggleStealth();
    }
  });

  syncServerState();
  fetchRates(false);
})();
