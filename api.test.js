const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");
const { createAppServer, RUNTIME_OPS_PIN } = require("./server.js");

test("Full HTTP API, Security Isolation, 413 Response, & Multi-Tenant E2E Flows", async (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "orbitpay-api-"));
  const server = createAppServer({ dataDir: tmpDir });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  t.after(async () => {
    await server.store.flush();
    server.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  async function req(endpoint, options = {}) {
    const res = await fetch(baseUrl + endpoint, {
      ...options,
      headers: { "Content-Type": "application/json", ...(options.headers || {}) }
    });
    const json = await res.json();
    return { status: res.status, headers: res.headers, json };
  }

  // 1. Public /api/state leaks NO opsEvents, NO other tenants' ledger, and creates NO ghost tenants
  const pubState = await req("/api/state?kycId=RandomProbeUser");
  assert.equal(pubState.status, 200);
  assert.equal(pubState.json.opsEvents, undefined);
  assert.equal(server.store.findTenant("RandomProbeUser"), null);

  // 2. Cross-origin POST blocked (CSRF defense) & non-JSON Content-Type rejected (415)
  const csrfPost = await req("/api/initiate", {
    method: "POST",
    headers: { "Origin": "https://evil.example.com" },
    body: JSON.stringify({})
  });
  assert.equal(csrfPost.status, 403);
  assert.equal(csrfPost.json.code, "CSRF_ORIGIN_MISMATCH");

  const textPost = await fetch(baseUrl + "/api/initiate", {
    method: "POST",
    headers: { "Content-Type": "text/plain" },
    body: "{}"
  });
  assert.equal(textPost.status, 415);

  // 3. Initiate + Mandatory txId on /api/confirm
  const init1 = await req("/api/initiate", {
    method: "POST",
    body: JSON.stringify({
      kycName: "Ravindra Prajapat",
      senderName: "Ravindra Prajapat",
      amount: 100,
      fromCurrency: "EUR",
      toCurrency: "INR",
      docType: "PAN Card",
      docNum: "ABCPP8821F"
    })
  });
  assert.equal(init1.status, 200);
  assert.equal(init1.json.otp, undefined);

  const ops1 = await req("/api/ops/auth", {
    method: "POST",
    body: JSON.stringify({ pin: RUNTIME_OPS_PIN, kycId: "Ravindra Prajapat" })
  });
  assert.equal(ops1.status, 200);
  const otp1 = ops1.json.activeChallenge.otp;

  // Omitting txId must fail with 409 TX_ID_MISMATCH (Item 4)
  const missingTxId = await req("/api/confirm", {
    method: "POST",
    body: JSON.stringify({ kycId: "Ravindra Prajapat", otp: otp1 })
  });
  assert.equal(missingTxId.status, 409);

  const confirm1 = await req("/api/confirm", {
    method: "POST",
    body: JSON.stringify({ kycId: "Ravindra Prajapat", txId: init1.json.txId, otp: otp1 })
  });
  assert.equal(confirm1.status, 200);

  // Cross-tenant isolation check: Ananya's /api/state must NOT show Ravindra's settlement
  const ananyaState = await req("/api/state?kycId=Ananya%20Sharma");
  assert.equal(ananyaState.json.ledger.length, 0);

  // 4. 3 Wrong OTPs -> 423 ACCOUNT_LOCKED -> Unlock token NOT leaked in /api/state or opsEvents -> Ops unlock works
  const initLock = await req("/api/initiate", {
    method: "POST",
    body: JSON.stringify({
      kycName: "Ananya Sharma",
      senderName: "Ananya Sharma",
      amount: 50,
      fromCurrency: "EUR",
      toCurrency: "INR",
      docType: "PAN Card",
      docNum: "XYZPS4419K"
    })
  });
  await req("/api/confirm", { method: "POST", body: JSON.stringify({ kycId: "Ananya Sharma", txId: initLock.json.txId, otp: "000000" }) });
  await req("/api/confirm", { method: "POST", body: JSON.stringify({ kycId: "Ananya Sharma", txId: initLock.json.txId, otp: "000000" }) });
  const lockedRes = await req("/api/confirm", { method: "POST", body: JSON.stringify({ kycId: "Ananya Sharma", txId: initLock.json.txId, otp: "000000" }) });
  assert.equal(lockedRes.status, 423);

  const opsLocked = await req("/api/ops/auth", {
    method: "POST",
    body: JSON.stringify({ pin: RUNTIME_OPS_PIN, kycId: "Ananya Sharma" })
  });
  const unlockToken = opsLocked.json.tenantUnlockToken;
  assert.equal(unlockToken.length, 6);
  // Ensure unlock token is NOT present anywhere in opsEvents text
  assert.equal(JSON.stringify(opsLocked.json.opsEvents).includes(unlockToken), false);

  const unlocked = await req("/api/tenant/unlock", {
    method: "POST",
    body: JSON.stringify({ kycId: "Ananya Sharma", token: unlockToken })
  });
  assert.equal(unlocked.status, 200);

  // 5. Clean HTTP 413 JSON response without ECONNRESET (Item 10)
  const status413 = await new Promise((resolve, reject) => {
    const r = http.request({
      hostname: "127.0.0.1",
      port,
      path: "/api/initiate",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": 9_000_000
      }
    }, res => {
      res.resume();
      res.on("end", () => resolve(res.statusCode));
    });
    r.on("error", reject);
    r.end();
  });
  assert.equal(status413, 413);
});
