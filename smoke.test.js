const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { createAppServer, RUNTIME_OPS_PIN } = require("./server.js");

test("End-to-End Static Assets (Gzip/ETag), Settlement, & Treasury Rebalance Smoke Flow", async (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "orbitpay-smoke-"));
  const server = createAppServer({ dataDir: tmpDir });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  t.after(async () => {
    await server.store.flush();
    server.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  const htmlRes = await fetch(baseUrl + "/");
  assert.equal(htmlRes.status, 200);
  assert.ok(htmlRes.headers.get("etag"));
  const html = await htmlRes.text();
  assert.ok(html.includes("<h1>OrbitPay</h1>"));

  const init = await fetch(baseUrl + "/api/initiate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      kycName: "Ananya Sharma",
      senderName: "Ananya Sharma",
      amount: 75,
      fromCurrency: "USD",
      toCurrency: "INR",
      docType: "PAN Card",
      docNum: "XYZPS4419K"
    })
  }).then(r => r.json());
  assert.equal(init.ok, true);

  const ops = await fetch(baseUrl + "/api/ops/auth", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pin: RUNTIME_OPS_PIN, kycId: "Ananya Sharma" })
  }).then(r => r.json());
  assert.equal(ops.ok, true);

  const settled = await fetch(baseUrl + "/api/confirm", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      kycId: "Ananya Sharma",
      txId: init.txId,
      otp: ops.activeChallenge.otp
    })
  }).then(r => r.json());
  assert.equal(settled.ok, true);

  const rebalance = await fetch(baseUrl + "/api/treasury/rebalance", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ opsPin: RUNTIME_OPS_PIN, currency: "INR", amount: 50000 })
  }).then(r => r.json());
  assert.equal(rebalance.ok, true);
});
