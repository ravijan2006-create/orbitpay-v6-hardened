const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const zlib = require("zlib");
const OrbitCompliance = require("./compliance.js");
const { createLedgerStore, timingSafeEqualStr } = require("./store.js");

const PORT = Number(process.env.PORT || 8080);
const MAX_PIN_LEN = 128;

// Generate a random runtime Ops PIN if ORBITPAY_OPS_PIN is not provided (zero hardcoded credentials in source!)
const RUNTIME_OPS_PIN = (process.env.ORBITPAY_OPS_PIN || ("OPS-" + crypto.randomBytes(4).toString("hex").toUpperCase())).trim().toUpperCase();
const OPS_PIN_SALT = crypto.randomBytes(16).toString("hex");
const OPS_PIN_HASH = crypto.scryptSync(RUNTIME_OPS_PIN, OPS_PIN_SALT, 32).toString("hex");

const AUTH_WINDOW_MS = 60_000;
const AUTH_MAX_FAILS = 10;
const TX_IP_WINDOW_MS = 60_000;
const TX_IP_MAX_REQS = 30;
const MAX_TRACKED_IPS = 10_000;
const MAX_BODY_BYTES = 8_000_000;

const MIME_TYPES = Object.freeze({
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8"
});

function setSecurityHeaders(res) {
  res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data: blob:; frame-ancestors 'none';"
  );
}

function sendJson(res, status, data) {
  if (res.headersSent) return;
  setSecurityHeaders(res);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(data));
}

// Item 10: Pre-check Content-Length AND send clean 413 JSON response BEFORE destroying socket
function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const contentType = String(req.headers["content-type"] || "").toLowerCase();
    if (!contentType.includes("application/json")) {
      const err = new Error("Content-Type must be application/json.");
      err.statusCode = 415;
      req.resume();
      return reject(err);
    }

    const declaredLen = Number(req.headers["content-length"] || 0);
    if (Number.isFinite(declaredLen) && declaredLen > MAX_BODY_BYTES) {
      const err = new Error("Payload too large");
      err.statusCode = 413;
      req.resume();
      return reject(err);
    }

    const chunks = [];
    let totalBytes = 0;
    let rejected = false;

    req.on("data", chunk => {
      if (rejected) return;
      totalBytes += chunk.length;
      if (totalBytes > MAX_BODY_BYTES) {
        rejected = true;
        const err = new Error("Payload too large");
        err.statusCode = 413;
        reject(err);
        req.resume();
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => {
      if (rejected) return;
      if (totalBytes === 0) return resolve({});
      try {
        const raw = Buffer.concat(chunks, totalBytes).toString("utf8");
        resolve(JSON.parse(raw));
      } catch (e) {
        const err = new Error("Invalid JSON body");
        err.statusCode = 400;
        reject(err);
      }
    });

    req.on("error", err => {
      if (!rejected) reject(err);
    });
  });
}

function verifyOpsPin(pin) {
  const clean = String(pin || "").trim().toUpperCase();
  if (!clean || clean.length > MAX_PIN_LEN) return false;
  const candidateHash = crypto.scryptSync(clean, OPS_PIN_SALT, 32).toString("hex");
  return timingSafeEqualStr(candidateHash, OPS_PIN_HASH);
}

function isSameOriginPost(req) {
  const origin = req.headers["origin"];
  if (!origin) return true; // Non-browser curl/API clients omit Origin
  const host = req.headers["host"];
  if (!host) return false;
  try {
    const parsed = new URL(origin);
    return parsed.host === host;
  } catch (_) {
    return false;
  }
}

function createAppServer(options = {}) {
  const store = options.store || createLedgerStore({
    dataDir: options.dataDir || process.env.ORBITPAY_DATA_DIR || path.join(__dirname, "data")
  });
  const authFailuresByIp = new Map();
  const txRequestsByIp = new Map();
  let lastFxFetchTs = 0;
  let inFlightFxPromise = null;

  function getClientIp(req) {
    if (process.env.TRUST_PROXY === "true") {
      const fwd = req.headers["x-forwarded-for"];
      if (typeof fwd === "string" && fwd.trim()) {
        const parts = fwd.split(",").map(s => s.trim()).filter(Boolean);
        if (parts.length > 0) return parts[parts.length - 1];
      }
    }
    return req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : "unknown";
  }

  function checkSlidingWindow(map, ip, windowMs, maxCount, recordNow) {
    const now = Date.now();
    const list = (map.get(ip) || []).filter(ts => now - ts < windowMs);
    if (list.length >= maxCount) {
      map.set(ip, list);
      return true;
    }
    if (recordNow) {
      if (map.size >= MAX_TRACKED_IPS && !map.has(ip)) {
        const oldestKey = map.keys().next().value;
        map.delete(oldestKey);
      }
      list.push(now);
    }
    if (list.length === 0) map.delete(ip);
    else map.set(ip, list);
    return false;
  }

  function isAuthRateLimited(ip) {
    return checkSlidingWindow(authFailuresByIp, ip, AUTH_WINDOW_MS, AUTH_MAX_FAILS, false);
  }

  function recordAuthFailure(ip) {
    checkSlidingWindow(authFailuresByIp, ip, AUTH_WINDOW_MS, AUTH_MAX_FAILS, true);
  }

  function clearAuthFailures(ip) {
    authFailuresByIp.delete(ip);
  }

  function isTxIpRateLimited(ip) {
    return checkSlidingWindow(txRequestsByIp, ip, TX_IP_WINDOW_MS, TX_IP_MAX_REQS, true);
  }

  async function refreshLiveFxFromProviders(force = false) {
    if (!force && Date.now() - lastFxFetchTs < 60_000) {
      return { ok: true, source: "Server Cache", rates: store.getStatus("").rates };
    }
    if (inFlightFxPromise) return inFlightFxPromise;

    inFlightFxPromise = (async () => {
      const providers = [
        { name: "OpenER-API", url: "https://open.er-api.com/v6/latest/USD" },
        { name: "Frankfurter", url: "https://api.frankfurter.app/latest?from=USD&to=INR,EUR,GBP" }
      ];
      for (const p of providers) {
        try {
          const ctrl = new AbortController();
          const timer = setTimeout(() => ctrl.abort(), 3500);
          const res = await fetch(p.url, { signal: ctrl.signal });
          clearTimeout(timer);
          if (!res.ok) continue;
          const d = await res.json();
          const usdInr = d && d.rates && Number(d.rates.INR);
          const usdEur = d && d.rates && Number(d.rates.EUR);
          const usdGbp = d && d.rates && Number(d.rates.GBP);
          if (!OrbitCompliance.isRateWithinCircuitBreaker("USD_INR", usdInr)) continue;
          const candidate = {
            USD_INR: +usdInr.toFixed(4),
            INR_USD: +(1 / usdInr).toFixed(6)
          };
          if (usdEur && OrbitCompliance.isRateWithinCircuitBreaker("EUR_INR", usdInr / usdEur)) {
            candidate.EUR_INR = +(usdInr / usdEur).toFixed(4);
            candidate.INR_EUR = +(usdEur / usdInr).toFixed(6);
          }
          if (usdEur && OrbitCompliance.isRateWithinCircuitBreaker("USD_EUR", usdEur)) {
            candidate.USD_EUR = +usdEur.toFixed(4);
            candidate.EUR_USD = +(1 / usdEur).toFixed(4);
          }
          if (usdGbp && OrbitCompliance.isRateWithinCircuitBreaker("GBP_INR", usdInr / usdGbp)) {
            candidate.GBP_INR = +(usdInr / usdGbp).toFixed(4);
            candidate.INR_GBP = +(usdGbp / usdInr).toFixed(6);
          }
          if (usdGbp && OrbitCompliance.isRateWithinCircuitBreaker("GBP_USD", 1 / usdGbp)) {
            candidate.GBP_USD = +(1 / usdGbp).toFixed(4);
            candidate.USD_GBP = +usdGbp.toFixed(4);
          }
          const upd = store.updateRates(candidate);
          if (upd.ok) {
            lastFxFetchTs = Date.now();
            return { ok: true, source: p.name, rates: upd.rates };
          }
        } catch (e) {}
      }
      return { ok: true, source: "Server Locked", rates: store.getStatus("").rates };
    })();

    try {
      return await inFlightFxPromise;
    } finally {
      inFlightFxPromise = null;
    }
  }

  async function serveStaticFile(req, res, filePath, ext) {
    try {
      const stat = await fs.promises.stat(filePath);
      if (!stat.isFile()) return false;
      const etag = `W/"${stat.size}-${Math.floor(stat.mtimeMs)}"`;
      setSecurityHeaders(res);
      res.setHeader("Cache-Control", "public, max-age=300, must-revalidate");
      res.setHeader("ETag", etag);
      if (req.headers["if-none-match"] === etag) {
        res.writeHead(304);
        res.end();
        return true;
      }

      const contentType = MIME_TYPES[ext] || "application/octet-stream";
      const acceptEnc = String(req.headers["accept-encoding"] || "");
      const stream = fs.createReadStream(filePath);
      stream.on("error", () => {
        if (!res.headersSent) sendJson(res, 500, { ok: false, message: "Static asset read error" });
        else res.destroy();
      });

      if (acceptEnc.includes("gzip")) {
        res.writeHead(200, { "Content-Type": contentType, "Content-Encoding": "gzip", "Vary": "Accept-Encoding" });
        const gzip = zlib.createGzip();
        gzip.on("error", () => res.destroy());
        stream.pipe(gzip).pipe(res);
      } else {
        res.writeHead(200, { "Content-Type": contentType });
        stream.pipe(res);
      }
      return true;
    } catch (_) {
      return false;
    }
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const pathname = url.pathname;
    const ip = getClientIp(req);

    try {
      if (req.method === "POST" && !isSameOriginPost(req)) {
        return sendJson(res, 403, { ok: false, code: "CSRF_ORIGIN_MISMATCH", message: "Cross-origin POST blocked." });
      }

      if (req.method === "GET" && ["/healthz", "/api/health"].includes(pathname)) {
        return sendJson(res, 200, { ok: true, persistence: "append-only-jsonl", multiTenant: true });
      }

      if (req.method === "GET" && pathname === "/api/state") {
        const kycId = url.searchParams.get("kycId") || "";
        return sendJson(res, 200, { ok: true, ...store.getStatus(kycId) });
      }

      if (req.method === "GET" && pathname === "/api/rates/refresh") {
        const force = url.searchParams.get("force") === "1";
        const fx = await refreshLiveFxFromProviders(force);
        return sendJson(res, 200, fx);
      }

      if (req.method === "POST" && pathname === "/api/rates") {
        if (isAuthRateLimited(ip)) {
          return sendJson(res, 429, { ok: false, code: "RATE_LIMITED", message: "Too many failed Ops requests. Retry in 60s." });
        }
        const body = await readJsonBody(req);
        if (!verifyOpsPin(body.opsPin || body.pin)) {
          recordAuthFailure(ip);
          return sendJson(res, 403, { ok: false, code: "UNAUTHORIZED_OPS", message: "Valid Ops Console PIN required to override server FX rates." });
        }
        clearAuthFailures(ip);
        const result = store.updateRates(body.rates || body);
        return sendJson(res, result.status || 200, result);
      }

      if (req.method === "POST" && ["/api/ops", "/api/ops/auth"].includes(pathname)) {
        if (isAuthRateLimited(ip)) {
          return sendJson(res, 429, { ok: false, code: "RATE_LIMITED", message: "Too many failed attempts. Retry in 60s." });
        }
        const body = await readJsonBody(req);
        if (!verifyOpsPin(body.pin || body.opsPin)) {
          recordAuthFailure(ip);
          return sendJson(res, 403, { ok: false, code: "UNAUTHORIZED_OPS", message: "Invalid Ops Console PIN." });
        }
        clearAuthFailures(ip);
        return sendJson(res, 200, { ok: true, ...store.getOpsStatus(body.kycId || "") });
      }

      if (req.method === "POST" && ["/api/initiate", "/api/transfer/initiate"].includes(pathname)) {
        if (isTxIpRateLimited(ip)) {
          return sendJson(res, 429, { ok: false, code: "IP_RATE_LIMITED", message: "Too many transfer requests from this IP. Retry in 60s." });
        }
        const body = await readJsonBody(req);
        const result = store.initiateTransfer(body);
        return sendJson(res, result.status || 200, result);
      }

      if (req.method === "POST" && ["/api/confirm", "/api/settle", "/api/transfer/settle"].includes(pathname)) {
        if (isTxIpRateLimited(ip)) {
          return sendJson(res, 429, { ok: false, code: "IP_RATE_LIMITED", message: "Too many settlement requests from this IP. Retry in 60s." });
        }
        const body = await readJsonBody(req);
        const result = await store.verifyOtpAndSettle(body);
        return sendJson(res, result.status || 200, result);
      }

      if (req.method === "POST" && ["/api/unlock", "/api/tenant/unlock"].includes(pathname)) {
        if (isAuthRateLimited(ip)) {
          return sendJson(res, 429, { ok: false, code: "RATE_LIMITED", message: "Too many failed unlock attempts. Retry in 60s." });
        }
        const body = await readJsonBody(req);
        const result = store.unlockTenant(body);
        if (!result.ok && result.status === 403) {
          recordAuthFailure(ip);
        } else if (result.ok) {
          clearAuthFailures(ip);
        }
        return sendJson(res, result.status || 200, result);
      }

      if (req.method === "POST" && pathname === "/api/treasury/rebalance") {
        if (isAuthRateLimited(ip)) {
          return sendJson(res, 429, { ok: false, code: "RATE_LIMITED", message: "Too many failed Ops requests. Retry in 60s." });
        }
        const body = await readJsonBody(req);
        if (!verifyOpsPin(body.opsPin || body.pin)) {
          recordAuthFailure(ip);
          return sendJson(res, 403, { ok: false, code: "UNAUTHORIZED_OPS", message: "Valid Ops Console PIN required." });
        }
        clearAuthFailures(ip);
        const result = await store.rebalancePool({
          currency: body.currency,
          amount: body.amount,
          source: body.source || "TREASURY_NOSTRO_TOPUP",
          operator: "OPS_CONSOLE"
        });
        return sendJson(res, result.status || 200, result);
      }

      if (req.method === "POST" && ["/api/demo/reset", "/api/reset"].includes(pathname)) {
        if (isAuthRateLimited(ip)) {
          return sendJson(res, 429, { ok: false, code: "RATE_LIMITED", message: "Too many failed Ops requests. Retry in 60s." });
        }
        const body = await readJsonBody(req);
        if (!verifyOpsPin(body.opsPin || body.pin)) {
          recordAuthFailure(ip);
          return sendJson(res, 403, { ok: false, code: "UNAUTHORIZED_OPS", message: "Valid Ops Console PIN required to reset sandbox pools." });
        }
        clearAuthFailures(ip);
        return sendJson(res, 200, await store.resetDemo());
      }

      if (req.method === "GET") {
        if (pathname === "/compliance.js") {
          const served = await serveStaticFile(req, res, path.join(__dirname, "compliance.js"), ".js");
          if (served) return;
        }

        const relPath = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
        const publicRoot = path.join(__dirname, "public");
        const safePath = path.normalize(path.join(publicRoot, relPath));
        if (safePath.startsWith(publicRoot)) {
          const served = await serveStaticFile(req, res, safePath, path.extname(safePath));
          if (served) return;
        }
      }

      sendJson(res, 404, { ok: false, message: "Not found" });
    } catch (err) {
      const status = err.statusCode || 400;
      const publicMsg = status >= 500 ? "Internal server error" : (err.message || "Bad request");
      sendJson(res, status, { ok: false, message: publicMsg });
    }
  });

  server.store = store;
  server.authFailuresByIp = authFailuresByIp;
  return server;
}

if (require.main === module) {
  const app = createAppServer();
  const shutdown = async () => {
    await app.store.flush();
    app.close(() => process.exit(0));
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`OrbitPay Mesh server running on http://0.0.0.0:${PORT}`);
    console.log(`Ops Console Runtime PIN: ${RUNTIME_OPS_PIN}`);
  });
}

module.exports = { createAppServer, RUNTIME_OPS_PIN };
