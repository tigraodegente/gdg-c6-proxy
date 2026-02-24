/**
 * C6 Bank mTLS Proxy
 *
 * Cloudflare Workers can't do mTLS to origins behind Cloudflare.
 * This proxy runs on Fly.io and bridges the mTLS gap:
 *   Worker → this proxy (Bearer auth) → C6 Bank (mTLS)
 */

import { createServer } from "node:http";
import { writeFileSync, mkdirSync } from "node:fs";
import https from "node:https";

const PORT = process.env.PORT || 8080;
const PROXY_SECRET = process.env.PROXY_SECRET || "";

// Certs come as base64 env vars, decode and write to disk for https.Agent
const CERT_DIR = "/tmp/certs";
mkdirSync(CERT_DIR, { recursive: true });

const certB64 = process.env.C6_CERT_B64 || "";
const keyB64 = process.env.C6_KEY_B64 || "";

if (!certB64 || !keyB64) {
  console.error("C6_CERT_B64 and C6_KEY_B64 env vars required");
  process.exit(1);
}

const certPem = Buffer.from(certB64, "base64").toString("utf8");
const keyPem = Buffer.from(keyB64, "base64").toString("utf8");
writeFileSync(`${CERT_DIR}/cert.pem`, certPem);
writeFileSync(`${CERT_DIR}/key.pem`, keyPem, { mode: 0o600 });
console.log("mTLS certificates loaded from env vars");

function verifyAuth(req) {
  if (!PROXY_SECRET) return false;
  const auth = req.headers["authorization"] || "";
  return auth === `Bearer ${PROXY_SECRET}`;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString()));
    req.on("error", reject);
  });
}

function proxyToC6(method, targetUrl, headers, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(targetUrl);
    const options = {
      hostname: url.hostname,
      port: 443,
      path: url.pathname + url.search,
      method,
      cert: certPem,
      key: keyPem,
      headers: { ...headers },
      rejectUnauthorized: true,
    };

    // Remove hop-by-hop headers
    delete options.headers["host"];
    delete options.headers["authorization"];
    delete options.headers["connection"];
    delete options.headers["content-length"];
    if (body) {
      options.headers["content-length"] = Buffer.byteLength(body);
    }

    const req = https.request(options, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks).toString(),
        });
      });
    });

    req.on("error", reject);
    req.setTimeout(15000, () => {
      req.destroy(new Error("Request timeout"));
    });

    if (body) req.write(body);
    req.end();
  });
}

const server = createServer(async (req, res) => {
  // Health check
  if (req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, service: "gdg-c6-proxy" }));
    return;
  }

  // Auth check
  if (!verifyAuth(req)) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Unauthorized" }));
    return;
  }

  // Proxy: POST /proxy
  // Body: { method, url, headers, body }
  if (req.method === "POST" && req.url === "/proxy") {
    try {
      const raw = await readBody(req);
      const payload = JSON.parse(raw);
      const { method: m, url: targetUrl, headers: targetHeaders, body: targetBody } = payload;

      if (!targetUrl || !targetUrl.startsWith("https://baas-api")) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Only C6 Bank URLs allowed" }));
        return;
      }

      const result = await proxyToC6(
        m || "GET",
        targetUrl,
        targetHeaders || {},
        targetBody || null,
      );

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        status: result.status,
        headers: result.headers,
        body: result.body,
      }));
    } catch (e) {
      console.error("Proxy error:", e.message);
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});

server.listen(PORT, () => {
  console.log(`C6 mTLS Proxy running on port ${PORT}`);
});
