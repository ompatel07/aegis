// Test fixture for ai_code_taint/javascript.yaml (semgrep --test).
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

function weakCrypto(payload) {
  // ruleid: ai-code-weak-crypto-js
  const a = crypto.createHash("md5").update(payload).digest("hex");
  // ruleid: ai-code-weak-crypto-js
  const b = crypto.createHash("sha1").update(payload).digest("hex");
  // ok: ai-code-weak-crypto-js
  const c = crypto.createHash("sha256").update(payload).digest("hex");
  return [a, b, c];
}

function randomTokens() {
  // ruleid: ai-code-insecure-random-js
  const sessionToken = Math.random().toString(36).substring(2);
  // ok: ai-code-insecure-random-js
  const jitter = Math.random() * 100;
  return { sessionToken, jitter };
}

function emptyCatch(data) {
  // ruleid: ai-code-empty-catch-js
  try {
    return JSON.parse(data);
  } catch (e) {}
}

function handledCatch(data) {
  // ok: ai-code-empty-catch-js
  try {
    return JSON.parse(data);
  } catch (e) {
    console.error("parse failed", e);
    return null;
  }
}

function readToken(token, secret) {
  // ruleid: ai-code-jwt-no-verify-js
  const claims = jwt.decode(token);
  // ok: ai-code-jwt-no-verify-js
  const verified = jwt.verify(token, secret);
  return { claims, verified };
}

function runQuery(db, uid) {
  // ruleid: ai-code-sql-concat-js
  db.query("SELECT * FROM users WHERE id = " + uid);
  // ruleid: ai-code-sql-concat-js
  db.query(`SELECT * FROM users WHERE id = ${uid}`);
  // ok: ai-code-sql-concat-js
  db.query("SELECT * FROM users WHERE id = ?", [uid]);
}

// ruleid: ai-code-hardcoded-secret-js
const apiKey = "sk-live-abc123def456";
// ok: ai-code-hardcoded-secret-js
const apiKeyFromEnv = process.env.API_KEY;
// ok: ai-code-hardcoded-secret-js
const retryCount = "3";
