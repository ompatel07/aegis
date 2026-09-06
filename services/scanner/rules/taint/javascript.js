// Test fixtures for rules/taint/javascript.yaml — consumed by `semgrep --test`.
// Positive cases fire the rule; sanitized negatives must not. Never scanned in
// production (real scans target the cloned repo; --config only loads *.yaml).
/* eslint-disable */
const child_process = require("child_process");
const fs = require("fs");
const path = require("path");
const axios = require("axios");

function escapeHtml(s) { return s; }
function validateUrl(u) { return u; }
function escapeFilter(s) { return s; }

// ── SQL injection ────────────────────────────────────────────────────────────
function sqliBad(db, req) {
  const id = req.query.id;
  // ruleid: aegis-js-sql-injection
  db.query("SELECT * FROM users WHERE id = " + id);
}

function sqliOk(db, req) {
  const id = req.query.id;
  // ok: aegis-js-sql-injection
  db.query("SELECT * FROM users WHERE id = ?", [id]);
}

// ── Cross-site scripting ─────────────────────────────────────────────────────
function xssBad(res, req) {
  const name = req.query.name;
  // ruleid: aegis-js-xss
  res.send("<h1>Hello " + name + "</h1>");
}

function xssOk(res, req) {
  const name = req.query.name;
  // ok: aegis-js-xss
  res.send("<h1>Hello " + escapeHtml(name) + "</h1>");
}

// ── OS command injection ─────────────────────────────────────────────────────
function cmdBad(req) {
  const host = req.query.host;
  // ruleid: aegis-js-command-injection
  child_process.exec("ping -c 1 " + host);
}

function cmdOk(req) {
  const host = req.query.host;
  // ok: aegis-js-command-injection
  child_process.execFile("ping", ["-c", "1", host]);
}

// ── SSRF ─────────────────────────────────────────────────────────────────────
function ssrfBad(req) {
  const url = req.query.url;
  // ruleid: aegis-js-ssrf
  return axios.get(url);
}

function ssrfOk(req) {
  const url = req.query.url;
  const safe = validateUrl(url);
  // ok: aegis-js-ssrf
  return axios.get(safe);
}

// ── Path traversal ───────────────────────────────────────────────────────────
function pathBad(req) {
  const f = req.query.file;
  // ruleid: aegis-js-path-traversal
  return fs.readFileSync("/var/data/" + f);
}

function pathOk(req) {
  const f = req.query.file;
  // ok: aegis-js-path-traversal
  return fs.readFileSync(path.join("/var/data", path.basename(f)));
}

// ── NoSQL injection ──────────────────────────────────────────────────────────
function nosqlBad(users, req) {
  // ruleid: aegis-js-nosql-injection
  return users.findOne({ username: req.body.username, password: req.body.password });
}

function nosqlOk(users, req) {
  // ok: aegis-js-nosql-injection
  return users.findOne({ username: String(req.body.username) });
}

// ── LDAP injection ───────────────────────────────────────────────────────────
function ldapBad(client, req) {
  const user = req.query.user;
  const opts = { filter: "(uid=" + user + ")", scope: "sub" };
  // ruleid: aegis-js-ldap-injection
  client.search("dc=example,dc=com", opts, () => {});
}

function ldapOk(client, req) {
  const user = req.query.user;
  const opts = { filter: "(uid=" + escapeFilter(user) + ")", scope: "sub" };
  // ok: aegis-js-ldap-injection
  client.search("dc=example,dc=com", opts, () => {});
}

// ── Code injection ───────────────────────────────────────────────────────────
function codeBad(req) {
  const expr = req.body.expr;
  // ruleid: aegis-js-code-injection
  return eval(expr);
}

function codeOk(req) {
  const data = req.body.data;
  // ok: aegis-js-code-injection
  return JSON.parse(data);
}

// ── React XSS via dangerouslySetInnerHTML ────────────────────────────────────
function reactXssBad(searchParams) {
  const q = searchParams.get("q");
  // ruleid: aegis-react-xss
  return <div dangerouslySetInnerHTML={{ __html: q }} />;
}

function reactXssOk() {
  // Safe: static JSON-LD structured data (no user-controlled source).
  const schema = { "@type": "Organization", name: "Acme" };
  // ok: aegis-react-xss
  return <script dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }} />;
}

// ── MongoDB $where code injection (G1/A1) ────────────────────────────────────
// Real shape from NodeGoat allocations-dao.js:78 — the DAO gets `threshold` as a
// plain parameter (the req.query lives in another file), so this is deliberately
// NOT taint-based; the interpolated $where is decisive on its own.
function whereBad(threshold, parsedUserId, allocationsCol) {
  const searchCriteria = () => {
    // ruleid: aegis-js-nosql-where-injection
    return { $where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'` };
  };
  return allocationsCol.find(searchCriteria());
}

function whereConcatBad(threshold, coll) {
  // ruleid: aegis-js-nosql-where-injection
  return coll.find({ $where: "this.stocks > " + threshold });
}

function whereOk(coll) {
  // a constant $where carries no injection risk
  // ok: aegis-js-nosql-where-injection
  return coll.find({ $where: "this.qty > 5" });
}

function whereTypedOk(threshold, coll) {
  // the correct fix: a typed operator, not $where
  // ok: aegis-js-nosql-where-injection
  return coll.find({ stocks: { $gt: parseInt(threshold, 10) } });
}

// ── Catastrophic-backtracking regex / ReDoS (G1/A2) ──────────────────────────
// Real shape from NodeGoat profile.js:59.
function redosBad(req) {
  const { bankRouting } = req.body;
  // ruleid: aegis-js-redos-nested-quantifier
  const regexPattern = /([0-9]+)+\#/;
  return regexPattern.test(bankRouting);
}

function redosStarBad(x) {
  // ruleid: aegis-js-redos-nested-quantifier
  const re = /(a*)*b/;
  return re.test(x);
}

function redosOk(req) {
  const { bankRouting } = req.body;
  // the documented fix: drop the outer quantifier
  // ok: aegis-js-redos-nested-quantifier
  const regexPattern = /([0-9]+)\#/;
  return regexPattern.test(bankRouting);
}

function redosPlainOk(x) {
  // ok: aegis-js-redos-nested-quantifier
  const re = /^[a-z0-9_-]{3,16}$/;
  return re.test(x);
}

module.exports = {
  sqliBad, sqliOk, xssBad, xssOk, cmdBad, cmdOk, ssrfBad, ssrfOk,
  pathBad, pathOk, nosqlBad, nosqlOk, ldapBad, ldapOk, codeBad, codeOk,
  reactXssBad, reactXssOk,
};
