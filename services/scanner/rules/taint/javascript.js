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

module.exports = {
  sqliBad, sqliOk, xssBad, xssOk, cmdBad, cmdOk, ssrfBad, ssrfOk,
  pathBad, pathOk, nosqlBad, nosqlOk, ldapBad, ldapOk, codeBad, codeOk,
  reactXssBad, reactXssOk,
};
