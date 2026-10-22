// Fixtures for rules/taint/javascript_weakness.yaml (Pass N3). Every `ruleid:` line
// must fire and every `ok:` line must stay silent (`semgrep --test`).
const crypto = require('crypto');
const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';

// ── weak random: fires only where the value must be unguessable ──────────────
function weakRandomBad(user, res) {
  // ruleid: aegis-js-weak-random-secret
  const csrfToken = Math.random().toString(36).slice(2);

  const r = Math.random();
  // ruleid: aegis-js-weak-random-secret
  user.passwordSalt = String(Math.floor(r * 1e9));

  // ruleid: aegis-js-weak-random-secret
  const opts = { resetToken: Math.random().toString(16) };

  let sessionToken = '';
  for (let i = 0; i < 24; i++) {
    // ruleid: aegis-js-weak-random-secret
    sessionToken += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  // ruleid: aegis-js-weak-random-secret
  res.cookie('remember_me', Math.random().toString(36), { httpOnly: true, secure: true });
  return [csrfToken, opts, sessionToken];
}

function generateApiKey() {
  // ruleid: aegis-js-weak-random-secret
  return Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
}

// ruleid: aegis-js-weak-random-secret
const makeSalt = () => Math.random().toString(36).slice(2);

// Real-code shapes that are NOT secrets (redash, n8n, Dolibarr/TeamPass, N3 triage):
function nonSecretValues(api) {
  // a fetch/race-cancellation "token" (redash ItemsSource)
  // ok: aegis-js-weak-random-secret
  const fetchToken = Math.random().toString(36).substr(2);
  // a correlation id named like a session (n8n MCP)
  // ok: aegis-js-weak-random-secret
  const meta = { mcpSessionId: Math.random().toString(36) };
  // a protocol nonce only needs uniqueness (OAuth1, HTTP Digest)
  // ok: aegis-js-weak-random-secret
  const nonce = Math.random().toString(36);
  // CSPRNG output mixed in
  // ok: aegis-js-weak-random-secret
  const csrfToken = crypto.randomBytes(16).toString('hex') + Math.random();
  return [fetchToken, meta, nonce, csrfToken, api];
}

// a function that VERIFIES a code is not generating one
function verifyOtp(input) {
  // ok: aegis-js-weak-random-secret
  return input === String(Math.random());
}

function weakRandomOk(items, api) {
  // shuffles, jitter, UI ids and colours are not secrets
  // ok: aegis-js-weak-random-secret
  const delay = 1000 + Math.random() * 500;
  // ok: aegis-js-weak-random-secret
  const elementId = 'el-' + Math.random().toString(36).slice(2);
  // ok: aegis-js-weak-random-secret
  const color = '#' + Math.floor(Math.random() * 0xffffff).toString(16);
  // the secret word is not the head noun: an expiry, a URL, a round count
  // ok: aegis-js-weak-random-secret
  const tokenExpiry = Date.now() + Math.random() * 1000;
  // ok: aegis-js-weak-random-secret
  const saltRounds = 10 + Math.floor(Math.random() * 2);
  // a cache-buster passed to a request does not make its response a weak token
  // ok: aegis-js-weak-random-secret
  const authToken = api.fetchToken('/token?_=' + Math.random());
  // a CSPRNG is the fix
  // ok: aegis-js-weak-random-secret
  const apiToken = crypto.randomBytes(32).toString('hex');
  // ok: aegis-js-weak-random-secret
  const tokenizer = Math.random();
  return [delay, elementId, color, tokenExpiry, saltRounds, authToken, apiToken, tokenizer, items];
}

// ── session cookie: session/auth-shaped names only ───────────────────────────
function cookies(req, res, token, prefs, cookieOptions) {
  // ruleid: aegis-js-insecure-session-cookie
  res.cookie('sessionId', token);
  // ruleid: aegis-js-insecure-session-cookie
  res.cookie('auth_token', token, { httpOnly: true });
  // ruleid: aegis-js-insecure-session-cookie
  res.cookie('refresh_token', token, { secure: true, httpOnly: false });
  // ok: aegis-js-insecure-session-cookie
  res.cookie('auth_token', token, { httpOnly: true, secure: true, sameSite: 'strict' });
  // environment-dependent `secure` is a deliberate choice, not a missing flag
  // ok: aegis-js-insecure-session-cookie
  res.cookie('sid', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
  // a CSRF double-submit token must be readable by the page
  // ok: aegis-js-insecure-session-cookie
  res.cookie('XSRF-TOKEN', req.csrfToken());
  // a UI preference is not sensitive
  // ok: aegis-js-insecure-session-cookie
  res.cookie('theme', prefs.theme);
  // options passed by variable are not guessed at
  // ok: aegis-js-insecure-session-cookie
  res.cookie('session', token, cookieOptions);
  // deleting a cookie carries no secret
  // ok: aegis-js-insecure-session-cookie
  res.cookie('session', '', { expires: new Date(0) });
  // flags supplied by a spread options object (n8n ChatTrigger)
  // ok: aegis-js-insecure-session-cookie
  res.cookie('session', token, { ...cookieOptions, maxAge: 60000 });
}

// ── trust boundary ───────────────────────────────────────────────────────────
function trustBoundary(req, res) {
  // the request chooses which session key is written
  req.session[req.body.field] = req.body.value;
  // a privilege-shaped key set from the request
  req.session.role = req.body.role;
  req.session['isAdmin'] = req.query.admin === 'true';
  // a preference from the request is not a trust decision
  req.session.locale = req.query.lang;
  // a privilege key set from verified server state
  req.session.role = res.locals.user.role;
  req.session['returnTo'] = req.originalUrl;
}
