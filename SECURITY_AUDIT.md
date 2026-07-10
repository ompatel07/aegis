# Aegis Security Audit (Phase 2D, Track 3)

_Aegis is a security company; our own platform must be exemplary._ This document
records a full self-audit of the Aegis platform — every finding, its fix, and the
verification. Fixes landed as code; residual items are tracked with rationale.

**Scope:** the three services (`api` Go, `orchestrator` Go, `scanner` Python) and
the `web` Next.js frontend, plus container and CI posture.

**Method:** static review of the whole codebase, dependency scanning
(govulncheck / npm audit / pip-audit), the platform's own scanner run against
itself (3a), and targeted fixes compiled + re-verified.

| Track | Area | Result |
| --- | --- | --- |
| 3a | Aegis-scans-Aegis + CI gate | Self-scan run; CI workflow added |
| 3b | Dependency CVEs | **Fixed**: axios (2 HIGH), Go stdlib→1.25, pgx, x/net; scanner leaf bumps; majors tracked |
| 3c | Container hardening | **Fixed**: dropped curl, `cap_drop: ALL`, `no-new-privileges`, non-root confirmed |
| 3d | Auth & session | Solid; **added** `RevokeAllForUser`/`CountForUser`; password-reset gap tracked |
| 3e | RBAC / IDOR | Org-scoping enforced in every repo query (7 files); tests recommended |
| 3f | Injection (SQLi/cmd/path/SSRF) | SQL parameterized; **fixed** Slack-webhook SSRF |
| 3g | Webhook security | Timing-safe HMAC everywhere; replay note |
| 3h | Scanner sandbox | No code execution (pure SAST); timeout enforced; limits recommended |
| 3i | Rate limiting | **Added** strict per-IP limiter on `/auth` |
| 3j | CORS/CSP/HSTS | **Added** security-headers middleware (CSP, HSTS, frame-deny, nosniff) |
| 3k | Pen-test simulation | Attack classes reviewed against fixes (below) |

---

## 3a — Aegis scans Aegis

The platform scanned its own source end-to-end through the real pipeline
(orchestrator clone → all engines → aggregation → scoring). Because the GitHub
repo is private, the run used a `file://` clone of the committed tree (no
`node_modules`/`.venv`; those are git-ignored) staged in the shared workspace
volume — an identical code path to a normal scan.

**Raw engine output** on the Aegis tree: SAST 115, secrets 4, SCA 155,
deployment 2. Triaged (intentional Semgrep taint-rule fixtures + `tests/fixtures`
smoke targets are deliberately vulnerable and excluded — 26 crit / 59 high / 45
med of the raw counts are these expected fixtures):

| Source | Real crit | Real high | Verdict |
| --- | --- | --- | --- |
| **Our application code** (SAST + secrets) | **0** | **2** | Both **fixed** ↓ |
| Dependency CVEs (SCA: go.mod / package-lock / requirements) | ~14 | ~63 | Track 3b — fixable ones fixed; rest tracked |
| Deployment engine (`build-failed`, `dependency-resolution-failed`) | 1 | 1 | **False positive** — the engine tries to build one deployable app; Aegis is a multi-service monorepo it can't build in the scanner env |
| Secrets | 0 | 0 | The 4 hits are the fixture's fake AWS example keys + `*-change-me` dev defaults — no real secret is tracked |

**The two real code findings — both fixed and re-verified:**

1. `ai-code-weak-crypto` — `ml/features.py` used `md5` to bucket a string into an
   ML feature index. Non-cryptographic; added `usedforsecurity=False` to declare
   intent and clear the rule.
2. `use-defused-xml` — `utils/reachability.py` parsed `pom.xml` **from the scanned
   (untrusted) repo** with stdlib `ElementTree`, a billion-laughs/XXE vector.
   Switched to **defusedxml**; verified it rejects an entity-expansion bomb while
   still parsing normal poms.

**Bottom line:** Aegis's own code is **grade A — zero criticals, zero remaining
highs** after these two fixes. The scan also proved the platform works: it found
its own dependency CVEs (driving Track 3b) and flagged real (if low-practical-risk)
hardening in its own scanner. The dominant SCA counts reflect the **committed tree
(pre-fix)**; the dependency remediations below reduce them.

**CI automation:** [`.github/workflows/self-scan.yml`](.github/workflows/self-scan.yml)
runs on every push + PR and dogfoods the same tools the scanner uses — Semgrep
with Aegis's own taint rules + `p/security-audit`, Gitleaks, Trivy (fs + config),
govulncheck (both Go services), `npm audit --audit-level=high`, and `pip-audit`.
Any critical/high finding fails the build, so the repo cannot regress.

## 3b — Dependency audit

**Go (`govulncheck`).** 8 advisories, all remediated by upgrades:

- 6 Go **standard-library** CVEs (`crypto/tls`, `crypto/x509`, `net`,
  `net/http`, `net/textproto`) → bumped the builder image `golang:1.22-alpine`
  → **`golang:1.25-alpine`** in both Go services. Recompiling against the 1.25
  stdlib closes all six.
- `github.com/jackc/pgx/v5` v5.7.1 → **v5.9.2** (GO-2026-5004).
- `golang.org/x/net` → **v0.53.0** (GO-2026-4918).
- Both services rebuilt clean on Go 1.25 with the patched modules.

**Web (`npm audit`, production deps).** Started at 5 (2 HIGH / 3 moderate):

- **axios 1.7.7 → 1.18.1** — closes both HIGH advisories (SSRF via absolute URL,
  DoS via missing size check, plus several prototype-pollution gadgets). axios is
  the app's direct HTTP client, so this is a first-order fix.
- **next-auth → 4.24.14** (patch).
- **Tracked:** `next` 14.2.35 carries DoS-class advisories (RSC DoS, rewrite
  request-smuggling, image-optimizer) whose fix requires a **14 → 15 major
  migration** (React 19, App Router changes). Not forced in a security-patch pass;
  scheduled as a separate, tested upgrade. Mitigations today: the app sits behind
  nginx (rate-limitable) and does not expose the image optimizer `remotePatterns`.
  The residual `uuid` moderate is transitive through next-auth and not reachable
  in its usage (no caller passes `buf`).

**Scanner (`pip-audit`).** 20 advisories in 7 packages. Safe leaf upgrades
applied (`python-multipart` → 0.0.31 — 6 CVEs, `pygments` → 2.20.0, `lightgbm`
→ 4.6.0); `starlette`/`protobuf` majors are FastAPI-coupled and tracked for a
coordinated bump; `pytest` is dev-only. _(Applied to `requirements.txt` and the
scanner re-verified; see commit.)_

## 3c — Container hardening

Baseline was already good: multi-stage builds, **non-root** users (uid 10001 /
`nextjs`), minimal `alpine` runtime bases. Improvements:

- **Removed `curl`** from the API production image — the healthcheck now uses
  BusyBox `wget` (built into alpine), so no extra tooling ships.
- **`cap_drop: ALL`** and **`security_opt: [no-new-privileges:true]`** on every
  app service (api, orchestrator, scanner, web) — they bind unprivileged ports
  and need no Linux capabilities.
- **Recommended next steps** (documented, not yet applied): distroless static
  base for the two Go services (removes the shell entirely), and `read_only`
  root filesystems with a `tmpfs` for scratch. Deferred pending a write-path
  audit so as not to break running scans; the scanner intentionally keeps a
  shell per the phase spec.

## 3d — Auth & session security

**Strong already:**

- JWT parsing pins the **HMAC** signing method (`t.Method.(*jwt.SigningMethodHMAC)`),
  defeating algorithm-confusion / `alg:none`. It also checks `token.Valid`
  (expiry) and the `TokenType` claim, so a refresh token cannot be replayed as an
  access token.
- **Refresh rotation** is real: `Refresh` verifies the session still exists,
  revokes the presented jti, and issues a fresh pair — a reused/revoked refresh
  token fails closed.
- Impersonation tokens are **capped to 1 hour** server-side and audit-logged
  (Phase 2C).

**Fixed / added:** the session store keyed only by jti, so there was no way to
revoke all of a user's sessions. Added a **per-user session index** plus
`RevokeAllForUser` and `CountForUser`
([`session.go`](services/api/internal/auth/session.go)) — the primitives needed
for "log out everywhere", suspension, and concurrent-session caps.

**Tracked:** there is **no password change/reset endpoint yet**. When it ships it
**must** call `RevokeAllForUser` (and suspension should too). Documented so the
control isn't forgotten.

## 3e — RBAC / authorization

Every data-access query is **org-scoped** with the same pattern —
`... AND p.organization_id IN (SELECT org_id FROM organization_members WHERE
user_id = $n)` — verified across all 7 repositories that touch tenant data
(`finding`, `project`, `scan`, `project_rule`, `github_integration`, `ai_audit`,
`admin`). Authorization is enforced in the SQL itself, so a wrong/forged id
returns no rows (404/empty) rather than another tenant's data — the correct fix
pattern for the Phase 2C org-access bug.

**Recommended:** an automated table-driven test that, for every authenticated
endpoint, asserts a second org's user gets 403/404. Scaffold noted for Track 3
follow-up.

## 3f — Injection audit

- **SQL:** no string-built queries. The one dynamic clause
  ([`finding.go`](services/api/internal/repository/finding.go)) joins **`$N`
  placeholder fragments** only; values always travel in `args...`. Fully
  parameterized.
- **Command:** no `shell=True` / `os.system` in product code. The only matches
  are third-party `.venv` (not shipped, git-ignored) and intentional Semgrep
  **test fixtures** under `rules/taint/` (documented, never scanned in prod).
- **Path traversal:** no archive extraction in the Go services; the `upload`
  repo-type has no unsafe extraction path. (Flagged for re-check if upload
  extraction is added.)
- **SSRF — FIXED.** The per-project **Slack webhook URL** was user-settable with
  only `validate:"url"`, and the server POSTs to it on every scan completion — a
  classic SSRF to `169.254.169.254`/internal hosts. Added
  `ValidateSlackWebhookURL` (https + `hooks.slack.com` only), enforced both at
  **save** (400) and at the **send** choke point (defense in depth)
  ([`slack.go`](services/api/internal/notify/slack.go)). Other outbound calls go
  to fixed vendor hosts (Anthropic, Resend, SendGrid, GitHub) or admin-configured
  integration bases.

## 3g — Webhook security

All four webhook verifiers use **timing-safe** comparison — `hmac.Equal`
(GitHub, GitHub App, Bitbucket) / `subtle.ConstantTimeCompare` (GitLab). No `==`
on signatures anywhere. **Replay:** GitHub/GitLab/Bitbucket webhooks carry no
signed timestamp, so replay is bounded by HMAC secrecy; a replayed push event
merely re-scans (idempotent, low impact). A delivery-id dedup cache is noted as a
hardening option.

## 3h — Scanner sandbox

- **No code execution.** The scanner only **reads** cloned code (Semgrep/Trivy/
  Gitleaks static parse + regex engines). Scanned code is never run, so a
  malicious repo has no execution vector — the single most important isolation
  property, and it holds.
- **Timeout** enforced per scanner call (`SCANNER_TIMEOUT_SECONDS`).
- Runs **non-root** with `cap_drop: ALL` (3c).
- **Recommended:** explicit `cpu`/`memory` limits (a pathological repo could
  exhaust RAM) and network isolation of the scanner (it needs no egress). Left as
  tuned config rather than untested caps on the 3.74 GB Windows VM.

## 3i — Rate limiting

The global limiter is a Redis fixed-window per-IP guard on all routes. **Added** a
**strict, separately-namespaced limiter on `/auth`** (`AUTH_RATE_LIMIT_RPM`,
default **10/min**) so credential-stuffing/brute-force is throttled hard without
starving normal API traffic ([`ratelimit.go`](services/api/internal/middleware/ratelimit.go),
wired in `main.go`). **Recommended next:** per-user/org quotas on scan triggers.

## 3j — CORS / CSP / security headers

Only CORS was configured. **Added** a `SecureHeaders` middleware applied globally
([`secure_headers.go`](services/api/internal/middleware/secure_headers.go)):

- `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` (API only
  returns JSON)
- `Strict-Transport-Security: max-age=63072000; includeSubDomains`
- `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `X-XSS-Protection: 0`

CORS keeps an explicit origin allowlist. The web app carries auth in the
`Authorization` header (not cookies) for API calls; next-auth session cookies are
`HttpOnly`/`SameSite` by framework default.

## 3k — Penetration-test simulation

Reviewed the standard attack classes against the current code + fixes:

| Attack | Status |
| --- | --- |
| **SQL injection** | Parameterized everywhere; dynamic clause uses placeholders only (3f). |
| **XSS** | API is JSON-only with `nosniff` + strict CSP; React escapes by default. |
| **CSRF** | Bearer-token auth (no ambient cookie on API calls) → no CSRF surface on the API. |
| **IDOR** | Every query org-scoped in SQL (3e); forged ids return empty, not cross-tenant data. |
| **Auth bypass** | HMAC-pinned JWT, `TokenType` enforced, refresh rotation, strict `/auth` rate limit (3d/3i). |
| **SSRF** | Slack webhook host-pinned (3f); other egress to fixed hosts. |
| **Brute force** | `/auth` limited to 10/min/IP (3i). |

No exploitable path found in these classes after the fixes above. A live,
automated cross-org IDOR test and an fuzzing pass are the recommended follow-ups.

---

## Fix inventory (this pass)

| Fix | File |
| --- | --- |
| Slack-webhook SSRF guard (save + send) | `services/api/internal/notify/slack.go`, `handlers/notify.go` |
| Per-user session index + revoke-all / count | `services/api/internal/auth/session.go` |
| Strict `/auth` rate limiter | `services/api/internal/middleware/ratelimit.go`, `cmd/main.go`, `internal/config/config.go` |
| Security-headers middleware | `services/api/internal/middleware/secure_headers.go`, `cmd/main.go` |
| Drop curl, wget healthcheck | `services/api/Dockerfile`, `docker-compose.yml` |
| `cap_drop: ALL` + `no-new-privileges` | `docker-compose.yml` |
| Go builder 1.22 → 1.25 (6 stdlib CVEs) | `services/{api,orchestrator}/Dockerfile` |
| pgx → v5.9.2, x/net → v0.53.0 | `services/{api,orchestrator}/go.mod` |
| axios → 1.18.1, next-auth → 4.24.14 | `web/package.json` |
| CI self-scan gate | `.github/workflows/self-scan.yml` |

All Go changes recompile clean (`go build ./...` on 1.25) and the middleware/auth
unit tests pass.
