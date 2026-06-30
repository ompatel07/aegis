# Aegis — Phase 1 Verification Summary

**Date:** 2026-06-30
**Scope:** Full compile-time + runtime verification of the Phase 1 stack
**Verdict:** ✅ **Ready for Phase 2A** — pipeline proven end-to-end on a fresh stack; 6 real bugs found and fixed.

---

## TL;DR

The entire Phase 1 platform was built, compiled, containerized, booted, and exercised end-to-end against a known-vulnerable repository (OWASP NodeGoat). It works.

- All 4 services compile/build/boot **healthy** on a from-scratch `docker compose up`.
- A real scan produced **174 findings** across all four engines, correctly classified by severity, pillar, CWE, and OWASP category.
- **6 real bugs were found and fixed** during verification — including one critical one (Semgrep was silently dead) that only surfaced under rigorous per-engine analysis.
- All fixes are committed.

---

## What was verified

Aegis is a 3-pillar code intelligence platform (Quality · Security · Deployment) made of:

| Service | Stack | Role |
| --- | --- | --- |
| `api` | Go / Chi | Auth (JWT), projects, scans, findings, webhooks |
| `orchestrator` | Go / Asynq | Clone repo → fan out to scanner → score → persist |
| `scanner` | Python / FastAPI | Semgrep (SAST), Trivy (SCA), Gitleaks (secrets), radon/lizard (quality), build/smoke (deployment) |
| `web` | Next.js 14 | Dashboard |
| infra | Postgres 16, Redis 7, nginx | Data, queue, reverse proxy |

---

## Environment

| Item | Value |
| --- | --- |
| OS | Windows 11 Home (build 26200), x64 |
| Docker | 29.5.3 (Docker Desktop 4.78.0, **WSL2** backend, linux/amd64 engine) |
| Docker Compose | v5.1.4 |
| Toolchains used for local checks | Go 1.22.12 (portable), Node 24, Python 3.13 |

---

## Step-by-step results

| # | Step | Result |
| --- | --- | --- |
| 1 | Docker functional (`version`, `compose version`, `hello-world`) | ✅ PASS |
| 2 | Compose config validation (`.env` + `docker compose config`) | ✅ PASS — 8 services, secrets valid |
| 3 | Build all images | ✅ PASS — warm cache 5.6 s; scanner `pip` rebuild 57 s |
| 4 | Boot stack + health + migrations + logs | ✅ PASS — 7/7 healthy, migrate exited 0 (5 migrations) |
| 5 | End-to-end scan on OWASP/NodeGoat | ✅ PASS — completed in 183 s |
| 6 | Findings quality validation | ⚠️ → ✅ — **critical Semgrep bug found & fixed** |
| 7 | Dashboard verification | ✅ PASS — pages serve, auth-guarded, bundles load |
| 8 | Teardown (`docker compose down -v`) | ✅ PASS — containers + volumes + network removed |
| 9 | Report | ✅ this document + `VERIFICATION_REPORT.md` |

### Boot detail

| Service | Status |
| --- | --- |
| postgres / redis | healthy |
| migrate | exited 0 — applied `users, projects, scans, findings, github_integrations` |
| api | healthy — "http server listening :8080", DB + Redis connected |
| orchestrator | healthy — "worker listening for scan jobs", Asynq processing |
| scanner | healthy — tools reported `{semgrep: true, trivy: true, gitleaks: true}` |
| web | healthy — "Ready in 85 ms" |
| nginx | up — reverse proxy |

`/api/health` → 200 `{database: ok, redis: ok}` · scanner `/health` → 200.

---

## 🔴 The critical bug (and why it matters)

The first scan returned **144 findings** — which looks healthy. But breaking the findings down **by engine** revealed:

```
semgrep: 0      ← the SAST engine produced nothing
trivy:   133
gitleaks: 3
quality: 8
```

Semgrep — the SAST / taint-analysis engine, i.e. the SonarQube-and-Snyk-competing core of the platform — was returning **zero**. Investigation showed it wasn't finding nothing; it was **crashing on every single invocation**:

```
ModuleNotFoundError: No module named 'pkg_resources'
```

**Root cause:** Semgrep's `opentelemetry-instrumentation` dependency imports `pkg_resources` at runtime, which is provided by `setuptools`. **Python 3.12 no longer bundles `setuptools`**, so Semgrep died on startup. Worse, it exited with code `1`, which the engine treated as "findings present" — so the failure was completely silent.

**Fix:** add `setuptools==75.6.0` to `services/scanner/requirements.txt`.

**After the fix:** Semgrep produces 30 findings on NodeGoat, correctly flagging the code-injection in `app/routes/contributions.js` (CWE-95 / OWASP A03 Injection) and private-key/bcrypt-hash exposure.

> **Why this matters:** the aggregate count (144) looked fine. Only engine-level validation exposed that a third of the security pillar's purpose was dead. This is exactly the failure mode the verification brief warned about.

---

## All bugs found & fixed

| # | Severity | Component | Bug | Fix | Commit |
| --- | --- | --- | --- | --- | --- |
| 1 | 🔴 Critical | scanner | Semgrep crashed every run (`pkg_resources` missing) → 0 SAST findings | add `setuptools==75.6.0` | `48991bc` |
| 2 | 🟠 High | scanner | Trivy pinned to non-existent `0.58.1`; flaky piped `install.sh` | direct tarball download, bump to `0.71.2` | `12d1dbc` |
| 3 | 🟠 High | api | `GET /scans/:id` → 500 (`column "id" is ambiguous` in JOIN) | qualify columns with `s.` alias | `12d1dbc` |
| 4 | 🟡 Med | web/scanner | no `.dockerignore` → 347 MB context; Windows `node_modules` overwriting Linux deps | add `.dockerignore` files | `12d1dbc` |
| 5 | 🟡 Med | web | `next build` failed — `useSearchParams()` without `<Suspense>` | wrap login form in `<Suspense>` | (compile pass) |
| 6 | 🟢 Low | orchestrator | healthy worker reported "unhealthy" (busybox `pgrep -x`) | drop `-x` | `bba36dc` |

---

## End-to-end scan result — OWASP/NodeGoat

- **Repo:** https://github.com/OWASP/NodeGoat (branch `master`)
- **Duration:** 183 s · **Status:** completed
- **Scores:** security **0** · quality **84** · deployment **100** → **overall 54, grade D**
  - Scoring spec verified exactly: `0.40·0 + 0.35·84 + 0.25·100 = 54.4 → 54`. Security floored at 0 by 17 criticals + 83 highs.

### Findings — 174 total

**By engine:** semgrep 30 · trivy 133 · gitleaks 3 · quality 8
**By severity:** critical 17 · high 83 · medium 41 · low 33
**By pillar:** security 166 · quality 8

**Field completeness:** file_path 100% · rule_id 100% · CWE on 74 · OWASP on 136 · CVE on 76 (line numbers present where applicable — SCA/secret findings reference a manifest, not a line).

### Sample findings

| Engine | Severity | Location | Rule | CWE / OWASP |
| --- | --- | --- | --- | --- |
| semgrep | high | `app/routes/contributions.js:32` | `code-string-concat` | CWE-95 / A03 Injection |
| semgrep | high | `artifacts/db-reset.js:19` | `detected-bcrypt-hash` | CWE-798 |
| semgrep | high | `artifacts/cert/server.key:1` | `detected-private-key` | CWE-798 / A07 |
| gitleaks | critical | `config/env/development.js:6` | `generic-api-key` | CWE-798 |
| trivy | critical | `package-lock.json` | `CVE-2020-7788` | A06 Vulnerable Components |
| trivy | critical | `package-lock.json` | `CVE-2021-44906` | A06 |
| quality | low | `Gruntfile.js:50` | `quality/long-function` | — |
| quality | low | `app/routes/profile.js` | `quality/duplicated-code` | — |

---

## What this proves works

Auth (register/login/JWT) · project CRUD with slug generation · scan trigger → Redis/Asynq enqueue · orchestrator clone (go-git) → language detection → **parallel** scanner fan-out → aggregation → scoring → transactional persistence → cleanup · all four scanning engines · the API read/report/findings paths · nginx reverse-proxy routing (including the `/api/auth/` vs `/api/` split) · the Next.js dashboard with auth-guarded routes.

---

## Commit history

```
82af9fa  docs: append runtime verification re-run (semgrep fix, 174 findings)
48991bc  fix(scanner): semgrep crashed on startup (missing pkg_resources)
bba36dc  fix(orchestrator): healthcheck used busybox-incompatible pgrep -x
12d1dbc  Phase 1 verification: fix Docker build + scan read path; full stack verified
f772c83  Aegis Phase 1: scaffold + verification pass
```

---

## Recommendation

✅ **Ready to proceed to Phase 2A.**

The full 3-pillar pipeline is proven on a fresh, from-scratch boot. Every compile/build/runtime failure encountered has been root-caused and fixed (no workarounds, no skipped tests, no silenced errors).

### Carry into Phase 2 (non-blocking)
1. **Add a Semgrep smoke assertion to CI** — run the scanner against a tiny known-vulnerable fixture and assert `semgrep findings > 0`. This bug was invisible at the aggregate level; a guard prevents a future dependency bump from silently killing SAST again.
2. **Bump `next@14.2.18`** — it carries a published security advisory; move to the latest patched 14.2.x.
3. **Add the create-integration endpoint** — webhook verification is implemented; the integration-creation route is still deferred.
4. **Deepen the deployment pillar** — per-language build matrices beyond the current build/smoke harness.
