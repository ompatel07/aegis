# Aegis Phase 1 — Verification Report

_Last updated: 2026-06-30 — full runtime verification (Docker now installed)._

## Environment

| Item | Value |
| --- | --- |
| OS | Windows 11 Home Single Language, build 26200 (x64) |
| Docker | 29.5.3 (Docker Desktop 4.78.0, WSL2 backend, linux/amd64 engine) |
| Docker Compose | v5.1.4 |
| node / npm | v24.15.0 / 11.12.1 |
| python | 3.13.7 |
| go | portable go1.22.12 (used for local compile checks) |
| git | 2.53.0 |

Docker + WSL2 were installed by the user between verification passes, which
unblocked the full containerized run. Every step has now been executed for real.

---

## Step-by-step results

### Step 1 — Toolchain check · ✅ PASS
Docker 29.5.3 + Compose v5.1.4 present and the engine is running
(`docker run hello-world` succeeded on the WSL2 Linux backend).

### Step 2 — Go services compile check · ✅ PASS
Portable Go 1.22.12: `go mod tidy`, `go vet ./...` (0 warnings), `go build ./...`,
`go test ./...` all clean for **api** and **orchestrator**; scoring unit tests
pass; `gofmt` clean.

### Step 3 — Python scanner static checks · ✅ PASS (runtime via Docker)
`compileall` clean; normalizer unit tests 5/5 pass locally. Native Windows can't
install Semgrep — but inside the Docker image all three tools are present and the
scanner's `/health` reports `semgrep:true, trivy:true, gitleaks:true`.

### Step 4 — Frontend typecheck + build · ✅ PASS (1 fix)
`npm install` (lockfile generated), `tsc --noEmit` 0 errors, `npm run lint` clean,
`npm run build` green after fixing the `/login` Suspense issue (see Issues).

### Step 5 — Docker compose config + build · ✅ PASS (3 fixes)
`docker compose config` valid. `docker compose build` produced all 4 images
(scanner 1.44 GB, web 226 MB, orchestrator 34 MB, api 39.8 MB) after fixing the
Trivy install + adding `.dockerignore` files (see Issues).

### Step 6 — Full stack boot · ✅ PASS
`docker compose up -d` brought up all services healthy:

```
postgres      healthy        redis         healthy
scanner       healthy        api           healthy
web           healthy        orchestrator  running (worker processing)
nginx         running        migrate       exited 0
```

- **migrate** applied all 5 migrations (users, projects, scans, findings,
  github_integrations) and exited 0.
- **api** `/api/health` → 200 `{database:ok, redis:ok}`.
- **orchestrator** logs: "database connected", "worker listening for scan jobs",
  asynq "Starting processing".
- **scanner** `/health` → 200 with all three tools available.

### Step 7 — End-to-end smoke test · ✅ PASS (1 fix — see below)
Registered a user → created a project for **OWASP/NodeGoat** → triggered a scan →
polled to completion → fetched findings. First attempt surfaced a real API bug
(ambiguous `id` column on the scan read path, fixed below); after the fix the
scan completed and returned rich, well-formed findings. **Details in the next
section.**

### Step 8 — Dashboard check · ✅ PASS
Through nginx: `/login` → 200 (renders "Aegis"), `/register` → 200, `/` → 307
redirect to login (auth middleware working), `/api/auth/providers` → 200
(NextAuth reachable, confirming the nginx `/api/auth/` vs `/api/` split).

### Step 9 — Teardown + commit · ⚠️ PARTIAL (by request)
The user asked to set up + test and pause for the next prompt, so the **stack was
left running** (not torn down). Verification fixes were committed.

---

## End-to-end smoke test result

- **Repo scanned:** https://github.com/OWASP/NodeGoat (branch master)
- **Scan duration:** 180 s
- **Status:** completed
- **Pillar scores:** security **0**, quality **84**, deployment **100** →
  overall **54**, grade **D**
  - Verifies the scoring spec exactly: 0.40·0 + 0.35·84 + 0.25·100 = 54.4 → 54,
    grade D (≥40). Security floored at 0 by the volume of critical/high findings.
- **Findings:** 136 security · 8 quality · 3 secrets · **76 dependency CVEs**
  - Security severity mix included 17 critical.

### Sample findings (engine · severity · location · rule)
1. `gitleaks` · **critical** · `artifacts/cert/server.key:1` · `private-key`
   — exposed private key (CWE-798).
2. `gitleaks` · **critical** · `config/env/development.js:6` · `generic-api-key`.
3. `trivy` · **critical** · `package-lock.json` · `CVE-2020-7788`
   — vulnerable npm dependency.
4. `trivy` · **critical** · `package-lock.json` · `CVE-2021-44906`.
5. `quality` · low · `Gruntfile.js:50` · `quality/long-function`
   — function is 97 lines long.
6. `quality` · low · `app/routes/profile.js` · `quality/duplicated-code`.

Every finding carried proper `severity`, `engine`, `file_path`, `line_start`
(where applicable — SCA findings reference the manifest), `rule_id`, and where
relevant `cwe_id` / `cve_id`. **A known-vulnerable repo produced abundant,
correctly-classified findings — the core scanning pipeline is verified working.**

---

## Issues found and fixed

1. **`services/scanner/Dockerfile` — Trivy install failed (build blocker).**
   Two problems: (a) the piped `install.sh` from Trivy's `main` branch is flaky
   and aborted right after resolving the version; (b) the pinned `TRIVY_VERSION=
   0.58.1` **does not exist** (latest is 0.71.2 — the URL 404'd). **Fix:** download
   the Trivy release tarball directly (like Gitleaks), consolidate arch detection,
   and bump to `0.71.2` (verified all download URLs resolve before rebuilding).

2. **`web/.dockerignore` (new) — broken/oversized web image.** The web build
   context was 347 MB because the host `node_modules`/`.next` were shipped, and
   the Dockerfile's `COPY . .` would overwrite the Linux deps with **Windows**
   binaries. **Fix:** added a `.dockerignore` excluding `node_modules`, `.next`,
   `.env`, etc.

3. **`services/scanner/.dockerignore` (new).** Excludes the local `.venv` and
   caches from the build context.

4. **`services/api/internal/repository/scan.go` — `GET /scans/:id` returned 500.**
   `column reference "id" is ambiguous (SQLSTATE 42702)`: the scan
   `GetByIDForUser` query JOINs `scans` and `projects`, but `scanColumns` listed
   bare column names present in both tables (`id`, `created_at`, ...). **Fix:**
   qualified every column in `scanColumns` with the `s.` alias and aliased the
   table in `ListByProject` (`FROM scans s`). Verified the read path returns 200
   and the scan completes. _(No tests were weakened; this was a real query bug.)_

5. **`web/app/(auth)/login/page.tsx` (prior pass) — `useSearchParams()` without
   `<Suspense>`** broke `next build` prerender of `/login`. Wrapped the form in a
   `<Suspense>` boundary.

6. **Dependency lock files generated** (prior pass): `web/package-lock.json`,
   `services/api/go.sum`, `services/orchestrator/go.sum` (+ go.mod indirect).

---

## Outstanding issues

1. **`next@14.2.18` security advisory** (npm flagged at install). Recommend
   bumping to the latest patched 14.2.x in Phase 2. Low risk for local dev.
2. **Deployment-pillar smoke test depth.** Deployment scored 100 on NodeGoat; the
   build/smoke harness ran but deeper validation (per-language build matrices)
   would strengthen Phase 2. Not a defect — works as designed.
3. **GitHub integration creation endpoint** remains deferred (webhook verification
   is implemented and unit-consistent; no create-integration route yet).

---

## Recommendation

✅ **Ready to proceed to Phase 2.**

The full stack builds, boots healthy, and the end-to-end pipeline is **proven
working**: a scan of a known-vulnerable repository produced 136 security findings,
76 dependency CVEs, and 3 secrets, with correct severities, locations, rule IDs,
and a correctly-computed grade. Auth, project CRUD, queue → worker → scanner
fan-out, scoring, persistence, the API read paths, the reverse proxy, and the
dashboard all function. Four real bugs were found and fixed during verification
(Trivy version/install, two `.dockerignore` gaps, the ambiguous-column query, and
the login Suspense boundary).

Carry into Phase 2: bump Next.js to a patched release; add the
create-integration endpoint; consider seeding a tiny in-repo vulnerable fixture
for fast CI smoke scans.

---
---

# Runtime Verification (2026-06-30, re-run)

A second, independent runtime pass on a fresh stack (`docker compose down -v`
first). It found and fixed a **critical SAST bug** the first pass missed.

## Build time
- Docker engine had been stopped between sessions; started Docker Desktop (engine
  ready in ~5 s on the WSL2 backend).
- `docker compose build` with warm layer cache: **5.6 s** (all 4 images already
  built). The cold build's long pole is the scanner image (1.44 GB) — apt + Trivy
  + Gitleaks + Go + Node + `pip install` of Semgrep. After the Semgrep fix the
  scanner `pip` layer rebuilt in **57 s**.

## Stack boot
Fresh `docker compose up -d` → all services healthy within ~60 s:

| service | result |
| --- | --- |
| postgres / redis | healthy |
| migrate | exited 0 — applied all 5 migrations |
| api | healthy — "http server listening :8080", db+redis connected |
| orchestrator | healthy — "worker listening for scan jobs", asynq processing |
| scanner | healthy — tools `{semgrep, trivy, gitleaks}: true` |
| web | healthy — "Ready in 85ms" |
| nginx | up |

`/api/health` → 200 `{database:ok, redis:ok}`; scanner `/health` → 200.

## End-to-end scan — OWASP/NodeGoat (branch master)

Two scans were run (before and after the Semgrep fix). Final (post-fix) result:

- **Duration:** 183 s · **Status:** completed
- **Scores:** security **0** · quality **84** · deployment **100** → overall
  **54**, grade **D** (security floored by 17 criticals + 83 highs; grade math
  0.40·0 + 0.35·84 + 0.25·100 = 54.4 → 54).

### Findings — 174 total

**By engine** (this is what exposed the bug):

| engine | pre-fix | post-fix |
| --- | --- | --- |
| semgrep | **0 (broken)** | **30** |
| trivy | 133 | 133 |
| gitleaks | 3 | 3 |
| quality | 8 | 8 |
| **total** | 144 | **174** |

**By severity (post-fix):** critical 17 · high 83 · medium 41 · low 33.
**By pillar:** security 166 · quality 8.

**Field completeness (pre-fix sample of 144):** file_path 144/144 · rule_id
144/144 · line_start 43 (SCA/secret findings reference a manifest, not a line) ·
cwe_id 74 · owasp_category 136 · cve_id 76.

### Sample findings
| engine | severity | location | rule | CWE / OWASP |
| --- | --- | --- | --- | --- |
| semgrep | high | `app/routes/contributions.js:32` | `code-string-concat` | CWE-95 / A03 Injection |
| semgrep | high | `artifacts/db-reset.js:19` | `detected-bcrypt-hash` | CWE-798 |
| semgrep | high | `artifacts/cert/server.key:1` | `detected-private-key` | CWE-798 / A07 |
| gitleaks | critical | `config/env/development.js:6` | `generic-api-key` | CWE-798 |
| trivy | critical | `package-lock.json` | `CVE-2020-7788` | A06 Vulnerable Components |
| trivy | critical | `package-lock.json` | `CVE-2021-44906` | A06 |
| quality | low | `Gruntfile.js:50` | `quality/long-function` | — |
| quality | low | `app/routes/profile.js` | `quality/duplicated-code` | — |

Semgrep correctly flagged NodeGoat's code-injection in `contributions.js` (a
known NodeGoat vulnerability) — confirming the SAST engine now works.

## Dashboard
Through nginx: `/login` 200 (renders "Aegis"), `/register` 200, `/` 307 (auth
redirect), the scan-detail route 307 (correctly auth-guarded without a session),
`/api/auth/providers` 200, and a `/_next/static` JS bundle loaded 200. Findings
rendering is client-side React over the verified API; a headless browser was not
available for pixel-level confirmation.

## Bugs found and fixed in this pass

1. **CRITICAL — Semgrep crashed on every run (`ModuleNotFoundError: No module
   named 'pkg_resources'`).** Semgrep's `opentelemetry-instrumentation` dependency
   imports `pkg_resources`, which ships with `setuptools`; Python 3.12 no longer
   bundles it, so Semgrep died on startup and exited 1 — which the engine treated
   as "findings present", silently yielding **0 SAST findings**. The first
   runtime pass missed this because it didn't break findings down by engine.
   **Fix:** added `setuptools==75.6.0` to `services/scanner/requirements.txt`.
   After the fix Semgrep produces 30 findings on NodeGoat. _Commit `48991bc`._

   This is exactly the failure mode the verification brief warned about
   ("a scan producing few findings means the scanner is broken"). The aggregate
   count (144) looked fine, but a third of the security pillar's purpose (SAST /
   taint analysis) was silently dead. Engine-level validation caught it.

## Teardown
`docker compose down -v` removed all containers, the 3 named volumes
(pgdata, redisdata, workspaces), and the network. `docker compose ps -a` empty.

## Recommendation

✅ **Ready to proceed to Phase 2.**

After fixing the Semgrep crash, the full 3-pillar pipeline is genuinely proven:
**174 findings** across all four engines (semgrep 30, trivy 133, gitleaks 3,
quality 8), distributed across every severity, with CWE/OWASP tags, file paths,
line numbers, and rule IDs — on a fresh, from-scratch stack boot. All five real
bugs from both passes are fixed and committed (`48991bc` Semgrep, `bba36dc`
orchestrator healthcheck, `12d1dbc` Trivy version + ambiguous-column query +
`.dockerignore`, plus the login Suspense fix).

Outstanding for Phase 2 (non-blocking): bump `next@14.2.18` (security advisory);
add a Semgrep smoke assertion to CI so a future dependency change can't silently
disable SAST again; add the create-integration endpoint.
