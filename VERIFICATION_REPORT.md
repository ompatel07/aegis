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
