# Aegis Phase 1 — Verification Report

_Date: 2026-06-29_

## Environment

| Item | Value |
| --- | --- |
| OS | Windows 11 Home Single Language, build 10.0.26200 |
| Architecture | x64 (AMD64) |
| Shell | PowerShell 5.1 (non-elevated) |
| node | v24.15.0 |
| npm | 11.12.1 |
| python | 3.13.7 (`python`; `python3` is only the MS Store stub) |
| git | 2.53.0 |
| go | **not installed** → worked around with a portable `go1.22.12` zip (no admin needed) |
| docker / docker compose | **not installed** |
| make | **not installed** |
| openssl | **not installed** |
| WSL2 | **not installed** |

> **Key constraint:** Docker is absent and cannot be installed here (no admin
> rights, no WSL2, requires a reboot). Because the scanner engines (Semgrep,
> Trivy, Gitleaks) are Linux-only and the whole runtime is container-based, the
> live-runtime steps (5–8) could not be executed. Everything that can be verified
> **without** Docker was verified for real.

---

## Step-by-step results

### Step 1 — Toolchain check · ❌ FAIL (blocking tools missing)
Missing: `go`, `docker`, `docker compose`, `make`, `openssl`, WSL2. Present:
node, npm, python, git. I did not stop entirely — I obtained a **portable Go
toolchain** (official `go1.22.12` zip, extracted to a temp dir, no admin/UAC) to
unblock Step 2, and proceeded with every check that does not require Docker.

### Step 2 — Go services compile check · ✅ PASS
Ran against both modules with portable Go 1.22.12:

| Check | services/api | services/orchestrator |
| --- | --- | --- |
| `go mod tidy` (generates go.sum) | ✅ | ✅ |
| `go vet ./...` | ✅ 0 warnings | ✅ 0 warnings |
| `go build ./...` | ✅ all 12 pkgs | ✅ all 10 pkgs |
| `go test ./...` | ✅ (no test files) | ✅ **scoring tests pass** (`ok internal/scoring`) |
| `gofmt -l` | ✅ clean after `gofmt -w` | ✅ clean after `gofmt -w` |

The orchestrator scoring unit tests (security penalties, quality weights,
deployment step weighting, overall score + grade thresholds) all pass.

### Step 3 — Python scanner static checks · ⚠️ PASS WITH CAVEATS
- `python -m compileall` on the whole scanner: ✅ syntax-clean (all 23 modules).
- Scanner unit tests (`tests/test_normalizer.py`, severity normalization /
  CVSS→severity / CWE extraction): ✅ **5/5 pass** in a minimal venv (pydantic +
  pytest).
- `pip install -r requirements.txt`: ❌ **not possible on native Windows** —
  `semgrep` has no Windows wheel and fails to build from source (`pip install
  --dry-run semgrep==1.97.0` → "Getting requirements to build wheel did not run
  successfully"). This is expected: Semgrep/Trivy/Gitleaks are Linux tools. The
  scanner is designed to run **only inside its Linux Docker image**, so this is a
  platform limitation of the verification host, not a code defect.

### Step 4 — Frontend typecheck + build · ⚠️ PASS WITH FIXES
- `npm install`: ✅ 461 packages, **`package-lock.json` generated**.
- `npx tsc --noEmit`: ✅ **0 type errors** (all hand-written API/response types
  are internally consistent).
- `npm run lint`: ✅ no ESLint warnings or errors.
- `npm run build`: ❌ → ✅ after **1 fix** (see Issues). Final build is green:
  all 8 routes compiled, middleware bundled, standalone output produced.

### Step 5 — Docker compose config + build · ❌ NOT RUN
Docker is not installed. Compose file was hand-validated for schema in the build
phase but **not** validated by `docker compose config`, and **no images were
built**.

### Step 6 — Full stack boot · ❌ NOT RUN
Requires Docker. Stack was never booted.

### Step 7 — End-to-end smoke test · ❌ NOT RUN (most important gap)
Requires the running stack. **A real scan against a vulnerable repo was never
executed**, so I cannot confirm the pipeline produces findings/scores end to end.
This is the single most important unverified item.

### Step 8 — Dashboard check · ❌ NOT RUN (live)
No running server to curl. However, `next build` proves every page compiles and
`/login` prerenders, which is partial evidence the dashboard is structurally sound.

### Step 9 — Teardown + commit · ⚠️ PARTIAL
- Teardown: N/A (nothing was running).
- Commit: the directory was **not a git repository**, so I initialized one and
  committed the scaffold plus all verification artifacts (lockfiles, go.sum,
  fixes, this report).

---

## End-to-end smoke test result

**NOT EXECUTED.** Blocked by the missing Docker runtime. No repository was
scanned, so there are no scores, no findings, and no sample findings to report.
This must be run on a machine with Docker/WSL2 before relying on the scanner.

---

## Issues found and fixed

1. **`web/app/(auth)/login/page.tsx` — build-breaking `useSearchParams()` without
   Suspense.** `next build` failed prerendering `/login` with
   "useSearchParams() should be wrapped in a suspense boundary". This is a hard
   Next.js 14 App Router requirement, not a warning. **Fix:** extracted the form
   into an inner `LoginForm` component and wrapped it in `<Suspense>` in the
   default-exported page. Rebuild is green. _(No `@ts-ignore`/`any` used.)_

2. **`gofmt` formatting on 6 Go files** (`config.go`, `httpx/response.go`,
   `models/finding.go`, `models/scan.go`, `services/scan.go` in api;
   `types/types.go` in orchestrator). Struct-tag alignment only. **Fix:**
   `gofmt -w` (whitespace-only; no behavior change — build/vet/test still pass).

3. **Generated dependency lock files** (were intentionally omitted from the
   scaffold): `web/package-lock.json`, `services/api/go.sum` + go.mod indirect
   block, `services/orchestrator/go.sum` + go.mod indirect block.

---

## Outstanding issues

1. **Live runtime unverified (Docker required).** Image builds (Step 5), stack
   boot (Step 6), the end-to-end scan (Step 7), and the live dashboard (Step 8)
   were not run. **Next step:** on a host with Docker Desktop + WSL2, run
   `docker compose build`, `make dev`, then the DEVELOPMENT.md §3 curl flow
   against a vulnerable repo (e.g. OWASP/NodeGoat) and confirm findings are
   produced.

2. **Scanner cannot run on native Windows** (Semgrep/Trivy/Gitleaks are Linux
   tools). This is by design — it runs in its Docker image — but means scanner
   *runtime* verification is impossible outside Linux/containers.

3. **`next@14.2.18` has a published security advisory** (npm flagged it during
   install: nextjs.org/blog/security-update-2025-12-11). Recommend bumping to the
   latest patched 14.2.x in Phase 2.

4. **Go was run from a portable zip**, not a managed install. The generated
   `go.sum`/`go.mod` are valid and committed; a permanent Go install is only
   needed for future local Go work (the Docker image builds Go itself).

---

## Recommendation

⚠️ **Proceed with caveats.**

What is genuinely verified now: **all four codebases are sound at compile/build
time** — the Go API and orchestrator compile, vet, and test clean (including the
scoring tests); the scanner's pure-Python logic compiles and its unit tests pass;
the Next.js frontend type-checks, lints, and builds (after one real fix). That is
strong evidence the implementation is internally consistent and free of the
compile/type errors that "never compiled" code usually hides.

What is **not** verified and must be before depending on Phase 1: the **live,
containerized end-to-end run** — most importantly, that triggering a scan on a
known-vulnerable repo actually yields findings and scores. That requires Docker
(or WSL2), which this machine lacks.

**Bottom line:** the code is build-clean and safe to continue developing on, but
do **not** treat the scanning pipeline as proven until the Docker-based Steps 5–7
are executed on a capable host.

### To finish verification (on a Docker-capable machine)
```bash
wsl --install                 # then reboot, if not already present
# install Docker Desktop, enable the WSL2 backend, start it
cp .env.example .env          # set TOKEN_ENCRYPTION_KEY=$(openssl rand -hex 32), JWT secrets, NEXTAUTH_SECRET
make dev                      # build + boot the whole stack
# then run DEVELOPMENT.md §3: register → create project → trigger scan → poll → findings
```
