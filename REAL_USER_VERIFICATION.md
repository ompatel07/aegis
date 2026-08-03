# Real-User End-to-End Verification (Phase 2G, Prompt 1 — Functional Correctness)

The backend path was fully verified in Passes 1–5, but driving Aegis as a real
customer through the product exposed a broken real-user path: a scan **failed**
with `clone failed: couldn't find remote ref refs/heads/main` because the product
**assumed every repo's default branch is `main`**. This pass fixes that and every
other "works in backend, not in the product" gap — and proves the verified
accuracy actually reaches the user.

**Everything below was driven through the real HTTP endpoints the browser UI
calls** (`/auth/register`, `/projects/detect-branches`, `/projects`,
`/projects/{id}/scans`, `/scans/{id}/…`, `/report/compliance`), **not** backend
shortcuts.

---

## Headline

> ## Accuracy parity: **EXACT** ✅
> The same repo (`pallets/flask`) run through **(a) the real-user UI path** and
> **(b) the direct backend engines** produced **138 findings each, an identical
> set** (rule + file + line + severity), **0 differences**. The 8/8-engine
> accuracy proven in Pass 3 reaches the real user unchanged.

| Part | Verdict |
|------|---------|
| 1 — Branch clone/branch bug | ✅ **FIXED** (auto-detect + manual + graceful error) |
| 2 — Full real-user scan flow | ✅ **PASS** (incl. exact accuracy parity) |
| 3 — Wire backend-only features | ✅ **PASS** (compliance wired; orphan text removed) |
| 4 — Exports work for a real user | ✅ **PASS** (all 4 + RBAC) |
| 5 — Graceful error handling | ✅ **PASS** |

---

## Part 1 — The branch bug: root cause + fix

**Root cause.** `ProjectService.Create` hard-defaulted the branch to `"main"` when
the user gave none, and the orchestrator cloned `refs/heads/main` — so any repo on
`master`/`develop`/custom failed to clone.

**Fix (never assume "main"):**
- New `internal/gitremote` (go-git `ListContext`) detects a remote's default
  branch from the server's symbolic HEAD (fallback `main`→`master`) and lists all
  branches — **without cloning**.
- `POST /projects/detect-branches` powers the connect-repo UI.
- Project create **auto-detects** the default when none is given; otherwise stores
  empty and the orchestrator clones the remote's default HEAD.
- `NewProjectModal`: **"use default branch (auto-detect)"** vs **"choose a
  branch"**, plus a **Detect branches** button.

**Verified live through the real create/scan endpoints:**

| Repo (default) | Connected via | Result |
|----------------|---------------|--------|
| `pallets/flask` (**main**) | auto-detect → `main` | ✅ completed, **138 findings** |
| `octocat/Hello-World` (**master**) | auto-detect → `master` | ✅ **completed** — the mycellium bug is fixed |
| `pallets/flask` @ `stable` | manual branch | ✅ completed, 138 findings |
| `pallets/flask` @ `stable-2.3.x` (doesn't exist) | manual branch | ✅ **graceful failure**: *"branch 'stable-2.3.x' was not found … Available branches: automatic-options, main, stable, workflow"* |

`detect-branches` correctly returned `main` for flask and `master` for
Hello-World.

---

## Part 2 — Full real-user scan flow (end-to-end)

Driven as a real user via the UI's HTTP:

1. **Sign up / log in** → `POST /auth/register` → access token. ✅
2. **Connect a repo — all methods:**
   - **Direct git URL (public):** flask connected + scanned (138 findings). ✅
   - **Archive upload:** `POST /projects/{id}/scans/upload` → completed, 5
     findings, real pillar scores. ✅
   - **GitHub App / token (private):** the connect endpoint + token-clone path were
     **live-verified on a real private repo (`coupleapp`) in Pass 2**; the
     `detect-branches`/connect flow accepts a token and the orchestrator clones
     with it. (Not re-run this pass — no active private token — but the code path
     is the same one proven in Pass 2.)
3. **Trigger scan from the UI** → `POST /projects/{id}/scans` → runs. ✅
4. **Scan completes** (not stuck/failed) → real findings appear. ✅
5. **ACCURACY PARITY (the #1 requirement): EXACT.** See headline —
   real-user 138 == direct-backend 138, identical set, **0 diff**. ✅
6. **Findings render with correct data** — the API the UI reads equals the DB
   field-for-field (all 138, proven in Pass 5). ✅
7. **Finding detail → Steps-of-Reproduction** — on an uploaded taint finding the
   real-user API returned SoR **source `L6 request.args.get("name")` → sink `L7
   "SELECT … n='"+name+"'"`**, matching the code. ✅
8. **All 3 pillars show real scores** — flask: security **0** (13 issues) ·
   quality **71** (125) · deployment **100**; upload: 35 · 75 · 100. ✅

---

## Part 3 — Wire up what wasn't reachable

**Compliance reports (were a repo-only CLI that crashed in the container).**
- Fixed the path bug (`Path(__file__).parent/"frameworks"`, not `parents[3]`) and
  **shipped the 6 framework YAMLs into the scanner image**.
- New scanner `POST /report/compliance` (+ `/frameworks`).
- New API `GET /scans/{id}/report/compliance?framework=…[&download=1]`
  (org-scoped) → scanner. New **compliance card** on the report page (pick
  framework, preview in-page, download HTML).
- **Verified via the real user API — all 6 frameworks generate with real scores**
  from the flask scan: SOC 2 44% · PCI-DSS 22% · HIPAA 33% · ISO 27001 56% · OWASP
  ASVS 38% · NIST CSF 50%. A user can now generate + download one from the UI.

**Orphan AI-code text.** Removed the "AI-code safety score" merge-gate text from
`PolicyCard` (the backend `PolicyConfig` has no such gate after the AI-detection
removal).

---

## Part 4 — Exports work for a real user

All generated via the real user API and returned valid files:

| Export | Result |
|--------|--------|
| Executive report | ✅ real data (JSON the report page renders; PDF via browser print) |
| Compliance (6 frameworks) | ✅ HTML report + download, real control scores |
| SARIF | ✅ 2.1.0, 85 KB, results = findings |
| SBOM CycloneDX / SPDX | ✅ 68 KB / 41 KB |
| **RBAC / org-scoping** | ✅ another org exporting this scan's SARIF / SBOM / exec / **compliance** → **404** on all |

---

## Part 5 — Graceful error handling (clear messages, no raw errors)

Driven through `detect-branches` (connect) + the scan failure path:

| Situation | Message shown |
|-----------|---------------|
| Branch doesn't exist | *"branch '…' was not found … Available branches: …"* (lists them) |
| Repo not found / bad URL | *"Couldn't find the repository at that URL. Check the URL…"* |
| Private repo, no token | *"This repository is private or doesn't exist. If private, provide an access token…"* |
| Access token rejected | *"…the access token was rejected. Check that the token is valid and has read access."* |
| Empty repo (no branches) | *"This repository has no branches yet (it looks empty)…"* (handled in code) |
| Oversized repo | *"Repository is too large to scan (N MB, limit M MB). Scope the scan to specific directories…"* (size guard; the daemon-crash hardening remains the deferred perf-pass item in PERFORMANCE_TODO) |
| Any scan failure | the reason is shown on the scan page (`getScan.error_message`) — e.g. the missing-branch message with available branches |

---

## What's verified live vs. referenced

- **Live this pass (real HTTP):** branch auto-detect/manual/error, full scan flow
  (public URL + upload), **exact accuracy parity**, SoR, 3 pillars, all 6
  compliance frameworks, all exports, export RBAC, connect-time error messages,
  failed-scan error display.
- **Referenced (proven earlier):** the private-repo **token** clone was
  live-verified on `coupleapp` in Pass 2 (same code path; not re-run here for lack
  of an active private token). The oversized-repo **daemon-crash** graceful
  shutdown (vs. the size *guard*, which works) remains the deferred item in
  `PERFORMANCE_TODO.md`.

## Remaining gaps (honest)

- Private-repo token method not re-exercised this pass (no active private token);
  code path unchanged from the Pass-2 live proof.
- Oversized-repo **hard-failure hardening** (fail fast without stressing the host)
  is still the deferred performance-pass item; the pre-scan size guard returns a
  clear message today.

**Bottom line: a real user can sign up, connect a repo on any default branch (or a
chosen one), run a scan that completes, and see findings that exactly match the
verified backend accuracy — plus generate compliance reports and every export from
the UI, with clear errors when something is wrong.**
