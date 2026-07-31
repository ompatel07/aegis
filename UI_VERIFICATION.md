# UI ↔ Backend Accuracy + Reports/Charts/Exports — Verification

**Phase 2F pre-launch hardening, Pass 5 of 6.** Verifies that what the user sees in
the dashboard exactly matches backend/DB truth, that all charts use real data, and
that every export is valid + accurate + RBAC-scoped — then gives the user a working
way to open the dashboard.

Real data used throughout: a live scan of **`pallets/flask`** (138 findings) on a
**demo project**, plus an uploaded taint sample (for Steps-of-Reproduction).

---

## Verdicts

| Part | Verdict |
|------|---------|
| 1 — UI ↔ backend data accuracy | ✅ **PASS** (1 minor CONCERN: orphan policy text) |
| 2 — Three pillars display clearly | ✅ **PASS** |
| 3 — Charts + visualizations (real data only) | ✅ **PASS** |
| 4 — Reports + exports | ✅ **PASS** for exec/SARIF/SBOM · ⚠️ **CONCERN**: compliance reports |
| 5 — Let the user see the UI | ✅ **PASS** (working URL below) |

**Scan-data accuracy is exact — the dashboard never lies about a finding, count, or
score.** Two non-data-accuracy concerns are reported (orphan AI-code policy text;
compliance reports not wired to the product), both report-before-fix.

---

## Part 1 — UI ↔ backend data accuracy ✅ PASS

The dashboard is a thin, faithful render of the API, which serializes the DB
directly. Verified field-by-field, not just spot-checked:

- **Finding counts reconcile exactly (API = DB):**

  | | API report | DB |
  |--|:---------:|:--:|
  | total findings | 138 | 138 |
  | security / quality issues | 13 / 125 | 13 / 125 |
  | secrets / vulnerabilities | 6 / 0 | 6 / 0 |
  | by engine | semgrep 7 · gitleaks 6 · quality 125 | identical |
  | by severity | crit 6 · high 2 · med 33 · low 97 | identical (=138) |

- **Every individual finding matches.** Dumped all **138** findings from the API and
  from the DB (id, rule_id, file_path, line_start, severity, cwe_id, pillar), sorted,
  and diffed → **0 differences**. The API serves exactly the DB rows; `FindingCard`
  renders those fields directly (rule, `path:line`, severity, engine, CWE/CVE/OWASP,
  remediation).
- **Scores match, no drift / no stale cache.** API `overall 50 (D) · security 0 ·
  quality 71 · deployment 100` == DB score columns == what `ScoreCard` renders.
- **Steps-of-Reproduction match the code.** On an `aegis-py-sql-injection` finding:
  SoR **source `L6 request.args.get("name")` → sink `L8 "SELECT … '"+name+"'"`** —
  exactly the uploaded source. `FindingCard`'s `StepsToReproduceSection` renders the
  backend `context_metadata.steps_to_reproduce` structure verbatim.
- **Baseline / new tags are correct.** First scan establishes the baseline
  (`is_new = 0`). A second identical scan → `is_new = 0` (all grandfathered) — the
  baseline comparison works; `FindingCard` shows the `new` badge from `finding.is_new`.
- **AI-code detection is removed from the findings UI.** No AI-generated badge,
  column, or filter; web types/api carry no `ai_generated` field. (The only "AI" in
  a finding is the opt-in *AI fix suggestion* and the *likely-FP* ML badge — both
  legitimate, current features.)

**⚠️ CONCERN (orphan AI-code text, not a data lie).** `PolicyCard.tsx` still
advertises an **"AI-code safety score"** merge gate ("*score + AI-safety floors*",
"*the AI-code safety score can each block a merge*"). The backend `PolicyConfig`
has **no** such field (only `max_severity`, `block_new_*`, `min_security_score`,
`min_quality_score`), so this is stale text describing a gate that no longer exists
after the Phase-2D AI-code removal. **Fix:** delete the two AI-safety mentions in
`PolicyCard.tsx` (and the enterprise template blurb). Reported, not fixed.

---

## Part 2 — Three pillars display clearly ✅ PASS

The scan detail page shows all three pillars as score cards + a tabbed findings
view, all from real backend fields:

- **Security** — score 0, with `13 issues · 6 secrets` subtitle; findings tab lists
  SAST/secrets, severity-sorted, with SoR where applicable.
- **Quality** — score 71, `125 issues`; findings carry the specific, actionable
  suggestions verified in Pass 3 (e.g. *"…takes N parameters (threshold 6). Consider
  grouping related arguments into an object."*), rendered in the finding detail.
- **Deployment** — score 100 (flask built cleanly → 0 build findings); a broken
  build would surface a CRITICAL `build-failed` with the compiler output.

Pillar scores + counts are visually clear (grade, color-coded score tiles) and match
the backend exactly (Part 1).

---

## Part 3 — Charts + visualizations ✅ PASS (real data only)

- **`TrendChart`** plots each completed scan's Overall/Security/Quality/Deployment
  scores straight from the API `scans` array (filters to completed, oldest→newest).
  The demo project's 3 scans render as real points; honest empty state ("No completed
  scans yet") when none.
- **Scan-history table** renders real per-scan grade + 4 scores + trigger + duration.
- **No mock / hardcoded / placeholder data anywhere.** A full sweep of `web/app`,
  `web/components`, `web/lib` found no fabricated datasets — every widget is fed by a
  `useQuery` → API call. (The only literal "sample" is an example rule YAML in the
  custom-rules editor, which is intended template text, not displayed data.)

---

## Part 4 — Reports + exports

| Export | Result |
|--------|--------|
| **Executive report** | ✅ real data (grade D, 5 top-risks w/ SoR, 3 priorities); "Save as PDF" = browser `window.print()` on a print-styled page (not a server-rendered `.pdf`). |
| **SARIF** | ✅ **valid 2.1.0**, tool `Aegis`, **138 results = 138 backend findings**, well-formed locations. (Minor: omits the optional `$schema` URL.) |
| **SBOM — CycloneDX** | ✅ **CycloneDX 1.7**, 34 components. |
| **SBOM — SPDX** | ✅ **SPDX-2.3**, `CC0-1.0`, 35 packages. |
| **Export RBAC / org-scoping** | ✅ another org exporting this scan's SARIF / SBOM / exec-report → **404** on all three. |

**⚠️ CONCERN — Compliance reports (the 6 frameworks).** The generator exists
(`services/scanner/compliance/report.py`) and **works from a repo checkout** — it
produced valid HTML for **all six** frameworks with real scores (SOC 2 67 %, PCI-DSS
56 %, HIPAA 67 %, ISO 27001 67 %, OWASP ASVS 62 %, NIST CSF 75 %). **But it is not
usable from the running product:**
1. **Not wired to the API or dashboard** — no endpoint, no button; a user cannot
   generate one from the UI.
2. **Crashes in the deployed scanner container** — `report.py` locates the framework
   YAMLs via `Path(__file__).parents[3]` (repo layout), which is out of range at
   `/app/compliance/report.py` → `IndexError`, and the `compliance/frameworks/*.yaml`
   files are **not shipped** into the scanner image (build context is
   `services/scanner/`, the frameworks live at repo-root `compliance/`).

**Fix (deferred — deep compliance-mapping accuracy is Pass 6):** ship the framework
YAMLs into the scanner image, make the path resolution container-safe, and add an
API endpoint + dashboard export button. Reported, not fixed.

---

## Part 5 — See the dashboard ✅

- **Web builds clean:** `tsc --noEmit` → 0 errors; the production image builds and the
  container runs healthy (Next.js `next start`), serving the real dashboard.

### ▶ Open the dashboard (works right now)

> **URL:** **http://127.0.0.1:8890**  (use `127.0.0.1`, **not** `localhost`)
> **Login:** `demo@aegis.local`  /  `AegisDemo!2026`

Then open the **"Flask (demo)"** project — it has **3 completed scans**:
- two `pallets/flask` scans (138 findings each) → drives the **score-trend chart** +
  scan-history table,
- one uploaded sample → a finding with **Steps-to-Reproduce** to click into.

**Key screens to look at:**
1. **Dashboard home** — projects + recent scans overview.
2. **Project page** (Flask demo) — score-trend chart, scan history, policy/memory cards.
3. **A scan's results** — 3 pillar score tiles + Security/Quality/Deployment finding tabs.
4. **A finding detail** — click any finding; open the SoR one to see source→sink→flow,
   "why exploitable", and the *Get AI fix suggestion* / triage actions.
5. **Executive report** — from a completed scan → "Executive report" → *Save as PDF*.
6. **Exports** — SARIF + SBOM (CycloneDX/SPDX) buttons on the scan page.
7. **Admin area** (`/admin/*`) — requires a super-admin account (the demo user is not
   one, so this correctly returns 403 — see Pass 4).

### Why `127.0.0.1:8890` and not `http://localhost`

`http://localhost` is the **designed** URL (nginx on port 80) and works on a healthy
Docker Desktop. In *this* session the Windows→container port-forwarding is faulted:
`localhost` resolves to IPv6 `::1`, where a stray `dllhost` is squatting ports 80/3000
and resetting HTTP, and the IPv4 bind for those ports is unhealthy (a side effect of
this session's repeated Docker Desktop restarts). To give a working view now, the web
was rebuilt against a clean IPv4 port and bridged through nginx via a small `socat`
proxy — hence **http://127.0.0.1:8890**. On a healthy Docker Desktop (or after a
Windows reboot / `wsl --shutdown` + Docker restart), plain **http://localhost** works
with no proxy.

### Known UI rough edges (honest)

- **Polished:** finding cards + detail (SoR, remediation, triage), score tiles, trend
  chart, scan history, exec report, SARIF/SBOM exports, dark/light theme.
- **Rough / basic:** the `PolicyCard` still shows the orphan AI-safety text (Part 1);
  compliance reports aren't reachable from the UI (Part 4); the exec-report "PDF" is a
  browser print (no server-side PDF styling polish); the admin panels are functional
  but plain tables.

---

## Summary

| # | Part | Verdict |
|---|------|---------|
| 1 | UI ↔ backend accuracy | ✅ PASS — all 138 findings + scores API=DB exactly; SoR matches code; 1 orphan-text CONCERN |
| 2 | Three pillars | ✅ PASS |
| 3 | Charts | ✅ PASS — real data only |
| 4 | Reports/exports | ✅ exec/SARIF/SBOM + RBAC · ⚠️ compliance not wired/deployed |
| 5 | View the UI | ✅ working URL provided + honest env note |

**The dashboard tells the truth about scan data** (exact, field-for-field). The two
concerns — orphan AI-code policy text and unwired compliance reports — are cosmetic /
feature-completeness, not data-accuracy lies, and are reported for a follow-up fix.
