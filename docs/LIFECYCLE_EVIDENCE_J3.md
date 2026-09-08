# Pass J3 — lifecycle as compliance evidence, churn resilience, freshness, flow

**HEAD:** `e3891ae` + this change · **Run date:** 2026-09-08
**Evidence base:** the real stack (api, orchestrator, scanner, web, postgres, redis, nginx) with
freshly built images; two live scans of `OWASP/NodeGoat`; 136 scans / 14,041 findings in the
database; the real fingerprint code path.

**Framing (from Om, who has worked in compliance):** auditors do not verify every guideline in a
standard. What they consume is **open vs closed** — this vulnerability appeared, it was remediated,
and a later scan proves it closed. Our compliance value is the finding **lifecycle**, not
control-mapping breadth.

**Headline: measured against that framing, the compliance report was a point-in-time snapshot with
no remediation history at all.** Every element existed in the database and none of it reached the
report. Fixed. Separately, two churn conditions break the fingerprint, and one of them produces a
**factually wrong audit claim** — stated plainly in §3.

---

## 1. Part A — did compliance use lifecycle state?

Traced `compliance/report.py` and the API path that feeds it
(`services/api/internal/services/report.go`). The payload carried ten fields:
`rule_id, severity, title, cwe_id, owasp_category, file_path, engine, pillar, is_false_positive,
is_suppressed`. No fingerprint, no lifecycle status, no timestamps.

| question | answer before J3 |
|---|---|
| **1. Does the report distinguish OPEN from RESOLVED?** | **No.** `_is_open()` checked only `is_false_positive` / `is_suppressed`. The report had no concept of resolution at all. |
| **2. If a vulnerability was fixed three scans ago, does its control still read failing today?** | **No — but by accident, not design.** A resolved finding is absent from `findings WHERE scan_id = X`, so it cannot fail a control. Correct outcome, arrived at by omission. |
| **3. Does the report show WHEN a finding opened and closed?** | **No.** No timestamps in the payload, and no remediation section in the report. |

Confirmed empirically, not just by reading: a project with 4 resolved command-injection findings
(each with `resolved_scan_id`, `first_seen_at`, `times_seen`) returns **0 matching rows** in the
latest scan's findings. The evidence existed; nothing connected it to the report.

**Q1 is "no", so this was the P0 and it was fixed in this pass.**

### What changed

- `RemediationEvidenceFor()` (new) reads the project's resolved findings from
  `project_finding_states`. That table has no `cwe_id`/`owasp_category`, so those are recovered by
  joining back to the finding row from the last scan that saw it — the authoritative record of what
  the finding was. Verified: CWE-78 and opened/closed dates recovered for all four.
- The API passes them as `remediated`, plus `lifecycle_status` and `fingerprint` on open findings.
- `map_findings()` attributes remediated findings **by the same precedence rule** as open ones, into
  a separate bucket. A control's status is driven by **open findings only** — a fixed weakness is
  evidence *for* the control, never against it.
- The report renders **"Remediation evidence — vulnerabilities proven closed"**: control, finding,
  location, first seen, confirmed fixed, and the scan id that proved it.
- The disclaimer now states the rule: *"A control's status reflects OPEN findings only: a
  vulnerability that was found and later proven fixed appears under Remediation evidence and never
  counts against the control."*

Verified against the four real resolved findings: CC6.6 renders **4 closed alongside 1 open**, and
its status stays `needs-attention` because of the open one — not because of the four fixed ones.

**Honest states preserved.** If the lifecycle store cannot be read, the report says *"Remediation
history unavailable … not because nothing was fixed"* rather than rendering an empty section, which
would assert a different and false claim.

---

## 2. Part B — lifecycle under realistic conditions

### 2.1 Long run: six sequential scans (B1) and reopened (B4)

Run against the real `project_finding_states` table using the literal SQL from
`orchestrator/internal/store/lifecycle.go`, inside a transaction that rolls back.

Scenario — **A** present throughout; **B** fixed at scan 3; **C** appears at 2, fixed at 4,
reintroduced at 6; **D** appears at 5.

| fingerprint | final status | times_seen | first seen | last seen | resolved at |
|---|---|--:|--:|--:|--:|
| A | existing | 6 | 1 | 6 | — |
| **B** | **resolved** | 2 | 1 | 2 | **scan 3** |
| **C** | **reopened** | 3 | **2** | 6 | — |
| D | existing | 2 | 5 | 6 | — |

- **B1 passes.** B was fixed at scan 3 and still reads `resolved` after scans 4, 5 and 6. It does
  not silently reappear as New. This holds by construction: the resolve statement only touches rows
  whose status is `new`/`existing`/`reopened`, so a resolved row is never re-evaluated.
- **B4 passes.** C reads `reopened`, not `new` — and `first_seen` correctly stays at scan 2, so the
  original sighting is preserved rather than reset by the regression.

### 2.2 Determinism across time (B5) — measured live

Two independent scans of the same commit of `OWASP/NodeGoat`, ~20 minutes apart, through the real
API, with live feeds between them:

| | scan 1 | scan 2 | identical | only in 1 | only in 2 |
|---|--:|--:|--:|--:|--:|
| fingerprints | 200 | 200 | **200** | **0** | **0** |

All 200 read `existing` on the second scan; nothing was reported New, and nothing was falsely
resolved. **No drift.** This is the property compliance depends on: a repeated scan of unchanged
code must not manufacture churn an auditor would read as regression-and-fix.

### 2.3 Churn resilience (B2) — which operations break the fingerprint

Measured by calling the real `utils.snippet.attach()` over a real file before and after each
operation. The basis is `rule_id + file_path + (cve_id) + normalized_flagged_code`, where
normalization is `re.sub(r"\s+", " ", line).strip()`.

| operation | fingerprint |
|---|---|
| Add 200 lines above the finding | **survives** |
| Reformat surrounding code (docstrings, blank lines) | **survives** |
| Rename the enclosing function | **survives** |
| Re-indent the flagged line (4→8 spaces, or tabs) | **survives** |
| Collapse a double space *inside* the flagged line | **survives** |
| Trailing whitespace | **survives** |
| **Change token spacing inside the flagged line** (`f(` → `f( `, or removing spaces around `+`) | **BREAKS** |
| **Move the file to a new path** | **BREAKS** |
| **Rename the file** | **BREAKS** |
| Change the flagged code itself | breaks — *correct, it is a different finding* |

**File moves break every finding in the file — confirmed, as expected.** `file_path` is in the
basis, so moving `app/tasks.py` to `app/jobs/tasks.py` resolves every finding in it and opens an
identical set as New. **To an auditor that reads as a wave of regressions and a wave of fixes on the
same day, and neither happened.** A refactor that reorganises directories will produce exactly this.

**The reformatter nuance is narrower than "prettier breaks it".** Whitespace *runs* are collapsed,
so re-indentation is safe. What breaks it is a formatter changing *token* spacing on the flagged
line itself — `black` removing spaces around an operator, `gofmt` realigning. That happens on the
first run over unformatted code and is idempotent thereafter, so it is a one-off event per file
rather than continuous churn.

### 2.4 Duplicate code in one file (B3) — an identity swap that produces a wrong claim

Two identical vulnerable lines in one file get distinct fingerprints via a per-basis ordinal. Fix
the **first** one, and:

```
before:   line 5 -> a243400442cd02d5      line 9 -> a6d5e45d2646a71c
after fixing line 5, the surviving finding (line 9) has fingerprint a243400442cd02d5
    equals the original SECOND (correct)     : False
    equals the original FIRST (identity swap): True
```

The survivor inherits the fixed one's identity. The lifecycle therefore records **the line-9 finding
as resolved and the line-5 finding as still open — the exact inverse of the truth.**

The counts stay right (1 open, 1 closed), so a summary number is unaffected. What is wrong is the
**identity**: the remediation evidence names the wrong instance, and the still-open finding is
reported at a location that has been fixed. In an audit document that is a false statement about a
specific vulnerability, which is worse than a missing one.

**Not fixed in this pass** — the ordinal is the only thing distinguishing byte-identical findings in
one file, and removing the ambiguity needs a positional component in the basis, which would
re-introduce line-shift fragility. It is recorded here as a known defect with a concrete shape, and
it only bites when two byte-identical matches of the same rule exist in one file and one is fixed.

---

## 3. Part C — the audit trail

For a finding an auditor asks about, this query produces the trail (run against a real resolved
finding):

| element | available | source |
|---|:--:|---|
| First-seen scan and timestamp | ✅ | `first_seen_scan_id`, `first_seen_at` |
| Resolved-in scan and timestamp | ✅ | `resolved_scan_id`, `updated_at` |
| Scan history between | ✅ | reconstructable — `findings` joined to `scans` by fingerprint (`times_seen`, `scans_present_in`) |
| The rule that found it | ✅ | `rule_id` |
| `rule_pack_version` at each point | ✅ | `scans.rule_pack_version`, populated on **108 of 136** scans (the 28 blanks predate G2) |
| **The commit it was fixed in** | ❌ | **gap — see below** |

Real example:

```
fingerprint            | 2ce965e528cf058b12429dbf2e51c2fb
rule_id                | php.lang.security.injection.tainted-sql-string
first_seen_at          | 2026-09-03 03:24:07+00
rulepack_at_first_seen | rp-20260903-4711a0756e
resolved_at            | 2026-09-03 03:26:10+00
rulepack_at_resolution | rp-20260903-4711a0756e
times_seen             | 4        scans_present_in | 4
```

### Two gaps, named

1. **`commit_sha` is populated on 3 of 136 scans (2%).** It is stored only when the API caller
   supplies it; the orchestrator clones a specific commit and **never writes back which one** —
   `adapters.Checkout` carries `Dir` and `Cleanup` and no resolved revision. So "which commit fixed
   this" — the natural auditor question — is unanswerable for 98% of scans, and the SARIF
   `versionControlProvenance.revisionId` is empty for the same reason. The fix is bounded (resolve
   `HEAD` after clone, carry it on `Checkout`, persist on the scan row) but it changes the clone
   path, so it is named here rather than done in a pass already spanning five parts.
2. **Reopening erases the prior closure.** The upsert sets `resolved_scan_id = NULL` when a finding
   comes back, and `project_finding_states` holds only current state, not an event log. A finding
   that went open → closed → reopened cannot answer "when was it first fixed". The row above shows
   this: `C` reopened and its earlier resolution is gone. An append-only event table would fix it.

---

## 4. Part D — engine and feed freshness

Actual installed versions and real refresh timestamps, read from the running scanner.

| component | ours | latest upstream | assessment |
|---|---|---|---|
| **semgrep** | **1.97.0** | **1.176.1** | **materially behind** — ~79 minor releases |
| **gitleaks** | **8.21.2** | **8.30.1** (2026-03-21) | **behind** — 9 minor releases |
| **ruff** | **0.8.6** | **0.16.6** | **behind** — 8 minor releases |
| trivy | 0.71.2 | 0.74.0 (2026-08-14) | 3 minor behind — closest to current |

| feed | last refresh | mechanism |
|---|---|---|
| Trivy vulnerability DB | **2026-09-08 07:08 UTC** (downloaded 13:35 UTC) | automatic, next update 2026-09-09 — **current** |
| Trivy check bundle | 2026-09-07 18:55 UTC | automatic — current |
| CISA KEV | rides on the Trivy DB | inherits the above — current |
| EPSS | on demand, 24 h in-process cache | fetched from FIRST per scan; cache is memory-only and resets on restart |
| Vendored Semgrep packs (G2) | **pinned 2026-09-07** | current, but see below |
| Gitleaks rules | `useDefault = true` + 2 custom rules | **inherits the binary's built-in ruleset**, so rule freshness = binary freshness (8.21.2) |

**Two things to flag:**

- **Semgrep at 1.97.0 against 1.176.1 is the material gap.** That is the engine behind most of our
  SAST output. Upgrading is not free — G2 pinned 2,791 vendored rules against this version, and the
  0-FP gates in T2/T3/G1/H1/H2 were all measured on it — but the distance is large enough that it
  should be a planned pass, not a drift.
- **The monthly vendored-pack refresh is documented but not scheduled.** `manifest.yaml` says
  `refresh_cadence: monthly, reviewed`, and `scripts/vendor_rules.py --refresh` exists — but
  `self-scan.yml` is the only workflow and it has **no `schedule:` trigger** (push, pull_request,
  workflow_dispatch only). Nothing runs monthly. Today's pins are fresh because G2 ran yesterday, not
  because a schedule maintains them.

The gitleaks position is better than "the rules are manually maintained": our config sets
`useDefault = true` and adds two rules, so we inherit whatever ruleset the pinned binary ships.
There is no separately-drifting rule list — but upgrading the binary is how rules get updated.

---

## 5. Part E — full flow and UI/backend parity

Run against the real stack with freshly built `api` and `orchestrator` images.

| step | result |
|---|---|
| Register + authenticate | ✅ new org created |
| **Tenant isolation** | ✅ the fresh org sees **0 projects** — the other 136 scans / 14,041 findings are invisible |
| Connect repo (`OWASP/NodeGoat`) | ✅ project created |
| Scan | ✅ completed — 153 security + 47 quality = **200 findings**, grade F |
| View findings | ✅ **API 200 = DB 200**, all 200 carry a fingerprint and `lifecycle_status` |
| Rescan (same commit) | ✅ **200/200 identical fingerprints, 0 drift**, all `existing` |
| Export SARIF | ✅ 2.1.0, **200 results** — matches the finding count exactly |
| Export SBOM | ✅ CycloneDX 1.7, 381 components |
| Compliance report | ✅ SOC 2 and PCI DSS generated |

**Parity: exact at every measured point** — findings 200 = 200, SARIF results 200 = 200.

### The J1/J2/J3 work is live end-to-end, verified through the API

- SBOM `metadata.component.name` = `https://github.com/OWASP/NodeGoat` — the repository, **not an
  internal path** (the J1 leak fix).
- SBOM `metadata.authors` = `[{name: Aegis}]` — the NTIA element-6 fix.
- Compliance response carries `controls_assessed: 7`, `controls_not_assessed: 2` alongside
  `score_pct: 14`.
- The report HTML carries the scope banner; **PCI prints "SUPPORTING EVIDENCE ONLY" and SOC 2 does
  not** — the headline/supporting distinction reaches the artifact.
- The remediation section and the "OPEN findings only" disclaimer are present.

### A parity defect found by running the flow, and fixed

`findings_remediated` came back **`null`**: the scanner computed it, but the Go `ComplianceReport`
struct had no field for it, so it was dropped in transit. Added, rebuilt, re-verified — now returns
a real value. This is precisely the class this part exists to catch, and reading the code would not
have found it.

### UI honest-state audit (the P4a re-run)

The compliance report is rendered in the UI as an `<iframe srcDoc={result.html}>`, so **everything
J1, J2 and J3 added to the report HTML — scope banner, not-assessed rows, remediation evidence —
appears in the UI automatically.**

The summary line *above* the iframe did not. It read *"Compliance score: X% (N of M **in-scope**
controls need attention)"* while the score is computed over **assessed** controls — a denominator
mismatch introduced by J1's own change. **Fixed**: it now reads *"X% of assessed controls have no
findings (N of 7 assessed controls need attention; 2 not assessed and excluded from this figure)"*,
and shows the remediated count when there is one.

| honest state | surfaced? |
|---|---|
| `excluded_bundled` (T2) | ✅ in the UI |
| `filtered_secrets` | ✅ in the UI |
| `degraded` engines | ✅ in the UI (5 files) |
| "not measured" | ✅ in the UI (5 files) |
| `controls_not_assessed` (J1) | ✅ **now** in the UI summary — was backend-only |
| `findings_remediated` (J3) | ✅ **now** in the UI summary |
| SARIF `truncated` | ✅ — surfaced as a SARIF **notification inside the export**, not in the web UI. That is the right place: the artifact declares its own incompleteness to whoever receives it. Not triggered here (200 findings, cap is far higher) |

### What was not done through a browser

The walkthrough was driven through the **HTTP API on the real stack**, not by clicking the web UI.
Host→container port forwarding was not usable in this environment (requests to `localhost:8080`
timed out despite healthy containers), and the Playwright browsers were removed during the earlier
disk reclamation. The web layer was verified by reading the components that render each field and by
type-checking the app. **A human click-through of the browser UI has not been performed in this
pass** — stated rather than implied.

---

## Gate

| requirement | status |
|---|---|
| Part A answered explicitly; fixed if lifecycle unused | ✅ §1 — all three answered "no"; P0 fixed, verified against real resolved findings |
| Churn-resilience table | ✅ §2.3 — file move/rename and intra-line token spacing break it; everything else survives |
| Long-run lifecycle result | ✅ §2.1 — 6 scans; resolved-at-3 still resolved at 6; reopened ≠ new |
| Audit-trail element list with gaps | ✅ §3 — 5 of 6 elements available; `commit_sha` (2% populated) and erased reopen-history named |
| Engine/feed freshness with actual timestamps | ✅ §4 — semgrep 79 minors behind; monthly pack refresh documented but **not scheduled** |
| Full-flow walkthrough + parity | ✅ §5 — exact parity; one parity defect found and fixed; browser click-through not done, stated |
| Full suite + `go build ./...` + web typecheck | ✅ **247 passed, 0 failed, 4 skipped** (was 235; +12 lifecycle-evidence tests); both Go services build clean; `tsc --noEmit` clean |
