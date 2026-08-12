# Fix-Rescan Intelligence — Verification (Part A)

**What this tests:** does Aegis track findings correctly across the fix cycle —
scan → fix → rescan → re-break — with no phantom findings and a correct
per-project baseline. Verified with real scans against a modifiable repo copy
(upload path, deterministic flat files), 2026-08-12.

## Method

A three-scan cycle on one project (`Fix-Rescan (Part A)`), three Python files:

| File | Vuln planted | Rules that fire |
|------|--------------|-----------------|
| `a.py` | SQL injection (`request.args` → `execute("…"+u)`) | `aegis-py-sql-injection` + registry |
| `b.py` | Command injection (`request.args` → `os.system("…"+h)`) | `aegis-py-command-injection` + registry |
| `c.py` | XSS (`request.args` → `render_template_string("…"+n)`) | `aegis-py-xss` + 3 registry — **never fixed** (control) |

- **Scan 1** — all three vulnerable.
- **Scan 2** — `a.py` and `b.py` **fixed** (parameterized query / `subprocess` list); `c.py` byte-identical.
- **Scan 3** — `a.py` **re-broken** (SQLi restored); `b.py` still fixed; `c.py` byte-identical.

## Results

| # | Check | Result | Evidence |
|---|-------|--------|----------|
| 1 | **Fix detection** | ✅ PASS | Scan 1 = 13 findings (a+b = 9, c = 4). Scan 2 = **4** — every finding in the two fixed files disappeared; the count dropped by exactly the 9 findings that were fixed. |
| 2 | **No phantom findings** | ✅ PASS | `c.py` (unchanged) produced the **identical** 4 rule IDs in every scan (`aegis-py-xss` + 3 registry). No new finding ever appeared in code that didn't change — consistent with Pass-1 determinism. |
| 3 | **Persistence** | ✅ PASS | The unfixed `c.py` XSS is present in all three scans — an unfixed finding never silently vanished. |
| 4 | **Re-introduction (detection)** | ✅ PASS | Re-breaking `a.py` in Scan 3 re-detected the SQLi (5 findings back on `a.py`). A fixed-then-reintroduced vuln is caught on the next scan. |
| 5 | **Baseline / new-existing-resolved state** | ⚠️ PARTIAL — see below | `is_new` was `false` on every finding in all three scans, including Scan 3's re-introduced vuln. |

Checks 1–4 — the core fix-rescan mechanics — **pass cleanly**. Fixed code stops
producing findings, unchanged code is stable, and re-introduced bugs come back.

## Check 5 — baseline granularity (the honest gap)

Aegis's per-project baseline is **rule-level, not finding-instance-level**
([`orchestrator/internal/store/baseline.go`](services/orchestrator/internal/store/baseline.go)).
The first completed scan grandfathers every rule it saw; on later scans a finding
is flagged `is_new` **only when its `rule_id` was never seen in the project
before**. There is no per-instance fingerprint (file + line + rule + snippet hash)
and no stored record of resolved findings.

Consequences, all observed:

- **Resolved state is not tracked.** A fixed finding simply stops appearing — there
  is no "resolved" record, no resolved count, and no fixed-on-scan-N history. Fix
  *detection* works (check 1); fix *state* is not surfaced.
- **Re-introduced / genuinely-new instances of an already-seen rule are not flagged
  `is_new`.** Scan 3's restored SQLi is `is_new = false` because `aegis-py-sql-injection`
  was already grandfathered in Scan 1. A brand-new SQLi a developer adds in new code
  is likewise not "new" if that rule ever fired before — which weakens the
  `block_new_findings` PR gate ([`services/policy.go`](services/api/internal/services/policy.go)).
- **No "reopened" concept.**

This is a deliberate noise-reduction design (grandfather a rule so the PR gate isn't
swamped), and it is not *broken* — it does exactly what it documents. But it is
**coarser than the market leaders'** finding-state model. Snyk, SonarQube ("New
Code"), and Checkmarx all track per-issue state via a stable fingerprint:
**New / Existing / Fixed(Resolved) / Reopened**, and show it per finding.

### Recommendation (logged, not built — out of audit scope)

Add a stable per-finding fingerprint and an instance-level state table so Aegis can
report New / Existing / Resolved / Reopened per finding and per scan. This is a
subsystem (schema + migration + diff + API + UI), not a precision-safe one-line
hardening, so it is **logged as the top fix-rescan priority** rather than built in
this audit. Tracked in `COMPETITIVE_AUDIT.md` (P1). Until then, the honest
statement is: **Aegis detects fixes and re-introductions correctly, but does not
yet label per-finding lifecycle state.**

## Bottom line

Detection across the fix cycle is **correct and stable** (checks 1–4). The gap is
**presentation of finding lifecycle state** (check 5) — logged as P1, feeds both a
backend state-tracking build and the UI pass.
