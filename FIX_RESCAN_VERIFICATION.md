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
| 5 | **Instance-level lifecycle: new / existing / resolved / reopened** | ✅ PASS (built — P1a) | See below. Every finding now carries `fingerprint` + `lifecycle_status`; resolved findings are tracked with the scan that resolved them. |

Checks 1–5 — the full fix-rescan lifecycle — **pass cleanly**.

## Check 5 — instance-level lifecycle (built in P1a, 2026-08-12)

The old baseline was **rule-level**: a finding was `is_new` only when its `rule_id`
had never fired in the project, so resolved state wasn't tracked and a new instance
of an already-seen rule wasn't flagged. That is now replaced by an **instance-level
lifecycle** keyed on a stable, deterministic, line-shift-resilient fingerprint
(scanner [`utils/snippet.py`](services/scanner/utils/snippet.py): `sha256(rule + file
+ normalized flagged code + per-basis ordinal)` — never the raw line number). The
orchestrator ([`store/lifecycle.go`](services/orchestrator/internal/store/lifecycle.go))
diffs each scan against `project_finding_states` and classifies every finding.

**Verified on the extended Part-A cycle** (scan → fix → rescan → re-break → add a
brand-new vuln), real code, upload path:

| Event | Expected | Observed |
|-------|----------|----------|
| Scan 1 (baseline: a.py SQLi, b.py cmd-inj, c.py XSS) | all grandfathered `existing`, `is_new=false` | ✅ e.g. a.py `aegis-py-sql-injection` → `existing`, is_new=false |
| Scan 2 (fix a.py + b.py; c.py unchanged) | a.py + b.py **resolved** (record the resolving scan); c.py `existing` | ✅ b.py's 4 findings → `resolved`, `resolved_scan_id` = scan 2; c.py `existing` |
| Scan 3 (re-break a.py) | a.py SQLi **reopened**, `is_new=true` | ✅ a.py → `reopened`, is_new=true |
| Scan 4 (add **new** file d.py with SQLi) | d.py SQLi **new**, `is_new=true` — *even though `aegis-py-sql-injection` fired before* | ✅ d.py → `new`, is_new=true |
| c.py fingerprint across all 4 scans | byte-identical (determinism) | ✅ stable = `b886e677…` |
| Same repo scanned 3× | identical fingerprint set (determinism) | ✅ 9/9 fingerprints byte-stable across 3 runs, no nulls |
| Finding moved down N lines (code inserted above) | same fingerprint | ✅ unit-verified: shifted down 2 lines → identical fingerprint |

**The `block_new_findings` PR-gate weakness is fixed:** the gate keys on `is_new`
([`services/policy.go`](services/api/internal/services/policy.go)), which is now
instance-level — a genuinely new finding in new code is flagged `is_new=true` even
when its rule fired before, so the gate blocks it.

**Surfaced in the API:** every finding carries `fingerprint`, `lifecycle_status`
(new/existing/reopened), and `is_new`. Resolved findings — absent from the current
scan — are exposed via `GET /api/v1/projects/{id}/lifecycle`, which returns
per-status counts and each resolved finding with its `resolved_scan_id`. Verified:
`{existing: 9, new: 5, resolved: 4}` with the 4 resolved findings correctly
attributed to the fixing scan.

This matches the finding-state model of Snyk, SonarQube ("New Code"), and Checkmarx.

## Bottom line

Detection **and** lifecycle presentation across the fix cycle are **correct and
stable** (checks 1–5). The former P1 gap is closed: Aegis now tracks
New / Existing / Resolved / Reopened per finding via a deterministic fingerprint,
records which scan resolved each fixed finding, and gates PRs on genuinely-new
findings. Remaining work is UI presentation of the new lifecycle data (UI pass).
