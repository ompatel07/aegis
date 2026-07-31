# Data Architecture — Isolation, RBAC, Memory, Concurrency, ML Feeding

**Phase 2F pre-launch hardening, Pass 4 of 6.** Verifies the data layer: cross-
tenant isolation (the #1 multi-tenant-SaaS risk), role-based access control,
per-project/per-user memory, concurrent-scan safety, and the ML learning feed.

Every result below is a **live run** against the running stack (two real orgs
with separate users/projects/scans), plus a static audit of the SQL query layer.

---

## Headline verdict

> ## Cross-tenant isolation: **CONFIRMED** ✅
> Across ~32 direct cross-org attempts on every data type (projects, scans,
> findings, reports, exec/SBOM/SARIF, integrations, policy, members, settings,
> baselines) — **zero** returned another org's data. Every attempt was denied
> (404/403) or returned empty; no mutation of Org A's data by Org B ever
> succeeded; uploaded/cloned code never crossed orgs.

| Part | Verdict |
|------|---------|
| 1 — Cross-tenant data isolation | ✅ **PASS (CONFIRMED)** |
| 2 — RBAC enforcement | ⚠️ **CONCERN** — org-level + super-admin solid; project/scan **write** actions don't enforce the read-only *viewer* boundary |
| 3 — Per-project + per-user memory | ✅ **PASS** |
| 4 — Concurrent scan safety | ✅ **PASS** |
| 5 — ML learning-layer feeding | ✅ **PASS** (privacy invariant holds; retrain is manual) |

**One concern to fix (Part 2), no cross-tenant leaks.**

---

## Part 1 — Cross-tenant data isolation ✅ CONFIRMED

**Setup.** Registered two users → two orgs (A, B), each auto-getting a personal
org (owner). Org A: a project + a completed scan (9 findings, via upload) + a
policy + an integration. As **User B**, attempted every one of Org A's resources
by ID.

**The isolation mechanism (SQL layer, the Phase-2C fix — audited).** Every
tenant-scoped repository query filters by org membership:

```sql
... WHERE ... organization_id IN (SELECT org_id FROM organization_members WHERE user_id = $N)
```

The service layer **authorizes the top-level resource first** (`projects.GetByIDForUser`
/ `scans.GetByIDForUser`), then runs sub-queries by the pre-validated id. Audited
across `project.go`, `scan.go`, `finding.go`, `github_integration.go`, `policy.go`
(service-gated), `project_memory.go`, `report.go`, `notify.go` — the pattern is
consistent and complete.

**Live IDOR matrix — every attempt DENIED (never Org A's data):**

| Resource (as User B, on Org A's id) | Result |
|-------------------------------------|--------|
| read / update / delete project | 404 |
| list scans · trigger scan · upload scan | 404 / 400 |
| rules · baseline/memory · slack settings | 404 |
| read scan · findings · report · exec report · SARIF · SBOM · policy-eval | 404 |
| PATCH finding triage · finding feedback · suggest-fix | 400 / 404 — **Org A's finding unchanged** |
| read/update org · members · invitations · set-role · remove-member | 404 |
| project list / org list | **do not include Org A's resources** |
| **positive control** (B reads own project) | 200 ✓ |

**Mutation attempts confirmed harmless:** B set no data on A — A's policy remained
`A-SECRET-POLICY` after B's overwrite attempt (404); A's finding
`is_false_positive` stayed `False` after B's triage/feedback attempts.

**Uploaded/cloned code isolation.** Each scan clones/extracts into a per-scan
sandbox `/workspaces/<scanID>` (unique id), removed on completion; the upload
staging dir held **0** archives post-scan. No API serves raw workspace files, so
even a leftover dir (only one, from a Pass-2 SIGKILL'd scan) is unreachable
cross-org.

**Minor cosmetic note (not a leak):** `GET /projects/{id}/integrations` and
`/policy` return `200` with **empty/null** for a non-member's project id instead
of `404` like every other endpoint. Verified this exposes **no data and no
existence oracle** (a random/nonexistent project id returns the identical empty
response). Cosmetic 200-vs-404 inconsistency only.

---

## Part 2 — RBAC enforcement ⚠️ CONCERN

Roles: `owner > admin > member > viewer` (`RoleAtLeast`); non-members get 404 (no
existence leak). Tested every role via **direct API** (not UI).

**Org-level RBAC — correctly enforced (`requireRole`):**

| Action | viewer | member | admin | Correct? |
|--------|:------:|:------:|:-----:|:--------:|
| read project / members | ✅ | ✅ | ✅ | ✓ |
| delete project | ❌ 404 | ✅ | ✅ | ✓ |
| invite member | ❌ 403 | ❌ 403 | ✅ | ✓ |
| change org settings | ❌ 403 | ❌ 403 | ✅ | ✓ |
| set member role | ❌ 403 | ❌ 403 | ✅ | ✓ |

**Super-admin panel + impersonation — solid.** `/admin/*` is gated by
`RequireSuperAdmin(adminRepo.IsSuperAdmin)`, a **DB check**
(`is_super_admin AND suspended_at IS NULL`), not a JWT claim — a normal user hits
403 on every `/admin/*` route (live-verified). Every admin mutation writes
`admin_audit_log`; impersonation issues a **1-hour-capped** token and is audited.

**The concern — project/scan write actions enforce membership, not role:**

| Action | viewer | should be | Result |
|--------|:------:|:---------:|--------|
| **trigger scan** | ✅ 202 | denied | ❌ **VIOLATION** |
| **update project** | ✅ 200 | denied | ❌ **VIOLATION** |
| **create rule** | ✅ 201 | denied | ❌ **VIOLATION** |

A **viewer** (deliberately read-only) can trigger scans, edit project settings,
and create custom rules. Root cause: `Trigger`, project `Update`, rule `Create`,
integration `Connect`, and upload gate on `projects.GetByIDForUser` (org
*membership*, any role) but **not** a minimum role. The intended pattern **does**
exist — project `Delete`'s query restricts to `role IN ('owner','admin','member')`
(so viewers can't delete) — it just wasn't applied to the other write paths.

- **Severity:** medium. **Not** a cross-tenant leak (confined to the actor's own
  org), but it breaks the least-privilege promise ("viewer = read-only").
- **Fix (precision-safe):** require `≥ member` on the write paths — either add the
  `role IN ('owner','admin','member')` filter to `GetByIDForUser`'s write callers
  or a `requireRole(member)` guard in `Trigger`/`Update`/rule/integration/upload.
- **Reported, not fixed** (per the "report before fixing" rule).

---

## Part 3 — Per-project + per-user memory ✅ PASS

- **Per-project baselines/memory** are keyed by `project_id`:
  `project_baselines` (PK project_id), `project_baseline_findings`,
  `project_rule_stats` — each project's history/grandfathering/trend is its own.
- **Per-project scan history** — scans key on `project_id`; `ListByProject`
  filters by it; Part 1 confirmed no cross-project bleed.
- **Two orgs, same repo → independent** — all state keys on `project_id` /
  `scan_id`, **never `repo_url`**. Org A and Org B each own a separate project for
  the same URL, hence separate scans/findings/baselines (no shared state).
- **Deletion cascade — live-verified.** Created project Z (1 scan, 4 findings, 1
  baseline), deleted it → **scans 0, findings 0, baseline 0, policy_eval 0, sbom
  0**; project A (6 scans, 9 findings) **untouched**. Every project-scoped table is
  `ON DELETE CASCADE` (scans→findings→sbom/policy/vcs, rules, integrations,
  memory, notifications).

---

## Part 4 — Concurrent scan safety ✅ PASS

Fired **4 scans simultaneously** — 2 in Org A, 2 in Org B — each uploading a
uniquely-named marker file (`marker_A1`…`marker_B2`).

| Scan | status | findings | findings referencing a **foreign** marker |
|------|--------|:--------:|:-----------------------------------------:|
| marker_A1 / A2 / B1 / B2 | completed | 4 each | **0 each** |

- **No result mixing** — every scan's findings reference only its own file; **0**
  cross-contamination across the 4 concurrent scans spanning both orgs.
- **Correct association** — each scan's findings landed on the right scan/project
  record.
- **Sandboxes don't collide** — per-scan `/workspaces/<scanID>` dirs; concurrent
  clones stay isolated (clean results prove it).
- **Asynq correctness** — each job processed **exactly once** (4 findings each, no
  doubling, none lost); worker concurrency 5.

---

## Part 5 — ML learning-layer feeding ✅ PASS

- **Feedback capture** — `POST /findings/{id}/feedback` writes `finding_feedback`
  (org-scoped) **and** upserts `project_rule_stats` (per-project). Verified rows
  captured.
- **Privacy invariant — NO source code (audited, the critical check).**
  `ml/features.py` produces a **13-feature metadata-only vector**: severity
  ordinal, file-path **depth**, LOC **count**, test/generated-path booleans,
  is-direct boolean, and bucketed md5 hashes of rule_id/engine/extension/language/
  CWE/OWASP. `ml/train.py` consumes only `featurize(row)` + label. **Not one
  feature is derived from code** — and `record_from_finding` doesn't even persist
  the raw file *path* (only its extension + depth). No snippets, no identifiers.
- **Per-team isolation — verified.** Marking Org A's `aegis-py-sql-injection`
  findings as FP moved **Org A's** `project_rule_stats` fp_rate `None → 1.0`, while
  a control rule confirmed-TP stayed `0`. **Org B's project team-learning remained
  empty** — Org A's feedback never touched Org B's predictions. The global model
  is metadata-only and shared; the per-team learning (`project_rule_stats`) is
  strictly per-project/org-scoped.
- **P(fp) shift works, control stable** — target rule fp_rate rose on FP feedback;
  control rule stayed low on confirmed-TP feedback.
- **Retrain status: MANUAL** — training is a CLI (`python -m ml.train --data
  feedback.jsonl`); there is no auto-export or scheduled retrain. Unchanged from
  Track 2e.6. (The startup path only trains the seed model if none exists.)

---

## Summary

| # | Part | Verdict | Note |
|---|------|---------|------|
| 1 | Cross-tenant isolation | ✅ CONFIRMED | 0 leaks / ~32 attempts; SQL org-scoping consistent |
| 2 | RBAC | ⚠️ CONCERN | viewer can trigger scans / update projects / create rules (membership checked, not role) — reported, not fixed |
| 3 | Memory | ✅ PASS | per-project baselines; deletion cascade clean |
| 4 | Concurrency | ✅ PASS | 0 contamination; Asynq once-only |
| 5 | ML feeding | ✅ PASS | metadata-only (no code); per-team isolated; retrain manual |

**The most serious class of bug — cross-tenant data leakage — is CONFIRMED absent.**
The one open item is a within-org least-privilege gap (viewer write access) that
is fixable precision-safely and does not cross tenant boundaries.
