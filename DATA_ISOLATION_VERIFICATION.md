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
| 2 — RBAC enforcement | ✅ **PASS** — viewer-write gap **found and fixed this pass** (backend-enforced) |
| 3 — Per-project + per-user memory | ✅ **PASS** |
| 4 — Concurrent scan safety | ✅ **PASS** |
| 5 — ML learning-layer feeding | ✅ **PASS** (privacy invariant holds; retrain is manual) |

**All five parts pass. No cross-tenant leaks; the one RBAC concern found was fixed
and re-verified (viewer is now read-only, isolation intact).**

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

## Part 2 — RBAC enforcement ✅ PASS (gap found + fixed this pass)

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

### The gap that was found (before)

A **viewer** (deliberately read-only) could trigger scans, edit project settings,
and create custom rules. Root cause: `Trigger`, project `Update`, rule `Create`,
integration `Connect`, upload, and the project-scoped policy/slack/finding-triage
writes gated on `projects.GetByIDForUser` (org *membership*, any role) but **not**
a minimum role. (Project `Delete` already restricted to
`role IN ('owner','admin','member')` — the intended pattern, just not applied
everywhere.)

| Action | viewer (before) | should be |
|--------|:---------------:|:---------:|
| trigger scan / update project / create rule | ✅ allowed | denied |

### The fix

Added a role lookup per resource — `RoleInProjectOrg` / `RoleInFindingOrg` /
`RoleInRuleOrg` / `RoleInIntegrationOrg` (each returns the caller's role in the
resource's org, or `ErrNotFound` for a non-member) — and a shared
`ensureWriteRole(role, err)` guard (`services/authz.go`) applied to **every**
state-changing project/scan path: scan **Trigger** + **upload**, project
**Update** + **Delete**, rule **Create** + **Delete**, integration **Connect** +
**Delete**, **policy Set**, **slack Set**, finding **triage** + **feedback**.
`ensureWriteRole` returns `ErrForbidden` (403) for a member below `member` (a
viewer) and passes `ErrNotFound` (404) through unchanged — so **cross-tenant
isolation is untouched** (a non-member still can't tell a foreign resource from a
missing one).

### The fixed matrix (backend-enforced, verified via direct API per role)

| Action | viewer | member | admin |
|--------|:------:|:------:|:-----:|
| read project | ✅ 200 | ✅ 200 | ✅ 200 |
| trigger scan | ❌ **403** | ✅ 202 | ✅ 202 |
| update project | ❌ **403** | ✅ 200 | ✅ 200 |
| create rule / delete rule | ❌ **403** | ✅ | ✅ |
| delete project | ❌ **403** | ✅ 200 | ✅ 200 |
| connect integration | ❌ **403** | ✅ 201 | ✅ 201 |
| set policy / set slack | ❌ **403** | ✅ 200 | ✅ 200 |
| finding triage / feedback | ❌ **403** | ✅ | ✅ |
| invite member / change org settings / set role | ❌ 403 | ❌ 403 | ✅ |

**viewer = read-only (403 on every write); member = project/scan management, no
org admin; admin = full within org; owner = full.** No violations, no gaps.

### No isolation regression

Re-ran the cross-tenant spot-check after the fix: **User B (non-member of Org A)
on all of Org A's write endpoints — 7/7 returned 404** (not 403, not 2xx). The
new guards deny non-members with `ErrNotFound`, so there is **no existence oracle
and no weakening of org-scoping**. Build compiles clean; middleware tests pass.

*(Pre-existing, out of scope: `githubapp_test.go` references a `models.Scan` field
`AIGeneratedPct` that doesn't exist — a broken test unrelated to this change;
noted, not touched.)*

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
| 2 | RBAC | ✅ PASS | viewer-write gap **found + fixed** this pass; viewer now read-only (403), isolation intact |
| 3 | Memory | ✅ PASS | per-project baselines; deletion cascade clean |
| 4 | Concurrency | ✅ PASS | 0 contamination; Asynq once-only |
| 5 | ML feeding | ✅ PASS | metadata-only (no code); per-team isolated; retrain manual |

**The most serious class of bug — cross-tenant data leakage — is CONFIRMED absent**,
and the one within-org least-privilege gap (viewer write access) has been **fixed
and re-verified** without weakening isolation. Pass 4 is fully clean.
