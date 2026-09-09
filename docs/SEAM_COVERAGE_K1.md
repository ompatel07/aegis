# Pass K1 — make the seams run, then audit every skip

**HEAD:** `d079b5c` + this change · **Run date:** 2026-09-09

**Headline: neither test suite ran in CI at all.** The brief expected to find no Go
test job; there was also no Python one. 255 scanner tests and every Go test were
manual-only, and `self-scan.yml` ran linters and scanners exclusively. That is how
the same P0 shipped twice.

---

## 1. What actually let it through

Two identical P0s, both breaking every scan-read endpoint by adding a column to a
table read with `SELECT *`:

| pass | column | caught by |
|---|---|---|
| T2 | `excluded_bundled` on `scans` | F1, a later audit pass |
| J4 | `code_key` on `findings` | calling the endpoint by hand |

The tests for it existed. `column_seam_test.go` is *named* for this failure mode.
Both seams skipped, because nothing set `AEGIS_SEAM_DB_URL` and no job stood up a
database. `go build`, `go vet` and the full unit suite were green for both.

J2 established the rule — *a test that always skips is not a guard* — and this is
the same defect one layer down.

---

## 2. Part A — the seams now run, and fail loudly when they cannot

**`.github/workflows/tests.yml`** (new) has two jobs:

- **`scanner-tests`** — builds the scanner image and runs pytest inside it. The
  image is where semgrep, trivy, gitleaks and ruff live; running the suite
  anywhere else turns a dozen `skipif` guards into silent no-ops (§3).
- **`go-tests`** — `docker compose up -d --wait postgres redis migrate api`, then
  `go test ./...` for both services with the seam environment set. Compose is
  reused rather than re-declared so CI exercises the wiring the product ships.
  The DSN is read from the running API rather than restated, because a second
  copy of the credentials is a second thing to drift.

**The seams now fail in CI rather than skip.** `apiseam/seamenv_test.go` (new)
centralises the decision:

```go
if os.Getenv("CI") != "" {
    t.Fatalf("seam environment is not configured in CI. ...")
}
t.Skip("set AEGIS_SEAM_DB_URL (and AEGIS_SEAM_API_URL) to run the API seams locally")
```

Skipping locally is convenient; skipping in CI is the bug. Verified both ways:

```
--- local (CI unset, no seam env) ---
ok      github.com/aegis-platform/api/internal/apiseam   0.007s

--- CI=true, no seam env (must FAIL) ---
    These seams exist to catch schema/struct drift that unit tests, `go build`
    and `go vet` all miss. Letting them skip in CI is how that class shipped twice.
FAIL    github.com/aegis-platform/api/internal/apiseam   0.006s
```

And against the live stack, with the environment present — they run and pass:

```
--- PASS: TestSeamSelectStarTablesMatchTheirStructs (0.09s)
--- PASS: TestSeamAllNullScanIsReadableEverywhere   (0.78s)
--- PASS: TestSeamNullColumnsRenderHonestly         (0.28s)
ok      github.com/aegis-platform/api/internal/apiseam   1.158s
```

---

## 3. Part B — every skip, with a verdict

The last full run reported **255 passed, 4 skipped**. The 4 are now known
precisely, and every binary-guarded test was already running.

### The 12 binary/dependency guards — all currently RUN

Every one of these is `skipif not binary_available(...)`, and every binary is
present in the scanner image:

```
semgrep present   trivy present   gitleaks present   ruff present
lightgbm/sklearn present          lizard present
```

| test | guards on | skipped in last run? | verdict |
|---|---|:--:|---|
| `test_rulepacks.py` | semgrep | no | **MUST RUN** — now pinned to the image by `tests.yml` |
| `test_taint_rules.py` | semgrep | no | **MUST RUN** |
| `test_bug_rules.py` | semgrep | no | **MUST RUN** |
| `test_iac_rules.py` | semgrep | no | **MUST RUN** |
| `test_cicd_rules.py` | semgrep | no | **MUST RUN** |
| `test_custom_pack_loads.py` | semgrep | no | **MUST RUN** — guards the rules-not-loading P0 |
| `test_seams.py` | semgrep | no | **MUST RUN** — guards the seam invariants |
| `test_engines_smoke.py` ×4 | semgrep / trivy / gitleaks / lizard | no | **MUST RUN** |
| `test_ruff_engine.py` | ruff | no | **MUST RUN** |
| `test_ml.py` | lightgbm+sklearn | no | **MUST RUN** |

**These were never the problem** — they run today because the suite is executed
inside the image. The risk was latent: run pytest on a host without the binaries
and a dozen files go quietly green. `tests.yml` removes that by making the image
the only place CI runs them.

### The 4 actual skips

| skip | count | verdict |
|---|--:|---|
| `test_compliance_mappings.py:211` — *"not a git checkout (running inside the scanner image)"* | 1 | **LEGITIMATE, and separately guarded.** The J2 single-framework-tree check is a repository-level invariant; inside the image `services/scanner` is the root and there is no repo to walk. It cannot run there, and it does not need to: `check_single_framework_tree.py` enforces the same thing unconditionally in `self-scan.yml`. The test is the local convenience; the script is the guard. |
| `test_compliance_mappings.py:335` — *"verified against normative text"* | 3 | **LEGITIMATE.** A conditional assertion, not an environment guard: the test asserts that a framework whose control text is paywalled says so on its report, and skips for the three verified against public normative text (HIPAA, NIST CSF, ASVS). Skipping is the correct outcome for a case the assertion does not apply to. |

**Both are deliberate. Neither hides a capability gap.**

---

## 4. Part C — the guard that cannot skip

`services/scanner/tools/check_select_star_columns.py`, wired into the existing
Structural-guard job in `self-scan.yml`. No database, no services, no environment:
it reads the migrations and the Go source.

It replays every `*.up.sql` in order (`CREATE TABLE`, `ADD COLUMN`, `DROP COLUMN`,
`RENAME COLUMN`) to get each table's surviving columns, extracts `db:` tags from
the model structs, and enforces two things:

1. **Every `SELECT * FROM <table>` in the Go source must be registered.** A new
   unguarded one fails the build instead of joining silently.
2. **Every column of a registered table must have a struct field.**

Current state — a wider exposure than the two known incidents:

```
SELECT * column coverage OK: 14 tables, 151 columns, all covered by their Go structs
```

**Proven to catch all three shapes**, then restored:

| planted defect | result |
|---|---|
| Remove `CodeKey` from `models.Finding` (recreates the J4 P0 exactly) | `findings: models.Finding has no field for ['code_key']` — **rc=1** |
| Add a new column with no struct field | `findings: models.Finding has no field for ['k1_probe_column']` — **rc=1** |
| Point a query at an unregistered table | `` `SELECT * FROM some_new_table` … is not registered `` — **rc=1** |

---

## 5. Part D — the deploy hazard, and why the stated rule is backwards

Full analysis in **`docs/DEPLOY_ORDERING.md`**. The short version, because it
inverts the premise the brief and I both started from.

Measured, not assumed:

| direction | result |
|---|---|
| Struct field with **no column** *(new binary, old schema)* | `<nil>` — fine |
| Column with **no struct field** *(old binary, new schema)* | `missing destination name` — **fails** |

So *"migrations must run before new binaries serve traffic"* is **the wrong rule
for `SELECT *` tables**. Migrating first is precisely what breaks the **old** pods
that are still serving during a rolling upgrade.

Both deploy paths already enforce migrate-first, verified:

| path | mechanism |
|---|---|
| `docker-compose.yml` | `api` **and** `orchestrator` declare `depends_on: migrate: {condition: service_completed_successfully}` |
| `deploy/helm/aegis` | `migrate-job.yaml`, `helm.sh/hook: pre-install,pre-upgrade`, `hook-weight: -5` |

Compose stops the old container before starting the new one, so no window exists
there. **Helm is a rolling upgrade and the window is real**: between the
`pre-upgrade` migration landing and the last old pod terminating, every read of
that table 500s.

For J4's `code_key` specifically, neither order is clean — migrate-first breaks
old readers, rollout-first breaks new writers. The document states the three-step
release that is actually safe, and names the durable fix: stop reading migrating
tables with `SELECT *`. `repository/scan.go` already does this deliberately;
`findings` is the highest-value table to convert next.

**Not guarded, and said so in the doc:** nothing enforces the three-step release.
One commit adding a column, a struct field and a write will pass every check here
and still break a Helm rolling upgrade. That is a process constraint, not a
scriptable one.

---

## Gate

| requirement | status |
|---|---|
| CI job running both services' Go tests against a live Postgres | ✅ `tests.yml` → `go-tests`; compose-backed, DSN derived not restated |
| Proof it goes red on a planted mismatch, then green | ✅ §4 — three planted defects, each rc=1, restored to `14 tables, 151 columns` OK |
| Full skip inventory with a verdict per entry | ✅ §3 — 12 binary guards (all MUST RUN, all already running), 4 real skips (both LEGITIMATE, one separately guarded) |
| Every MUST-RUN skip now running in CI | ✅ `scanner-tests` runs the suite inside the image where every guarded binary exists |
| Unconditional column-coverage check | ✅ §4 — no DB, no services, wired into the Structural-guard job |
| Deploy ordering documented and verified | ✅ §5 + `docs/DEPLOY_ORDERING.md` — both paths verified; the stated rule corrected |
| Full suite green, remaining skips named and justified | ✅ see commit message |
