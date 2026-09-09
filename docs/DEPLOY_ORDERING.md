# Deploy ordering: migrations, binaries, and `SELECT *`

**Written during K1, after J4's `code_key` migration made the hazard concrete.**

This document exists because the obvious rule — *"always run migrations before the
new binaries serve traffic"* — is **not** safe for the tables Aegis reads with
`SELECT *`, and both of our deploy paths implement exactly that rule.

---

## 1. The asymmetry that causes it

`sqlx` treats the two mismatch directions differently. Measured against the live
database, not assumed:

| situation | result |
|---|---|
| Struct has a field with **no matching column** *(new binary, old schema)* | `<nil>` — the field stays zero, the query succeeds |
| Table has a column with **no matching struct field** *(old binary, new schema)* | `missing destination name code_key` — **the query fails** |

A `SELECT *` read therefore breaks the moment a column appears that the running
binary does not know about. Adding a column is **not** a backward-compatible
change for those tables, even though it is for every other consumer.

## 2. What that means for a rolling upgrade

For a table read with `SELECT *`, there is **no ordering that is safe in both
directions** while two binary versions are live at once:

| order | old pods (still serving) | new pods |
|---|---|---|
| **Migrate first**, then roll out | **500 on every read of that table** until the last old pod terminates | fine |
| **Roll out first**, then migrate | fine | writes that reference the new column fail until the migration lands |

With J4's `code_key` specifically:

- **Migrate first** → old API pods `SELECT * FROM findings` and 500. That is the
  findings list, SARIF export and the compliance report, for the whole rollout
  window.
- **Roll out first** → the new orchestrator's `INSERT INTO findings (... code_key)`
  fails until the migration runs, so scans complete but fail to save results.

Neither is acceptable silently. Pick deliberately per migration.

## 3. What our deploy paths actually do

Both enforce **migrate-first**. Verified, not assumed:

| path | mechanism | enforced? |
|---|---|---|
| `docker-compose.yml` | `api` and `orchestrator` both declare `depends_on: migrate: {condition: service_completed_successfully}` | **yes** |
| `deploy/helm/aegis` | `templates/migrate-job.yaml` is a Job with `helm.sh/hook: pre-install,pre-upgrade` and `hook-weight: -5` | **yes** (default `migrate.enabled: true`) |

Compose is not a rolling-upgrade path — it stops the old container before
starting the new one — so the hazard does not arise there. **Helm is**, and the
`pre-upgrade` hook means the migration lands while old pods are still serving.

## 4. Rules

**For an additive migration on a table read with `SELECT *`** (today: `findings`,
`projects`, `users`, and the eleven others registered in
`services/scanner/tools/check_select_star_columns.py`):

1. **Add the struct field and deploy the binaries FIRST**, in a release that does
   not yet write the column. The field with no column is harmless (§1).
2. **Then** run the migration.
3. **Then** release the code that writes the column.

That is a three-step release. It is the price of `SELECT *`.

**Or take the short cut, knowingly:** if a brief window of failed reads is
acceptable (an internal deployment, a maintenance window), migrate first and
accept it. Do not do this silently — the failure mode is a 500, not a degraded
response, and it will page someone.

**The durable fix is to stop using `SELECT *` on tables that migrate.**
`repository/scan.go` already does this and says why:

> We avoid SELECT * because the table also has raw_* columns.

An explicit column list makes an additive migration fully backward compatible in
both directions, and removes the three-step dance. `findings` is the highest-value
table to convert, because it is the one every scan-read endpoint touches.

## 5. What guards this today

| guard | what it catches | where |
|---|---|---|
| `check_select_star_columns.py` | a column with no struct field, and any new unregistered `SELECT *` | `self-scan.yml`, unconditional |
| `column_seam_test.go` | the same, against a live schema | `tests.yml`, fails in CI if the DB is absent |
| This document | the ordering itself | manual — see below |

**Not guarded:** nothing enforces the three-step release. A single release that
adds a column, a struct field and a write in one commit will pass every check
here and still break a Helm rolling upgrade. That is a process constraint, and it
is why this file exists rather than a script.
