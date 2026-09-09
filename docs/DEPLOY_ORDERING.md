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

## 3a. Which tables are still affected (updated by K2)

K2 converted the highest-churn tables to explicit column lists derived from their
models. Migration churn, counted from `database/migrations/*.up.sql`:

| table | `ALTER TABLE` count | read with | subject to the three-step release? |
|---|--:|---|:--:|
| `scans` | 16 | explicit list (always was) | **no** |
| `findings` | 15 | **explicit list (K2)** | **no** |
| `projects` | 3 | **explicit list (K2)** | **no** |
| `users` | 2 | **explicit list (K2)** | **no** |
| the other 11 registered tables | ≤1 each | `SELECT *` | **yes** |

That covers every table with more than one migration in its history. The eleven
remaining are low-churn (`feature_flags`, `beta_invitations`, `support_tickets`,
`github_integrations`, `notification_settings`, `project_slack`,
`organization_invitations`, `project_policies`, `scim_tokens`, `sso_connections`,
`sso_identities`) and `check_select_star_columns.py` still guards them; it now
reports which tables have been converted and stops checking those.

**For a converted table, an additive migration is safe in both directions.**
Verified rather than assumed: a column was added by migration *without* touching
`models.Finding`, and the whole API suite — including all nine scan-read
endpoints — passed with it present. Under `SELECT *` that same column returned
500 from every one of them.

The one direction that changed: an explicit list asks for columns by name, so a
binary whose struct declares a field with no column behind it now fails with a
plain SQL error instead of working. That is louder and earlier than the silent
mismatch it replaces, and migrate-first — which both deploy paths enforce — means
the column always exists by the time the new binary runs.

## 4. Rules

**For an additive migration on a table still read with `SELECT *`** (the eleven
low-churn tables listed in §3a and registered in
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

**The durable fix is to stop using `SELECT *` on tables that migrate — done for
the four highest-churn tables in K2 (§3a).** `repository/scan.go` set the
precedent and says why:

> We avoid SELECT * because the table also has raw_* columns.

An explicit column list makes an additive migration backward compatible and
removes the three-step dance. The lists are **derived from the model's `db:` tags**
at startup (`repository/columns.go`), never transcribed — a hand-maintained list
that goes stale is the same defect wearing different clothes, and `scanColumns`
was exactly that shape for its whole life.

## 5. What guards this today

| guard | what it catches | where |
|---|---|---|
| `check_select_star_columns.py` | a column with no struct field, and any new unregistered `SELECT *` | `self-scan.yml`, unconditional |
| `column_seam_test.go` | the same, against a live schema | `tests.yml`, fails in CI if the DB is absent |
| `columns_test.go` | a derived list drifting from its model | `go test ./internal/repository` |
| `column_seam_test.go` (converted tables) | the binary asking for a column the schema lacks | `tests.yml`, against a live schema |
| This document | the ordering itself | manual — see below |

**Not guarded:** nothing enforces the three-step release for the eleven tables
still on `SELECT *`. A single release that adds a column, a struct field and a
write in one commit will pass every check here and still break a Helm rolling
upgrade on those tables. That is a process constraint, and it is why this file
exists rather than a script.

The scope of that constraint is now small and shrinking: it no longer applies to
`scans`, `findings`, `projects` or `users`, which between them account for every
table that has taken more than one migration. Converting the remaining eleven is
mechanical — add `var xColumns = columnsOf(models.X{}, "")` and swap the query —
and each one removes another table from this rule.
