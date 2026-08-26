# Aegis Validation Run V1 — 15 real OSS repos, customer-grade profile

**Purpose:** measure YIELD and PRECISION of Aegis on the kind of code customers
actually ship — management systems, self-hosted SaaS, web apps — across PHP, TS,
Python, Go, Java. This run does **not** measure recall (no ground truth); no
recall/coverage claim is made anywhere below.

**Author's standing caveat:** I am not the final judge. For every assessed finding
I give the raw evidence and a **proposed** verdict with a confidence level.
Anything I could not verify is called out explicitly. "0 FP" is never asserted as
a conclusion — the evidence is presented and the reviewer decides.

---

## 0. PRE-RUN — a run-invalidating regression was found and fixed first

The first attempt at this run (7 repos) was **discarded**. While inspecting its
results I found that **every** SAST-completed repo returned findings from the
`registry` ruleset only — zero `aegis-*` findings, on all 7 repos. Aegis's custom
packs were not running.

**Root cause (bisected + reproduced):** commit `a95fd0e` (Q3) placed
`ruff_map.yaml` — the Ruff allowlist, *not* a Semgrep rule file — inside
`services/scanner/rules/quality/`, a directory the SAST engine passes to
`semgrep --config` wholesale. semgrep tried to parse it as rules, failed schema
validation, and the whole combined SAST invocation exited code 2. The engine's
fallback then retried with **registry packs only**, silently dropping the custom
taint engine, AI-code taint, the IaC pack, and the Q1/Q2 reliability bug pack —
while still reporting `status=completed`. It was invisible because 85 unit tests
and the 36/36 taint suite never exercised the real combined-config scan path.

- **Live window:** `a95fd0e` (Q3 commit) → `aa0121c` (this fix). Every SAST scan
  in that window silently ran registry-only.
- **How caught:** this validation run; `rulesets={registry}` + zero `aegis-*` on
  every repo. Bisected: `bugs.yaml` alone loads (exit 0); `ruff_map.yaml` alone
  exits 2; the directory exits 2.
- **Fix (`aa0121c`, packaging only — no rule/threshold changes):** moved
  `ruff_map.yaml` to `services/scanner/config/`; added
  `tests/test_custom_pack_loads.py`, which drives the **real** `semgrep_engine.run`
  entrypoint against a planted `aegis-bug-js-length-lt-zero` violation and asserts
  that rule id returns — proven to FAIL when a broken YAML is reintroduced. Full
  suite: 86 passed.
- **Dedup re-verified** (Q3's claim had passed vacuously): with the pack loading,
  a mutable-default arg and an `is`-literal comparison each fire exactly once (Ruff
  B006 / F632); no Semgrep rule — custom or registry — double-reports them.
- **The silent-degradation BEHAVIOUR is logged as a separate P0** in
  `PERFORMANCE_TODO.md` (a load failure must surface an explicit `degraded` scan
  state, not pass as clean) — deliberately NOT changed during this run.

This run was then executed from repo 1 against the fixed build `aa0121c`, with an
added per-repo **CUSTOM PACK LOADED** preflight that aborts the run on any "no".
All 15 repos below record **PACK=YES**.

---

## 1. Methodology

- **Aegis commit:** `aa0121c` (fix on top of the Q3 tree).
- **Engines:** semgrep `1.97.0`, ruff `0.8.6`, trivy `0.71.2`, gitleaks `8.21.2`,
  quality (lizard/radon/duplication + Ruff), Python `3.12.13`.
- **Date:** 2026-08-26. **Hardware:** Om's box, Docker Desktop, ~3.7 GB total RAM
  shared across 8 containers, **no per-container memory limit**. Scanner is a
  single-worker uvicorn.
- **Corpus prep:** each repo `git clone --depth 1`, URL verified via `git
  ls-remote` first, scanned, then the clone deleted before the next. Strictly
  sequential, one repo at a time.
- **Per repo, five engines** were invoked over HTTP against the running scanner
  (`POST /scan/{sast,sca,secrets,deployment,quality}`) on the shared `/workspaces`
  volume. Order: sast → sca → secrets → deployment → quality (quality last; see §9
  for why). Between every repo the scanner container is **restarted** to clear
  memory pressure and any zombie scan.
- **Deployment engine run with `build_enabled=false`** (a request parameter, not a
  code change). Aegis's deployment engine otherwise runs `npm ci / pip install /
  go mod download / mvn package` — executing untrusted customer code, which
  violates the locked no-execute boundary and is infeasible on a 3.7 GB box. So the
  deployment pillar here is **Dockerfile static analysis only**; it reports
  `skipped` when there is nothing static to flag. This is a deliberate scope limit,
  not a deployment measurement.
- **Ratings** (Reliability / Security / Maintainability) are computed with the
  exact Go formulas from `internal/scoring/ratings.go`: Reliability = worst
  severity among `issue_type=bug` findings (none→A, low→B, medium→C, high→D,
  crit→E); Security = worst severity among `issue_type=vulnerability`;
  Maintainability = maintainability_score buckets (≥90 A, ≥80 B, ≥70 C, ≥50 D,
  else E).
- **Rule Zero:** OBSERVE, do not fix. No rule/threshold/exclude/engine change was
  made *during* the measurement. The pre-run regression fix (§0) was done and
  committed **before** the run, with the user's explicit approval.
- **Raw audit trail:** one JSON per repo in `docs/validation_v1/<repo>.json`, each
  with every finding, a code snippet, a 5-line source window for every bug, the
  metadata, and per-engine timings. The driver + assembler are
  `scripts/validation_v1_driver.py` and `scripts/validation_v1_report.py`.

---

## 2. Repo table

| # | repo | lang | stars | LOC (code) | files | self-linted? | pack | scan s | status |
|---|------|------|-------|-----------|-------|--------------|------|--------|--------|
| 1 | snipe/snipe-it | PHP | 14,876 | 600,531 | 8,852 | SELF (phpstan, pint, pmd, psalm) | YES | 1483 | done |
| 2 | monicahq/monica | PHP | 25,109 | 151,063 | 2,086 | SELF (phpstan, psalm, eslint, prettier, sonar) | YES | 96 | done |
| 3 | akaunting/akaunting | PHP | 10,092 | 231,029 | 4,177 | SELF (eslint, prettier) | YES | 131 | done |
| 4 | pterodactyl/panel | PHP | 9,178 | 66,105 | 1,402 | SELF (phpstan, php-cs-fixer, phpcs, eslint, prettier) | YES | 58 | done |
| 5 | documenso/documenso | TS | 14,762 | 230,044 | 2,842 | *detector: NOT* (turborepo — eslint in packages/*, false read) | YES | 704 | done (SAST ok) |
| 6 | formbricks/formbricks | TS | 12,827 | 456,573 | 4,715 | SELF (eslint, prettier, sonar, pre-commit) | YES | 878 | **SAST timeout** |
| 7 | outline/outline | TS | 40,339 | 303,993 | 2,721 | SELF (eslint; detector matched "black" spuriously) | YES | 432 | done |
| 8 | mealie-recipes/mealie | Python | 13,077 | 102,188 | 1,631 | SELF (ruff, flake8, pylint, pre-commit) | YES | 119 | done |
| 9 | paperless-ngx/paperless-ngx | Python | 44,610 | 170,797 | 1,476 | SELF (ruff, flake8, pylint, pre-commit, sonar) | YES | 226 | done |
| 10 | netbox-community/netbox | Python | 21,391 | 331,887 | 2,157 | SELF (ruff, flake8, eslint, pre-commit) | YES | 245 | done |
| 11 | usememos/memos | Go | 62,553 | 171,218 | 1,284 | SELF (golangci-lint, staticcheck, go vet) | YES | 187 | done |
| 12 | navidrome/navidrome | Go | 23,124 | 230,414 | 2,124 | SELF (golangci-lint, staticcheck, go vet, pre-commit) | YES | 155 | done |
| 13 | pocketbase/pocketbase | Go | 60,826 | 167,212 | 829 | SELF (golangci-lint) | YES | 180 | done |
| 14 | macrozheng/mall | Java | 84,632 | 68,598 | 717 | **NOT self-linted** | YES | 85 | done (SCA fail) |
| 15 | elunez/eladmin | Java | 21,918 | 20,913 | 305 | **NOT self-linted** | YES | 39 | done (SCA fail) |

No substitutions were needed — all 15 URLs resolved. **Self-lint caveat:** the
detector reads root-level config + `.github/workflows`; it is approximate and has
false reads on monorepos (documenso) and on spurious substring matches ("black" in
outline, "pint" in mealie). 13/15 repos self-lint with a real linter; the two Java
repos genuinely do not. This column matters because a low bug yield on a
self-linted repo is partly tautological (its own CI already removed those bugs).

---

## 3. Aggregate findings

| # | repo | total | security | quality | deploy | crit | high | med | low | bugs (semgrep/ruff) |
|---|------|-------|----------|---------|--------|------|------|-----|-----|---------------------|
| 1 | snipe/snipe-it | 857 | 175 | 682 | 0 | 9 | 65 | 243 | 540 | **1**/0 |
| 2 | monicahq/monica | 228 | 97 | 130 | 1 | 1 | 25 | 127 | 75 | 0/0 |
| 3 | akaunting/akaunting | 556 | 67 | 489 | 0 | 0 | 19 | 173 | 364 | 0/0 |
| 4 | pterodactyl/panel | 277 | 87 | 190 | 0 | 11 | 37 | 46 | 183 | 0/0 |
| 5 | documenso/documenso | 1002 | 194 | 808 | 0 | 27 | 50 | 338 | 587 | 0/0 |
| 6 | formbricks/formbricks | 1689 | 134 | 1555 | 0 | 128 | 66 | 684 | 811 | 0/0 |
| 7 | outline/outline | 1175 | 295 | 879 | 1 | 14 | 185 | 587 | 389 | 0/0 |
| 8 | mealie-recipes/mealie | 578 | 143 | 434 | 1 | 20 | 38 | 342 | 178 | 0/0 |
| 9 | paperless-ngx/paperless-ngx | 714 | 84 | 630 | 0 | 4 | 39 | 460 | 211 | 0/0 |
| 10 | netbox-community/netbox | 979 | 296 | 683 | 0 | 7 | 31 | 619 | 322 | 0/**3** |
| 11 | usememos/memos | 930 | 240 | 690 | 0 | 10 | 71 | 591 | 258 | 0/0 |
| 12 | navidrome/navidrome | 1169 | 224 | 945 | 0 | 9 | 84 | 818 | 258 | **1**/0 |
| 13 | pocketbase/pocketbase | 996 | 476 | 520 | 0 | 413 | 42 | 356 | 185 | 0/0 |
| 14 | macrozheng/mall | 137 | 56 | 80 | 1 | 5 | 24 | 91 | 17 | 0/0 |
| 15 | elunez/eladmin | 105 | 18 | 87 | 0 | 2 | 6 | 21 | 76 | 0/0 |

**Corpus totals:** 11,392 findings — 2,586 security, 8,802 quality, 4 deployment.
Severity: **660 critical, 782 high, 5,496 medium, 4,454 low**. Engine totals: SAST
1,579 · SCA 379 · secrets 630. **Total bug findings: 5** (see §4).

Two numbers dominate the criticals and deserve early scepticism (see §5, §7):
pocketbase's **413 critical** is ~404 JWT secrets in `*_test.go`, and formbricks'
**128 critical** is mostly secrets in config/example files.

---

## 4. Bug findings — full evidence (all 5, no sampling)

The reliability bug pack + Ruff produced **5 findings across 15 repos**. Each is
below with a source window and a proposed verdict. My assessment: **5/5 look like
true positives, 0 false positives** — but see the confidence notes; the reviewer
decides.

### 4.1 snipe/snipe-it — `app/Models/Traits/Loggable.php:167` — TRUE POSITIVE (high)
`aegis-bug-identical-if-else-branches` (semgrep, medium). Full branches fetched
from GitHub:
```php
167  if ($log->target_type == Location::class) {
168      $log->location_id = $target->id;
169  } elseif ($log->target_type == Asset::class) {
170      $log->location_id = $target->location_id;
171  } else {
172      $log->location_id = $target->location_id;
173  }
```
The `elseif (… == Asset::class)` branch (line 170) and the `else` branch (line 172)
run the **identical** statement. The `Asset` condition has no effect — a genuine
redundant/copy-paste branch. **Why TP:** the two branches are byte-identical; the
rule's claim holds.

### 4.2 navidrome/navidrome — `plugins/cmd/ndpgen/internal/types.go:518` — TRUE POSITIVE (high)
`aegis-bug-identical-if-else-branches-go` (semgrep, medium). Full branches from
GitHub:
```go
518  if prevIsUpper && !nextIsLower {
519      result = append(result, unicode.ToLower(r))   // "lowercase it"
520  } else if prevIsUpper && nextIsLower {
521      // "End of acronym … Keep uppercase"
522      result = append(result, r)
523  } else {
524      // "Regular word boundary - keep uppercase"
525      result = append(result, r)
526  }
```
The `else if prevIsUpper && nextIsLower` branch and the final `else` both run
`result = append(result, r)`. The condition is redundant (the comments claim two
cases but the code is identical). **Why TP:** identical branch bodies; the
`nextIsLower` distinction does nothing.

### 4.3 / 4.4 netbox — `netbox/dcim/svg/cables.py:85` — TRUE POSITIVE (high, pattern)
`aegis-bug-mutable-default-arg` (Ruff B006, medium) — two findings on one line:
```python
85  def __init__(self, start, url, color, wireless, labels=[], description=[], end=None, text_offset=0, **extra):
```
`labels=[]` and `description=[]` are mutable default arguments — the canonical
B006. **Why TP:** genuine mutable defaults on a class `__init__`; if either list is
mutated it is shared across instances. Confidence high on the pattern; real-world
impact depends on whether the lists are mutated (not verified — I did not trace the
class body), so I would not escalate above medium severity.

### 4.5 netbox — `netbox/dcim/tests/test_api.py:2797` — TRUE POSITIVE (high, pattern; test code)
`aegis-bug-mutable-default-arg` (Ruff B006, medium):
```python
2797  def _perform_interface_test_with_invalid_data(self, mode: str = None, invalid_data: dict = {}):
```
`invalid_data={}` is a genuine mutable default. **Why TP:** real B006. Caveat: it
is a **test helper**, so impact is low; arguably a code_smell more than a runtime
bug, but the rule match is correct.

**Bug-pack precision on this corpus: 5 proposed TP / 0 proposed FP.** Note netbox
is `ruff`-self-linted yet these B006 slipped through — netbox does not enable Ruff's
bugbear (`B`) rules in its own config, which is exactly the gap Aegis's explicit
allowlist covers. UNCERTAIN list for §4: none.

---

## 5. Security findings — evidence sample

### 5a. SAST critical/high — 266 findings, by rule (top)
| count | rule | note |
|------:|------|------|
| 74 | `ai-code-sql-concat-js` | **custom AI-code-taint rule.** Fires on template-literal SQL. Sampled 3 (all in outline `server/migrations/*.js`): SQL built from **internal** values (schema/table names, `new Date()`), no request-reachable user input. **Proposed: mostly FALSE POSITIVE / low-risk** (medium confidence) — the string-built-SQL pattern is real but there is no external taint source in a migration script. Needs review as a group. |
| 30 | `detected-bcrypt-hash` | Mostly `database/factories/UserFactory.php` (snipe, monica) — bcrypt hashes in **test factories**. Proposed FALSE POSITIVE / expected (high conf): seeded fake password hashes, not secrets. |
| 24 | `avoid-sqlalchemy-text` | Python raw `text()` SQL. Proposed UNCERTAIN — legitimate hardening signal; TP as a "raw SQL used" flag, but injection risk depends on interpolation (not traced). |
| 21 / 16 | `node_secret` / `node_password` | njsscan hardcoded secret/password. Overlaps the secrets pillar; needs per-hit triage. |
| 9 | `regex_injection_dos` | ReDoS. Plausible; not individually verified. |
| 8+6 | `dangerous-exec-command`, `run-shell-injection` | exec/shell sinks. Higher prior of being real; not traced to a source here. |

The custom taint packs are clearly contributing post-fix (outline SAST 157→278 vs
the registry-only broken run; snipe 78→89). The **`ai-code-sql-concat-js` group is
the biggest precision concern** — see §7.

### 5b. SCA — version-math cross-check (sample of 15 package/CVE pairs)
Version math (installed vs fixed) is internally consistent for the real packages.
Two problems to flag, per the brief ("do not assume the scanner is right"):

- **`lodash` 4.17.21, `CVE-2026-4800`, fixed=`4.18.0`, cvss 9.8 — PROBABLE FALSE
  POSITIVE / bad advisory.** lodash `4.18.0` **does not exist** (4.17.21 has been
  the latest for years). A "fixed in 4.18.0" advisory is not credible. Flagged.
- **`axios` 1.13.5 → 4 separate CVEs** (`CVE-2026-42043` cvss 10, `-42264`,
  `CVE-2025-62718`, `-42044`), all fixed in 1.15.x, `reachable=true`,
  `is_direct=true`. Version math is consistent (1.13.5 < 1.15.x). **But these are
  2026/2025 advisories I cannot independently verify** (past my Jan-2026 knowledge
  cutoff), and the environment's trivy DB may contain synthetic/test advisory data
  (round CVSS values, future dates). **Proposed: version-in-range TP, advisory
  existence UNVERIFIABLE** — do not treat as confirmed real CVEs without checking
  the live advisory DB.
- `postcss` 8.5.6→8.5.12, `league/commonmark` 2.8.3→2.9.0: plausible, version math
  consistent.
- paperless `DS-0002/0026/0029`: these are Trivy **Dockerfile misconfig** IDs (no
  package/version), surfacing in the SCA channel — a labelling nit, not CVEs.

**Reachability is a real differentiator when present** (axios flagged reachable +
direct; lodash flagged not-reachable + transitive) — useful for prioritisation,
assuming the advisory itself is real.

### 5c. Secrets — 630 total, dominated by test-fixture false positives
| repo | n | in test/example | rules |
|------|--:|--:|------|
| pocketbase | **410** | **406** | `jwt`×404, `private-key`×5, `generic-api-key`×1 |
| formbricks | 128 | 30 | `generic-api-key`×98, `aegis-db-connection-string`×29, `discord-client-secret`×1 |
| documenso | 25 | 0 | `generic-api-key`×16, `aegis-db-connection-string`×7, `private-key`×2 |
| mealie | 18 | 18 | `generic-api-key`×13, `aegis-db-connection-string`×5 |
| outline | 12 | 4 | `generic-api-key`×9, `private-key`×3 |
| others | ≤10 each | — | mix of jwt/private-key/generic-api-key/curl-auth-header |

Redacted samples: pocketbase `jwt` at `apis/backup_test.go:41,57` (entropy ~5.5) —
**JWT test tokens in Go test files. Proposed FALSE POSITIVE cluster (high conf).**
formbricks `aegis-db-connection-string` at `.env.example:58,67` (entropy 2.75,
placeholder) — **FALSE POSITIVE (high conf): placeholder connection string in an
example env file.** Every secret was redacted before display (first/last 3-4 chars
only). **Proposed:** the secrets pillar has a large test-fixture / example-file FP
problem; real credentials in these mature public repos are expected to be ~none
(they'd have been revoked/scrubbed). See §7.

---

## 6. Quality pillar

| repo | Reliab | Secur | Maint | maint score | coverage | dup% | top 5 smells |
|------|:---:|:---:|:---:|--:|------|--:|------|
| snipe | **C** | E | A | 90.1 | not measured | 40.1 | Magic numbers×433; Cyclomatic×77; Duplicated×60; Tech-debt marker×48; Too-many-params×35 |
| monica | A | E | B | 89.7 | not measured | 51.1 | Duplicated×60; Magic numbers×57; Params×4; Cyclomatic×3 |
| akaunting | A | D | B | 80.4 | not measured | 20.1 | Magic numbers×308; Duplicated×60; Deep nesting×37; Params×33 |
| pterodactyl | A | E | C | 71.6 | not measured | 7.4 | Magic numbers×104; Duplicated×60; Params×11; Tech-debt×6 |
| documenso | A | E | C | 70.2 | not measured | 46.3 | Magic numbers×390; Cyclomatic×93; Deep nesting×93; Long fn×85 |
| formbricks | A | E | C | 71.1 | not measured | 25.6 | Magic numbers×553; Deep nesting×460; Cyclomatic×224; Long fn×115 |
| outline | A | E | C | 74.7 | not measured | 25.0 | Deep nesting×236; Cyclomatic×213; Long fn×166; Magic numbers×103 |
| mealie | A | E | **E** | 48.5 | not measured | 32.3 | Deep nesting×121; Cyclomatic×79; Params×69; Magic numbers×63 |
| paperless-ngx | A | E | D | 69.9 | not measured | 23.5 | Deep nesting×253; Cyclomatic×111; Long fn×75; Params×65 |
| netbox | **C** | E | B | 82.8 | not measured | 24.0 | Deep nesting×210; Cyclomatic×145; Long fn×98; Magic numbers×83 |
| memos | A | E | D | 64.1 | not measured | 43.2 | Cyclomatic×261; Magic numbers×146; Deep nesting×115; Long fn×85 |
| navidrome | **C** | E | D | 64.6 | not measured | 26.3 | Deep nesting×475; Cyclomatic×173; Magic numbers×111; Duplicated×60 |
| pocketbase | A | E | D | 67.8 | not measured | 44.4 | Cyclomatic×158; Deep nesting×119; Long fn×92; Magic numbers×73 |
| mall | A | E | A | 90.2 | not measured | 90.5 | Duplicated×60; Leftover debug×5; Cyclomatic×4; Params×4 |
| eladmin | A | E | **E** | 45.3 | not measured | 41.5 | Duplicated×60; Leftover debug×8; Cyclomatic×6; Params×5 |

- **Coverage renders as "not measured" on all 15 — never 0%.** Confirms the Q1
  None-handling holds: no repo shipped a coverage report the scanner parses, and
  None is displayed as "not measured" (the composite renormalizes; not re-derived
  here since scoring is the Go orchestrator's job).
- **Reliability = C** exactly for the 3 repos with a bug (snipe, netbox,
  navidrome); A elsewhere. One medium bug → C, as designed.
- **Security = E** for almost all — every repo has at least one critical
  vulnerability/secret; the rating is worst-severity, so a single critical (often a
  test-fixture secret, see §5c) pins it to E. This makes the Security *letter* a
  weak signal on this corpus — it says "≥1 critical somewhere", which is nearly
  always true once test-fixture secrets are counted.
- **`Duplicated code ×60` appears in every single repo, always exactly 60** — this
  is a **hard cap in the duplication detector**, not a real "all repos have 60
  clones" result. mall shows dup%=90.5 with only 60 findings. Flagged in §9 as a
  measurement artifact.

---

## 7. Suspected false-positive patterns (grouped by root cause)

1. **Test-fixture / example-file secrets — the biggest FP source.** `jwt` tokens in
   `*_test.go` (pocketbase ×404), placeholder connection strings in `.env.example`
   (formbricks, mealie), bcrypt hashes in `database/factories/*` (snipe, monica,
   surfaced as SAST `detected-bcrypt-hash` ×30). Root cause: the secrets/SAST
   detectors key on entropy/shape and do not down-rank paths that are obviously
   fixtures (`*_test.*`, `*.example`, `factories/`, `fixtures/`, `mock*`). **Impact:
   ~500+ of the 630 secrets and ~30 SAST criticals are proposed FPs.** Highest-value
   precision fix: a fixture-path prior that caps severity or suppresses in
   test/example/factory paths.
2. **`ai-code-sql-concat-js` on trusted SQL (×74).** Fires on any template-literal
   SQL, including DB **migration scripts** interpolating internal schema names and
   `new Date()`. No request-reachable user input. Root cause: the rule matches
   string-built SQL by shape without a taint source. Fix direction: require a
   user-controlled source, or exclude `migrations/`, or drop to low severity.
3. **SCA advisories that cannot be trusted at face value.** `lodash` "fixed in
   4.18.0" (nonexistent version) is a concrete bad-advisory FP; the axios 2026 CVEs
   are unverifiable here. Root cause is the advisory DB, not Aegis logic, but Aegis
   surfaces them at critical without a credibility check (e.g. "fixed version does
   not exist in the package's release history").
4. **`Duplicated code` capped at exactly 60** — not an FP per se, but every repo
   reporting the same 60 is a misleading artifact; the true clone count is
   truncated (see §9).

---

## 8. Notable misses — informal observation, NOT a recall measurement

Speculative; I read only fragments and have no ground truth. Recorded for a
reviewer to chase, not as a recall claim:
- The `ai-code-sql-concat-js` rule flags templated SQL but I did **not** see Aegis
  separately flag the migration files' use of `queryInterface.sequelize.query`
  with genuinely dynamic identifiers as a distinct "dynamic identifier" issue —
  worth a manual look at outline's migrations if that is in scope.
- The two Java repos (mall, eladmin) are **not self-linted** and yielded 0 reliability
  bugs. Given the Java bug pack has only `string-literal-equality` and
  `return-in-finally`, it is plausible real `==`-on-boxed-types or resource-leak
  bugs exist that these narrow rules don't cover. This is a coverage observation,
  not a measured miss.

---

## 9. Operational results

| repo | LOC | sast | sca | secrets | deploy | quality |
|------|----:|------|-----|---------|--------|---------|
| snipe | 600k | ok 232s | ok | ok | skip | ok **1305s** |
| documenso | 230k | ok 505s | ok | ok | skip | ok 191s |
| formbricks | 457k | **FAIL 600s** | ok | ok | skip | ok 260s |
| outline | 304k | ok 313s | ok | ok | ok | ok 114s |
| netbox | 332k | ok 120s | ok | ok | skip | ok 113s |
| mall | 69k | ok 39s | **FAIL 11s** | ok | skip | ok 35s |
| eladmin | 21k | ok 27s | **FAIL 10s** | ok | skip | ok 2s |
| (others) | — | ok | ok | ok | skip | ok |

**Failures / limits (all are DATA, not run aborts):**
1. **formbricks SAST timeout (457k LOC TS).** Hit the scanner's internal 600s
   semgrep timeout → SAST `failed`, 0 findings, whole security pillar lost.
   documenso (230k) completed at 505s; outline (304k) at 313s. So the ceiling is
   real and sits around ~450k LOC of TS. (In the discarded first run, documenso
   *also* failed here — but that was the packaging bug forcing a second full
   semgrep pass; post-fix, one clean pass completes. The remaining formbricks
   timeout is genuine scale.) → `PERFORMANCE_TODO.md`.
2. **mall + eladmin SCA failure (Java/Maven).** trivy needs a **populated Maven
   cache** (`mvn dependency:resolve`) to enumerate deps from `pom.xml`; Aegis's
   no-build boundary forbids running Maven, so SCA cannot resolve the Java
   dependency tree and fails. This is a **real SCA coverage gap for Maven/Java**,
   and a direct (correct) consequence of never building customer code. Contrast:
   PHP `composer.lock`, JS `package-lock.json`, Go `go.sum` are committed resolved
   lockfiles trivy reads statically — SCA works there. → track as a Java-SCA gap.
3. **`Duplicated code` capped at 60** per repo (every repo shows exactly 60). The
   real clone count is truncated; the duplication metric is a floor, not a count.
4. **Memory pressure (first run only).** In the discarded first attempt, akaunting
   (231k PHP) saw trivy+gitleaks `subprocess` spawns fail with `FileNotFoundError`
   after a heavy SAST run (fork/exec under low free RAM; no OOM-kill). The
   restart-before-each-repo protocol prevented any recurrence in the real run. →
   `PERFORMANCE_TODO.md` (mem floor / serialize heavy spawns / distinct error).
5. **Scan time vs LOC is roughly linear for quality, super-linear for SAST on TS.**
   Quality scales ~linearly (snipe 600k → 1305s dominated by duplication).
   SAST on TS degrades fast (documenso 230k→505s, formbricks 457k→timeout): TS
   parsing + the full ruleset is the long pole.

**Single-worker note:** a client-side HTTP timeout does not cancel the server-side
semgrep run. Running quality last + restarting between repos was required to stop a
hung engine from blocking the next; this is a harness workaround for a real
scanner property (no scan cancellation / single worker).

---

## Also-verified invariants

- **Determinism:** two repos scanned twice (same tree), fingerprints compared.
  **eladmin: 105 = 105 findings, identical, zero diffs. pterodactyl: 277 = 277
  findings, identical, zero diffs.** The Pass-1 byte-stability invariant holds.
- **Coverage None-handling:** all 15 render "not measured", never 0% (§6).
- **No security finding tagged `issue_type=bug`:** verified 0 across all 11,392
  findings. **No bandit/`S` Ruff codes present:** verified 0. All 5 bugs are
  `pillar=quality`.
- **Custom pack loaded:** all 15 repos PACK=YES via the real-scan preflight.
- **Code ownership:** `app` vs `third_party` tagging works (e.g. snipe 779 app / 78
  third_party; netbox's 3 Ruff bugs tagged `app`). **Measured asymmetry:** semgrep
  scans and tags `third_party` findings, but **Ruff never emits a `third_party`
  finding** because its `--exclude` removes vendored/`site-packages` dirs before
  scanning. So a bug in vendored Python is invisible to Ruff by design, while
  semgrep would still report (and tag) it. Not a correctness bug — Ruff's exclusion
  is the safer default — but it is a real inconsistency in what the two engines
  cover for third-party code.

---

## 10. Raw data

Per-repo JSON audit records: `docs/validation_v1/<repo>.json` (every finding, code
snippet, 5-line bug windows, metadata, timings) — **kept locally, git-ignored (~14
MB); regenerate with the driver**. Harness:
`scripts/validation_v1_driver.py`, `scripts/validation_v1_report.py`. Operational
log: `docs/validation_v1/_operational_notes.md`.

---

## Headline

- **15/15 scanned, all with custom packs confirmed loaded** (after a P0 packaging
  regression was found by this very run and fixed first).
- **Bug pack precision: 5 findings, all 5 proposed true positives** (2 identical-
  branch, 3 mutable-default), 0 proposed FP. Low yield is consistent with a corpus
  that is 13/15 self-linted.
- **The precision problems are in secrets and one AI-code SQL rule**, not the bug
  pack: ~500+ test-fixture/example secrets and ~74 templated-SQL findings on
  trusted code are the proposed-FP mass to address next.
- **Two real coverage gaps:** SAST times out on ~450k-LOC TypeScript; SCA cannot
  scan Maven/Java without building (a consequence of the no-execute boundary).
- **One bad SCA advisory surfaced** (`lodash` fixed-in-4.18.0, a nonexistent
  release); the 2026 CVEs could not be independently verified.
