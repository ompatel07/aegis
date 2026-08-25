# Per-Engine Real-World Accuracy + False-Negative Report

**Phase 2F pre-launch hardening, Pass 3 of 6.** Engine-by-engine confirmation that
each performs in **real-world use** as its scorecard claims, with a specific focus
on **false negatives** (missed real vulnerabilities) — the highest-stakes error
type for a security tool.

Every result below is a **live run** against the running scanner (semgrep 1.97.0,
trivy 0.71.2, gitleaks 8.21.2), using real known-vulnerability test sets, not
synthetic-only. Where a real gap was found it is stated plainly; where a probe
turned out to be a false alarm, that is stated too (no inflation either way).

Scorecard cross-referenced: [ACCURACY_VALIDATION.md](ACCURACY_VALIDATION.md).

---

## Verdicts at a glance

| # | Engine | Claim | This pass (real runs) | Verdict |
|---|--------|-------|-----------------------|---------|
| 1 | **SAST** (Semgrep + Aegis taint) | F1 0.775 / recall 88.4% | **10/10** canonical CWEs caught across Py/JS/Go/Java, 0 FN | ✅ **PASS** |
| 2 | **SCA** (Trivy) | 100% precision | **6/6** pinned known-CVE packages flagged (40 CVEs); reachability correct | ✅ **PASS** |
| 3 | **Secrets** (Gitleaks) | precision 1.00 / recall 0.92 | gap found (DB connection strings + JWT secrets) **→ FIXED**: recall 0.42→0.92 on the extended corpus, precision still 1.00 | ✅ **PASS** (fixed) |
| 4 | **IaC** (Trivy + Aegis compose) | 9/9 recall, 0 hi-FP | 9/9 + S3 public buckets + K8s host/root all caught | ✅ **PASS** |
| 5 | **Taint / dataflow + SoR** | 144/144 nodes | intra-fn taint + **SoR 6/6 nodes match real code**; cross-fn/file benign-sink missed | ✅ **PASS** (scope) |
| 6 | **Deployment** | 4/4 builds | 4/4 + missing-dependency build correctly failed | ✅ **PASS** |
| 7 | **Code Quality** | metrics exact | CC/params integer-exact; suggestions specific + actionable | ✅ **PASS** |
| 8 | **CVE Intelligence** | live + retro re-score | 4 feeds synced today; retro re-score proven; no false flags | ✅ **PASS** |

All eight engines pass on real-world code. The one concern found (Engine 3 — DB
connection-string + JWT secrets) was **fixed in this pass, precision-safe** (see
below).

---

## Engine 1 — SAST (Semgrep + Aegis taint) — ✅ PASS

- **OWASP recall 88.4% / F1 0.775** — cross-referenced from Pass 1 (determinism +
  regression: the saved OWASP TP/FP/FN/TN did not move). The Phase-2D recall-safe
  FP tuning is byte-identical on the OWASP corpus (§2 of the scorecard), so it
  introduced **no** false negatives — recall is still 88.4%.
- **Cross-language false-negative probe (the new work).** Planted canonical,
  clearly-vulnerable source→sink code — one file per language:

  | Language | Planted CWEs | Result |
  |----------|--------------|--------|
  | Python | SQLi, command-injection, path-traversal | **all 3 caught** |
  | JavaScript | SQLi, command-injection, reflected XSS | **all 3 caught** |
  | Go | SQLi, command-injection | **both caught** |
  | Java | SQLi, command-injection | **both caught** |

  **10/10 planted real vulnerabilities detected, 0 false negatives.** The Aegis
  custom **taint-mode** rules (`aegis-py/js/go/java-sql-injection`,
  `aegis-*-command-injection`, `aegis-js-xss`) fired cross-language alongside the
  registry rules — corroborating detection, not single-rule reliance.

- **Code-ownership tagging added (Phase 2G validation).** A real PHP repo
  (`whxitte/Project-Taaza`) that vendors PHPMailer/FPDF by copying them in produced
  27 findings — the user's 11 SQLi + 1 XSS mixed with 15 bundled-library findings.
  Every finding is now tagged `code_ownership` = `app` / `third_party`
  (`utils/code_ownership.py`, applied to all engines via `enricher.enrich_all`);
  the UI leads with "Your code" and collapses "Third-party / bundled libraries", and
  SARIF carries a `code_ownership` property. Precision-first (unsure → app): 23/23
  unit, `pallets/click` 203 all-app, `client1` 82 all-app, **0 app-code
  misclassified**; scoring unchanged. See [VALIDATION_REPORT.md](VALIDATION_REPORT.md).

- **React XSS coverage added (Phase 2G validation).** A real-repo validation on
  `github.com/ompatel07/client1` (Next.js) surfaced a false negative: React
  **`dangerouslySetInnerHTML`** XSS was not detected (even when tainted by
  `searchParams`). Fixed with a new precision-safe taint rule **`aegis-react-xss`**
  (sources: searchParams / router query / `window.location` / form input; sink: the
  React `{__html: …}` payload; sanitizer-aware). Verified: the planted
  `searchParams.q → __html` XSS is now caught, while safe static JSON-LD stays clean
  — **0 false positives** on client1's 5 real uses and `vercel/next-learn`'s 4
  (`semgrep --test` 31/31, scanner suite 51/51). See
  [VALIDATION_REPORT.md](VALIDATION_REPORT.md).

- **PHP cross-function taint pack added (P2a, competitive parity).** PHP previously
  got registry rules only — no `aegis-php-*` taint layer. Added 5 taint-mode rules
  (`rules/taint/php.yaml`) matching the quality bar of the other 43:

  | Rule | Class (CWE) | Sources | Silencing sanitizers |
  |------|-------------|---------|----------------------|
  | `aegis-php-sql-injection` | SQLi (CWE-89) | `$_GET/$_POST/$_REQUEST/$_COOKIE`, request `$_SERVER` keys, `php://input` | prepared stmts (by construction), `intval`/`(int)`, `mysqli_real_escape_string`, `PDO::quote` |
  | `aegis-php-xss` | XSS (CWE-79) | request superglobals + reflected `$_SERVER` keys | `htmlspecialchars`, `htmlentities`, `strip_tags`, casts, `urlencode` |
  | `aegis-php-command-injection` | Cmd (CWE-78) | request superglobals, `php://input` | `escapeshellarg`, `escapeshellcmd`, casts |
  | `aegis-php-path-traversal` | Path/LFI (CWE-22) | request superglobals | `basename`, `realpath`, casts |
  | `aegis-php-ldap-injection` | LDAP (CWE-90) | request superglobals | `ldap_escape` |

  **Precision-first, verified:** positive + sanitized-negative fixture per rule
  (`rules/taint/php.php`) via `semgrep --test` → **5/5 pass**; full custom-taint
  suite **36/36** (was 31/31). **Re-scan of `whxitte/Project-Taaza`:**
  `aegis-php-sql-injection` fires on **11 findings across the same 11 real vuln
  spots** the registry SQLi rule flags (`admin-login`, `reset_pass`, `checkout`,
  `login`, `update-payment`, … — parity, ±1 line as aegis anchors the sink), plus
  **1 genuine reflected XSS** the registry SQLi rule doesn't surface
  (`table-booking-handler.php:100`, request input → `echo` into a `<script>` alert).
  **No spurious findings on Taaza's safe code** (12 aegis-php findings, all true
  positives).

---

## Engine 2 — SCA (Trivy) — ✅ PASS

- **100% precision** — cross-referenced (40/40 OSV-verified on the scorecard).
- **Known-CVE false-negative probe.** Pinned six packages to specific
  **known-vulnerable versions** and confirmed every one is flagged:

  | Package@version | CVEs flagged | A named CVE present |
  |-----------------|-------------:|---------------------|
  | Jinja2 2.10 | 6 | CVE-2019-10906 ✓ |
  | PyYAML 5.1 | 3 | CVE-2020-1747 ✓ |
  | urllib3 1.24.1 | 12 | CVE-2019-11236 ✓ |
  | Flask 0.12.2 | 4 | CVE-2018-1000656 ✓ |
  | requests 2.19.1 | 5 | CVE-2018-18074 ✓ |
  | cryptography 2.3 | 10 | CVE-2020-25659 ✓ |

  **6/6 known-vulnerable packages flagged (40 CVEs), no known CVE missed.**
- **Reachability works.** The app imported `yaml` + `requests` but only *declared*
  the other four. Findings carried `reachable=True` for the imported packages and
  `reachable=False` for the declared-but-unused ones — exactly the discrimination
  the scorer needs to prioritize reachable, direct-dependency CVEs.
- **Vendored (copied-in) library coverage added (Phase 2G validation).** Trivy is
  manifest-based, so a repo that vendors a library by copying its source in (no
  composer.json / package.json) was invisible to SCA — a repo bundling an old
  PHPMailer (5.2.x, incl. the CVE-2016-10033 RCE) got a clean "0 vulnerable
  dependencies." New **curated fingerprinting** (`utils/vendored_fingerprint.py`,
  run in the SCA engine) detects copied-in libs by a verified file+marker+exact-
  version signature (PHPMailer, FPDF, jQuery, Bootstrap) and resolves CVEs via OSV.
  **Precision-first:** flags only on an exact version match, skips `vendor/`/
  `node_modules/`, dedups against Trivy (no double-count). **Verified:** Project-
  Taaza's *current* PHPMailer 6.8.1 → **0 phantom CVEs**; planted **PHPMailer 5.2.0
  → 10 real CVEs** (incl. CVE-2016-10033), jQuery 1.12.4 → 4, Bootstrap 3.3.7 → 7;
  **0 false positives** on app `VERSION` consts, same-named non-lib files, doc
  mentions, `vendor/` copies, and comparative repos. See
  [VALIDATION_REPORT.md](VALIDATION_REPORT.md).
- **CISA KEV — actively-exploited flag (P1b).** Every CVE finding is checked against
  the CISA Known Exploited Vulnerabilities catalog; a hit sets `kev` +
  `kev_date_added` + `kev_ransomware`, leads the impact with "⚠ Actively exploited
  in the wild", raises risk to critical, and multiplies the score penalty ×1.5.
  Verified: Log4Shell CVE-2021-44228 flagged (date 2021-12-10, ransomware); all
  non-KEV CVEs on the same package unflagged (0 FPs). See
  [INTELLIGENCE_VERIFICATION.md](INTELLIGENCE_VERIFICATION.md).
- **EPSS + dependency path (P2b, Snyk-parity data).** Two additions to each SCA
  finding's data, matching what Snyk shows:
  - **EPSS** — one batched first.org lookup per scan (per-CVE 24 h cache, EPSS's
    daily cadence) attaches `epss_score` + `epss_percentile` (probability the CVE
    is exploited in the next 30 days). Complements KEV (confirmed) with a
    probability for the long tail. Best-effort: a CVE EPSS doesn't score simply
    carries no field (no fabricated 0). **Verified:** on a real lockfile, 30/32
    CVEs got real scores (e.g. CVE-2019-10744 → 0.05006 / p0.915); the 2 misses
    were brand-new CVEs EPSS hasn't rated yet.
  - **Dependency path** — from Trivy's dependency graph (`Relationship` +
    `DependsOn`), each finding shows the introduced-through chain + which **direct**
    dep to update (`dependency_path`, `introduced_through`, `is_transitive`).
    **Verified:** a transitive vuln shows `your app → wrapper@1.0.0 →
    lodash@4.17.11` (`introduced_through=wrapper`, transitive=true); a direct vuln
    shows `your app → axios@0.21.0` (transitive=false). 32/32 findings carried a
    correct path.

---

## Engine 3 — Secrets (Gitleaks) — ✅ PASS (gap found + fixed this pass)

- **Precision 1.00 / recall 0.92 reproduced exactly** on the 12-planted + 8-decoy
  corpus (11/12 TP, 0/8 FP). All decoys (AWS docs example key, placeholders,
  UUID, git SHA, MD5, base64, env lookups) correctly ignored.
- **The one inherent miss reproduced:** the bare **AWS secret access key**
  (40-char blob with no paired `AKIA…` id) — information-theoretically
  indistinguishable from any base64 string; unfixable without destroying precision.

### The false negative found — and the fix

A supplemental probe of formats the original corpus didn't cover surfaced a real,
high-value gap: **database connection strings with embedded credentials** and
**hard-coded JWT signing secrets** were **not detected** by the stock Gitleaks
ruleset.

**Fix (precision-first):** a bundled Gitleaks config that *extends* the defaults
(`useDefault = true`) with two targeted rules —
[`services/scanner/rules/gitleaks.toml`](services/scanner/rules/gitleaks.toml),
wired via `--config` in `gitleaks_engine.py`:

- `aegis-db-connection-string` — fires only on the strong `scheme://[user]:password@host`
  shape (postgres/postgresql/mysql/mariadb/mongodb/mongodb+srv/redis/rediss/amqp(s)/mssql/ftp),
  requiring a real ≥3-char password before the `@`.
- `aegis-jwt-signing-secret` — fires on `jwt[_-]?(signing)?(secret|key) = "literal"`
  (a quoted string, so code expressions like `os.environ.get(...)` never match).

Both carry allowlists for **env-var references** (`${VAR}`, `$VAR`, `process.env`,
`os.environ`), **credential-less URIs** (`postgres://localhost/db`,
`postgres://user@host`), and **placeholder passwords/secrets** (`pass`, `changeme`,
`your-secret`, …).

**Verification — positive AND negative fixtures:**

| Fixture set | Result |
|-------------|--------|
| **Positives** — postgres / mysql / mongodb+srv / redis / amqps conn strings + 2 JWT secrets | **7/7 detected** |
| **Negatives** — localhost, no-creds, `user@host`, `${DB_PASSWORD}`, `$VAR`, placeholder passwords (`pass`/`changeme`/`password`), JWT env lookups, `your-secret-here` | **13/13 clean — 0 FP** |

**Before / after on an extended corpus** (original secrets + the DB/JWT classes +
credential-less/placeholder decoys):

| | Precision | Recall | Notes |
|--|:---------:|:------:|-------|
| **Before** (stock rules) | 1.000 | **0.417** | all 5 conn strings + a JWT secret missed |
| **After** (Aegis config) | **1.000** | **0.917** | only the inherent bare-AWS secret still missed |

**Recall 0.42 → 0.92, precision held at 1.00, zero new false positives.** The
original 12+8 corpus is **unchanged** (still 1.00 / 0.917 — no regression), and a
smoke of SAST/SCA/Quality confirmed no cross-engine impact.

---

## Engine 4 — IaC (Trivy + Aegis compose rules) — ✅ PASS

- **9/9 recall reproduced** across Dockerfile / Terraform / Kubernetes /
  docker-compose (latest-tag, root user, unencrypted/public, open security group,
  privileged, hostPath, exposed 0.0.0.0 port, SYS_ADMIN), **0 high/critical FP**
  on hardened files, example-dir scoping intact.
- **Supplemental FN probe.** Explicit **S3 public-read bucket** (AVD-AWS-0086/87/88
  + public-access ACL) → **8 findings, 6 HIGH, caught**; **K8s hostNetwork,
  hostPID, allowPrivilegeEscalation, runAsNonRoot=false** → **all caught** (19
  findings on the pod).
- **Honest note (a false alarm I chased down, not a gap).** An initial S3 probe
  reported 0 findings — that was **my own malformed, compressed one-liner HCL**
  which Trivy's HCL parser silently parses to nothing. Re-tested with
  conventionally-formatted HCL (what `terraform fmt` produces, i.e. every real
  repo), the scanner catches all 8. So: **no S3 gap** — verified before reporting.
  The only residual is Trivy's parser being formatting-sensitive on unusual HCL,
  which real-world Terraform doesn't trigger.

---

## Engine 5 — Taint / dataflow + Steps-of-Reproduction — ✅ PASS (on claimed scope)

- **SoR is real and accurate.** Scanned the `vulnerable_app` fixture: 6 taint
  findings carried steps-to-reproduce (source / flow / sink / cwe / why_exploitable
  / example_input, built from Semgrep's `--dataflow-traces`). Every SoR **source
  node's `file:line:code` matched the actual fixture code — 6/6.** E.g.
  `aegis-py-command-injection` source = `host = request.args.get("host")` (L35) →
  sink `os.system(...)` (L37). Not fabricated; omitted entirely on non-dataflow
  findings.
- **Intra-function taint caught with SoR** (source + sink in one function):
  `aegis-py-sql-injection` fires, SoR present. ✓
- **The honest false-negative boundary.** A **cross-function** flow into a sink
  that is **benign in isolation** (`cur.execute(v)` where `v` is a bare parameter,
  tainted only via another function) was **NOT caught** (0 findings). The fast
  (Semgrep-OSS) taint engine is **intra-procedural**: it does not track taint
  across function/file boundaries. This is the **shelved-Joern deep-scan gap**,
  already documented. Mitigation in practice: vulnerabilities whose sink is
  independently suspicious (string-concat in a query, `os.system` on a variable)
  are still caught by pattern rules — just without a SoR flow. What's missed is the
  narrow case where the sink looks safe on its own and only a cross-procedural
  dataflow reveals the taint.

---

## Engine 6 — Deployment testing — ✅ PASS

- **4/4 reproduced** — good Go/Node builds pass (no `build-failed`), broken
  (syntax-error) Go/Node builds emit a **CRITICAL `build-failed`** with the real
  compiler message.
- **Missing-dependency FN probe (new).** A Go module importing a nonexistent
  package → **CRITICAL build-failed** finding carrying the real `go build ./...`
  output (`main.go:2:8: …`). So both broken-build classes tested — **syntax error
  and missing dependency — correctly fail.** Builds actually execute; this is not a
  heuristic.
- **False-negative risk (honest).** Verification only covers build systems the
  engine recognizes and can invoke (Go, Node, …). A project whose build it cannot
  determine gets **no** build-failed signal even if genuinely broken — inherent to
  build-based verification, not a detection defect.

---

## Engine 7 — Code Quality — ✅ PASS

- **Metrics integer-exact vs hand-computed:** cyclomatic complexity 13→13 and
  25→25, parameter count 7→7, Type-2 (token-normalized) duplication detected.
- **Suggestions are specific + actionable, not filler.** Example real finding:
  *"'process' takes 8 parameters (threshold 6). Consider grouping related arguments
  into an object."* — names the function, the measured value, the threshold, and a
  concrete refactor. Deterministic measurements: "accuracy" here is arithmetic
  correctness, and it is exact.
- **SonarQube-style typing + A–E ratings (P2c).** Every finding now carries an
  `issue_type` — **bug | vulnerability | code_smell** — set in enrichment:
  security-pillar findings (SAST/SCA/secrets) are **vulnerabilities**; quality
  findings (complexity/duplication/magic-numbers/tech-debt/style) are **code
  smells**. Precision-first: when unsure between bug and smell we keep smell (the
  bug-class quality-rule set is deliberately empty until a clear crash/logic rule
  exists), so a maintainability finding is never mislabelled a reliability bug.
  Each completed scan also gets three **A–E ratings** derived from data already
  computed:
  - **Reliability** = worst-severity Bug (SonarQube model; no bugs → A).
  - **Security** = worst-severity Vulnerability (no vulns → A).
  - **Maintainability** = maintainability sub-score bucketed **A ≥ 90, B ≥ 80,
    C ≥ 70, D ≥ 50, else E**.

  **Verified on real scans:** a vulnerable repo (SQLi + command-injection + high
  complexity) → 9 findings typed `vulnerability`, 2 typed `code_smell`, ratings
  **reliability A / security E / maintainability E**; a clean, documented module →
  **A / A / A** (quality_score 85, security_score 100). Ratings track the scores
  (not degenerate), and **0 quality findings were mistyped** as bug/vulnerability.

---

## Engine 8 — CVE Intelligence — ✅ PASS

- **Feeds live and current** — all four sources synced **today (2026-07-30)** with
  `status=success`: NVD (6,781 CVEs, newest modified today; +4 added / 1,996
  updated), GHSA (192, +17/83), OSV (268), Semgrep rules. Genuinely fresh, not a
  stale snapshot.
- **Retroactive re-scoring proven end-to-end.** On a real recent scan (had a `bson`
  dependency finding): reset `needs_reeval=FALSE`, ran the exact `FlagAffectedScans`
  UPDATE for a new CVE affecting `bson` → flipped to **`TRUE`** with the reason
  *"New vulnerability CVE-RETRO-P3-0001 affects a dependency in this scan."* Original
  value restored afterward.
- **No false CVE flags.** The same flag query for a package **not** present in any
  recent scan flagged **0 scans** — a CVE only re-flags a scan that actually
  contains the affected package. Combined with SCA's version-precise matching
  (Engine 2), a CVE is never attached to a package it doesn't affect.

---

## Consolidated false-negative summary (brutally honest)

What classes of real issues does Aegis miss, and why?

| Gap | Engine | Status | Notes |
|-----|--------|--------|-------|
| **DB connection strings + JWT signing secrets** | Secrets | ✅ **FIXED** | `scheme://user:pass@host` URIs + named JWT secrets now detected via a bundled Gitleaks config (extends defaults). Recall 0.42→0.92, precision still 1.00, 0 new FP. |
| **Bare AWS secret key** (no `AKIA` id) | Secrets | ⛔ **INHERENT** | Indistinguishable from any base64 string; flagging all would destroy precision. The access-key id (which identifies the account) *is* caught. |
| **Cross-function / cross-file taint into a benign-looking sink** | Taint | ⏸️ **DEFERRED** | Fast engine is intra-procedural (shelved-Joern deep scan). Vulns with independently-suspicious sinks still caught (no SoR). |
| **Architectural / business-logic / broken-auth-logic bugs** | SAST | ⛔ **INHERENT** | No static analyzer catches logic bugs that require understanding intended behavior. Industry-wide SAST limitation. |
| **Broken builds in unrecognized build systems** | Deployment | ⛔ **INHERENT** | Can't verify a build it can't invoke. Recognized systems (Go/Node/…) verified for real. |
| ~~S3 public buckets~~ | IaC | ✅ **NOT A GAP** | Initial probe was my malformed HCL; well-formatted HCL is caught (8 findings). |

**Bottom line:** across all eight engines on real-world code, detection matches the
scorecard. The **one genuine false-negative found (DB connection-string + JWT
secrets) was fixed this pass, precision-safe** (recall 0.42→0.92, precision 1.00);
the remaining gaps are **inherent** (bare-AWS, SAST logic bugs, unrecognized
builds) or **known-deferred** (cross-file taint = shelved Joern), honestly
disclosed rather than hidden. No engine silently underperforms its claimed
accuracy on the vulnerabilities it claims to catch.

**Reproduce:** planted-corpus probes were run in-container against `/scan/{sast,
sca,secrets,quality,deployment}`; existing harnesses in
[`benchmarks/comparative/`](benchmarks/comparative/) and
[`benchmarks/iac/`](benchmarks/iac/); intelligence checks are DB queries against
`intelligence_sync_log` / `cve_database` / `scans.needs_reeval`.

---

## Quality pillar — reliability-bug pack (Q1)

Powers the SonarQube-style **Reliability** rating, which was previously a
hardcoded `A` for 100% of scans (`_QUALITY_BUG_RULES` was an empty set, so no
finding could ever be typed `issue_type=bug`). A "bug" is the highest-trust-cost
claim we make — "your code is wrong", not "this is a smell" — so every rule runs
on Semgrep's **real grammar** (never regex/line heuristics, the source of our
last three FP incidents f221bd2 / 43bc13f / 299c2e1) and is gated to **zero FP**
on the five validated repos before shipping.

**Pack:** `services/scanner/rules/quality/bugs.yaml`. Each rule carries
`metadata.pillar=quality` (routes it to the QUALITY pillar in
`semgrep_engine._parse`, not security) and `metadata.issue_type=bug`
(`enricher._QUALITY_BUG_RULES` is loaded from this pack at import — single source
of truth, never hand-maintained).

**Severity cap:** no rule emits `ERROR`, so the normalizer's worst output is
`medium` (WARNING). One reliability bug therefore caps a repo's Reliability
rating at **C**, never D/E, on day one. `high` (→ D) and any critical (→ E) are
reserved for a future, separately-proven pack of genuine crash / data-loss rules.

| Rule | Languages | Semgrep severity → ours | Bug class |
|---|---|---|---|
| `aegis-bug-identical-if-else-branches` | js, ts, php | WARNING → medium | both branches run the same statement — condition is dead (copy-paste bug) |
| `aegis-bug-return-in-finally` | js, ts, java | WARNING → medium | `return` in `finally` silently discards exceptions |
| `aegis-bug-mutable-default-arg` | python | WARNING → medium | mutable default (`[]`/`{}`/`set()`) shared across calls |
| `aegis-bug-java-string-literal-equality` | java | WARNING → medium | `==`/`!=` against a String literal (reference, not value, equality) |

**Dropped at the 0-FP gate (do not re-add without new evidence):**
- `aegis-bug-self-assignment` (`$X = $X`): **48 FP / 0 TP** across the five repos.
  `readonly EntityType = EntityType;` is the Angular template-exposure idiom (LHS
  is a new class field, RHS the imported enum), `$s = (string)$s;` is a PHP
  defensive cast, `a = b = c` is a JS chained assignment — all textually `X = X`,
  none bugs, and the Angular form is *syntactically indistinguishable* from a
  real self-assignment.
- `empty catch/except`: SonarQube classifies it as a code **smell** (S108), not a
  bug; intentional `catch {/* ignore */}` blocks make it FP-prone.
- `unreachable-after-return`, `assignment-in-condition`: deferred — semgrep
  statement-sequencing / intentional-assignment (`while ((l = read()) != null)`)
  make a 0-FP form non-trivial; not shipped until proven.
- duplicate object keys / case labels, Go `_ = err` discard/shadow: not precisely
  expressible in semgrep OSS without cross-`...` equality or type/flow info.

**Validation (bug findings per repo, zero FP):**

| Repo | Language | `aegis-bug-*` findings | Reliability before → after |
|---|---|---|---|
| whxitte/Project-Taaza | PHP | 0 | A → A |
| mohaiminur/laundry | PHP | 0 | A → A |
| booklore-app/booklore | Angular + Java | 0 | A → A |
| ryndngl/Salon_Desktop_App_Client | Electron/React | 1 (true positive) | A → **C** |
| The-Weirdos-NFT | React | 0 | A → A |

The one finding — `salon/src/main/main.js:101`, `if (response.ok) { return result; }
else { return result; }` — is a genuine bug (the `response.ok` check is dead).
Compliance grade is unaffected (bug CWEs 691/597/584/665 map to no SOC2 control;
the compliance grade is driven by security-pillar findings). Maintainability is
unaffected (bug findings come from the semgrep engine, not the quality engine's
smell density).

---

## Quality pillar — real test coverage (Q1 Defect 2)

Previously `test_coverage_score = 60.0 if has_tests else 0.0` — a coverage number
**fabricated** from the mere presence of a test directory. That both credits a
repo it shouldn't (any tests → 60%) and punishes one it shouldn't (no tests → 0%,
dragging the composite down 15%). Killed.

**Now:** coverage is parsed from a real report when one is shipped, else it is
**UNKNOWN (None)** — never 0, never a constant. Parsed formats & locations
(`quality_engine._coverage_percentage`, priority order): Istanbul
`coverage-summary.json`, `lcov.info`, Cobertura `coverage.xml`, JaCoCo
`jacoco.xml` (`target/site/jacoco/`, `build/reports/jacoco/`), Istanbul
`coverage-final.json` (statement coverage), coverage.py `coverage.json`, Go
`coverage.out` coverprofile — searched at repo root and under `coverage/`,
`target/site/jacoco/`, `build/reports/`, `htmlcov/`, `.coverage/`.

**Unknown is excluded, not zeroed.** When coverage is None the orchestrator's
`QualityScore` drops the 0.15 coverage weight and **renormalizes** the remaining
four metrics over their own weights (0.85), scoring only what we measured. Counting
None as 0 would punish every repo that doesn't publish coverage. `has_tests`
remains a separate, honest boolean ("are there tests at all") distinct from a
coverage percentage. `QualityMetrics.test_coverage_score` is `float | None`
(Python) / `*float64` (Go, JSON null round-trips).

**Blast radius (5 validated repos — none ships a coverage report, so all → None):**

| Repo | has_tests | coverage before → after | composite quality before → after | maintainability rating |
|---|---|---|---|---|
| whxitte/Project-Taaza | false | 0 → None | 57 → **67** | E → E |
| mohaiminur/laundry | false | 0 → None | 58 → **68** | E → E |
| booklore-app/booklore | true | 60 → None | 70 → **72** | C → C |
| ryndngl/Salon | true | 60 → None | 56 → 56 | E → E |
| The-Weirdos-NFT | true | 60 → None | 87 → **92** | A → A |

Every shift is in the honest direction: no-test repos are no longer punished by a
fabricated 0 (Taaza/laundry +10), test-bearing repos are no longer credited by a
fabricated 60 (booklore +2, weirdos +5, salon net-neutral). No composite craters.
Maintainability rating is coverage-independent (unchanged); compliance grade does
not consume quality sub-scores (unchanged).
