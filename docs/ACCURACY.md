# Aegis accuracy — the single source of claims

This file is the **only** place Aegis's accuracy numbers are stated. Every number
below carries the four things that make it a claim and not a vibe: **what** was
measured, on **which corpus**, on **what date**, at **which commit**. A number
without those four does not belong in this file, and no accuracy number belongs
anywhere else in the repo, marketing, or UI without a pointer back here.

**Aegis is a two-pillar product** — Security and Code Quality — and never builds or
runs customer code. Deployment testing is **CI-only** (it requires the customer's own
pipeline to have built the workspace; Aegis inspects the artifacts and never builds),
so it is not a pillar on the default web/API path and carries no accuracy claim here.
See `docs/SCORING_CALIBRATION_C1.md` § Two-pillar composition.

Two numbers are two different things, and this file keeps them apart:

- **Benchmark** precision/recall — measured on a *synthetic* corpus (planted
  secrets, OWASP Benchmark's generated Java). Repeatable, but it is a lab number:
  it says how well the tool does on inputs built to be measured.
- **Real-world** precision — hand-triaged on the V1 corpus of 15 real OSS repos.
  Messier, smaller sample, stated with a confidence per verdict. This is the number
  that predicts what a customer sees.

---

## Provenance

| corpus | what it is | date | Aegis commit | tool versions |
|---|---|---|---|---|
| **V1** | 15 real OSS repos, full scan, stored findings in `docs/validation_v1/` | 2026-08-26 | `aa0121c` | gitleaks 8.21.2, trivy 0.71.2, semgrep 1.97.0 |
| **V1 (S1-corrected)** | 5 biggest-offender repos re-scanned LIVE with real secret values (585/630 secrets); offline signals for the other 10 | 2026-08-27 | `e9e2e65` (S1 series `0c0d6f0`→`e9e2e65`) | same |
| **P1 replay** | offline replay of Parts A+B over the V1 corpus (`scripts/precision_p1_replay.py`) | 2026-08-31 | `ad0dd66` | n/a (no re-scan) |
| **secrets-bench** | synthetic: 12 planted real-format secrets + 8 decoys (`benchmarks/comparative/secrets_bench.py`) | 2026-08-31 | `ad0dd66`+P2 | gitleaks 8.21.2 |
| **OWASP Benchmark v1.2** | 2,740 generated Java taint testcases (`benchmarks/owasp/`) | per `QUALITY_BENCHMARK.md` | `aa0121c`-era | semgrep 1.97.0 + Aegis Java taint rules — **superseded by N1 below** |
| **N1 — sovereign rule set** | the same OWASP harness, 5 ground-truth repos (45 documented vulns), V2's 15 repos re-cloned, 114 hand-triaged findings — each run **before and after** the cut, same day, same checkout | 2026-09-19 | N1 (`b651c94` → N1) | semgrep 1.97.0; Aegis rules + njsscan (LGPL-3.0) only |
| **P2 taint audit** | per-rule audit + FP fixes to `rules/taint/`, verified on minimal reproductions of each V1 FP shape | 2026-08-31 | `ad0dd66`+P2 | semgrep 1.97.0 |

"P1"/"P2" = precision passes. P1 deleted the `ai-code-*` pack and suppressed
placeholder/expired secrets; P2 root-caused and fixed the taint-rule FPs, added the
documentation-path prior, and sourced the OWASP comparison. Replays measure
before/after offline — they **do not re-scan** the 15 repos. Dates are the calendar
day of the work; `git log` is authoritative for commit dates.

---

## Secrets (gitleaks)

| metric | value | corpus | date / commit | confidence |
|---|---|---|---|---|
| **Benchmark precision** | **1.00** (11 TP / 0 FP) | secrets-bench (synthetic) | 2026-08-31 / `ad0dd66`+P2 | exact (planted labels) |
| **Benchmark recall** | **0.917** (11 TP / 1 FN) | secrets-bench | 2026-08-31 / `ad0dd66`+P2 | exact; the 1 FN is a context-free AWS *secret* (not id), a pre-existing gitleaks miss unrelated to P1/P2 |
| **Real-world precision, actionable severity** | **≤ 0.77, and likely lower** (bound, see below) | V1 (S1-corrected) | 2026-08-27 / `e9e2e65` | medium (path/rule triage; values redacted) |

**Real-world bound.** V1 raw: **630 secret findings, all reported CRITICAL.** After
S1 + P1 + P2 (LIVE classification, 585/630 findings):

- **425 test-fixture** → kept at LOW + tagged (may be real; a human still triages).
- **60 suppressed by P1** (46 placeholder-shape + 14 expired JWT) — definitively not
  credentials; removed from findings, counted in `EngineResult.filtered_secrets`.
- **23 documentation-path** (P2 doc-path prior) → down-ranked to LOW + tagged
  `documentation`. These are the `generic-api-key` / `private-key` matches in `.mdx`
  API docs and self-hosting config docs — confirmed FPs (API-usage examples).
- **The actionable bound.** Of **100** findings that S1 left at actionable severity:
  **≥ 23 are confirmed FP** (the doc-path matches, now down-ranked); the remaining
  **77 are untriaged** (values redacted — cannot confirm real vs config-placeholder).
  So actionable-secret precision is **≤ (100 − 23) / 100 = 0.77**, and likely lower
  because the untriaged 77 are dominated by `generic-api-key` (a low-precision rule)
  and include config placeholders. **n = 100; untriaged remainder = 77.** This is a
  *bound*, not a point estimate — a redacted corpus does not permit one.
- **Offline 10 repos** (45 findings, redacted): reproducible lower bound of 21
  fixture + (≥0) placeholder; true suppression ≥ shown.

The benchmark plants real-format secrets; it does not contain the doc/config noise
that dominates real-world false positives — which is why benchmark precision (1.00)
and real-world precision (≤ 0.77) are different numbers. The provider-key override
(AWS `AKIA`, GitHub `ghp_`, Stripe `sk_live_`, PEM key body, …) wins over every
signal in every path — including documentation paths — and is regression-tested
(`test_secret_context.py`).

---

## SAST (semgrep)

### Benchmark — withdrawn from the headline (N2, 2026-10-21)

**Aegis makes no SAST benchmark claim.** The OWASP Benchmark comparison that stood here
measured *synthetic Java* — the language Aegis lost most of when N1 removed the
Semgrep-licensed rules, and one this file now classifies as `limited` coverage (seven
rules, seven CWE classes). A number measured on the weakest thing we do is not a
headline, in either direction:

- the pre-N1 figures (F1 0.775 / Youden 0.459) are **not ours to cite** — they were
  produced by rules we no longer ship;
- the post-N1 figures (F1 0.247 / Youden 0.051) are real but **not representative** —
  they score the one language where our coverage is thinnest, on generated code.

Both are preserved with their method and dates under
[Superseded benchmark history](#superseded-benchmark-history) at the end of this file.
They may be cited there, as history. They may **not** be used as a current capability
claim in the README, a deck, or any customer-facing material.

What replaces it: the **per-language coverage** table below (what we can and cannot
read), the **ground-truth recall** in `docs/RULE_REMOVAL_N1.md` §C.2 (22 of 45
documented vulnerabilities across five corpora), and the hand-triaged precision in
§C.4. Those measure the product as it ships. Rebuilding a benchmark claim needs the
Java rules in `docs/RULE_REMOVAL_N1.md` §E first.

### Real-world — V1 corpus

| metric | value | corpus | date / commit | confidence |
|---|---|---|---|---|
| **Actionable findings, before → after Part A** | **266 → 180** crit+high (removed 188 `ai-code-*`: 86 high + 102 medium) | V1 / P1 replay | 2026-08-31 / `ad0dd66` | exact (mechanical) |
| **`aegis-*` taint FPs root-caused & fixed** | **5 of 7** V1 findings (n = 7) | V1 + minimal reproductions | 2026-08-31 / `ad0dd66`+P2 | high per verdict, **wide interval** on n=7 |

**Per-rule audit (P2).** The cascadia FP was not a one-off: it traced to two
structural defects — a sink keying on a bare method name with an unbound receiver,
and (the actual cause here) an over-broad *source*.

| rule | defect | status |
|---|---|---|
| `aegis-go-sql-injection` | shared source `$C.Query(...)` matched *any* `.Query` — `url.Values.Query()`, `cascadia.Query(node,…)` — making unrelated calls phantom taint sources | **fixed** — gin accessors constrained to a string-literal key `$C.Query("...")` |
| `aegis-go-nosql/xss/ssrf/cmd/path/ldap` (share that source) | same phantom-source exposure | **fixed** by the same source constraint (all six inherit the shared `request_sources`) |
| `aegis-java-xss` | sink `$OUT.print/println/write` matched `System.out`/`System.err` (stdout ≠ XSS) | **fixed** — `System.out`/`System.err` excluded |
| `aegis-go-nosql-injection` (sink) | `$COLL.Find/FindOne` matches any `.Find` (e.g. gorm) | source fix removes the V1 exposure; a bson-filter sink constraint was validated as a further tightening but **not shipped** (the source fix suffices, and no V1 FP came from this sink) |
| `aegis-java-sql` (`.execute`), `aegis-js-sql` (`.query`/`.execute`), `aegis-php-sql` (`->query`), `aegis-py-sql` (`.execute`), `aegis-go-xss` (`$W.Write`), `aegis-js-xss` (`$RES.send`) | sink keys on a generic method name; receiver type would disambiguate | **documented boundary** — semgrep cannot resolve the receiver's package/type without building the customer's code (which Aegis never does), so these keep name-based sinks; `aegis-java-sql` is OWASP-measured, so it is left unchanged to preserve the measured number |

**Re-triage of the 7 V1 taint findings after the fix** (verified on minimal
reproductions of each shape; the V1 repos are not re-scanned):

| repo / rule | before | after P2 | confidence |
|---|---|---|---|
| navidrome `aegis-go-sql-injection` (cascadia.Query) | FP | **eliminated** (source fix) | high |
| pocketbase `aegis-go-sql-injection` ×3 (url.Query()) | FP | **eliminated** (source fix) | high |
| eladmin `aegis-java-xss` (System.out) | FP | **eliminated** (stdout exclusion) | high |
| monica `aegis-js-ssrf` (sentry DSN) | FP | **still fires** — config-URL FP, not this defect class | medium |
| navidrome `aegis-go-ssrf` (internal proxy) | uncertain | **may fire** — internal-URL question, not this defect class | low |

**0-FP evidence.** Each fixed FP shape is now an `ok:` fixture in `rules/taint/go.go`
and `java.java` (`sqliUrlQueryOk`, `xssStdoutOk`) with a positive `ruleid:` guard
that real gin input still fires (`sqliGinBad`); `semgrep --test` passes 7/7 for both,
run by `test_taint_rules.py` — the same zero-FP discipline as the bug pack. Net: 5 of
7 (**n = 7**, wide interval — do not read a bare percentage off 7 samples) V1 taint
FPs eliminated; the 2 residual are SSRF *config/internal-URL* FPs, a distinct
signal-quality problem left as a documented follow-up.

**Accepted false-negative class (the cost of the source fix).** Constraining the gin
accessors to a string-literal key means `c.Query("id")` is a source but
`c.Query(paramName)` — a variable key — is **not**. Variable-keyed accessor calls
are real gin code, so a genuine SQLi/XSS/SSRF flowing through one is now **missed**.
This is a deliberate trade — a large precision gain (4 of the 5 fixed FPs) for a
narrow recall loss on an uncommon coding shape — but it is an accepted FN class, not
a free win. It applies to every rule sharing `request_sources`
(`aegis-go-{sql,nosql,xss,ssrf,command,path-traversal,ldap}-injection`), since the
literal-key constraint lives in the shared source. Named-key access — the dominant
form — is unaffected.

The 180 actionable SAST findings also included **82 "secret-shaped" registry rules**
(`node_secret`, `detected-bcrypt-hash`, …) overlapping the secrets pillar, and **91
other community rules**; these were not exhaustively triaged. **Since N1 the community
rules are gone**; of the secret-shaped ones only njsscan's `node_secret`/`node_password`
remain, and N1's triage found them firing on message strings (CORRECTION 11).

### Per-language SAST — what ships (N1, 2026-09-19)

Since N1 there are no registry rules to be "additive over": for most languages our own packs
**are** the whole of SAST. Measured on V2's 15 repositories, each cloned once and scanned with the
full rule set and the sovereign one (`docs/RULE_REMOVAL_N1.md` §C.3), plus ground truth (§C.2) and
hand-triage (§C.4):

| language | what runs | SAST findings kept (V2, before → after) | documented-vuln evidence | status |
|---|---|---|---|---|
| **PHP** | `aegis-php-*` (5 taint rules) | 247 → 45 (18 %) on the 4 repos that completed before; **Dolibarr now completes: 2,649** | DVWA 3/6 unchanged; M1: 25 of 31 DVWA findings TP | **real on vulnerable apps; see the Dolibarr caveat** — `aegis-php-xss` fires 2,362 times there, effectively all false (an app-wide WAF on `PHP_SELF`) |
| **JS / TS** | `aegis-js-*` (11) + **njsscan** (114, LGPL-3.0) | JavaScript 323 → 103 (32 %), TypeScript 173 → 130 (75 %) | NodeGoat 5/7 unchanged; juice-shop 9 → **7**/25 (directory listing lost) | **strongest** — our taint rules precise; njsscan 27 % precise |
| **Java** | `aegis-java-*` (7 taint, intraprocedural) | 60 → 6 (10 %) | WebGoat 6/6 unchanged | **narrow** — injection, path traversal, SSRF only; OWASP Benchmark Youden 0.051 |
| **Python** | `aegis-py-*` (8 taint + 4 H1 pattern) | 78 → 19 (24 %) | dvpwa 1/1 unchanged | **narrow** — H1's 17/17 TP stands |
| **Go** | `aegis-go-*` (7 taint) | no Go repo in V2 | — | **narrow, unmeasured on real code** |
| **Ruby** | none | 582 → **0** | — | **no application-code SAST** |
| **C#** | none | 26 → **0** | — | **no application-code SAST** |
| **(any) CI/CD** | `aegis-cicd-*` (3) | 37 → 37 | H2: 32/32 TP | unchanged; the only SAST that fires on Ruby and C# repos |
| **Dockerfile / Terraform / k8s** | Trivy misconfig | registry duplicates removed | — | unchanged (Trivy) |

**The honest position.** Before N1 this section argued our packs added value *on top of* the
registry. There is no longer a registry. On PHP and JS/TS our own packs carry every documented
vulnerability we detected before the cut. On Java, Python and Go they cover the injection classes
and little else. On Ruby and C# we do no application-code SAST at all. Everything outside SAST —
SCA, secrets, IaC, quality, prioritisation, lifecycle — is unaffected. The rebuild plan, ranked by
measured loss, is `docs/RULE_REMOVAL_N1.md` §E.

---

## SCA (trivy)

| metric | value | corpus | date / commit | confidence |
|---|---|---|---|---|
| **Actionable findings, before → after CVSS fix** | **185 → 165** crit+high | V1 / P1 replay | 2026-08-31 / `ad0dd66` | exact (mechanical) |
| **Severity corrections (v3.1 vector vs old `max()`)** | **22 findings** (18 high→med, 2 crit→high, 1 crit→med, 1 high→low) | V1 / P1 replay | 2026-08-31 / `ad0dd66` | exact |
| **Real-world precision (is the CVE real for this version?)** | **spot-checked, NOT measured** | V1 | 2026-08-26 / `aa0121c` | low (n=1 detailed) |

SCA's true/false question is version math: does this package@version have this CVE?
Trivy matches against advisory databases, so phantom matches are rare by
construction — but **this was not measured**: only **1 of the 165** actionable
findings was verified in detail (`dompdf/dompdf@2.0.8` → CVE with fix in 3.1.6, a
real advisory match), plus the aggregate structure (155/165 carry a fixed-version,
consistent with real advisories). A real precision number needs each finding's
advisory checked against the installed version; that is not done here. SCA's known
problem was never phantom CVEs — it was **severity inflation** (the `_best_cvss`
`max()` bug, CORRECTION 3) and **prioritization**: 135 of 185 pre-fix actionable
were transitive + not-reachable, real but lower-urgency.

---

## Bug pack (reliability)

| metric | value | corpus | date / commit | confidence |
|---|---|---|---|---|
| **Real-world precision** | **5 TP / 0 FP (n = 5)** | V1 (`docs/VALIDATION_RUN_V1.md`) | 2026-08-26 / `aa0121c` | high per verdict, **wide interval** on n=5 |
| **Real-world recall** | **NOT MEASURED — no ground-truth corpus run** | — | — | — |

Unchanged by P1/P2. **n = 5** is a small sample: 5/5 is a strong signal that the
pack is not spraying false positives, but the confidence *interval* on a 5-sample
precision is wide (a Wilson 95% lower bound sits near ~0.57), so "5 TP / 0 FP" is
the honest statement, not "100% precision". **Recall is unmeasured**: it needs a
labelled bug corpus — BugsInPy, Defects4J, or QuixBugs — run end-to-end, which has
not been done. The pack ships gated to zero false positives; see
`services/scanner/tests/test_bug_rules.py`.

---

## Other capabilities — measured, or explicitly not

The doc claims to be the single source, so every capability that has ever carried an
accuracy-flavoured claim is listed here with its real status. "Verified" = a
functional test proves the behaviour on fixtures; "not measured" = no rate/accuracy
number exists.

| capability | status | evidence / what's missing |
|---|---|---|
| **Determinism** (same repo → same findings) | **verified, functional** (not a rate) | `test_seams.py::test_seam_scan_is_deterministic` — byte-identical findings on a repeat scan of one fixture; **N1 (2026-09-19): five ground-truth repos scanned twice on the sovereign rule set — identical `rule_pack_version` and byte-identical findings on all five** |
| **Cross-tenant isolation** | **not measured as a rate** | it is an access-control property (org-scoped queries), not a detection rate; belongs in a security review, not here. No isolation-accuracy number is claimed |
| **Reachability accuracy** (is a "reachable" CVE truly reachable?) | **NOT MEASURED** | Trivy/our reachability sets a `reachable` flag; its precision/recall against ground truth has not been measured. On V1, 135/185 actionable SCA were transitive+not-reachable, but "not-reachable" itself is unverified |
| **KEV flagging** | **not measured** | we tag CVEs present in CISA KEV; the tag's correctness (list freshness, id match) has no measured accuracy — it inherits the KEV feed's |
| **EPSS scores** | **passthrough, not ours** | EPSS is attached from FIRST's model; we do not compute or validate it. Not an Aegis accuracy claim |
| **Lifecycle / fingerprint tracking** (same finding across scans) | **verified, functional** (not a rate) | stable-fingerprint enrichment; F1 exercised New→Existing→Resolved→Reopened plus a 20-line shift with unchanged fingerprints on a purpose-built repo. **N1:** a finding is resolved only when the detector that raised it ran; a finding whose rule no longer ships is `retired` (neither open nor fixed), and a failed engine resolves nothing — DB-backed test `TestLifecycleNeverResolvesWhatDidNotRun` (CORRECTION 11) |
| **ML false-positive filter — safety** | **verified, functional** (not a rate) | advisory only: `false_positive_probability` appears solely in `ORDER BY` (API) and the web sort comparator — no `WHERE` filters on it. F1 marked 3 criticals as FP: all stayed visible and stayed `critical` |
| **ML false-positive filter — learning from your feedback** | **NOT automatic — manual retrain only** | see CORRECTION 7. Feedback updates `project_rule_stats.fp_rate` (live, feeds project memory), but nothing changes the model's `P(fp)` without a manual `ml.train` run |
| **"Competes with SonarQube on quality"** | **NOT RUN — no evidence** | deferred three times. F2 (2026-09-06) got SonarQube CE 9.9.8 to `status:UP` at 1.53 GiB, but the scanner could not complete on a **3.744 GiB** Docker VM (analysis exceeded 10 min reading across a Windows named volume, then the engine died). Recorded NOT RUN in `docs/COMPETITIVE_F2.md` §A. Needs ≥ 8 GiB. Do not make this claim until a head-to-head exists |
| **Marginal value over registry-only Semgrep** | **no longer applicable** | Aegis no longer ships registry rules (N1), so our rules are not a margin on top of anything — for most languages they are the whole of SAST. See the per-language table |
| **Privacy guarantees** (self-hosted, source never leaves, AI opt-in) | **verified, functional** (not a rate) | code never executed (architectural); ML features metadata-only; secrets redacted at the egress chokepoint (18 tests + observed in Postgres on real repos); `ai_fix_enabled` defaults false. There is **no** graded privacy ladder — CORRECTION 6 |

None of the "not measured" rows should be cited as an accuracy claim anywhere until
a number with corpus + date + commit exists here.

---

## Compliance frameworks — what we assess, and how it was verified

Measured 2026-09-08 (J1 `0a3d992`, J2). **Aegis produces technical evidence toward these controls.
It does not assess a framework, and no report may be presented as coverage of one.** The
denominators below are the claim; the percentage on any report is computed over the *assessed*
column only.

| framework | standard total | assessed | claim | control text verified against |
|---|---|--:|---|---|
| **OWASP ASVS 4.0.3** | 286 requirements, 14 chapters | **11** | **headline** | published normative text |
| **SOC 2 (2017 TSC)** | 33 Common Criteria | **6** (7 before N1) | **headline** | numbering + titles only — **normative text paywalled, not read** |
| ISO/IEC 27001:2022 | 93 Annex A controls | **7** (8 before N1) | supporting evidence | numbering + titles only — **paywalled, not read** |
| NIST CSF 2.0 | 106 subcategories | **7** | supporting evidence | published normative text |
| HIPAA Security Rule | ~18 standards, 3 safeguard families | **5** | supporting evidence | published normative text (45 CFR 164.312) |
| PCI DSS 4.0 | 12 requirements, **~300 sub-requirements** | **7** | supporting evidence | numbering + titles only — **terms-gated, not read** |

Only **ASVS and SOC 2** are headline claims. Every other framework prints
*"SUPPORTING EVIDENCE ONLY"* on its own report, and the three paywalled ones print that their
normative text was not read. A test fails if that set drifts.

**Mapping integrity, enforced structurally** (`tests/test_compliance_mappings.py` +
`tools/check_single_framework_tree.py` in CI):

- One finding is attributed to **at most one control** — 9,871 double-attributions across 14,041
  real findings became 0 in J1.
- Every evidence identifier must be one an engine can actually emit — **36 dead entries removed** in
  J2, **71 more in N1** when the Semgrep-registry rules went; a control whose evidence could never
  fire would report "no findings" when the truth is "never checked". N1 turned SOC 2 CC6.3 and ISO
  27001 A.8.2 `not-assessed`: their only evidence (CWE-269) had come from removed rules. The
  inventory's "observed" half now counts only findings from detectors that still ship.
- The framework mappings exist in **exactly one place**; a second copy diverged silently through
  all of J1.
- A control we cannot evidence is **`not-assessed`** and excluded from both sides of the score, not
  counted as a pass. Status wording is **"no findings"**, never "passing".

## SBOM — conformance and the NTIA elements

Formats: **CycloneDX 1.7** and **SPDX 2.3**, generated by Trivy 0.71.2. Both validate clean against
the standards bodies' own validators (`cyclonedx-python-lib 11.12.0`, `spdx-tools 0.8.5`) — 5/5
documents each, 0 messages, 0 internal path leaks. Before J1 **every SPDX document failed** (937
errors) because Trivy embedded our internal checkout path as each package's `downloadLocation`.

| NTIA minimum element | npm | pip | composer | go | maven |
|---|--:|--:|--:|--:|---|
| **Supplier name** | **0%** | **0%** | **0%** | **0%** | not measured |
| Component name | 100% | 100% | 100% | 100% | not measured |
| Version | 99.7% | 99.6% | 85.7% | 97.1% | not measured |
| Other unique identifiers (purl) | 99.7% | 99.6% | 85.7% | 98.6% | not measured |
| Dependency relationships | 100%, depth 12 | 100%, depth 9 | 100%, depth 4 | 100%, depth 3 | not measured |
| Author of SBOM data | ✅ | ✅ | ✅ | ✅ | not measured |
| Timestamp | 100% | 100% | 100% | 100% | not measured |

**Two declared gaps, both deliberate:**

- **Supplier name — 0%, the one failing NTIA element.** Resolving it needs a registry lookup per
  package: outbound traffic per scan disclosing the customer's dependency list, in a self-hosted
  privacy-first product. Inferring it from the purl namespace gives a registry coordinate, not a
  supplier — and a guessed supplier in an audit document is fabricated provenance. Not attempted.
- **Maven — "not measured", not 0%.** Trivy resolves Maven projects by fetching parent POMs from
  Maven Central, which rate-limited and blocked us (`429`, ~30 min, still blocked on retry). Its own
  remedy is `mvn dependency:resolve` — building customer code, which the no-execution boundary
  forbids. A boundary consequence, not a bug. Options (offline resolution, customer-supplied
  `~/.m2`, CI-side generation) are open product decisions.

**Go relationships are complete, not flat** — J1 reported "3.6% (5/139), does not meet the NTIA
element" by counting nodes-with-children instead of edges. Re-measured: 138 edges, all 138
components reachable from the root, element met. The real limitation is depth (3 vs npm's 12), which
would need `go mod graph` or a per-module network fetch. See CORRECTION 9.

An SBOM that catalogues **zero** components (a manifest with no lockfile) is never stored, so it
cannot be presented as a complete inventory; the read path reports "none was generated".


---

## CORRECTIONS

Prior accuracy statements that were wrong or unscoped. Recording them is what makes
the numbers above trustworthy.

1. **"Secrets: 1.00 precision" was stated without scope.** It is true *on the
   synthetic secrets-bench* (planted real-format secrets). It was read as a
   real-world claim, which it is not: on V1 the actionable secret set is dominated
   by `generic-api-key` matches in documentation and config, and real-world precision
   is bounded at **≤ 0.77** (n=100, 77 untriaged). Benchmark and real-world are now
   separate rows.

2. **"Real-world FP ~0%" was measured on too narrow a corpus.** The V1 corpus
   surfaced FP classes the claim missed: secrets in documentation `.mdx` files, and
   authored-taint FPs (the navidrome `cascadia.Query` and eladmin `System.out`
   matches). FP is not ~0%. P1 removed two definite FP classes (`ai-code-*` pack;
   placeholder/expired secrets); **P2 removed more** — 5 of 7 authored-taint FPs
   (source + sink fixes) and 23 documentation-path secret FPs (down-ranked) — but
   the remainder is still not zero (2 SSRF config/internal-URL FPs; 77 untriaged
   secrets).

3. **OWASP was reported by F1, the metric that favours us.** The benchmark's own
   canonical score is the Youden index (TPR − FPR); F1 flatters our high-recall /
   high-FPR profile. Both are now published side-by-side. Rechecked against an
   independent source (*Sifting the Noise*, arXiv:2601.22952), Aegis leads CodeQL on
   **both** F1 (0.775 vs 0.744) and Youden (0.459 vs 0.288) *on that synthetic Java
   benchmark* — but it should never again be stated on F1 alone, and, per CORRECTION 8,
   it must no longer be generalised into an overall "beats CodeQL" claim.

4. **`_best_cvss` used `max()` across CVSS sources for the entire life of the SCA
   engine.** Every prior validation's SCA **severity** was therefore inflated (on V1,
   22 of 280 vector-bearing findings drop a band when recomputed from the single
   authoritative v3.1 vector; 20 of them leave the actionable crit+high tier).
   **TP/FP verdicts and version math were unaffected** — a real CVE stayed a real
   CVE; only its severity label was too high.

5. **The `ai-code-*` rule family shipped 188 findings on V1 (86 at actionable
   severity), overwhelmingly false.** It belonged to the AI-code-detection feature
   cut in migration `000022` (ROC-AUC 0.541), its customer-facing ids told people
   their handwritten code "looks AI-generated," and its SQL rules had no taint
   sources/sinks (74 fired on trusted `outline` DB migrations alone). Deleted in P1;
   real coverage is retained by the taint pack (`rules/taint/`, real sources+sinks),
   the registry security-audit pack, and gitleaks.

6. **A five-layer "privacy ladder" (L1–L5) was described in the README but never
   existed.** Pass F1 grepped the whole repository — Go, Python, SQL, TypeScript, config
   and docs — for any graded privacy or data-sharing control and found nothing: no
   privacy-level setting, no tiering, no code path that varies data exposure by level.
   What is real, and is what the README now says, is narrower and checkable: Aegis is
   self-hosted, it never executes the scanned code, source never leaves the customer's
   infrastructure, the ML features are metadata-only, secrets are redacted at the egress
   boundary, and AI is opt-in per project and off by default. A claimed capability that
   was never implemented belongs here rather than in a feature list.

7. **"Learns from your feedback" is a manual capability, not an automated loop, and the
   headline probability shift was never the product's runtime behaviour.** The
   0.035 → 0.995 shift recorded in `INTELLIGENCE_VERIFICATION.md` (and the earlier
   0.03 → 0.51) was produced by feeding feedback events to `ml.train` **by hand** in a
   verification harness. F1 tested the product path instead — marked 3 findings as false
   positives through the API, then ran a full rescan — and the probabilities came back
   byte-identical (0.0026 → 0.0026, 0.0093 → 0.0093, 0.0014 → 0.0014). This did **not**
   regress: commit `023c88d` documented the gap at the time ("the loop is NOT automated
   end-to-end … the global model ships trained on the seed only"). Two things are true
   and worth separating: feedback **is** consumed — `UpsertRuleStats` writes
   `project_rule_stats.fp_rate` live, and F1's three marks landed there with
   `fp_rate 1.000`, feeding the project-memory surface — but it does **not** reach the ML
   score, because there is no feedback→JSONL export and no scheduled retrain job. Until
   those are wired, no doc may claim the classifier learns from feedback automatically.
   The *safety* property is separate and does hold: the score can only re-rank, never
   hide (capability table above).

8. **"Beats CodeQL" was a cross-study claim on synthetic Java, and it does not survive a
   same-harness run on real code.** F2 (2026-09-06) ran **CodeQL CLI 2.26.4** against the
   *same checkouts* Aegis scanned, using the broader `security-extended` suites. On
   **NodeGoat**, scored against vulnerabilities the project plants deliberately and that
   were verified by reading the source, **CodeQL recalled 6/7 (86 %) and Aegis 4/7 (57 %)**.
   Aegis missed the flagship `$where` NoSQL injection (`allocations-dao.js:78`) and a
   planted nested-quantifier ReDoS (`profile.js:59`); hand-triage of CodeQL's unique
   findings found them mostly true positives. **The overall "beats CodeQL" framing is
   withdrawn.** What survives is narrower and still true: on the OWASP synthetic-Java
   benchmark Aegis is the more precise tool (FPR 0.425 vs 0.682); on **Python**, Aegis
   caught dvpwa's documented SQL injection and **CodeQL missed it** (confirmed not an
   extraction failure — the file is in CodeQL's database with 0 extraction errors); and
   **CodeQL cannot scan PHP at all**, so it had nothing to say about the 13.8k-LOC PHP app
   in the corpus. The defensible claim is *"CodeQL is deeper where it runs; Aegis runs in
   more places and adds the SCA/secrets/IaC/prioritisation layer CodeQL has no equivalent
   for"* — a breadth-and-workflow claim, not a depth claim. See `docs/COMPETITIVE_F2.md`.

9. **"Go SBOM dependency relationships are effectively flat (3.6%, 5/139)" was a measurement
   error, not a finding.** J1 (2026-09-08) reported that Go SBOMs fail the NTIA dependency-
   relationship element. That row counted **nodes that have children** rather than edges, and
   in a Go SBOM nearly every edge hangs off two module nodes (`api` → 75 children,
   `orchestrator` → 59). Re-measured by reachability in J2: **138 edges, all 138 components
   reachable from the root — 100 % coverage, and the element is met.** What Go genuinely lacks
   is *depth*: the graph is 3 levels deep against npm's 12, so we can say which module includes
   a component but not which direct dependency pulled in a given transitive one. Closing that
   requires `go mod graph` (running the Go toolchain over customer code) or fetching each
   module's `go.mod` (a network call per package); both are ruled out by existing boundaries, so
   it is declared rather than fixed. The correction moves the claim in our favour, which is
   exactly why it needed checking: **the same reachability metric is now applied to every
   ecosystem**, so npm/pip/composer are stated on the same basis. See
   `docs/COMPLIANCE_SCOPE_J2.md` §4.1.

10. **Compliance control mappings existed in two places, and only one was fixed.** J1 corrected
    the framework YAMLs the loader reads. A second, stale copy sat at the repository root with
    its own README, still carrying the wrong HIPAA control title, CC6.3's over-broad CWE-732 and
    CC8.1's wrong title — and its README still documented the pre-J1 double-counting behaviour as
    intended. Being at the root, it was the copy a reader found first. Deleted in J2, with a CI
    check that fails the build if a second tree reappears. No compliance number was wrong as a
    result (the loader never read it), but any reader of the repository would have been misled.

11. **Every SAST number before 2026-09-19 was measured with rules Aegis may not ship.**
    Pass N1 (2026-09-19) removed the 16 Semgrep-registry packs — 2,677 rule entries, 1,142
    unique rules, all under the **Semgrep Rules License v1.0** — after Semgrep's head of legal
    declined an OEM licence, declined relicensing, and confirmed permitted use is limited. What
    ships now is Aegis's own 60 rules plus njsscan (114 rules, LGPL-3.0-or-later, rebuilt from
    upstream source). The Semgrep CE engine (LGPL-2.1) is unaffected. Re-measured the same day,
    same harness, before and after:
    - **OWASP Benchmark v1.2: Youden 0.459 → 0.051, F1 0.775 → 0.247, TPR 0.884 → 0.154, FPR
      0.425 → 0.103.** Aegis now scores below CodeQL and base Semgrep on it. The "leads on
      Youden" claim is withdrawn.
    - **Ground truth: 24 → 22 of 45 documented vulnerabilities** on five repositories. DVWA,
      WebGoat, NodeGoat and dvpwa are unchanged; juice-shop loses two directory-listing
      challenges. G2's "no documented vulnerability is lost" held for its three repositories,
      not for five, and was corrected in G3 §5.
    - **Precision did not rise.** Hand-triaged sovereign findings: Aegis taint rules 73 %,
      njsscan 27 %, overall 46–56 %, against G3's 55 % for the rules removed. At corpus volume it
      is worse: Dolibarr, whose SAST timed out before and now completes, yields 2,362
      `aegis-php-xss` findings that are effectively all false (an application-wide WAF filters
      `PHP_SELF`; 25/25 sampled FP). SAST now completes on 14 of V2's 15 repositories, against 11.
    - **Compliance:** 71 dead evidence identifiers removed; SOC 2 CC6.3 and ISO 27001 A.8.2
      became `not-assessed`.
    - **A lifecycle defect the cut would have triggered:** every finding raised by a removed rule
      would have been marked *resolved* on each project's next scan, and so appeared as
      remediation evidence in compliance reports. Fixed before release with a `retired` state;
      the same fix stops a timed-out engine from resolving everything it had found.
    Full record: `docs/RULE_REMOVAL_N1.md`.

---

## Superseded benchmark history

Kept for provenance, **not for citation as a current claim** (N2). These measured synthetic
Java under two different rule sets, neither of which represents what Aegis ships today; see
the withdrawal note in the SAST section above.

The OWASP Benchmark's canonical score is the **Youden index (TPR − FPR)**, not F1.
F1 flatters a high-recall / high-FPR profile; Youden penalises the false positives.
Here is the side-by-side (Aegis measured by us; CodeQL and base Semgrep from an
independent 2026 study, *Sifting the Noise*, arXiv:2601.22952 Table 2 — all on
OWASP Benchmark v1.2, 2,740 cases):

| tool | TPR | FPR | F1 | **Youden** | source |
|---|---|---|---|---|---|
| **Aegis — what ships (N1, sovereign)** | **0.154** | **0.103** | **0.247** | **0.051** | ours, `docs/RULE_REMOVAL_N1.md` §C.1 — 2026-09-19 |
| CodeQL | 0.970 | 0.682 | 0.744 | 0.288 | *Sifting the Noise*, Table 2 |
| base Semgrep (default rules) | 0.904 | 0.748 | 0.694 | 0.156 | *Sifting the Noise*, Table 2 |
| ~~Aegis with the Semgrep-registry packs~~ — **no longer shipped** | ~~0.884~~ | ~~0.425~~ | ~~0.775~~ | ~~0.459~~ | pre-N1; re-confirmed to four decimals on 2026-09-19 before the cut |

**On this benchmark Aegis now scores below both CodeQL and base Semgrep** (Youden 0.051 vs 0.288
and 0.156). The earlier lead came from the Semgrep-registry rules, which Aegis no longer ships
(CORRECTION 11): 2,404 of the 2,865 findings in the pre-cut run were theirs. What ships is our own
Java taint pack — the 461 remaining findings are *exactly* its findings in the pre-cut run. It keeps
SQLi, XSS and path traversal at much lower recall and much lower FPR, and scores **zero** in five
categories (weak random, weak crypto, weak hash, insecure cookie, trust boundary) that were entirely
registry rules. Do not cite this benchmark in pitch material except with the sovereign row.

**Limitation — this is a cross-study comparison on SYNTHETIC JAVA, and a same-harness
run on real code now contradicts the framing it was used to support.**
> **Pass F2 (2026-09-06) ran CodeQL CLI 2.26.4 on the same checkouts as Aegis and found the
> opposite result on real JavaScript.** Against NodeGoat's documented, source-verified
> vulnerabilities, **CodeQL recalled 6/7 (86 %) and Aegis 4/7 (57 %)** — Aegis missed the
> flagship `$where` NoSQL injection and a planted ReDoS. **The "beats CodeQL" framing is
> therefore withdrawn** (see CORRECTION 8 and `docs/COMPETITIVE_F2.md` §B.2). The table below
> is retained because it is a real, correctly-cited benchmark result, but it measures
> *synthetic Java taint under the Youden metric* and must not be generalised into an
> overall "we beat CodeQL" claim. The same pass also found the reverse on Python (Aegis
> caught dvpwa's documented SQLi, CodeQL missed it) and that **CodeQL cannot scan PHP at
> all** — so the honest summary is "CodeQL is deeper where it runs; Aegis runs in more
> places", not that either tool wins outright.
>
> **Sovereign status (N1, 2026-09-19).** NodeGoat is now **5/7**, before and after the cut —
> later passes added the `$where` NoSQL and ReDoS rules F2 found missing. The dvpwa SQLi that
> F2 credited to the registry rule `sqlalchemy-execute-raw-query` is still caught, by our own
> `aegis-py-sql-string-construction` (H1).
Aegis's TPR/FPR were measured on our own harness; CodeQL's and base Semgrep's are
taken from Xiong & Zhang, *Sifting the Noise* (arXiv:2601.22952, Table 2). The
paper's figures were verified against the source (CodeQL FPR 0.682 matches their
reported value), but tool version, configuration, and which CWE categories were
scored can differ between their run and ours, so treat the gap as indicative, not
exact. The clean version — running CodeQL ourselves on our own harness — is a
pre-funding-deck TODO, not done here. And this is a *synthetic Java taint*
benchmark: a benchmark score is not a real-world precision claim (see the V1 triage
below, and CORRECTION 2).

