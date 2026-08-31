# Aegis accuracy — the single source of claims

This file is the **only** place Aegis's accuracy numbers are stated. Every number
below carries the four things that make it a claim and not a vibe: **what** was
measured, on **which corpus**, on **what date**, at **which commit**. A number
without those four does not belong in this file, and no accuracy number belongs
anywhere else in the repo, marketing, or UI without a pointer back here.

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
| **OWASP Benchmark v1.2** | 2,740 generated Java taint testcases (`benchmarks/owasp/`) | per `QUALITY_BENCHMARK.md` | `aa0121c`-era | semgrep 1.97.0 + Aegis Java taint rules |
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

### Benchmark — OWASP Benchmark v1.2, by the benchmark's own metric (Youden)

The OWASP Benchmark's canonical score is the **Youden index (TPR − FPR)**, not F1.
F1 flatters a high-recall / high-FPR profile; Youden penalises the false positives.
Here is the side-by-side (Aegis measured by us; CodeQL and base Semgrep from an
independent 2026 study, *Sifting the Noise*, arXiv:2601.22952 Table 2 — all on
OWASP Benchmark v1.2, 2,740 cases):

| tool | TPR | FPR | F1 | **Youden** | source |
|---|---|---|---|---|---|
| **Aegis** (semgrep + our Java taint rules) | 0.884 | **0.425** | 0.775 | **0.459** | ours, `QUALITY_BENCHMARK.md` |
| CodeQL | 0.970 | 0.682 | 0.744 | 0.288 | *Sifting the Noise*, Table 2 |
| base Semgrep (default rules) | 0.904 | 0.748 | 0.694 | 0.156 | *Sifting the Noise*, Table 2 |

**Aegis leads on both F1 (0.775 vs 0.744) and Youden (0.459 vs 0.288), and has by
far the lowest FPR (0.425 vs 0.682).** The comparative claim holds under the metric
that *disfavours* us, so it stays. Note our Java taint rules roughly halve base
Semgrep's FPR (0.748 → 0.425) — that FPR gap is the value the custom rules add.
Caveat: this is a *synthetic Java taint* benchmark; a benchmark score is not a
real-world precision claim (see the V1 triage below, and CORRECTION 2).

### Real-world — V1 corpus

| metric | value | corpus | date / commit | confidence |
|---|---|---|---|---|
| **Actionable findings, before → after Part A** | **266 → 180** crit+high (removed 188 `ai-code-*`: 86 high + 102 medium) | V1 / P1 replay | 2026-08-31 / `ad0dd66` | exact (mechanical) |
| **`aegis-*` taint FPs root-caused & fixed** | **5 of 7** V1 findings (P2) | V1 + minimal reproductions | 2026-08-31 / `ad0dd66`+P2 | high (mechanism verified) |

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
7 V1 taint FPs eliminated; the 2 residual are SSRF *config/internal-URL* FPs, a
distinct signal-quality problem left as a documented follow-up.

The 180 actionable SAST findings also include **82 "secret-shaped" registry rules**
(`node_secret`, `detected-bcrypt-hash`, …) overlapping the secrets pillar, and **91
other community rules**; these were not exhaustively triaged.

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
| **Determinism** (same repo → same findings) | **verified, functional** (not a rate) | `test_seams.py::test_seam_scan_is_deterministic` — byte-identical findings on a repeat scan of one fixture; not measured across the corpus |
| **Cross-tenant isolation** | **not measured as a rate** | it is an access-control property (org-scoped queries), not a detection rate; belongs in a security review, not here. No isolation-accuracy number is claimed |
| **Reachability accuracy** (is a "reachable" CVE truly reachable?) | **NOT MEASURED** | Trivy/our reachability sets a `reachable` flag; its precision/recall against ground truth has not been measured. On V1, 135/185 actionable SCA were transitive+not-reachable, but "not-reachable" itself is unverified |
| **KEV flagging** | **not measured** | we tag CVEs present in CISA KEV; the tag's correctness (list freshness, id match) has no measured accuracy — it inherits the KEV feed's |
| **EPSS scores** | **passthrough, not ours** | EPSS is attached from FIRST's model; we do not compute or validate it. Not an Aegis accuracy claim |
| **Lifecycle / fingerprint tracking** (same finding across scans) | **verified, functional** (not a rate) | stable-fingerprint enrichment; correctness across real re-scans over time is not measured |

None of the "not measured" rows should be cited as an accuracy claim anywhere until
a number with corpus + date + commit exists here.

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
   **both** F1 (0.775 vs 0.744) and Youden (0.459 vs 0.288), so the comparative claim
   holds — but it should never again be stated on F1 alone.

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
