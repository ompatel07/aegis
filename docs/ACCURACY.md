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
| **V1 (S1-corrected)** | 5 biggest-offender repos re-scanned LIVE with real secret values (585/630 secrets); offline signals for the other 10 | 2026-08-26 | `66db94d` | same |
| **P1 replay** | offline replay of Parts A+B over the V1 corpus (`scripts/precision_p1_replay.py`) | 2026-08-31 | `65fe09e`+P1 | n/a (no re-scan) |
| **secrets-bench** | synthetic: 12 planted real-format secrets + 8 decoys (`benchmarks/comparative/secrets_bench.py`) | 2026-08-31 | `65fe09e`+P1 | gitleaks 8.21.2 |
| **OWASP Benchmark v1.2** | 2,740 generated Java taint testcases (`benchmarks/owasp/`) | see `QUALITY_BENCHMARK.md` | per that doc | semgrep 1.97.0 + Aegis Java taint rules |

"P1" = this pass. Parts A (delete `ai-code-*` pack) and B (suppress placeholder /
expired secrets) change the finding set; the replay measures the before/after
offline — **it does not re-scan** the 15 repos.

---

## Secrets (gitleaks)

| metric | value | corpus | date / commit | confidence |
|---|---|---|---|---|
| **Benchmark precision** | **1.00** (11 TP / 0 FP) | secrets-bench (synthetic) | 2026-08-31 / `65fe09e`+P1 | exact (planted labels) |
| **Benchmark recall** | **0.917** (11 TP / 1 FN) | secrets-bench | 2026-08-31 / `65fe09e`+P1 | exact; the 1 FN is a context-free AWS *secret* (not id), a pre-existing gitleaks miss unrelated to P1 |
| **Real-world, actionable severity** | **NOT ~0% FP — materially lower precision** (see below) | V1 (S1-corrected) | 2026-08-26 / `66db94d` | medium (triaged; values redacted) |

**Real-world detail.** V1 raw: **630 secret findings, all reported CRITICAL.** After
S1 + P1 (LIVE classification, 585/630 findings):

- **425 test-fixture** → kept at LOW + tagged (may be real; a human still triages).
- **60 suppressed by P1** (46 placeholder-shape + 14 expired JWT) — definitively not
  credentials; removed from findings, counted in `EngineResult.filtered_secrets`.
- **100 "kept" at actionable severity** — no fixture/placeholder/expired/live-format
  signal fired. Triaging these by rule + path (values are redacted, so this is
  path/rule triage, medium confidence): **≥23 are `generic-api-key` / `private-key`
  matches inside documentation `.mdx` files** (`apps/docs/.../api/*.mdx`, webhook and
  self-hosting config docs) — API-usage examples, i.e. **false positives** the
  fixture-path prior misses because doc paths aren't in it. The remaining ~77 are
  mostly `generic-api-key` in source/config, a low-precision rule; a meaningful share
  are config placeholders. **Conclusion: real-world actionable-secret precision is
  well below the benchmark's 1.00.** The benchmark plants real-format secrets; it does
  not contain the doc/config noise that dominates the real-world false positives.
- **Offline 10 repos** (45 findings, redacted): reproducible lower bound of 21
  fixture + (≥0) placeholder; true suppression ≥ shown.

The provider-key override (AWS `AKIA`, GitHub `ghp_`, Stripe `sk_live_`, PEM key
body, …) wins over every signal in every path and is regression-tested
(`test_secret_context.py`).

---

## SAST (semgrep)

| metric | value | corpus | date / commit | confidence |
|---|---|---|---|---|
| **Benchmark F1 (OWASP)** | **0.775** (TPR 0.884, FPR **0.425**) | OWASP Benchmark v1.2, 2,740 cases | `QUALITY_BENCHMARK.md` | exact (generated labels) |
| **Actionable findings, before → after Part A** | **266 → 180** crit+high (removed 188 `ai-code-*`: 86 high + 102 medium) | V1 / P1 replay | 2026-08-31 / `65fe09e`+P1 | exact (mechanical) |
| **Real-world precision, our `aegis-*` taint** | **≤ 2 of 7 plausibly real; ≥1 confirmed FP** | V1 | 2026-08-26 / `aa0121c` | mixed (see below) |

**OWASP F1 0.775 is a *synthetic Java SAST-taint* number**, and it beats CodeQL's
published **0.744** on the same benchmark. But read it with its own FPR: **0.425** —
the benchmark rewards recall and tolerates a high false-positive rate. That FPR is
consistent with the real-world SAST FPs below; the F1 is not a precision claim.

**Real-world `aegis-*` taint triage (V1, from stored snippets — confidence noted):**

| repo / rule | file | verdict | confidence |
|---|---|---|---|
| navidrome `aegis-go-sql-injection` | `adapters/lastfm/agent.go` | **FP** — snippet is `cascadia.Query()` (an HTML/CSS selector), not SQL | high |
| monica `aegis-js-ssrf` | `resources/js/sentry.js` | **FP** — URL is the Sentry DSN (config), not user input | medium |
| pocketbase `aegis-go-sql-injection` ×3 | `apis/{collection,logs,record_crud}.go` | **likely FP** — PocketBase's `search.Provider` parses user filters through a safe expression builder | medium |
| eladmin `aegis-java-xss` | `AliPayController.java` | **uncertain** — `request.getParameter` source; sink appears to be `System.out` (stdout ≠ XSS) | low |
| navidrome `aegis-go-ssrf` | `plugins/host_subsonicapi.go` | **uncertain** — internal API proxy | low |

The 180 actionable SAST findings also include **82 "secret-shaped" registry rules**
(`node_secret`, `node_password`, `detected-jwt-token`, `detected-bcrypt-hash`, …)
that overlap the secrets pillar and share its false-positive classes, and **91 other
community rules**. These were not exhaustively triaged; the honest headline is that
our authored taint rules have **low real-world precision on V1** (a rule-quality
follow-up, not fixed in P1) despite a strong synthetic F1.

---

## SCA (trivy)

| metric | value | corpus | date / commit | confidence |
|---|---|---|---|---|
| **Actionable findings, before → after CVSS fix** | **185 → 165** crit+high | V1 / P1 replay | 2026-08-31 / `65fe09e`+P1 | exact (mechanical) |
| **Severity corrections (v3.1 vector vs old `max()`)** | **22 findings** (18 high→med, 2 crit→high, 1 crit→med, 1 high→low) | V1 / P1 replay | 2026-08-31 | exact |
| **Real-world precision (is the CVE real for this version?)** | **≈ high (~100%)** — these are real advisory-matched CVEs | V1 | 2026-08-26 / `aa0121c` | medium-high |

SCA's true/false question is version math: does this package@version have this CVE?
Trivy matches against advisory databases, and spot-checking the actionable set
(e.g. `dompdf/dompdf@2.0.8` → CVE with fix in 3.1.6) shows **real CVEs**, not
phantom matches. SCA's historical problem was never phantom CVEs — it was **severity
inflation** (the `_best_cvss` `max()` bug, corrected below) and **prioritization**:
135 of 185 actionable are transitive + not-reachable, real but lower-urgency.

---

## Bug pack (reliability)

| metric | value | corpus | date / commit | confidence |
|---|---|---|---|---|
| **Real-world precision** | **5 TP / 0 FP** | V1 (`docs/VALIDATION_RUN_V1.md`) | 2026-08-26 / `aa0121c` | high (hand-triaged with source windows) |

Unchanged by P1. The pack ships gated to zero false positives; see
`services/scanner/tests/test_bug_rules.py`.

---

## CORRECTIONS

Prior accuracy statements that were wrong or unscoped. Recording them is what makes
the numbers above trustworthy.

1. **"Secrets: 1.00 precision" was stated without scope.** It is true *on the
   synthetic secrets-bench* (planted real-format secrets). It was read as a
   real-world claim, which it is not: on V1 the actionable secret set is dominated
   by `generic-api-key` matches in documentation and config, and real-world
   precision is materially below 1.00. Benchmark and real-world are now separate
   rows above.

2. **"Real-world FP ~0%" was measured on too narrow a corpus.** The V1 corpus shows
   a residual false-positive class the earlier claim missed: secrets in
   documentation `.mdx` files (not caught by the fixture-path prior) and low-precision
   `generic-api-key` matches, plus SAST taint FPs like the navidrome `cascadia.Query`
   mismatch. FP is not ~0%. P1 removes two definite FP classes (the `ai-code-*` pack;
   placeholder/expired secrets) but does not make the remainder zero.

3. **`_best_cvss` used `max()` across CVSS sources for the entire life of the SCA
   engine.** Every prior validation's SCA **severity** was therefore inflated (on V1,
   22 of 280 vector-bearing findings drop a band when recomputed from the single
   authoritative v3.1 vector; 20 of them leave the actionable crit+high tier).
   **TP/FP verdicts and version math were unaffected** — a real CVE stayed a real
   CVE; only its severity label was too high.

4. **The `ai-code-*` rule family shipped 188 findings on V1 (86 at actionable
   severity), overwhelmingly false.** It belonged to the AI-code-detection feature
   cut in migration `000022` (ROC-AUC 0.541), its customer-facing ids told people
   their handwritten code "looks AI-generated," and its SQL rules had no taint
   sources/sinks (74 fired on trusted `outline` DB migrations alone). Deleted in P1;
   real coverage is retained by the taint pack (`rules/taint/`, real sources+sinks),
   the registry security-audit pack, and gitleaks.
