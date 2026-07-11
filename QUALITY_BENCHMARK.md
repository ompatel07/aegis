# Quality Benchmark

Objective accuracy measurements of Aegis against public ground-truth datasets.
Run in batches (one benchmark per session) per the Phase 2D plan.

## Track 2a — OWASP Benchmark v1.2

**Dataset.** OWASP Benchmark v1.2 — 2,740 Java test cases (1,415 real
vulnerabilities, 1,325 safe variants) across 11 CWE categories, with a
ground-truth `expectedresults-1.2.csv`. Cloned from `OWASP-Benchmark/BenchmarkJava`.

**Method.** Aegis SAST engine (Semgrep with `p/owasp-top-ten`,
`p/r2c-security-audit`, `p/cwe-top-25`, `p/default` + Aegis's own Java taint
rules) scanned the 2,740 `testcode` files in **168 s** (with the new `--jobs`
parallelism, Track 1e). A test case counts as **detected** when Aegis reports a
finding of the category's CWE (using standard related-CWE sets, e.g. crypto
327≈326≈310) anywhere in that test file — the OWASP scoring convention.

### Headline result

| Metric | Aegis | Reference |
| --- | --- | --- |
| **F1 score** | **0.774** | CodeQL ≈ 0.744 (target: within 5 pts) → **met, +3.0 pts** |
| True Positive Rate (recall) | **0.884** | — |
| False Positive Rate | 0.428 | — |
| Youden's J (Benchmark score, TPR−FPR) | 0.456 | competitive with top SAST |
| Confusion matrix | TP 1251 · FP 567 · FN 164 · TN 758 | — |

**F1 = 77.4% clears both gates** in the quality rules — within 5 points of CodeQL
(actually 3 points above) and comfortably over the 69% "stop and tune" floor. No
rule tuning was required to hit target.

Every finding carried a correct CWE — the CWE-matched and category-lenient scoring
modes produced identical numbers, so the result does not depend on fuzzy matching.

### Per-category breakdown (TP / FP / FN / TN)

| Category (CWE) | TP | FP | FN | TN | Recall | Note |
| --- | --- | --- | --- | --- | --- | --- |
| crypto (327) | 130 | 0 | 0 | 116 | 100% | perfect |
| weakrand (330) | 218 | 0 | 0 | 275 | 100% | perfect |
| securecookie (614) | 36 | 0 | 0 | 31 | 100% | perfect |
| hash (328) | 89 | 0 | 40 | 107 | 69% | 0 FP; misses some SHA-1 variants |
| sqli (89) | 253 | 170 | 19 | 62 | 93% | high recall, sanitizer-unaware FPs |
| xss (79) | 202 | 116 | 44 | 93 | 82% | dataflow FPs |
| pathtraver (22) | 123 | 113 | 10 | 22 | 92% | dataflow FPs |
| cmdi (78) | 117 | 109 | 9 | 16 | 93% | dataflow FPs |
| trustbound (501) | 43 | 18 | 40 | 25 | 52% | weakest recall |
| ldapi (90) | 26 | 28 | 1 | 4 | 96% | small N |
| xpathi (643) | 14 | 13 | 1 | 7 | 93% | small N |

### Honest analysis

- **Recall is excellent (88%)** — Aegis finds the overwhelming majority of real
  vulnerabilities, the property that matters most for a security gate.
- **The false positives are structural, not random.** The four dataflow
  categories (sqli, xss, pathtraver, cmdi) account for **508 of 567 FPs**. The
  Benchmark's "safe" cases route input through a sanitizer; Aegis's registry
  rules are largely *pattern*-based (flag the sink) rather than *taint*-based
  (require an unsanitized source→sink path), so they flag the sanitized variants
  too. The purely presence-based categories (weak crypto/RNG/cookie) have **zero**
  false positives.
- **This is the known trade-off** for high-recall SAST and is exactly what Track
  2d (FP deep-dive) targets: converting the high-FP dataflow rules to taint-mode
  would cut the FPR and lift Youden's J without sacrificing the 88% recall. It is
  scoped as follow-up, not a blocker — the F1 target is already met.
- **`trustbound` (52% recall)** and **`hash` (69% recall)** are the recall gaps
  worth a rule pass in a later session.

**Verdict: PASS.** Aegis matches top-tier SAST on OWASP Benchmark v1.2
(F1 77.4% vs CodeQL 74.4%), with recall as its strength and dataflow-sanitizer
false positives as the identified area for taint-rule investment.

### Reproduce

```bash
# 1. clone the benchmark into the shared workspace volume
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git
# 2. scan testcode/ via the scanner /scan/sast endpoint (see scripts)
# 3. score findings vs expectedresults-1.2.csv (CWE-matched, related-CWE sets)
```

---

## Remaining Track 2 (subsequent sessions)

- **2c** 20-repo multi-language comparative vs SonarQube/Semgrep/Trivy
  (`COMPARATIVE_ANALYSIS.md`, commit per repo).
- **2b** real-world vuln corpus — the Bennett et al. 2024 paper uses the public
  **SAP/Ponta MSR-2019** dataset (170 Java CVEs evaluated; best single tool
  FindSecBugs = 26.5%). A bounded SAP sample is the plan (full run needs ~170
  production-repo clones).
- **2e** AI-code detection real-world validation (`AI_CODE_DETECTION_VALIDATION.md`).
- **2f** Joern deep-scan value on 10 repos.

_(Track 2d — false-positive deep-dive — is complete; see the section below.)_

---

## Track 2d — False-positive deep-dive (OWASP Benchmark rules)

Following 2a's high FPR, we attributed every OWASP Benchmark false positive to the
exact rule that produced it, then acted on the finding.

**Diagnostic.** The 567 FPs are dominated by Semgrep's **`security.audit.*`**
registry tier — deliberately low-confidence "audit these" rules — across the four
dataflow categories:

| Rule | FP | TP | FP-rate |
| --- | --- | --- | --- |
| `…audit.sqli.tainted-sql-from-http-request` | 143 | 234 | 38% |
| `…audit.xss.no-direct-response-writer` | 108 | 202 | 35% |
| `…security.httpservlet-path-traversal` | 106 | 120 | 47% |
| `…audit.tainted-cmd-from-http-request` | 96 | 112 | 46% |
| `…audit.sqli.jdbc-sqli` | 81 | 97 | 46% |
| `…audit.command-injection-process-builder` | 30 | 33 | 48% |

Crucially these same rules provide **most of the recall** — they cannot simply be
deleted. Aegis's own taint rules are precise but narrow (they only catch 27/253
sqli, 7/126 cmdi, because the Benchmark routes input through ~15 synthetic
request-wrapper helper classes that our real-world direct-request sources don't
match — and we decline to overfit our sources to those synthetic wrappers).

**Actions.**

1. **Enriched Aegis taint sanitizers** with genuine real-world defenses — ESAPI
   codecs (`encodeForSQL/OS/HTML/HTMLAttribute`), numeric coercion for SQL,
   canonical-path / `normalize()` for traversal, more OWASP-Encoder + Apache
   variants for XSS. A real precision gain, no benchmark overfitting.
2. **Added a configurable high-precision profile** (`SEMGREP_EXCLUDE_RULES` →
   `--exclude-rule`) so teams can drop the noisy audit tier when they want
   low-noise triage over maximum recall.

**Measured operating points** (identical method, 2,740 cases):

| Profile | F1 | Recall (TPR) | FPR | Youden |
| --- | --- | --- | --- | --- |
| **Default (recall-first, shipped)** | **0.775** | 0.884 | 0.425 | 0.459 |
| **High-precision (audit tier excluded)** | 0.622 | 0.499 | **0.113** | 0.387 |

The sanitizer enrichment shaved FPs 567→563 (F1 0.7739→0.7749) with no recall
loss. Excluding the audit tier collapses FPR to **11.3%** but halves recall — a
fundamental recall/precision trade, not a rule bug.

**Honest conclusion.** For a security **gate**, recall-first is correct, and the
default already beats CodeQL (F1 0.775 vs 0.744). The high-precision profile is
now available for triage-first teams. Meaningfully closing the trade (high recall
*and* low FP) would require taint sources tuned to each application's
request-wrapper conventions — deliberately **not** overfit to the Benchmark's
synthetic wrappers, since that would inflate this score while hurting real-world
results. This is the same wall the Bennett et al. "Semgrep\*" paper documents.
