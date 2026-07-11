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

- **2b** real-world vuln corpus (Bennett et al. 2024, 502 Java vulns) — target
  ≥ 26.5% detection.
- **2c** 20-repo multi-language comparative vs SonarQube/Semgrep/Trivy
  (`COMPARATIVE_ANALYSIS.md`, commit per repo).
- **2d** false-positive deep-dive (top-100 findings; fix/downgrade rules > 30% FP;
  target overall FPR < 15% on real code — informed by the dataflow FPs above).
- **2e** AI-code detection real-world validation (`AI_CODE_DETECTION_VALIDATION.md`).
- **2f** Joern deep-scan value on 10 repos.
