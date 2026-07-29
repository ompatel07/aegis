# Aegis Accuracy Validation — Shipping Product Scorecard

Per-engine accuracy for the **shipping configuration** (fast-scan; the experimental
Joern deep-scan engine is gated **off** — see [DEEP_SCAN_VALUE.md](DEEP_SCAN_VALUE.md)).
Every number here comes from a **real run against real data**, reproduced from the
committed harnesses — not estimates. Where an engine is weaker than a headline
claim, it is said plainly and the limitation is documented. This is the master
accuracy-evidence document for marketing and enterprise sales; nothing in it is
tuned to a benchmark (the Track 2d / Consul-Vault discipline).

## Scorecard (shipping config)

| Engine | Metric | Result | Bar / comparison | Status |
| --- | --- | --- | --- | --- |
| **SAST** (Semgrep + Aegis taint) | F1 / recall (OWASP Benchmark v1.2) | **0.775 / 88.4%** | CodeQL F1 0.744 | ✅ beats CodeQL |
| **SAST** real-world FP | consolidated FP rate, 19 repos | _B2_ | claimed ~12% | _pending_ |
| **SCA** (Trivy) | dependency-CVE true-positive rate | _B3_ | — | _pending_ |
| **Secrets** (Gitleaks) | precision / recall | _B4_ | — | _pending_ |
| **Quality** (radon/lizard/dup) | metric correctness | _B5_ | hand-computed | _pending_ |
| **Deployment** test | pass good / fail broken | _B6_ | — | _pending_ |
| **CVE intelligence** | feed freshness + retro re-score | _B7_ | — | _pending_ |

_(Rows fill in as each engine is validated; each is committed separately.)_

---

## 1. SAST accuracy — OWASP Benchmark v1.2 (re-confirmed on shipping config)

**Dataset.** OWASP Benchmark v1.2 — 2,740 Java test cases (1,415 real
vulnerabilities + 1,325 safe look-alikes) across 11 CWE categories. The
gold-standard, tool-neutral SAST accuracy benchmark.

**Run.** Scanned via the scanner's `/scan/sast` endpoint (the shipping Semgrep
config + Aegis taint rules — **no Joern**), scored against
`expectedresults-1.2.csv` with CWE-matched (related-CWE) confusion counting.
Harness: [`benchmarks/owasp/`](benchmarks/owasp/) (`scan.py` + `score.py`).
2,960 findings, 191 s scan.

**Result — reproduces Track 2a exactly, confirming Joern-gating had zero effect:**

| Metric | This run (shipping) | Track 2a | Note |
| --- | --- | --- | --- |
| TP / FP / FN / TN | 1251 / 563 / 164 / 762 | same | — |
| **F1** | **0.7749** | 0.774 | vs CodeQL ≈ **0.744** → **+3.1 pts** |
| **Recall (TPR)** | **0.8841** | 0.884 | finds ~88% of real vulns |
| FPR | 0.4249 | 0.425 | recall-first trade-off (see below) |
| Youden's J | 0.4592 | 0.456 | competitive with top SAST |

**Per-category (TP/FP/FN/TN):**

| Category | TP | FP | FN | TN | Recall | Read |
| --- | --- | --- | --- | --- | --- | --- |
| crypto | 130 | 0 | 0 | 116 | 100% | perfect |
| weakrand | 218 | 0 | 0 | 275 | 100% | perfect, 0 FP |
| securecookie | 36 | 0 | 0 | 31 | 100% | perfect |
| sqli | 253 | 170 | 19 | 62 | 93% | high recall, sanitizer-unaware FPs |
| pathtraver | 123 | 113 | 10 | 22 | 92% | high recall, FP-heavy |
| xss | 202 | 112 | 44 | 97 | 82% | good recall |
| cmdi | 117 | 109 | 9 | 16 | 93% | high recall, FP-heavy |
| hash | 89 | 0 | 40 | 107 | 69% | 0 FP but misses weak-hash variants |
| ldapi | 26 | 28 | 1 | 4 | 96% | small n |
| xpathi | 14 | 13 | 1 | 7 | 93% | small n |
| trustbound | 43 | 18 | 40 | 25 | 52% | **weakest recall** |

**Verdict: ✅ PASS.** Aegis's shipping SAST **beats CodeQL on F1 (0.775 vs 0.744)**
with **88.4% recall** — best-in-class for a self-hosted, privacy-preserving
scanner. Confirmed unchanged after shelving Joern.

**Honest limitations (already characterized in Track 2d, not re-litigated here):**
- **FPR is 42%** — a deliberate **recall-first** posture correct for a security
  *gate*. The Track 2d high-precision profile (`SEMGREP_EXCLUDE_RULES`) collapses
  FPR to **11.3%** but halves recall; it ships as an opt-in for triage-first teams.
  The FPs are concentrated in `sqli`/`pathtraver`/`cmdi`/`xss` and are
  sanitizer-unaware matches, not random noise.
- **Recall gaps:** `trustbound` (52%) and `hash` (69%) are the two categories worth
  future rule investment; neither blocks the F1 result.
