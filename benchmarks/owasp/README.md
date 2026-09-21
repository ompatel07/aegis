# OWASP Benchmark v1.2 harness

> **SUPERSEDED — 2026-09-19 (Pass N1).** The SAST numbers in this document were measured with
> the Semgrep-registry rule packs loaded (Semgrep Rules License v1.0). Aegis no longer ships
> those rules: Semgrep declined an OEM licence and relicensing, so they were removed. Same
> harness, sovereign rule set: OWASP Benchmark v1.2 **TPR 0.154 · FPR 0.103 · F1 0.247 ·
> Youden 0.051** (was 0.884 · 0.425 · 0.775 · 0.459). Do not cite the older figures. Current
> numbers live only in `docs/ACCURACY.md`; the cut is documented in `docs/RULE_REMOVAL_N1.md`.

Reproduces the Track 2a accuracy measurement (see [`QUALITY_BENCHMARK.md`](../../QUALITY_BENCHMARK.md)).

```bash
# 1. Clone the benchmark into the scanner's shared workspace volume
docker run --rm --entrypoint sh -v codequalitytesting_workspaces:/workspaces alpine/git -c \
  "git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git /workspaces/owasp-benchmark"

# 2. Scan the 2,740 testcode files via the scanner /scan/sast endpoint.
#    scan.py writes findings to /v/_aegis_findings.json (mount a writable dir at /v).
docker compose run --rm --no-deps -T -v "$PWD/benchmarks/owasp:/v" scanner python3 /v/scan.py

# 3. Score against expectedresults-1.2.csv (CWE-matched with related-CWE sets).
docker compose run --rm --no-deps -T \
  -v "$PWD/benchmarks/owasp:/v" -v codequalitytesting_workspaces:/workspaces \
  scanner python3 /v/score.py
```

`scan.py` — POSTs the testcode dir to `/scan/sast`, dumps slimmed findings.
`score.py` — builds the confusion matrix and TPR/FPR/F1 overall + per category.

Latest result (N1, sovereign rule set, 2026-09-19): **TPR 0.154, FPR 0.103, F1 0.247, Youden 0.051** (2,740 cases, 32 s scan). The pre-N1 result with the Semgrep-registry packs loaded was F1 0.775, TPR 0.884, FPR 0.425 — no longer shipped.
