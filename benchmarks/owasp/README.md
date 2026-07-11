# OWASP Benchmark v1.2 harness

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

Latest result: **F1 0.774, TPR 0.884, FPR 0.428** (2,740 cases, 168 s scan).
