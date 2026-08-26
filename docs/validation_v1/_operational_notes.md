# Operational events log (raw, chronological)

> NOTE: this is the raw scratch log, written live and spanning BOTH the discarded
> first attempt (registry-only, before the custom-pack regression was found) and
> the fix. Some event framing here (e.g. documenso/formbricks SAST) was superseded
> once the packaging bug was fixed. **The authoritative operational results are
> §9 of `../VALIDATION_RUN_V1.md`.** This file is kept only as the primary source.


Environment: Om's box, Docker ~3.7GB total, **no per-container mem limit**
(`HostConfig.Memory=0`), 8 containers sharing RAM. Scanner is single-worker
uvicorn. Protocol: `docker restart` scanner before each repo (clears zombie
scans + memory pressure); quality engine runs LAST (a client-side HTTP timeout
does not cancel server-side work, so a hang would otherwise block later engines).

## 🔴 CRITICAL REGRESSION FOUND (run-invalidating for SAST/bugs)

**Symptom:** every SAST-completed repo returns `rulesets={registry}` only — zero
`aegis-*` findings, zero custom-taint findings, on all 7 repos.

**Root cause (reproduced):** `semgrep scan --config /app/rules/quality <t>` exits
**code 2**. Bisected: `bugs.yaml` alone → exit 0; **`ruff_map.yaml` alone → exit
2**. `ruff_map.yaml` is the Q3 Ruff allowlist (a plain config with a top-level
`rules:` map of ruff codes) — NOT a semgrep rule file. But semgrep loads EVERY
`.yaml` in a `--config` directory as rules, so it tries to parse `ruff_map.yaml`
as semgrep rules, fails schema validation, and the whole combined SAST invocation
(registry packs + `/app/rules/taint` + `/app/rules/ai_code_taint` + `/app/rules/iac`
+ `/app/rules/quality`) exits 2. The semgrep engine's fallback then RETRIES with
registry packs only — **silently dropping ALL custom rules**: the Q1/Q2 reliability
bug pack, the custom taint engine (Aegis's headline differentiator), AI-code taint,
and the IaC pack.

**Introduced by:** commit `a95fd0e` (Q3), which placed `ruff_map.yaml` inside
`services/scanner/rules/quality/` — a directory semgrep loads wholesale. Before
Q3 that dir held only valid semgrep rule files.

**Impact on this run:** the SAST security pillar and the entire Semgrep bug pack
were NON-FUNCTIONAL on all 7 repos scanned so far. Every "0 bugs (semgrep)" and
every SAST finding count is registry-packs-only — it does NOT reflect Aegis's
intended custom-rule behaviour. The run cannot measure custom-rule yield/precision
until this is resolved.

**Rule Zero note:** fixing this (moving `ruff_map.yaml` out of the semgrep-loaded
dir, ~1 line) is a code/config change, which Rule Zero forbids mid-run. Surfaced
to the user for a decision rather than auto-fixed.

## Events

- **repo 1 snipe/snipe-it (600k LOC PHP):** first attempt, quality engine hit the
  driver's 20-min client timeout → because uvicorn is single-worker, the still-
  running quality scan blocked the following deployment request, which then also
  timed out (cascade). Fixed by (a) running quality LAST and (b) raising quality
  client timeout to 25 min. Clean re-run: quality COMPLETED in 1312s (22 min),
  681 quality findings. **Data point: quality engine needs ~22 min on 600k LOC.**

- **repo 3 akaunting/akaunting (231k LOC PHP), first attempt:** SAST completed
  (44 findings, 212s), then **SCA (trivy) and secrets (gitleaks) both FAILED**,
  and quality returned in 0.0s with total_code_lines=0. Root cause (from scanner
  logs): `CommandError: binary not found: gitleaks` — a `FileNotFoundError` on
  subprocess spawn. The binaries were present the whole time (verified after);
  RestartCount=0, OOMKilled=false — so NOT a container OOM-kill, but a **transient
  fork/exec failure under memory pressure** after the heavy 212s SAST run left
  little free RAM. Cascade: trivy fork failed, gitleaks fork failed, quality read
  an empty result. Contaminated result discarded; re-scanned after a restart.
  **Data point: on a memory-starved box, a heavy SAST run can starve subsequent
  engines' subprocess spawns → silent cascade of engine failures. Feeds
  PERFORMANCE_TODO: set a scanner mem floor / serialize heavy subprocess spawns /
  surface spawn-failure as a distinct engine error, not a generic failure.**

- **repo 5 documenso/documenso (230k LOC TypeScript):** **SAST FAILED, 0 findings.**
  From scanner logs, two stacked failures: (1) the first semgrep pass (registry
  packs + custom /app/rules/{taint,ai_code_taint,iac,quality}) exited **code 2 at
  29.6s** with empty stderr → engine logged `semgrep.custom_rules_failed_retrying`
  and retried WITHOUT the custom rule dirs; (2) the retry (registry packs only)
  **hit the scanner's internal 600s semgrep timeout** on 230k LOC of TS and was
  killed → sast.done status=failed. Deterministic (a re-scan times out the same
  way), so not retried. Other engines fine (sca 13, secrets 25, quality 808).
  **Data point: large TS repos can blow the 600s internal semgrep timeout AND our
  custom TS rules threw a parse/loader error (code 2). Feeds PERFORMANCE_TODO
  (timeout/att-scaling) AND a rule-robustness follow-up (why did custom rules exit
  2 on documenso's TS?).** NOTE: self-lint detector reported NOT SELF-LINTED for
  documenso, almost certainly a FALSE read — it's a turborepo with eslint/prettier
  in packages/*, which the root-level detector misses. Treat the self-lint column
  as approximate for monorepos.

- **repo 6 formbricks/formbricks (454k LOC TypeScript):** **SAST FAILED at 630s —
  identical pattern to documenso** (600s internal semgrep timeout on large TS).
  This is now REPEATABLE: 2/2 large TS repos lose the entire SAST pillar. Other
  engines fine (sca 6, secrets **128**, quality 1552). The 128 secrets on a survey
  SaaS need heavy FP scrutiny (likely .env.example / demo / seed fixtures).
  **Firm finding: Aegis SAST does not complete on >200k-LOC TypeScript within the
  600s internal timeout — a real gap for TS/Next.js customers.**
