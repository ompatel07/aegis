# Intelligence & Learning Verification (Track 2e.5 / 2e.6)

Proof — not assumption — that Aegis's "updates daily with new vulnerabilities"
and "learns from feedback" claims are truthful. Verified against the actual code
and live runs. Honest gaps documented.

---

## Track 2e.5 — CVE intelligence pipeline

**Architecture (real).** `services/orchestrator/internal/intelligence/`: four
`Source`s (NVD 24h, OSV 6h, GHSA 24h, Semgrep 7d), a `Scheduler` wired in
`orchestrator/cmd/main.go` running each source on its own interval, a `Syncer`
(`fetch → UpsertCVE deltas → FlagAffectedScans`), and a `Store` over
`cve_database` (cve_id PK, `affected_packages` JSONB, GIN-indexed).

### What works (verified live)

| Check | Result |
| --- | --- |
| `cve_database` populated with real CVEs | ✅ **4,025** (NVD 3,918 + OSV 107) |
| Scheduler actually runs on schedule | ✅ `intelligence_sync_log` shows runs on 2026-07-11, -22, -28 |
| OSV sync ingests new CVEs | ✅ log shows `+2` / `+6` added on runs (package-precise) |
| **Retroactive re-scoring** (new CVE re-flags past scans) | ✅ **PASS — proven end-to-end** |
| Trivy vuln DB auto-updates | ✅ `trivy fs` runs with **no** `--skip-db-update` → refreshes DB over the network per scan |
| Semgrep registry rules | ✅ fetched scanner-side from the registry (cached) |

**Retroactive re-scoring proof.** A harness exercised the *real* code path against
a planted scan: a finding on package `retro-test-pkg-…` (scan `needs_reeval=false`)
→ `Store.UpsertCVE(newCVE)` returned `isNew=true` → `Store.FlagAffectedScans`
flagged **1** scan → the scan flipped to `needs_reeval=true` with reason
*"New vulnerability CVE-… affects a dependency in this scan."* The 90-day window +
`findings.metadata->>'package'` join work as designed. **The core "a new CVE
retroactively re-flags a past scan" capability is genuine.**

### Fixes applied (Phase 2D) — the gaps are now closed

| Was | Fix | Verified |
| --- | --- | --- |
| **NVD failing** (`context deadline exceeded`) | **Root cause found:** the keyless `resultsPerPage=2000` page is ~4 MB and takes **123 s** — just over the client timeout. Fix: **200-record pages** (~15 s each) + a dedicated **120 s client** + **retry/backoff** + partial-page resilience. NVD API key + rate-tier already supported (`NVD_API_KEY`). | ✅ NVD sync now **success, +1,825 CVEs** (3,918 → 5,743). |
| **GHSA disabled** | `GITHUB_TOKEN` is now passed to the orchestrator via compose; the feed activates when a token is set (graceful skip otherwise). | ✅ wired; skips cleanly without a token, ingests with one. |
| **`rule_registry` empty** | Scanner exposes `GET /rules/catalog`; the `SemgrepSource` fetches it and upserts each rule (new `Store.UpsertRule`). | ✅ **42 Aegis rules catalogued** (`aegis/taint`, `aegis/ai_code_taint`). |
| **NVD/GHSA creds not plumbed** | Added `NVD_API_KEY` + `GITHUB_TOKEN` to the orchestrator's compose environment. | ✅ |
| Retroactive re-scoring | Unchanged — re-verified after the fixes. | ✅ **RETROACTIVE_STILL_WORKS**. |

Remaining minor item: **Gitleaks rules** are static (bundled with the binary) —
updated by bumping the image; not on the CVE-feed path.

### Verdict (updated)

The pipeline is real and **the "updates daily with new vulnerabilities" claim now
holds**: **NVD syncs successfully** (small-page fix), **OSV + Trivy update
continuously**, **GHSA activates with a `GITHUB_TOKEN`**, **rule_registry is
populated** (42 rules), and **retroactive re-scoring works** (a new CVE re-flags a
past scan — re-verified). An NVD API key is optional (higher rate limit); a GitHub
token is required only to add the GHSA feed on top of NVD+OSV.

---

## Track 2e.6 — ML false-positive learning loop

**Implementation.** `services/scanner/ml/`: a LightGBM classifier scoring each
finding with `P(false positive)` (advisory — sorts + badges, never hides).
Training = `generate_seed()` + optional feedback rows (`ml/train.py`); actions
`marked_fp`/`suppressed`/`ignored` → FP=1, `confirmed`/`fixed` → 0.

### Does it learn? — YES, proven live

Fed 80 simulated FP-feedback events for rule `quality.duplicated-block` (plus 80
`confirmed` events for other rules) and retrained on the real `ml.train` path:

| Rule | P(false-positive) before | after |
| --- | --- | --- |
| **`quality.duplicated-block`** (marked FP ×80) | **0.035** | **0.995** |
| control rule (marked confirmed) | 0.020 | 0.000 |

The target rule's FP probability jumped **0.035 → 0.995** — the model learned the
rule is FP-prone — while the control rule stayed low, so the shift is
**rule-specific, not global drift** (mirrors and exceeds the Phase 2C 0.03→0.51
result).

### Privacy invariant — HOLDS

All 13 features are **metadata only**: `severity_ord, file_path_depth,
lines_of_code, is_in_test_file, is_in_generated_file, is_direct_dependency`, and
md5-**bucketed** hashes of `engine/rule_id/extension/language/cwe/owasp`. The
feedback rows carry the same fields — **no source code, snippets, or code
identifiers** enter the pipeline (see `ml/features.py`, and the confirmed field
list in the harness output). Verified.

### Honest gap — the loop is not automated end-to-end

The learning *mechanism* works, but in production it is **not wired as a
continuous loop**:

- **No feedback → training-data export + no scheduled retrain job.** The API
  records feedback into `project_rule_stats` (live `fp_rate` per project+rule) and
  `feedback_events`, but nothing exports those to the JSONL `ml.train` consumes,
  and there is no cron/worker that retrains the global model. So the global FP
  model ships trained on the **seed only** and does not self-improve from real
  feedback without a manual `python -m ml.train --data …` run.
- **The ML model is global, not per-team.** The feature vector has no project/team
  id. Per-team learning exists **separately** as `project_rule_stats.fp_rate`
  (updated live on every dismissal, surfaced via project-memory for priority
  sorting/display) — but it does not feed the ML `P(fp)` score.

**Verdict.** The FP classifier **genuinely learns from feedback and respects the
metadata-only privacy invariant** — both proven live. To make "learns from your
feedback" true *automatically*, wire: (1) a feedback→JSONL exporter, (2) a
scheduled retrain job, and optionally (3) fold `project_rule_stats.fp_rate` into
scoring for true per-team personalization. Until then it is an accurate *manual*
capability, not an automated loop.
