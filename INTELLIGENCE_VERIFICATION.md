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

### Honest gaps (the "daily update" claim is only PARTIALLY true today)

| Gap | Evidence | Impact | Fix |
| --- | --- | --- | --- |
| **NVD sync failing** | Last 2 runs (07-22, 07-28) `failed`: `context deadline exceeded` (30 s HTTP timeout; NVD is slow + rate-limited to 5 req/30 s without a key). Last success **07-11**. | NVD CVEs are **stale since 2026-07-11** — the largest feed isn't updating. | Set an **NVD API key** (50 req/30 s) + raise the NVD read timeout + resume-on-failure pagination. |
| **GHSA disabled** | `ghsa` runs `success` but adds **0** — `Fetch` returns *"requires a GitHub token (GITHUB_TOKEN)"*. | GitHub advisories not ingested. | Provide `GITHUB_TOKEN`. |
| **`rule_registry` table empty** | 0 rows; `SemgrepSource.Fetch` is a no-op (`Skipped`, *"handled by the scanner"*). | The DB-backed rule registry is unused; not a functional loss (Semgrep/Trivy self-update), but the table is dead. | Either populate it or remove it. |
| **Gitleaks rules static** | Built into the binary; no auto-refresh. | Secret patterns only update with a binary bump. | Pin + periodically bump the gitleaks image. |

### Verdict

The pipeline **architecture is real, OSV + Trivy update continuously, and
retroactive re-scoring genuinely works.** But **"updates daily with new
vulnerabilities" is not fully truthful as configured**: NVD (the biggest feed) is
timing out and stale since 2026-07-11, and GHSA is token-gated/off. With an NVD
API key + timeout fix and a GitHub token, the claim would hold. Until then, the
honest statement is: *"continuous OSV + Trivy updates; NVD/GHSA require
credentials to stay current."*

<!-- FP_LOOP -->
