# Performance TODO — Large-Monorepo Scan Pass (deferred to launch prep)

**Status: documented, NOT implemented.** Deferred to a dedicated performance pass
at launch prep, run on **real hardware** where it can actually be measured. This
file is scope only — no code changes here.

Raised by Phase 2F Pass 2 (see `CODE_CONNECTION_VERIFICATION.md` Part 3). Two
distinct problems came out of the 22k-file test; keep them separate because they
have different root causes and different "done" bars.

---

## Baseline to beat

| Repo | Files | Result on the 3.74 GiB dev VM |
|------|------:|-------------------------------|
| `grafana/grafana` | **22,164** | full scan ran **> 18 min without completing**, scanner peaked **~2.6 GiB**, sustained pressure **crashed the Docker daemon** |
| `coupleapp` (reference) | 111 | 132 s, no OOM — fine |
| `django/django` (Phase 2C) | ~2,700 | 546 s (9.1 min), no OOM |

**Target (from PERFORMANCE.md):** < 20k files in **< 10 min**, < 4 GB/scanner.
grafana currently fails both the time and the stability bar. Beat the row above.

---

## Item 1 — Efficiency (hardware-independent; the real task)

The > 18 min wall-clock is **not** just the dev box — semgrep re-scanning the full
tree with its full ruleset is a genuine efficiency problem that persists on any
hardware. Scope for the perf pass:

- **semgrep `--max-memory` tuning** — bound peak memory per invocation so a big
  repo degrades gracefully instead of ballooning.
- **Sharding** — split a large repo across scanner invocations/replicas (by
  directory or file batch) and merge results. The scanner is already stateless
  over the shared volume (PERFORMANCE.md, Track-1 1f), so the fan-out hook exists.
- **Per-engine timeouts** — enforce a real per-engine budget. The config names a
  900 s per-engine timeout, but the grafana run exceeded 18 min overall, so the
  cap is either not wired on this path or not summed across engines. Verify + fix.
- **Hard per-scan wall-clock cap** — a total scan budget that **fails fast** (see
  Item 2) rather than letting a scan run open-ended and loop on retry.
- **Larger prod scanner memory ceiling** — give the scanner a dedicated limit on
  real infra (the dev VM's 3.74 GiB is shared across every service).

**Already done / already tracked (don't re-scope, build on these):** semgrep
`--jobs` core parallelism is live (PERFORMANCE.md, Track-1 1e); streaming
findings persistence, content-hash file cache, and PR-diff/incremental scan modes
are designed-not-built (Track-1 1a/1b/1c/1g). The incremental subsystem is the
biggest lever for repeat scans and should be built + benchmarked together.

**Measure on real hardware:** full-scan wall-clock + peak memory per service +
incremental re-scan time on 10k / 20k / 30k-file repos; confirm no OOM.

---

## Item 2 — Graceful failure on oversized repos (platform stability)

**Separate hardening item — about stability, not speed. Worth doing in the perf
pass regardless of the efficiency work.**

Today, a repo large enough to exhaust scanner memory takes down the **Docker
daemon / host** (observed live on grafana), and Asynq then re-queues the job into
a crash loop. That is a platform-stability defect independent of how fast scans
are.

**Desired behavior:** the scanner (and orchestrator) must **fail gracefully** on
a repo that exceeds resource limits — detect the limit (memory pressure, file
count, per-scan wall-clock cap from Item 1) and return a clear, actionable
message such as:

> "Scan exceeded resource limits — scope the scan to specific directories, or
> contact us about a larger plan for monorepos of this size."

rather than crashing the host. The scan should end in a clean `failed` state with
that message, **no daemon crash, no retry loop**. This complements the existing
`MAX_REPO_SIZE_MB` clone guard (which only catches size *before* the scan) by
handling repos that pass the size guard but still blow the memory/time budget
*during* scanning.

---

## When

Both items are deferred to a dedicated performance pass at launch prep, on real
hardware. Do not implement piecemeal now — measure first on representative infra,
then tune against the grafana baseline above.

---

# Fast-follow backlog (non-performance)

Small, tracked items found during validation — **not yet fixed.**

## 1. Zip-upload: archives without explicit directory entries fail extraction

**Found:** Phase-2G Gap-1 validation (2026-08). Method B (zip/tar **upload**)
extraction fails when an archive entry references a nested path (e.g.
`PHPMailer/PHPMailer.php`) but the archive contains **no explicit directory record**
for the parent (`PHPMailer/`). The extractor opens the destination file without
creating its parent directory first, so the scan ends `failed` with
`open …/PHPMailer/PHPMailer.php: no such file or directory`.

- **Impact: LOW.** The primary connection path — **git clone** — preserves
  directories and is **unaffected**; only zip/tar uploads whose packaging tool omitted
  directory entries hit this, and it fails cleanly with a clear error (no crash, no
  data issue). Most zip tools *do* emit directory entries, so it's an edge case.
- **Fix (when scheduled):** in the archive extractor (`orchestrator/internal/adapters/
  archive.go`), `MkdirAll` the parent directory of each file entry before writing it
  (independent of explicit directory records). Keep the existing zip-slip / decompression-
  bomb guards.

## 2. Gap-2 scoring: app-code vs third-party weighting — DEFERRED (pending decision)

The Phase-2G Gap-2 work tags every finding `code_ownership` = `app` / `third_party`
and separates them in the UI/SARIF, but **the security-scoring formula was left
unchanged** (third-party findings still weight the score the same as app-code). The
**recommendation** — app-code findings drive the primary security score, third-party
down-weighted (you fix your own bug; you *update* a bundled library) — is **deferred
by decision until scoring is reviewed holistically** (alongside reachability
weighting and any other score levers), so score numbers aren't changed piecemeal. No
action until that review. (See `VALIDATION_REPORT.md`, Gap 2.)
