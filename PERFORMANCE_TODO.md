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

---

## Validation Run V1 findings (2026-08-26) — new items

### P0 (correctness / observability) — silent custom-rule degradation
**Do not fix during V1; fix after.** V1 discovered that a non-rule YAML placed in
a semgrep-loaded directory (`config/ruff_map.yaml`, then under `rules/quality/`)
made `semgrep --config rules/quality` exit 2. The semgrep engine's fallback then
retried with **registry packs only**, silently dropping the custom taint engine +
the reliability bug pack — yet the scan still reported `status=completed` with no
degraded signal to the API, UI, or report. It was invisible for 7 repos and only
caught by inspecting `ruleset` on findings.

The **packaging trigger** is fixed (ruff_map.yaml moved to `config/`, guarded by
`test_custom_pack_loads.py`). The **behaviour** is NOT fixed and is the P0: a
custom-rule load failure must surface an explicit **degraded-scan state**
(`status=degraded` + which packs were dropped) propagated to the scan record /
API / UI, so a silent fallback can never again pass as a clean scan. Any future
non-rule file, rule syntax error, or registry outage should trip it.

### Perf item — SAST internal 600s timeout on large TypeScript
`documenso` (230k LOC) and `formbricks` (454k LOC) both hit the scanner's internal
600s semgrep timeout → SAST `status=failed`, 0 findings, entire security pillar
lost. `outline` (304k LOC) completed at 437s — borderline. Large TS/Next.js is the
worst case. Feeds Item 1 (semgrep efficiency) + consider per-language time budgets.

### Perf item — subprocess fork/exec failure under memory pressure
`akaunting` (231k LOC PHP): after a heavy 212s SAST run, the next engines' trivy
and gitleaks `subprocess` spawns failed with `FileNotFoundError` (fork/exec under
low free RAM; binaries were present, no OOM-kill). Cascade of engine failures that
looked like "binary not found". Needs: a scanner memory floor, or serialized heavy
subprocess spawns, or a spawn-failure retry/backoff — and a distinct error, not a
generic failure.

### Data point — quality engine wall time
`snipe-it` (600k LOC PHP): quality engine (lizard/radon/duplication) took ~22 min.
Duplication detection is the long pole on very large repos.

---

## P0 (correctness) — a fully-failed pillar must not read as a clean A

Raised by C1's unknown-value audit. If ALL of a pillar's engines fail (or time out),
the absence of findings currently reads as CLEAN, not "not measured":
  - SecurityScore → 100, SecurityRating (letter) → A
  - ReliabilityRating → A (no bugs, because the bug-producing engines didn't run)
A half-failed scan showing A/100 is the Q1 constant-A defect resurfacing in the
failure path — the exact class this whole line of work exists to kill.

C1 fixed the pillars we can detect: Quality and Deployment return nil (not measured),
and Security returns nil when LOC is unknown (the quality engine failed). The
remaining gap is the SAME failure that leaves findings simply absent: the aggregator
records `EngineErrors`, but that is not wired into a per-pillar "not measured" state
for Security/Reliability/Security-rating. Fix: when a pillar's engines are all in
`EngineErrors`, that pillar's score AND letter are "not measured", excluded and
renormalized — never A/100. This is a P0, not a follow-up.
