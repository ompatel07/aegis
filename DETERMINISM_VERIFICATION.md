# Determinism Verification (Phase 2F Pass 1, Part 1)

**Property under test:** same code + same input ⇒ identical results, every time. A
customer scanning unchanged code twice must get the exact same findings and scores.
This had never been explicitly tested before.

## Method

- **Repos (pinned to fixed commits, cloned once so the source bytes are identical
  across runs):** Express (`a3714473feb3`, small), Flask (`36e4a824f340`, medium),
  Django (`274a1d494d11`, many findings).
- **Shipping configuration:** fast-scan, Joern off. CVE feeds are not consulted by
  SAST, and the SCA/Trivy DB is cached, so nothing external changes within the
  back-to-back window.
- **SAST determinism (10× each):** scanned the same directory 10 times and reduced
  each run to a canonical, order-independent representation of the finding set,
  then hashed it. The canonical form of each finding includes: **rule id, file
  path, line number, severity, CWE, the ML false-positive probability, and the
  steps-to-reproduce source/sink/flow.** Finding *order* is ignored (sorted before
  hashing); the *set* and every per-finding field must match.
- **Full-pipeline + score determinism (3×):** ran 3 complete scans (all engines +
  aggregation + scoring) of Express through the orchestrator and compared the
  security/quality/deployment/overall pillar scores, grade, and finding count.
- Harness: [`benchmarks/comparative/determinism_check.py`](benchmarks/comparative/determinism_check.py).

## Results — deterministic across the board

**SAST, 10 runs each — one distinct hash per repo (all runs identical):**

| Repo | Commit | Findings | Runs | Distinct hashes | Verdict |
| --- | --- | --- | --- | --- | --- |
| Express | a3714473feb3 | 2 | 10 | **1** | ✅ deterministic |
| Flask | 36e4a824f340 | 7 | 10 | **1** | ✅ deterministic |
| Django | 274a1d494d11 | **790** | 10 | **1** | ✅ deterministic |

Django is the strong test: **790 findings** from a large, `--jobs`-parallelised
scan, and all 10 runs produced a byte-identical canonical hash — including the ML
false-positive probability and the taint steps-to-reproduce for every finding.

**Full pipeline, 3 runs (Express, same pinned commit) — identical scores:**

| Scan | Security | Quality | Deployment | Overall | Grade | Findings |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 98 | 68 | 100 | 88 | B | 125 |
| 2 | 98 | 68 | 100 | 88 | B | 125 |
| 3 | 98 | 68 | 100 | 88 | B | 125 |

## Variation found

**None.** Zero `DIFFERS` across all 30 SAST runs; identical scores across all 3
full-pipeline runs. No non-determinism was observed, so **no fix was required.**

The specific risks the pass targeted, and why each is clean:
- **Parallel result assembly (`--jobs`):** Django's 790-finding parallel scan is
  identical 10×; Semgrep's output is order-stable and the canonical compare sorts
  regardless.
- **Ordering leaking into scores:** pillar scores are counts/severity rollups
  (`pipeline/aggregator.go` has no `rand`/`time.Now`/map-iteration in the math);
  identical across runs.
- **ML FP-classifier stability:** the model is loaded **once** at scanner startup
  and cached (`ml/classifier.py` `_state`), never retrained mid-scan; inference is
  deterministic. The `false_positive_probability` is part of the canonical hash and
  was identical every run.
- **Timestamp / random / scan-id bleed:** scan ids differ between runs but do not
  enter any finding field or score — the hashes are identical regardless.

## Conclusion

**✅ Aegis is deterministic.** Identical input yields byte-identical findings
(including ML scores and steps-to-reproduce) and identical pillar scores, verified
over 30 SAST runs (up to 790 findings) and 3 full-pipeline runs. No source of
non-determinism was found; no code change was needed.
