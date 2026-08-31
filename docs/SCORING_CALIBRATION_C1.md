# Scoring calibration C1 — make the numbers mean something

Every rating/score was a constant or an inverted metric. Fixed four defects and
calibrated against the **S1-corrected corpus (127 criticals)**, not V1's poisoned
660. Method: replay the S1-corrected findings for all 15 repos offline
(`scripts/c1_calibrate.py`), establish an EXPECTED ranking from evidence
independent of the formulas, then tune constants to match — no re-scanning.

## Before → after (same S1-corrected data; isolates the formula change)

| repo | security | quality | maint | deploy | overall |
|---|---|---|---|---|---|
| pterodactyl | 0E→**31E** | 90→91 | C→**B** | 100→**n/m** | 56D→**59D** |
| eladmin | 0E→42E | 74→80 | E→D | 100→n/m | 51D→**60C** |
| mealie | 0E→48E | 70→74 | E→D | 100→n/m | 50D→**60C** |
| mall | 0E→**73D** | 68→67 | **A→E** | 100→n/m | 49D→**70C** |
| pocketbase | 0E→65E | 80→75 | D→D | 100→n/m | 53D→**70C** |
| memos | 0E→72D | 73→74 | D→D | 100→n/m | 51D→**73C** |
| outline | 0E→67E | 82→84 | C→C | 100→n/m | 54D→**75B** |
| navidrome | 0E→74E | 78→80 | D→D | 100→n/m | 52D→**77B** |
| monica | 0E→76D | 81→80 | **B→D** | 100→n/m | 53D→**78B** |
| formbricks | 0E→75E | 79→82 | C→C | 100→n/m | 53D→**78B** |
| documenso | 0E→85E | 73→75 | C→D | 100→n/m | 51D→**80B** |
| paperless | 0E→88E | 78→83 | D→C | 100→n/m | 52D→**86B** |
| netbox | 0E→86E | 81→86 | **B→C** | 100→n/m | 53D→**86B** |
| snipe | 0E→91E | 82→83 | **A→C** | 100→n/m | 54D→**87B** |
| akaunting | 0E→92D | 83→87 | B→B | 100→n/m | 54D→**90A** |

**Overall grades BEFORE: {D:15} (a constant). AFTER: {A:1, B:8, C:5, D:1}.**
Security BEFORE 0/E on all 15; AFTER spreads 31–92. Letter still worst-severity
(one critical → E), so `sec` letters stay E where a critical exists — the SCORE now
distinguishes 9-crit-in-53k (pterodactyl 31) from 4-crit-in-548k (snipe 91).

## Expected vs computed ranking — from RAW evidence (de-circularized)

The first version of this check used the formula's own weighted density + pillar
weights, so expected and computed were two evaluations of the same function —
agreement proved nothing (the C1 follow-up caught this). Rebuilt from RAW inputs
only: **(critical+high) count per KLOC · duplicated-line % · non-dup smells per KLOC**
— no severity weights, no reachability, no KEV, no pillar weights.

**Raw-A (equal average of the three signal ranks) DISAGREES materially** with the
computed overall order (e.g. pterodactyl raw #11 vs computed #1). The cause is
structural: Raw-A has TWO debt signals (dup%, smells) to ONE security signal, so it
implicitly weights maintainability 2:1 over security — the opposite of the intended
priority — and it counts a critical the same as a high.

**Raw-B (equal SECURITY-category vs DEBT-category weight, debt = avg of dup+smell
ranks — still no severity/pillar weights) AGREES** on the extremes and most of the
order: worst {mealie, eladmin, mall, pocketbase}, best {akaunting, snipe, netbox,
paperless}; matches at eladmin, outline, monica, formbricks, paperless. The residual
gap (pterodactyl Raw-B #4 vs computed #1) is precisely the **severity weighting**
(critical 2.5× high) that the raw check omits — pterodactyl has 9 criticals.

So the disagreement reduces to two explicit, defensible formula choices the raw
check leaves out: **security ranks above maintainability**, and **a critical is
worse than a high**. This is a value judgement, not a bug — and per the review
protocol it was surfaced for a human decision, NOT resolved by declaring the
computed result "more correct" (the mistake the first check made with pterodactyl).

**Resolution (human decision):** the FORMULA is right, the raw expectation is too
naive — security *should* outrank maintainability and a critical *should* outweigh a
high. Raw-B (equal security/debt category weight, no severity weights) already
agrees, so it stands as the canonical formula-independent check and the constants
(`K_SEC=5.5`, `BD=0.55`, `BS=4.0`, pillar `0.40/0.35/0.25`) are validated. No
re-tuning. pterodactyl worst (9 criticals in 53k LOC) is the intended outcome.

## mall-vs-mealie duplication sanity (must hold)

`mall.maintainability(49, E) < mealie.maintainability(60, D)` — **PASS.** mall has
90.5% duplication; mealie 32.3%. The old metric inverted this (mall A, mealie E)
because a capped clone count (60 for every repo) fed scoring; now duplication enters
maintainability via the measured **percentage**, and the emitted-findings cap (still
60, for UI) never touches scoring.

## The unknown-value contract — what EVERY measurement returns when it does not know

The rule the whole D1 pass enforces: when Aegis does not know, it says **not
measured** (nil → NULL in the DB → "Not measured" in the UI). It never substitutes
a plausible number, a clean 100, or an A. "not measured" must never render as 0,
blank, or A. Every measurement below is checked by `TestUnknownValueContract`
(orchestrator `internal/scoring`) and, at the pipeline seam, by `aggregator_test.go`.

Legend: **nil** = not measured (NULL / "Not measured"). "engine failed/timed out"
columns assume ALL engines feeding that pillar failed — with partial coverage the
pillar IS measured on what ran, and the failed engine is listed in `engines_degraded`.

### Pillar scores & ratings

| measurement | no findings | LOC / metrics unknown | all pillar engines failed/timed out |
|---|---|---|---|
| **Security score** | 100 (clean, measured) | **nil** (can't normalize without LOC; no broken-formula fallback) | **nil** — not measured, never 100 |
| **Quality score** | high (few smells) | **nil** | **nil** |
| **Deployment score** | 100 (no vulns) | — | **nil** |
| **Overall score** | from measured pillars | renormalized over measured | **nil** / grade `N/A` when nothing measured |
| **Reliability rating** | A (no bugs) | A | **nil** — not measured, never A |
| **Security rating** | A (no vulns) | A | **nil** — not measured, never A |
| **Maintainability rating** | from score | **nil** (nil metrics; CHAR(1) can't hold a sentinel, so NULL) | **nil** |

### Sub-metrics that feed the pillars

| measurement | unknown path → value |
|---|---|
| **Complexity score** | metrics absent → quality is nil (sub-score never counted as 0) |
| **Maintainability sub-score** (`100 − 0.55·dup% − 4.0·smell-density`) | metrics absent → quality nil |
| **Test coverage score** | no coverage report → **nil**; its weight is DROPPED and the other sub-scores renormalize — never counted as 0 |
| **Duplication %** | not computed → maintainability metric absent → maintainability rating nil |
| **LOC / KLOC** | unknown → security nil (above); density undefined, no fallback |

### Raw counts & the degraded surface

| measurement | unknown path → value |
|---|---|
| **security_issues_total / secrets_found / vulnerabilities_found** | raw observation counts. If the engine did not run they surface as 0 **beside a populated `engines_degraded[]`** — a 0 is only honest next to the degraded banner that says coverage was lost. Never silently 0. |
| **engines_degraded[]** | the scan-level not-measured signal. Non-empty ⇒ the scan is DEGRADED (SARIF `executionSuccessful=false`, amber banner "results are incomplete, not clean"), never presented as clean. Fed by both failed engines (`status=failed`) and self-degraded engines (e.g. custom rule pack failed to load). |

The all-engines-failed → constant-A gap (previously footnoted here as an open P0 in
`PERFORMANCE_TODO.md`) is **CLOSED** by Pass D1: the aggregator computes per-pillar
"measured" from completed-engine presence and sets score AND rating to nil when a
pillar has no completed engine. See `fix(reliability): surface engine degradation
end-to-end` and `aggregator_test.go` (`TestAggregateAllSecurityEnginesFailed_NotMeasured`).

## Justification for every constant

- **`kSecurityDensity = 5.5`** (security = 100 − 5.5·weighted-density/KLOC): tuned so
  the S1 corpus spreads 31–92 with the densest-critical repo (pterodactyl, 12.5
  weighted/KLOC) landing ~30 and the sparsest (akaunting, 1.4) ~92. Lower → too
  compressed high; higher → low-density repos punished for size.
- **severity weights 25/10/3/1**: unchanged from the original penalty ladder; a
  critical is ~2.5× a high, matching CVSS band ratios. Reused as density weights.
- **reachability 0.5 / 1.0 / 1.2 and KEV 1.5**: unchanged; a not-imported CVE is half
  as urgent, a reachable direct dep +20%, an actively-exploited (KEV) CVE 1.5×.
- **maintainability `100 − 0.55·dup% − 4.0·(nondup smells/KLOC)`**: the two weights
  chosen so (a) the corpus spreads and (b) mall (90.5% dup) ranks below mealie
  (32.3% dup, 5.55 smells/KLOC) — the required inversion fix. `dup%` is already a
  0–100 measure; 0.55 makes 90% dup cost ~50 pts. 4.0 makes the worst smell density
  (mealie 5.55) cost ~22 pts.
- **quality weights complexity 0.30 / maintainability 0.55 / coverage 0.15**:
  duplication folded into maintainability (was a separate 0.20 — double-counting);
  documentation's 0.10 redistributed to maintainability (comment density rewards
  spam; SonarQube omits it). Maintainability carries the most weight as the primary
  tech-debt signal.
- **pillar weights security 0.40 / quality 0.35 / deployment 0.25**: unchanged base;
  security highest as the higher-stakes pillar. Deployment renormalizes OUT when not
  measured (0.40/0.75 + 0.35/0.75).
- **grade bands A≥90 B≥75 C≥60 D≥40 else F**: kept (analysis below).

## Grade-band calibration

Overall scores on the S1 corpus, sorted: **59, 60, 60, 70, 70, 73, 75, 77, 78, 78,
80, 86, 86, 87, 90** → **D:1, C:5, B:8, A:1** under A≥90 B≥75 C≥60 D≥40.

Is 8/15 in B a band artifact? No. Two independent reasons to KEEP the bands:
- They are **absolute**, not percentile — a 90 is an A on any corpus. Re-fitting
  bands to spread THESE 15 repos evenly would overfit to the sample and make a
  grade mean something different next month.
- The B cluster is **real, not lumped**: the 8 B-scores span 75–87 and the repos
  are genuinely similar (mature OSS, low vuln density, moderate tech debt). Moving
  the A cut to 85 would grade an 86 "excellent", which it is not; the split at 90
  reflects that none of these 15 is actually excellent. The corpus being mostly
  "good (B)" is a property of the corpus, not the bands — a catastrophic repo
  (e.g. 9 criticals in 10k LOC) lands in F, and pterodactyl's dense criticals put
  it at 59 (D), so the low bands are reachable, not compressed away.
- The letter is deliberately coarse; the SCORE (75 vs 87) differentiates finely for
  anyone who needs it.

Conclusion: the conventional academic mapping is the right absolute scale; no change.

## Down-ranked S1 secrets contribute at down-ranked severity — confirmed

The harness scores the **corrected** severities. pocketbase's 412 test-fixture JWTs
enter as LOW (weight 1), not critical: its security weighted-density is 6.3 → score
65. Had they stayed critical, weighted-density would be ~80 → score 0. The whole
point of S1 flows through into the score.

## Gate
- Full scanner suite green; `go build ./...` + Go scoring tests green.
- Before/after (above), expected-vs-computed (above), mall<mealie (above),
  unknown-value table (above), justifications (above), down-rank confirmation (above).
- Offline replay only — no repo re-scanned. Harness: `scripts/c1_calibrate.py`.
