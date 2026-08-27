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

## Expected (independent evidence) vs computed ranking

Expected = 0.55·(security weighted-density rank) + 0.45·(tech-debt rank), from the
raw metrics, weighting security higher because it is the higher-stakes pillar —
independent of the K/B constants. Computed = overall-score order.

Extremes agree: worst {mealie, eladmin, mall, pocketbase}, best {akaunting, snipe,
netbox, paperless}. **One material disagreement, justified:** pterodactyl is
EXPECTED #6 but COMPUTED #1 (worst). It has by far the densest criticals (9 crit +
31 high in 53k LOC); the security-weighted overall correctly makes it worst, while
the rank-average dilutes that because its duplication is the LOWEST (7.4%). Security
density this extreme *should* dominate — the computed result is the more correct of
the two. Remaining differences are ±1–2 positions within a tight mid-band (overall
73–80) — rank noise, not disagreement of kind.

## mall-vs-mealie duplication sanity (must hold)

`mall.maintainability(49, E) < mealie.maintainability(60, D)` — **PASS.** mall has
90.5% duplication; mealie 32.3%. The old metric inverted this (mall A, mealie E)
because a capped clone count (60 for every repo) fed scoring; now duplication enters
maintainability via the measured **percentage**, and the emitted-findings cap (still
60, for UI) never touches scoring.

## The unknown-value table — what each returns when it does not know

| score / rating | no findings | no files / LOC unknown | unsupported lang | engine failed | engine timed out |
|---|---|---|---|---|---|
| **Security** | 100 (clean) | count-based fallback (can't normalize; documented, not fabricated) | 100 if no findings | findings absent → scored on what ran¹ | same as failed¹ |
| **Quality** | high (few smells) | `nil` = **not measured** | `nil` | `nil` = not measured | `nil` |
| **Deployment** | — | — | — | `nil` = not measured | `nil` |
| **Overall** | from measured pillars | renormalized over measured | renormalized | excludes nil pillars | excludes nil pillars |
| **Reliability** | A (no bugs) | A | A | A (bugs absent)¹ | A¹ |
| **Security rating (letter)** | A (no vulns) | A | A | A¹ | A¹ |
| **Maintainability rating** | from score | **N/A** (nil metrics) | N/A | **N/A** | N/A |

¹ **Known gap, flagged not fixed:** if ALL of a pillar's engines fail, absence of
findings currently reads as "clean" (Security 100, Reliability/Security-rating A)
rather than "not measured". The aggregator records `EngineErrors`; wiring that into
a per-pillar "not measured" is a follow-up (the honest fix, out of C1's scope).
Quality and Deployment already return `nil` correctly.

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
- **grade bands A≥90 B≥75 C≥60 D≥40 else F**: unchanged.

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
