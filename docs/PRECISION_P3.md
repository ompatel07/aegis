# P3 — Real-code precision: fixed on the tuning half, measured on the held-out half (2026-10-23)

Prerequisite: D2 (`docs/D2_DETERMINISM.md`). Repeat scans of a commit now differ only in
files the scan discloses, and every precision figure here is on findings **stable across
three scans**, counted once per location (rule, file, line).

## A. Both gates on the Wilson 95% lower bound — before any rule edit

A point estimate cannot tell 4/5 from 400/500. From P3 a gate passes only if the
**lower bound of the Wilson 95% interval** clears its floor; there is no minimum-sample
rule (`MIN_CORPORA` is not one: it asks for detections in two independent codebases).

- **precision gate:** lower bound of TP / (TP + FP) on held-out real repositories ≥ 70 %.
- **recall gate, calibrated:** lower bound of Aegis's held-out recall ≥ CodeQL's recall on
  the same items. **Uncalibrated** (no CodeQL reference — PHP): lower bound ≥ 25 %.

`services/scanner/utils/tier_bar.py`; tests in `tests/test_tier_bar.py`, among them
Go's 4/5 failing (lower bound 38 %), a value exactly on its line failing at n = 1,000,
7/7 failing (65 %), 11/11 and 400/420 passing. Re-tier on the shipped evidence, rules
unchanged (`docs/ground_truth_p3/retier.py`):

| language | held-out recall (95 % CI) | CodeQL, same items | real held-out precision (95 % CI) | N6 | **P3 Part A** |
|---|---|---|---|---|---|
| PHP | 68/160 = 42 % [35 %, 50 %] | not run (no PHP) | 18/67 = 27 % [18 %, 39 %] | clean-only | **clean-only** |
| Python | 8/38 = 21 % [11 %, 36 %] | 5/38 = 13 % | 1/19 = 5 % [1 %, 25 %] | clean-only | **withheld** |
| Go | 4/21 = 19 % [8 %, 40 %] | 4/21 = 19 % | 4/5 = 80 % [38 %, 96 %] | problem-only | **withheld** |
| Java | 0/8 = 0 % [0 %, 32 %] | 3/8 = 38 % | none | withheld | withheld |
| JavaScript | 10/23 = 43 % [26 %, 63 %] | 18/23 = 78 % | 0/15 = 0 % [0 %, 20 %] | withheld | withheld |
| TypeScript | 2/17 = 12 % [3 %, 34 %] | 3/17 = 18 % | 0/10 = 0 % [0 %, 28 %] | withheld | withheld |

Two languages lose their claim on the interval alone. **Python's clean claim** rested on
8/38 against CodeQL's 5/38; the lower bound, 11 %, is below 13 %. **Go's problem claim**
rested on five findings. PHP keeps its clean claim (lower bound 35 % ≥ 25 %).
