# AI-Code Detection — Real-World Validation (Track 2e)

The AI-generated-code classifier (`services/scanner/ml/ai_detect/`, LightGBM over
14 **metadata-only** features — no source leaves the scanner) was trained in
Phase 2C on a **synthetic** dataset (human code deliberately refactored with "AI
tells"). Recorded synthetic baseline (5-fold CV):
**precision 0.899, recall 0.789, ROC-AUC 0.913** (738 samples, balanced).

This validates it on **real** data — and the result is a significant, honest
negative finding.

## Method

- **Real AI samples (n=250):** whole source files *created* in commits carrying a
  `Co-authored-by: Copilot` or `Co-Authored-By: Claude` trailer, mined from 47
  public GitHub repos (GitHub reports 2.36M Copilot- and 22M Claude-co-authored
  commits, so the population is large). Files created by the Copilot coding agent
  / Claude Code are predominantly AI-written.
- **Real human samples (n=179):** whole source files from **pre-2020 tags** of
  mature libraries (Django 2.0, Flask 1.0, requests, click, Express, Gin, Cobra,
  Gson) — guaranteed pre-LLM (Copilot GA was 2022; GPT-3 mid-2020).
- Languages: Python, JS/TS, Go, Java. Files 8–800 lines.
- Scored each with the **actual trained LightGBM model** (loaded from the model
  volume — confirmed `model_available: True`, not the heuristic fallback).

## Finding 1 — the shipped (synthetic-trained) model fails on real data

| Metric | Synthetic baseline | **Real data (shipped model)** |
| --- | --- | --- |
| ROC-AUC | 0.913 | **0.541** (near-random) |
| F1 @0.5 | — | 0.271 |
| Precision @0.5 | 0.899 | 0.642 |
| Recall @0.5 | 0.789 | **0.172** |
| Mean score (AI / human) | — | 0.228 / 0.203 (≈ identical) |

**The detector is essentially non-functional on real-world code.** Mean scores for
real AI and real human code are nearly identical (0.228 vs 0.203); ROC-AUC 0.541 is
barely above a coin flip. The synthetic "AI tells" (verbose boilerplate docstrings,
generic names, cargo-cult `except`) do **not** generalize: real AI-assisted code is
human-reviewed and reads like ordinary code, while mature human libraries *also*
have docstrings and consistent style — so the two overlap almost completely.

This is the same class of gap as the earlier Semgrep silent-failure and the
Consul/Vault noise: **built ≠ working.** The Phase 2C 0.90/0.79/0.91 numbers are
real, but they measure the *synthetic* task, not real-world detection, and must not
be presented as real-world accuracy.

## Finding 2 — retraining on real data recovers strong metrics (with a caveat)

Re-fitting the **same 14 features** on the real 429-sample dataset (5-fold
stratified CV, identical LightGBM params):

| Metric | Real-data CV |
| --- | --- |
| Precision | 0.866 |
| Recall | 0.884 |
| F1 | **0.874** |
| ROC-AUC | **0.919** |

So the **features can separate real AI from real human code** — the failure was the
synthetic *training distribution*, not the feature design. Top features:
`blank_ratio`, `avg_line_len`, `comment_ratio`, `generic_name_ratio`, `loc`.

### ⚠️ Confound — why 0.919 likely overstates true AI-detection

The AI set (47 **modern, small, personal** repos) and the human set (8 **mature
2018 libraries**) differ in more than AI-authorship — repo maturity, domain,
formatting era, and even file size all differ. The top separating features are
**stylistic** (blank ratio, line length, comment ratio), which track "modern small
project" vs "mature library" at least as much as "AI vs human." Because CV shuffles
**files** (not repos), files from one repo can land in both train and test, letting
the model **repo-fingerprint**. The honest read: the real-data model is a genuine
improvement over the broken synthetic one, but **0.919 is an optimistic upper
bound**; the true AI-authorship signal is weaker and not yet isolated.

A definitive measurement needs a **repo-controlled** dataset: AI-authored vs
human-authored files from the *same* repos/eras, with **grouped (leave-repo-out)**
CV. That is the recommended follow-up before any strong accuracy claim.

## Actions & recommendations

1. **Do not present 0.90/0.79/0.91 as real-world accuracy.** It is the synthetic-CV
   number; the shipped model is ~random (0.54) on real code. Admin/marketing
   surfaces are corrected to say so.
2. **Retrain on real data for deployment.** The real-data model (artifacts below)
   is strictly better on real code than the synthetic one. The classifier is
   **advisory** (sorts/badges, never hides findings), so shipping the improved-but-
   confounded model is safe and better than the broken one — labeled as such.
3. **Build the repo-controlled dataset + grouped CV** to isolate the true signal
   before elevating the AI-code % beyond an advisory hint.

The **privacy invariant holds throughout**: only the 14 metadata features
(ratios/densities/counts) are computed — no source code enters the model or leaves
the scanner (see `features.py`; the feature CSV artifact contains only numbers).

## Artifacts (committed)

`benchmarks/ai_detect/` — real feature dataset (`ai_detect_real_features.csv`, 429×14),
real-trained model (`ai_detect_real_model.txt`), metrics
(`ai_detect_real_metrics.json`), and the reproducible collectors/scorers
(`ai_collect.sh`, `human_collect.sh`, `score_samples.py`, `retrain_real.py`).
