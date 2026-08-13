# ML Learning & Self-Update Audit (pre-launch)

Verification-only (nothing built or enabled). Two questions, answered against real
code, real runs, and real timestamps — **2026-08-13**. No inflation: where a
source is rebuild-only or needs network, it's stated plainly.

**Launch ML config (the bottom line):** *Per-project memory is ON — isolated per
project, advisory-only, and it never hides a finding. Cross-project / global
learning is OFF — the global false-positive model is seed-trained only, with no
feedback exporter and no scheduled retrain. It is deferred post-launch, to be
enabled only with guardrails (incl. a severity/KEV floor).*

---

# PART 1 — Self-updating audit, every engine

| Engine / source | Update mechanism | Cadence | Auto vs rebuild-only | Last verified current | Could it go stale silently? |
|---|---|---|---|---|---|
| **SCA — Trivy vuln DB** | `trivy fs` downloads the DB (no `--skip-db-update`); a boot + 6 h loop runs `trivy image --download-db-only` | Trivy DB 24 h cycle | **Auto** (network) | `UpdatedAt 2026-08-13T07:15Z`, `NextUpdate 08-14` | Only if the scanner is **offline** — Trivy then reuses the last DB. Operationally monitorable. |
| **CVE feeds — NVD / OSV / GHSA** | intelligence `Scheduler` ticker → `UpsertCVE` + `FlagAffectedScans` | NVD 24 h · OSV 6 h · GHSA 24 h | **Auto** | all synced **2026-08-13 ~10:15**, `status=success`; newest CVE modified today | Only if the orchestrator is down — and the gap shows in `intelligence_sync_log` (not silent). |
| **CISA KEV** | `utils/kev.py` fetches the CISA JSON feed; boot + 6 h refresh | 6 h | **Auto** (network) | catalog **v2026.08.11**, 1,665 entries | Only if offline. |
| **EPSS** | `utils/epss.py` batch-fetches per scan; 24 h per-CVE cache | per-scan / ≤24 h TTL | **Auto** (network) | scores dated 2026-08-12 | Per-scan fetch ⇒ always ≤24 h fresh when online. |
| **SAST — Semgrep registry rules** | `semgrep` resolves `p/*` from the registry **at scan time** (no persisted cache) | per scan (live) | **Auto** (network) | registry **HTTP 200**; rules fire | If offline, semgrep can't fetch `p/*` → SAST degrades to the bundled custom rules (visible as fewer findings). |
| **Secrets — Gitleaks rules** | Gitleaks binary default ruleset (`useDefault = true`) + bundled `rules/gitleaks.toml` (2 custom rules) | none | **REBUILD-ONLY** | gitleaks **8.21.2** (pinned) | **YES — flagged.** New secret patterns arrive only via a gitleaks binary upgrade or a new custom rule; the ruleset does not self-update. |
| **Custom `aegis-*` rules (52)** | bundled in the scanner image (`rules/taint` 36 · `ai_code_taint` 12 · `iac` 4) | none | **REBUILD-ONLY** (by design) | **52/52 pass `semgrep --test`** today | No — static by design; we control when rules are added. Not silent. |
| **IaC** | Trivy misconfig (ships with the Trivy DB) + `aegis-compose-*` (bundled) | Trivy 24 h / compose rebuild-only | **Mixed** | Trivy DB today; `aegis-compose-privileged` fires | Trivy part auto; compose part rebuild-only (by design). |
| **Quality** | static threshold constants (`_CC_WARN=11`, `_GOD_FUNC_NLOC=500`, …) | none | **REBUILD-ONLY** | n/a — deterministic measurement, not time-sensitive vuln data | N/A — thresholds don't "go stale". |

### Stale-risk flags (Part 1)

1. **Gitleaks secret patterns are rebuild-only.** A brand-new secret format (e.g. a
   new provider's token) is not detected until the pinned gitleaks binary is
   upgraded or a custom rule is added. *Mitigation:* the gitleaks default ruleset is
   broad and upstream-maintained; bumping the pinned version is a routine image
   update. **Honest gap, not a blocker — but track it.**
2. **Offline scanner = silent-ish staleness for the network sources** (Trivy DB,
   Semgrep registry, KEV, EPSS). They degrade gracefully (last DB / bundled rules)
   but a prolonged network outage would age them without a hard failure. *Mitigation:*
   monitor the Trivy `metadata.json` age + `intelligence_sync_log`.
3. **Custom rules + quality thresholds are rebuild-only by design** — expected, not a
   silent-stale risk (we control releases).

Everything else (Trivy DB, CVE feeds, KEV, EPSS, Semgrep registry) **self-updates
automatically** and was verified current today.

---

# PART 2 — ML safety confirmation

## A) Per-project memory — ON, isolated, advisory-only ✅

**Mechanism.** User feedback (`POST /findings/{id}/feedback`, action
`marked_fp`/`ignored`/… ) → `finding_feedback` + `UpsertRuleStats` updates
`project_rule_stats(project_id, rule_id)` (`total_feedback`, `fp_count`,
`fp_rate`). At the next scan, `applyTeamPriors` blends that rate into the finding's
FP probability **only for rules with `total_feedback ≥ 3`**:
`blended = 0.5·base + 0.5·fp_rate`.

**Live proof** (real scans, project A):

| Step | Result |
|------|--------|
| Baseline `aegis-py-sql-injection` (3 findings) | fp_prob **0.0048**, all **3 visible** |
| Submit 3 × `marked_fp` feedback | HTTP 204 |
| Re-scan project A | fp_prob **0.5024** (= 0.5·0.0048 + 0.5·1.0 — exactly the documented blend) |
| Findings after feedback | **still 3/3 visible, finding SET unchanged** |

1. **`fp_rate` updates per project+rule and affects that project's score** — 0.0048
   → 0.5024. ✅
2. **Isolated per project** — the same repo scanned as **project B** kept fp_prob
   **0.0048** (baseline, *not* blended). Project A's feedback never touched B. ✅
3. **Advisory-only, NEVER hides** — after the feedback the 3 findings were still all
   present; only the score (and thus badge/within-band order) changed. The finding
   SET was byte-identical. `marked_fp` feedback does **not** set `is_suppressed`
   (that's a separate, explicit user "ignore" action). ✅

## B) Global / cross-project learning — OFF ✅

1. **Seed-trained only, no auto-learn.** `classifier.ensure_model` trains from
   `generate_seed()` only when no model exists. The on-disk model
   `fp_classifier.joblib` is **version 1, dated Jul 3** — untouched since the seed.
   `train.py`'s feedback path (`--data feedback.jsonl`) is **manual and optional**;
   there is **no feedback→JSONL exporter, no scheduled/cron retrain**, and no
   exported feedback file exists on disk.
2. **No cross-project bleed.** Feedback flows only into `project_rule_stats`
   (per-project, isolation proven in §A.2). It never flows into the global model,
   so one project's feedback cannot affect another's global score.
3. **No project-id in the model.** The 13 features (`ml/features.py`) are metadata
   shape only — severity, path depth, LOC, test/generated flags, dependency
   directness, and hashes of engine/rule/ext/language/cwe/owasp. **No project
   identifier**, so the global model structurally cannot learn per-project.
4. **Advisory-only, never hides** — same as §A.3: `false_positive_probability`
   appears in **no** filter/WHERE clause; the API code comments it "advisory:
   sorts + badge, never hides"; the only hide is the manual `is_suppressed` triage.

### CRITICAL — severity / KEV floor status

- **Hidden by ML: NEVER.** No ML score gates visibility (verified in code + live).
- **Cross-band deprioritized by ML: NEVER.** Both the API default order
  (`ORDER BY <severity-rank>, false_positive_probability ASC, …`) and the web
  default sort (`sort = "severity"`) are **severity-first** — ML can only reorder
  *within* a severity band. A critical/high finding is never pushed below a
  lower-severity one by ML. **This is a real severity floor and it holds.**
- **Within-band:** ML does push likely-FPs to the bottom of *their own* severity
  band (by design, to surface likely-real issues first) — a critical stays in the
  critical band, never hidden.
- **Two honest nuances (advisory, not blockers):**
  1. **KEV bumps `risk_level` + score weight (×1.5) + a prominent badge, but not the
     ordering `severity` column.** A KEV finding on a lower-CVSS CVE sorts by that
     CVSS band (it's still flagged "Actively exploited" and never hidden). Most KEV
     CVEs are already high/critical, so this rarely matters — but if the team wants
     KEV to always sort top-of-list, that's a small future change.
  2. **The "likely FP" badge has no severity/KEV floor** — a critical/KEV finding
     with a blended fp_prob > 0.5 *can* show the badge (it did in §A after 3 FP
     marks). It's advisory and never hides, but suppressing that badge on
     critical/KEV findings is a reasonable pre-launch polish.
- **Verdict:** the safety floor the question asks about (high-severity/KEV findings
  are **not hidden and not cross-band deprioritized** by ML) **exists and is
  verified.** The two nuances above are advisory-display refinements, **not**
  must-fix blockers.

### Privacy — metadata-only ✅

Re-confirmed: `ml/features.py` derives every feature from metadata (severity, path
*patterns*/depth, LOC count, dependency directness, and hashes of rule/engine/
ext/language/cwe/owasp). **No source code, no snippets, no raw file paths** enter
the model (the path is used only to compute depth + test/generated booleans +
extension). Training reads metadata rows only.

---

# PART 3 — Determinism + no-regression

Same repo scanned **twice** (project A, back-to-back):

- **18 = 18 findings**, **byte-identical fingerprint set**, **identical finding
  SET** (rule_id + file). The ML/memory layer introduces **no non-determinism**.
- **Per-project `fp_rate` updating does not change the raw finding SET** — after 3
  FP-marks + re-scan, the finding SET was unchanged; only the advisory
  `false_positive_probability` (and hence badge/within-band order) moved
  (0.0048 → 0.5024). Ordering/badges changed, **findings did not**.

---

## Launch readiness — plainly

- ✅ **Self-updating is current and firing** for every network source (Trivy DB,
  NVD/OSV/GHSA, KEV, EPSS, Semgrep registry) — verified with today's timestamps.
- ⚠️ **Gitleaks secret rules are rebuild-only** — the one honest self-update gap;
  track gitleaks version bumps. Not a launch blocker.
- ✅ **Per-project memory: ON, isolated, advisory-only, never hides** — proven live.
- ✅ **Global/cross-project learning: OFF** — seed-only, no exporter, no retrain, no
  project-id in features; defer post-launch with guardrails.
- ✅ **Severity floor holds** — ML never hides and never cross-band deprioritizes;
  the only refinements (KEV top-sort, badge-on-critical) are advisory polish.
- ✅ **Determinism intact** — ML/memory did not break byte-stable fingerprints.
