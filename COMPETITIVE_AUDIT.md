# Competitive Best-in-Class Audit (pre-launch)

**Goal:** within what static analysis *can* do, make Aegis best-in-class per use
case vs the 2026 market leader — on **detection quality** (miss nothing in-range)
and **what the user sees** (data richness, clarity). Structured gap-finding +
targeted hardening + data audit. **Engines were not rebuilt.**

**Date:** 2026-08-12. **Verified live** where marked; leader comparisons are from
public product docs (no leader instance was run).

**Discipline:** in-boundary misses → fixed now (precision-safe). Coverage-breadth
boundaries → logged honestly with priority. Data/UX gaps → logged for the UI pass.
No inflation.

---

## Fixed in this audit (in-boundary)

| Fix | What | Verify |
|-----|------|--------|
| **IaC compose rules locked into the test harness** | The 4 `aegis-compose-*` docker-compose rules fired correctly but had **no `--test` fixture** — a verification blind spot. Added a positive/negative fixture (`tests/fixtures/iac/docker_compose.yml`) + `test_iac_rules.py`, deliberately kept **outside** `rules/iac/` (the scanner loads that dir as a semgrep config, so a target file there would be parsed as a broken rule and silently disable compose scanning — the guard test `test_iac_rules_directory_holds_only_rule_files` now prevents that mistake). | `pytest tests/test_iac_rules.py` → 2 passed; `semgrep --test` → 4/4. |

No other in-boundary miss was found: **43/43 custom SAST rules pass their own
positive/negative fixtures** (see §Security below). The remaining items are
coverage-breadth boundaries (logged) and data/UX gaps (logged for UI).

---

## PART A — Fix-rescan intelligence

Full detail in **`FIX_RESCAN_VERIFICATION.md`**. Summary: fix-detection,
no-phantom-findings, persistence, and re-introduction **all verified PASS** via a
real scan→fix→rescan→re-break cycle. The one gap is **finding-lifecycle state**:
the baseline is rule-level, so resolved/reopened aren't tracked and a re-introduced
or new instance of an already-seen rule isn't flagged `is_new`. Logged **P1**.

---

## PART B — Within-boundary completeness per use case

### SECURITY — SAST (vs Checkmarx One, Semgrep Code, CodeQL)

**In-boundary completeness — VERIFIED.**

- **Custom rules: 43/43 fire on a known positive and stay silent on the sanitized
  version** (`semgrep --test`, run live in-image):
  - Taint rules **31/31** — SQLi, XSS, command-injection, SSRF, path-traversal,
    NoSQL-injection, LDAP-injection, code-injection across **Python (8), JS/TS (9),
    Go (7), Java (7)**; plus React `dangerouslySetInnerHTML` XSS.
  - AI-code failure-mode rules **12/12** (weak-crypto, insecure-random, empty-catch/
    broad-except, JWT-no-verify, SQL-concat, hardcoded-secret — JS + Python).
  - IaC compose rules **4/4** (now harnessed — see above).
- No rule has a coverage claim it fails to meet. **Zero in-boundary misses.**

**Coverage breadth vs leader — honest boundary.** Aegis SAST = **Semgrep public
registry packs** (`p/python`, `p/javascript`+`p/nodejsscan`, `p/typescript`,
`p/java`, `p/golang`, `p/php`, `p/ruby`, `p/csharp`) — i.e. **Semgrep-Code-equivalent
breadth** — **plus** Aegis's own cross-function taint layer on the top 5 languages.
CodeQL/Checkmarx go deeper on whole-program interprocedural dataflow; that is the
genuine boundary of registry+taint static analysis. Honest gaps:

| Gap | Priority | Note |
|-----|:--------:|------|
| **PHP / Ruby / C# get registry rules only** — no Aegis cross-function taint layer | **P2** | We validated a real PHP repo on registry rules (SQLi/XSS fired). Extending the `aegis-<lang>-*` taint pack to PHP is the highest-value language add (our validated user base skews PHP). |
| **C / C++ unsupported** (no pack) → memory-safety CWEs (787/125/416/119/190) out of range | **P3** | Out of Aegis's target (web/app) languages. State the boundary in docs; don't imply C/C++ coverage. |
| **CWE-502 deserialization** — registry-only (`p/python` pickle/`yaml.load`), no dedicated taint rule | **P3** | Common cases covered by registry; a precise Aegis rule would tighten it. |
| **CWE-352 CSRF, CWE-862/863 authz, CWE-287/306 authn** — registry-partial | **P3 (boundary)** | Genuinely hard for framework-agnostic SAST without framework models. Honest boundary, not a quick fix. |

CWE-Top-25 injection classes we **do** cover with custom taint: 79, 89, 78/77, 22,
918, 94, 90, plus 798 (hardcoded creds via gitleaks + ai-code). Breadth on the
non-injection Top-25 comes from the registry.

### SECURITY — SCA (vs Snyk)

**In-range completeness:** manifest-based CVEs via Trivy (verified across prior
phases) **plus** Aegis's vendored-library fingerprinting (Gap-1) for copied-in libs
Snyk-style manifest scanning misses. Good.

**Reachability prioritization — a genuine differentiator, present and best-in-class
in spirit:** Aegis carries `reachable` (import/usage graph) + `is_direct` per
dependency finding and penalizes unreachable vulns — matching Snyk's reachability
positioning.

**Data shown per dependency finding — Aegis vs Snyk:**

| Field | Aegis | Snyk | Gap |
|-------|:-----:|:----:|-----|
| Severity, CVSS score + vector + plain-English breakdown | ✅ | ✅ | — |
| CWE / CVE id | ✅ | ✅ | — |
| Installed + **fixed version** | ✅ | ✅ | — |
| **Reachability** (reachable/unreachable) | ✅ | ✅ | — |
| Direct vs transitive (`is_direct`) | ✅ (bool) | ✅ (full path) | **Dependency *path* (introduced-through chain)** — P2 |
| Advisory link | ✅ (1 primary URL) | ✅ (multiple refs) | **Multiple references** — P3 |
| **Exploit maturity** (mature / PoC / none) | ❌ | ✅ | **P1 data add** |
| **EPSS** (exploit-probability score) | ❌ | ✅ | **P2 data add** |
| **CISA KEV** (known-actively-exploited) | ❌ | ✅ | **P1 data add — free, authoritative, high-signal** |

The three exploitability signals (KEV, EPSS, exploit maturity) are where Snyk's
per-finding data is richer. **CISA KEV is free and authoritative** (a CVE being on
the actively-exploited list is the strongest triage signal there is) and is the
cheapest highest-value data add — logged **P1**.

### SECURITY — Secrets + IaC

- **Secrets:** Gitleaks (broad rule set) + `ai-code-hardcoded-secret`. In-range complete.
- **IaC:** Trivy misconfig (Kubernetes, CloudFormation, Terraform, Dockerfile) +
  `p/dockerfile` + `p/terraform` + **4 Aegis docker-compose rules** (privileged,
  host-network, dangerous-capability, port-on-all-interfaces) — the compose surface
  Trivy misses. All 4 now verified + harnessed. In-range complete.

### QUALITY (vs SonarQube)

**What Aegis shows per quality finding:** severity, cyclomatic complexity, nesting
depth, parameter count, function size, clone/duplication, tech-debt markers
(TODO/FIXME/HACK), magic numbers, debug statements, plus enrichment (impact,
remediation, coarse `estimated_effort` = trivial/quick/moderate/significant).

**What SonarQube gives the user that Aegis doesn't:**

| SonarQube data | Aegis | Priority |
|----------------|:-----:|:--------:|
| **Issue-type classification: Bug / Vulnerability / Code Smell** | ❌ (only pillar + severity) | **P2** |
| **Ratings A–E (Reliability / Security / Maintainability)** | ❌ (0–100 sub-scores exist internally) | **P2** |
| **Remediation effort as time (tech-debt minutes, e.g. "5 min")** | ⚠️ coarse buckets only | **P3** |
| **Quality Gate (pass/fail vs thresholds)** | ⚠️ policy engine exists; not surfaced as a QG | **P3** |
| Exact location, code context | ✅ | — |

Aegis's quality findings are actionable but **less classified** than SonarQube's.
The Bug/Vuln/Smell typing + A–E ratings are the two most visible gaps — both are
presentation/derivation over data Aegis already computes, so relatively cheap.

### DEPLOYMENT (best-executed — no direct competitor)

Deployment findings carry `name`, `command`, `success`, `duration`, **`output_tail`**
(last lines of stdout/stderr for diagnosis), plus `docker:`-keyed remediation
templates. They answer *what failed / why / how to fix*. In-range and actionable.
Enhancement (logged P3): surface the failing command + output tail prominently in
the finding card so the "why" is one glance, not a drill-in.

---

## PART C — What the user sees (per-finding data audit)

Aegis's finding model is already rich. Present per finding today: **severity, CWE,
CVE, OWASP category, exact location (file+line+col), remediation action + markdown
details, `estimated_effort`, reachability, ML false-positive probability, data-flow
/ steps-to-reproduce (taint findings), CVSS breakdown, fixed-version (SCA),
code-ownership (app vs third-party), `is_new`.** That already meets or beats the
leaders on several axes (reachability + FP-probability + steps-to-reproduce +
ownership are not all present in any single competitor).

**Concrete data additions to match/beat the leaders (feeds the UI pass):**

| # | Data addition | Closes gap vs | Priority | Cost |
|---|---------------|---------------|:--------:|------|
| 1 | **Raw code snippet per finding** (the offending line(s) inline) — present today only for taint SoR; SCA/secrets/quality findings show location but not the line | Snyk, SonarQube, Checkmarx (all show the code inline) | **P1** | low |
| 2 | **CISA KEV flag** (actively-exploited) on SCA findings | Snyk | **P1** | low |
| 3 | **Finding lifecycle state** — New / Existing / Resolved / Reopened per finding | Snyk, SonarQube "New Code", Checkmarx | **P1** | high (subsystem — see Part A) |
| 4 | **Exploit maturity + EPSS** on SCA findings | Snyk | **P2** | med (EPSS = free API; maturity partial) |
| 5 | **Dependency path** (introduced-through chain) for transitive vulns | Snyk | **P2** | med |
| 6 | **Bug / Vulnerability / Code-Smell type + A–E ratings** on quality findings | SonarQube | **P2** | low–med (derive from data we compute) |
| 7 | **Multiple advisory references** (not just primary URL) | Snyk | **P3** | low |
| 8 | **Remediation effort as time estimate** (tech-debt minutes) | SonarQube | **P3** | low |

---

## Prioritized backlog (consolidated)

**P1 — do first (biggest signal / cheapest-or-foundational):**
1. **CISA KEV + code-snippet per finding** — two low-cost, high-visibility data adds
   (SCA exploitability + inline code for every finding).
2. **Finding-lifecycle state subsystem** (New/Existing/Resolved/Reopened via stable
   fingerprint) — the one real fix-rescan gap; foundational for PR-gating and matches
   Snyk/SonarQube. Higher cost; schedule as a dedicated build.

**P2 — competitive parity:**
3. Extend Aegis cross-function taint pack to **PHP** (validated user base).
4. **EPSS** score + **dependency path** on SCA findings.
5. **Bug/Vuln/Smell typing + A–E ratings** on quality findings.

**P3 — polish / honest boundaries:**
6. CWE-502 deserialization taint rule; deployment card surfacing; multiple refs;
   tech-debt-minutes effort; Quality Gate surfacing.
7. **Documented boundaries (not gaps to fix):** C/C++ unsupported; CSRF/authz/authn
   registry-partial (hard for framework-agnostic SAST); CodeQL/Checkmarx-depth
   whole-program dataflow is beyond registry+taint.

---

## Honest bottom line

Within the static-analysis boundary, Aegis is **already competitive on detection**
(registry breadth + a verified custom taint layer, 43/43 rules firing) and
**ahead on some UX data** (reachability + FP-probability + steps-to-reproduce +
code-ownership). The real, honest gaps are: **(1) finding-lifecycle state** (P1,
a subsystem), **(2) SCA exploitability signals — KEV/EPSS/maturity** (P1–P2, mostly
free data), **(3) inline code snippet on every finding** (P1, low cost), and
**(4) SonarQube-style quality classification** (P2). None require rebuilding an
engine; all are additive. The one in-boundary miss found (unharnessed IaC rules)
is fixed.
