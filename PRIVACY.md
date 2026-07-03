# Aegis — Privacy & Data-Handling Architecture

Aegis is built so that **your source code never leaves your control**. This
document states exactly what data each subsystem touches, and proves the
boundaries architecturally. Enterprise buyers can audit every claim here against
the code paths referenced.

## TL;DR

| Subsystem | Touches source code? | Where it runs |
|-----------|----------------------|---------------|
| Scanners (Semgrep, Trivy, Gitleaks, quality, Joern) | Yes — reads the cloned repo to analyze it | Your infrastructure (self-hosted scanner) |
| Finding enrichment | No — operates on findings/metadata | Your scanner |
| **Local ML false-positive filter** | **No — metadata only** | **Your scanner** |
| Vulnerability intelligence feed | No — package names + public CVE data | Your orchestrator |
| **AI fix suggestions (opt-in)** | **Only the 10–30 flagged lines, if you enable it** | **Backend you choose** |
| Executive AI reports (opt-in) | No — findings JSON only | Backend you choose |

The two subsystems that could conceivably see code — the ML filter and the AI
layer — are the ones we constrain most tightly. Details below.

## 1. The scanners

The scanners read your checked-out repository because static analysis inherently
must. They run **inside your own infrastructure** (the self-hosted `scanner`
service). Aegis never uploads your repository anywhere. Cloning is done by your
orchestrator into a workspace volume; the scanner reads it by path and produces
findings.

## 2. Local ML false-positive filter — metadata only, auditable

The learning layer (`services/scanner/ml/`) predicts whether a finding is likely
a false positive so the UI can sort and badge accordingly. **It never sees source
code.** The only inputs are metadata:

- rule id, engine, severity
- file **extension** and **path depth** (never file contents)
- project language, project size bucket
- lines-of-code **count** in the file (a number, not the lines)
- CWE / OWASP category
- `is_in_test_file`, `is_in_generated_file` — derived from **path patterns**
- `is_direct_dependency` vs transitive (for dependency findings)

This is enforced in one place — `ml/features.py::record_from_finding` — which
constructs the feature record from a fixed allow-list of metadata fields.
`tests/test_ml.py::test_feature_record_is_metadata_only` feeds a finding carrying
raw code fields and asserts none of them appear in the feature record. The model
artifact is a set of numeric tree splits over these metadata features; it cannot
reconstruct code.

Training (`ml/train.py`) reads the same metadata rows (a heuristic cold-start
seed + your users' feedback, materialized into `ml_training_data`). The pipeline
is auditable end to end and produces cross-validated precision/recall metrics.

**The FP score never hides a finding.** It only affects ordering and a "likely
false positive" badge; every finding is always shown.

## 3. User feedback

When a user marks a finding false-positive / confirmed / fixed, we store the
**action** and the finding's **metadata** (`finding_feedback` →
`ml_training_data`). We do not store code. Feedback trains the local model on
your own instance; it is not shared across tenants.

## 4. Vulnerability intelligence feed

The feed syncs **public** CVE data (NVD, OSV, GHSA) and matches it against the
**package names + versions** already in your findings. No source code is
involved, and only package coordinates (never code) are sent to OSV to query for
advisories.

## 5. AI layer — off by default, opt-in, snippet-only, fully audited

The AI fix-suggestion and executive-report features are **disabled by default**
and enabled **per project**. When enabled:

- **Fix suggestions** send only the **10–30 lines around the finding**, never the
  whole file and never the repository. Extraction is centralized and bounded.
- **Executive reports** send only the **findings JSON** (titles, severities,
  counts) — never code.
- You choose the backend: **Aegis-hosted**, **bring-your-own** (your Azure
  OpenAI / AWS Bedrock), or a **self-hosted** endpoint. The backend is a single
  config switch and does not affect any other subsystem.
- **Every AI call is audited**: model used, prompt hash, timestamp, and the user
  who triggered it — so you can answer "show me every AI call in the last 30
  days for our data."
- Suggestions are **advisory only**. Nothing is ever auto-applied; a human must
  review and click Apply.

## 6. What we never do

- We never upload your repository off your infrastructure.
- We never train shared/cross-tenant models on your code or metadata.
- We never send source code to any AI backend beyond the minimal opt-in snippet.
- We never auto-apply an AI-suggested change.
