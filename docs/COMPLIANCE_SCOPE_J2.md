# Pass J2 — verified or declared: closing what is closeable, stating what is not

**HEAD:** `0a3d992` + this change · **Run date:** 2026-09-08
**Evidence base:** 14,041 findings across 101 scans; 156 CWE / 28 OWASP identifiers declared in
shipped rule packs; SBOMs for five ecosystems re-validated.

**Headline:** J1 fixed the mappings that were loaded. It missed that **a second, stale copy of every
framework file sat at the repository root** — still carrying all three defects J1 had just fixed,
and the copy a person browsing the repo finds first. That is gone, and a CI check now makes the
class impossible. The exhaustive evidence audit found **36 dead evidence entries** (J1 had spotted
3). And one J1 measurement was itself wrong: **Go dependency relationships are not "effectively
flat"** — they are complete but shallow, corrected in place.

---

## 1. Part A — the duplicate framework tree

Two trees existed:

| tree | loaded by `FRAMEWORK_DIR`? | state |
|---|:--:|---|
| `services/scanner/compliance/frameworks/` | **yes** | fixed by J1 |
| `compliance/frameworks/` (repo root, own README) | no | **stale — kept every J1 defect** |

All six files differed. The root copy still contained, verbatim:

```yaml
- id: "164.312(e)(2)(ii)"
  name: Guard against unauthorized access during transmission (SSRF/redirect)   # wrong control
- id: CC6.3
  cwe: ["CWE-269", "CWE-266", "CWE-732"]                                         # the F1 over-broad defect
- id: CC8.1
  name: Secrets and credentials not hard-coded (change management)               # wrong title
```

Its README also documented the **pre-J1 behaviour** — "each finding is attributed to every control
whose evidence matches" and "a control in scope with zero open findings is Passing" — i.e. exactly
the double-counting and the overclaiming J1 removed.

**Resolution: deleted.** The loaded copy is the single source. The root copy was not chosen as the
source deliberately: the loader resolves relative to `__file__` and the files ship inside the scanner
image via `COPY . .` from `services/scanner`. Making the root authoritative would require a Docker
build change, and `report.py` already carries a comment about that exact failure — a previous
`parents[3]` path "crashed in /app; the files weren't shipped". The README moved to
`services/scanner/compliance/README.md` and `COMPLIANCE_REPORTS.md` links were repointed.

**The guard.** `services/scanner/tools/check_single_framework_tree.py`, wired into the existing
*Structural guard* CI job. It fails the build if more than one framework tree exists, or if the tree
is not where the loader looks. Verified by reintroducing the duplicate:

```
compliance structure check FAILED:
  - expected exactly one compliance framework tree, found 2:
    ['compliance\frameworks', 'services\scanner\compliance\frameworks']
    A second copy diverges silently -- whichever one the loader does not read
    keeps its defects while looking authoritative.
```

There is a pytest equivalent, but it **skips inside the scanner image** — `services/scanner` is
mounted as `/app` and there is no repository to walk. A test that always skips is not a guard, so
the CI script is what actually enforces this.

---

## 2. Part B — the dead-evidence audit

J1 noticed CWE-937/1035/1104 were never emitted. That was 3 of 36.

**Method.** Every evidence entry in every framework, checked against two inventories: identifiers
**declared** in a shipped rule pack (`services/scanner/rules/**`, 156 CWE / 28 OWASP) and
identifiers **observed** on a real finding (105 CWE / 17 OWASP over 14,041 findings). Anything in
neither cannot fire.

### Results

| verdict | before | after | meaning |
|---|--:|--:|---|
| **OBSERVED** | 229 | 229 | has appeared on a real finding |
| **DECLARED** | 86 | 86 | written into a rule we ship; not yet seen on our corpora |
| **DEAD** | **36** | **0** | in neither — the rule could never fire |
| total entries | 351 | 315 | |

**The 8 distinct dead identifiers, and why each was dead:**

| identifier | why it can never fire |
|---|---|
| `CWE-937` | "OWASP Top Ten 2013 A9" — a *category*, not a weakness. In 0 rule files, 0 findings |
| `CWE-1035` | "OWASP Top Ten 2017 A9" — same. 0 rule files, 0 findings |
| `CWE-2` | "7PK — Environment", a Pillar-level CWE. Nothing emits Pillar CWEs |
| `CWE-1188` | Insecure default initialization — plausible, but no engine we run tags it |
| `CWE-312` | Cleartext storage — our crypto findings use CWE-311/327 instead |
| `CWE-259` | Hard-coded password — our secret findings use CWE-798 instead |
| `CWE-266` | Incorrect privilege assignment — CWE-269 is what actually fires |
| `CWE-434` | Unrestricted file upload — no detector |

All 36 entries removed. **No control lost its last live identifier**, so no control had to move to
`not-assessed` as a result — verified by the audit and asserted by a test.

**Also audited:** `pillars` (45 `security`, 5 `deployment` — all valid) and control-level `rule id`
references (none used; the mappings pivot only on CWE and OWASP category).

### The guard

`services/scanner/compliance/emittable_identifiers.yaml` is a checked-in inventory of what our
engines can emit, regenerated by `scripts/refresh_emittable_identifiers.py`. `declared` is derived
from the rule packs on every run; `observed` is a snapshot, because **CVE-sourced identifiers cannot
be recovered by reading the repository** — 4 of them (`CWE-285`, `CWE-863`, `CWE-1284`, `CWE-1321`)
appear on real findings via Trivy's vulnerability metadata and in no rule file, so a packs-only check
would have wrongly condemned them.

Both the CI script and a parameterised pytest fail on any identifier outside the inventory. Verified
by reintroducing `CWE-937`:

```
compliance structure check FAILED:
  - soc2.yaml: control CC6.3 references identifiers no engine can emit: ['CWE-937']
```

---

## 3. Part C — scope, declared in the mapping and printed on the report

The scope is now a field in each framework file, not a paragraph in a document, and it is rendered
as a banner on the generated report itself.

| framework | standard total | reachable by static analysis | **assessed** | claim | verification |
|---|---|--:|--:|---|---|
| **OWASP ASVS 4.0.3** | 286 requirements, 14 chapters | 13 | **11** | **headline** | normative text |
| **SOC 2** | 33 Common Criteria (CC1.1–CC9.2) | 9 | **7** | **headline** | numbering + titles only |
| ISO/IEC 27001:2022 | 93 Annex A controls | 10 | **8** | supporting evidence | numbering + titles only |
| NIST CSF 2.0 | 106 subcategories, 6 functions | 8 | **7** | supporting evidence | normative text |
| HIPAA Security Rule | ~18 standards across 3 safeguard families | 7 | **5** | supporting evidence | normative text |
| **PCI DSS 4.0** | 12 requirements, **~300 sub-requirements** | 9 | **7** | supporting evidence | numbering + titles only |

**PCI DSS was the one the brief singled out, and it is now explicitly scoped rather than dropped.**
It is narrowed to the software-security requirements a code scanner can speak to (6.2.x, 6.3.x, 8.x,
plus configuration and cryptography), and every generated PCI report opens with:

> **Scope.** SUPPORTING EVIDENCE ONLY. Aegis assesses a small technical subset of this framework.
> This report is an input to an assessment, not coverage of the standard, and must not be presented
> as either. This standard has 12 requirements, ~300 sub-requirements. Aegis assesses 7 of them; 2
> are in scope for the framework but cannot be evidenced by scanning a repository, and 4 require
> external evidence.

ISO 27001 and NIST CSF got the same treatment on the same test — both are similarly thin and both
are labelled supporting evidence. Only **ASVS and SOC 2** carry the headline claim, and a test fails
if that set ever drifts.

Reports for the three paywalled frameworks also print, on the artifact:

> *Control numbering and titles verified against the published list; the full normative text is
> behind a paywall and was NOT read.*

---

## 4. Part D — SBOM

### 4.1 Go dependency relationships — the J1 measurement was wrong

J1 reported Go at **"3.6% (5/139), effectively flat, does not meet the NTIA relationship element"**.
That is incorrect and has been corrected in `docs/COMPLIANCE_ACCURACY_J1.md` in place.

The error was the metric. J1 counted *nodes that have children*. In a Go SBOM almost every edge
hangs off two module nodes:

```
/tmp/j1/go                              -> 2 children
orchestrator/go.mod                     -> 1
api/go.mod                              -> 1
github.com/aegis-platform/api           -> 75 children
github.com/aegis-platform/orchestrator  -> 59 children
```

Five nodes have children; those five carry **138 edges**. Re-measured by reachability from the root:

| ecosystem | components | edges | reachable from root | coverage | max depth |
|---|--:|--:|--:|--:|--:|
| npm (NodeGoat) | 381 | 629 | 381 | **100%** | 12 |
| pip (redash) | 542 | 1087 | 542 | **100%** | 9 |
| composer (DVWA) | 7 | 7 | 7 | **100%** | 4 |
| **go (aegis)** | 138 | 138 | 138 | **100%** | **3** |

**The NTIA relationship element is met for Go.** Every component is related to the component that
includes it. What Go lacks is *depth*: 3 levels against npm's 12, so we can say which module includes
a component but not which direct dependency pulled in a given transitive one.

**Why the depth cannot be closed here.** `go.mod` gives the root's direct requires (17) and lists
indirect modules (58) without their parent edges; `go.sum` carries hashes, not edges. The real graph
needs either `go mod graph` — running the Go toolchain against customer code — or fetching each
module's `go.mod`, a network call per package. The first is barred by the no-customer-code-execution
boundary; the second is the same per-package-lookup objection that rules out supplier resolution.
So this is **declared, not fixed** — and unlike the supplier gap, it costs us no NTIA element.

### 4.2 NTIA completeness, re-measured

| NTIA element | npm | pip | composer | go | maven |
|---|--:|--:|--:|--:|---|
| Supplier name | **0%** | **0%** | **0%** | **0%** | not measured |
| Component name | 100% | 100% | 100% | 100% | not measured |
| Version | 99.7% | 99.6% | 85.7% | 97.1% | not measured |
| Other unique IDs (purl) | 99.7% | 99.6% | 85.7% | 98.6% | not measured |
| Dependency relationships | 100%, depth 12 | 100%, depth 9 | 100%, depth 4 | **100%, depth 3** | not measured |
| Author of SBOM data | ✅ | ✅ | ✅ | ✅ | not measured |
| Timestamp | 100% | 100% | 100% | 100% | not measured |

**One element now fails rather than two.** Supplier name is the single remaining NTIA gap.

### 4.3 Empty SBOMs can no longer be presented as complete

A manifest without a lockfile yields a schema-valid document cataloguing nothing (juice-shop:
`package.json`, no `package-lock.json`, **0 components**). J1 flagged it in the response; J2 stops it
being stored. `GenerateSBOM` now returns empty when the component count is zero, so nothing is
written and the read path reports *"none was generated (e.g. no lockfile)"* — a state the API
already modelled. A customer is never handed an empty inventory that looks like a complete one.

### 4.4 Validators re-run

`spdx-tools 0.8.5` (`validate_full_spdx_document`) and `cyclonedx-python-lib 11.12.0`
(`JsonStrictValidator`, schema 1.7):

```
=== OFFICIAL SPDX (spdx-tools 0.8.5) — J2 re-run ===
  composer_dvwa.spdx.json    VALID (0 messages)
  go_aegis.spdx.json         VALID (0 messages)
  npm_juiceshop.spdx.json    VALID (0 messages)
  npm_nodegoat.spdx.json     VALID (0 messages)
  pip_redash.spdx.json       VALID (0 messages)

=== OFFICIAL CycloneDX (cyclonedx-python-lib 11.12.0, schema 1.7) — J2 re-run ===
  composer_dvwa.cdx.json     VALID
  go_aegis.cdx.json          VALID
  npm_juiceshop.cdx.json     VALID
  npm_nodegoat.cdx.json      VALID
  pip_redash.cdx.json        VALID

internal path leaks across all documents: 0
```

---

## 5. Declared gaps — not attempted, by decision

**Supplier name (NTIA element 1).** Resolving a component's supplier means a registry lookup per
package. In a self-hosted, privacy-first product that is outbound network traffic per scan revealing
the customer's dependency list to third parties — the same objection that governs our reachability
and enrichment design. The alternative, inferring a supplier from the purl namespace, is not the
supplier: `pkg:npm/lodash` tells you the registry coordinate, not who publishes or maintains it.
**A guessed supplier in an audit document is fabricated provenance**, which is worse than an
acknowledged blank. Stated as a known NTIA gap, in the report and in ACCURACY.md.

**Maven.** Trivy resolves a Maven project by fetching parent POMs from Maven Central; during J1 it
returned `429 Too Many Requests` and blocked the IP for ~30 minutes, and it was still blocked on
retry. Trivy's own remedy is `mvn dependency:resolve` — building customer code, which our boundary
forbids. This is a **boundary consequence, not a bug**. The options, none chosen here: offline
resolution from a vendored dependency list; a cached `~/.m2` supplied by the customer; or a CI mode
where the customer's own pipeline produces the SBOM and Aegis ingests it. Each trades a different
principle, which makes it a product decision.

---

## 6. One line for Om

**Closing the paywalled-verification gap costs roughly $400–900 in documents.** The AICPA Trust
Services Criteria and ISO/IEC 27001:2022 are purchasable (ISO ~CHF 200 for 27001 plus ~CHF 200 for
27002, which carries the Annex A implementation guidance; the AICPA TSC is free to members and
otherwise a paid download). PCI DSS 4.0 is free from the PCI SSC but requires accepting its terms of
use, which is a licensing question rather than a cost. Buying them would move SOC 2, ISO 27001 and
PCI from *"numbering and titles verified"* to *"normative text verified"* — the difference between
a mapping we believe is right and one we can defend line by line to an auditor. **That is a decision
for you, not a task**; the code already records which state each framework is in and prints it on
the report.

---

## Gate

| requirement | status |
|---|---|
| Single framework tree + divergence test | ✅ §1 — root copy deleted; CI script fails on a second tree, verified by reintroducing one |
| Dead-evidence audit table + identifier test | ✅ §2 — 351 entries audited, **36 dead → 0**; inventory + CI script + pytest, verified by reintroducing `CWE-937` |
| Per-framework scope table with provenance | ✅ §3 — declared in each YAML, printed on the report, enforced by tests |
| Go relationships fixed or explained | ✅ §4.1 — J1's measurement was wrong; element **is** met, depth limitation declared with the reason |
| NTIA re-measured | ✅ §4.2 — one failing element (supplier), not two |
| Validators pasted | ✅ §4.4 — SPDX 5/5 valid, CycloneDX 5/5 valid, 0 path leaks |
| Empty-SBOM state verified | ✅ §4.3 — never stored; read path reports "not generated" |
| Full suite + `go build ./...` | ✅ **235 passed, 0 failed, 4 skipped** (was 203). The 4 skips are environment-gated and stated: 1 divergence test that needs a git checkout (enforced by the CI script instead), 3 paywall-disclosure tests that do not apply to normative-text frameworks. Both Go services build clean |
