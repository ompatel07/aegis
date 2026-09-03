# Pass F1 — feature-by-feature validation on current HEAD

**HEAD:** `9ca2614` (T3) · **Run date:** 2026-09-03 · **Rule Zero: observe, do not fix.**
Nothing here was repaired. Every failure is recorded and left in place.

Everything we claim was last validated at or before `bebe7ef`. Since then scoring was rewritten
(C1), the egress chokepoint landed (`67e02aa`/`d96a308`), the product went two-pillar (`b845240`),
ratings became nullable, bundled assets were excluded from SAST (T2), and the taint rules were
rewritten (P2/T3). This pass re-verifies every claimed feature end to end.

> **Headline: a P0 regression shipped in T2 (`b27b0b0`) breaks the entire scan-read API for the
> majority of scans.** See row 5b. It also blocked several rows of this very matrix.

---

## Corpus — small repos only, each scanned twice through the full pipeline

| repo | lang | LOC | manifests | why it is here |
|---|---|--:|---|---|
| **DVWA** (`digininja/DVWA`) | PHP | 13,771 | none | V2 repo; PHP taint ground truth. **The "no CVE-bearing dependencies" control** — no manifest, so SCA must find nothing rather than invent something. |
| **NodeGoat** (`OWASP/NodeGoat`) | JS/Node | 3,084 | package.json + lock | V2 repo. **The "real CVE-bearing dependencies" repo** — old lockfile, 86 dependency CVEs including transitive chains. |
| **dvpwa** (`anxolerd/dvpwa`) | Python | 10,684 | requirements.txt | Python coverage (V2's only Python repo, redash, is 77k — too big for this box). The only corpus repo carrying bundled JS, so it exercises T2 — and, by accident, the only repo whose scan-read API still works (row 5b). |
| **spring-petclinic** (`spring-projects/spring-petclinic`) | Java | 4,214 | pom.xml | Java/Spring coverage; exercises the T3 Spring taint sources. A clean, well-written app — the "should be near-silent" control. |
| *(support)* **F1-lifecycle** | PHP | 7 | none | Purpose-built mutable repo served over `git://` for the lifecycle and line-shift tests. |

8 corpus scans + 6 lifecycle scans, all through the real API → orchestrator → scanner → Postgres
path, never the scanner in isolation.

Legend: **PASS** · **FAIL** · **DEGRADED** (works, but not as claimed) · **BLOCKED** (untestable
because something else is broken) · **UNTESTED** (not testable on this hardware).

---

## 1. Core scanning

| # | Feature | How tested | Result | Evidence | Last validated | Notes |
|---|---|---|---|---|---|---|
| 1 | **Determinism** — same repo twice, byte-identical findings | All 4 repos scanned twice; full outer join of both finding sets on (rule_id, file_path, line_start, severity, fingerprint, title) + per-key counts | **PASS** | `only_in_run1=0, only_in_run2=0, count_mismatch=0` for **all four** repos. Scores identical too: DVWA 39/F, NodeGoat 30/F, dvpwa 30/F, petclinic 84/B in both runs. | Pass 1 | The strongest result in this pass. Survives the C1 scoring rewrite. |
| 1b | *(sub-claim)* **`rule_pack_version` is a reproducible id** | Compared the rule-pack id across the two identical DVWA runs | **FAIL** | DVWA run 1 `rp-20260902-aa68a18d2f` vs run 2 `rp-20260902-9a34819788` — **different id from identical rules and identical findings**. Root cause proven: `_augmented_taint_dir()` returns `tempfile.mkdtemp(prefix="aegis-taint-")`, a random path, appended to `configs` and hashed into the id. Three consecutive calls gave `/tmp/aegis-taint-rmb3w8ao`, `-cgfs6g3q`, `-p_3utxmu`. | — | Fires only where project sanitiser wrappers are detected (DVWA: `dvwaButtonSourceHtmlGet`, `dvwaGuestbook`, `escape`); the other three repos have stable ids. Defeats the field's stated purpose ("recorded so re-scans can surface rule-pack changes") — every re-scan now looks like a rule-pack change. |
| 2 | **All engines fire** (semgrep, trivy SCA, trivy IaC, gitleaks, quality, ruff) | Per repo: presence of `raw_*_output` (proves the engine *ran*, distinct from "found nothing") + finding counts by engine | **PASS** | All 5 repos: `semgrep_ran=t, trivy_ran=t, gitleaks_ran=t, quality_ran=t`, `raw_quality_output ? 'ruff' = t`. Run-1 counts — DVWA 115/4/1/100 · NodeGoat 60/87/3/47 · dvpwa 6/65/0/155 · petclinic 16/0/0/57 (semgrep/trivy/gitleaks/quality). **IaC live**: Dockerfile misconfigs `DS-0002/0005/0013/0026/0029` on DVWA (8), NodeGoat (2), dvpwa (14). | V1 | Ruff and IaC are *not* separate orchestrator calls — ruff runs inside the quality engine (`quality_engine.py:179`), IaC inside trivy (`--scanners vuln,misconfig`). Both verified present. **Per-engine wall time is persisted nowhere** — only whole-scan duration (DVWA 66/76 s, NodeGoat 63/73 s, dvpwa 62/61 s, petclinic 55/44 s). The "time per engine" half of this claim is **UNTESTED**. |
| 2b | *(observation)* **ruff yield** | `raw_quality_output->'ruff'` on every repo | **DEGRADED** | Ruff ran on all 5 repos and returned **0 findings on every one**, including dvpwa (10.7k LOC Python). `codes_selected = ASYNC251,B006,B015,F502,F506,F632,F701,F702,F706,F811,PLE0101` — 11 rules. | Q3 | Not a fault: Q3 deliberately narrowed ruff to a zero-FP set. But on this corpus ruff contributes nothing, so it should not be claimed as active quality coverage. |
| 3 | **Custom pack loaded** (the V1 P0) | `rule_pack_version` non-null per scan + `aegis-*` findings present | **PASS** | `pack=t` on **all 19 completed scans** (19/19). Per single scan: DVWA 31 `aegis-php-*`, NodeGoat 3 `aegis-js-*`, dvpwa 0, petclinic 0. | V1 P0 | dvpwa 0 and petclinic 0 are *correct*, not a pack failure: the Python taint pack has never yielded on real code (V2 §4), and petclinic is clean — T3's 0-FP property holding on well-written code. |
| 4 | **Bundled-asset exclusion (T2) counted and surfaced** | Read `scans.excluded_bundled` after a real pipeline scan | **PASS** | dvpwa: `{"files":3,"bytes":619130,"reasons":{"minified":2,"large-bundled":1},"sample":["sqli/static/js/jquery-3.2.1.min.js","sqli/static/js/materialize.js","sqli/static/js/materialize.min.js"]}` — carried scanner→orchestrator→DB→API. Not silent. | T2 | Correctly NULL on the three repos with no bundled JS — which is exactly the condition that triggers row 5b. |

---

## 2. Multi-tenancy and access

| # | Feature | How tested | Result | Evidence | Last validated | Notes |
|---|---|---|---|---|---|---|
| 5 | **Cross-tenant isolation** | Two real tenants. Pass-4 attack set re-run on current HEAD: 13 cross-tenant reads, 5 cross-tenant writes, own-list check, existence-oracle probe, unauthenticated probe | **PASS** | Every cross-tenant read → **404**, no tenant-A identifier in any body. Every cross-tenant write (trigger scan, rename, delete, PATCH finding, PUT policy) → **404**. `GET /projects` as B → `[]`. Unauthenticated → **401**. **Decisive policy test:** with a real policy set on A's project, B reads `data: null` while A reads the full object. | Pass 4 | No leak, no existence oracle. |
| 5a | *(sub-finding)* `/projects/{id}/policy` status code | Owner vs foreign-tenant vs random-ghost id | **DEGRADED (cosmetic)** | Foreign → `200 {"data":null}`; ghost → `200 {"data":null}`; owner-with-policy → `200 {full policy}`. | — | **Not a leak and not an oracle** — foreign and ghost responses are byte-identical. But it returns 200 where every sibling endpoint returns 404. |
| **5b** | **⛔ P0 REGRESSION — the scan-read API 500s whenever `excluded_bundled` is NULL** | Noticed as a 500 on `GET /projects/{id}/scans` for a tenant's *own* project; traced in the API log; blast radius then mapped endpoint by endpoint | **FAIL (critical)** | API log: `sql: Scan error on column index 30, name "excluded_bundled": unsupported Scan, storing driver.Value type <nil> into type *json.RawMessage`. **Every scan-scoped read 500s** when the column is NULL — `/scans/{id}`, `/findings`, `/report`, `/report/executive`, `/report/compliance`, `/export/sarif`, `/export/sbom`, `/policy`, and `/projects/{id}/scans`. Verified side by side: petclinic (NULL) → 500 on all 8; dvpwa (non-NULL) → 200 on all 8. 3 of 4 corpus projects affected. | — | **Introduced by me in T2 (`b27b0b0`).** Migration 000029 added `excluded_bundled JSONB` **nullable**, but `models.Scan` types it as `json.RawMessage`, which cannot scan NULL. `filtered_secrets` avoided this by being `NOT NULL DEFAULT '{}'`. Since most repos have no bundled JS, **the majority case is broken**. This blocked rows 7, 8, 17, 18 and 19 from API-level verification. |
| 6 | **RBAC — viewer is read-only, enforced backend-side** | Invited tenant B into A's org as `viewer`; 2 reads + 6 writes with B's token | **FAIL** | Reads → 200 (correct). Writes correctly denied **403 "insufficient role for this action"**: trigger scan, rename, delete, set policy, invite user. **But `POST /projects` → 201 CREATED**, and the new project landed in **A's organization** (`organization_id = 902febd4… = "F1 Tenant A's workspace"`), owned by the viewer. | Pass 4 | **Bounded impact:** having created it, the viewer then gets 403 on scan, rename **and even delete** of their own project. A read-only member can inject permanent, un-removable clutter into another org, but cannot consume scan resources. |

---

## 3. Finding lifecycle

Driven with a purpose-built PHP repo served over `git://`, mutated between six real pipeline
scans. Read from Postgres, because the scan-read API is 500 for this project (row 5b).

| # | Feature | How tested | Result | Evidence | Last validated | Notes |
|---|---|---|---|---|---|---|
| 7 | **scan → fix → rescan: New / Existing / Resolved / Reopened** | 5-phase mutation sequence: baseline A → add B → remove B → re-add B → shift | **PASS** | **new**: adding vuln B produced `tainted-sql-string` line 11 → `new` (fp `2ce965e528`). **existing**: vuln A `existing` in every phase (fp `3ea411fbbb` stable throughout). **reopened**: after remove→re-add, *both* rules on vuln B → `reopened` (`2ce965e528`, `23e9dae0be`). **resolved**: `GET /projects/{id}/lifecycle` → `counts: {existing: 2, resolved: 3}` with vuln B's fingerprint `23e9dae0beab…` and `status: "resolved"`. | Pass 3 | Resolved findings are surfaced on the **project** lifecycle endpoint, not as scan rows — correct by design, since the finding no longer exists in the current scan. Worth noting: that endpoint keeps working while `/scans/*` is broken, because it does not select the scan columns. First-scan findings are `existing` rather than `new` because projects default to `grandfather_mode = true`. |
| 8 | **Line-shift resilience** — insert 20 lines above a finding | Phase 5: 20 filler lines prepended, rescan | **PASS** | Every finding moved down exactly 20 lines with an **unchanged fingerprint and unchanged status**: `tainted-sql-string` 5→25 (`aa8f9a11d3`, existing), `aegis-php-sql-injection` 6→26 (`3ea411fbbb`, existing), `tainted-sql-string` 11→31 (`2ce965e528`, existing), `aegis-php-sql-injection` 12→32 (`23e9dae0be`, existing). | Pass 3 | Textbook. Fingerprints are genuinely content-based, not line-based. |
| 9 | **`block_new_findings` PR gate** | Set a real policy on dvpwa (`block_new_findings`, `max_severity: high`, `min_security_score: 80`), then `GET /scans/{id}/policy` | **PASS** | `passed:false` with per-rule detail — `max_severity`: *"worst finding: critical (gate: block high+)"* **fail**; `block_new_findings`: *"0 new finding(s) vs baseline"* **pass**; `min_security_score`: *"security score 0 (min 80)"* **fail**. | Pass 3 | Evaluates against a baseline and reports each rule separately rather than a bare boolean. |

---

## 4. Enrichment

| # | Feature | How tested | Result | Evidence | Last validated | Notes |
|---|---|---|---|---|---|---|
| 10 | **Reachability** — reachable vs non-reachable CVE correctly labelled | Compared `metadata.reachable` / `reachable_files` across the SCA findings of two repos | **PASS** | NodeGoat 30 reachable / 142 not; dvpwa 102 / 8. Discrimination is semantically right: `body-parser` → reachable, `["server.js"]`; `marked` → reachable, `["server.js"]`; `bson` (transitive, unused) → not reachable, 0 files; `fsevents` (macOS-only optional) → not reachable, 0 files. Every reachable finding carries ≥1 file; every unreachable one carries 0. | V1 | |
| 11 | **CISA KEV flag + top-of-list sort + "actively exploited" badge** | Live KEV lookup; API finding order; executive report text | **PASS** | Flag: dvpwa jQuery finding carries `kev:true, kev_name:"JQuery Cross-Site Scripting (XSS) Vulnerability", kev_date_added:"2025-01-23", kev_due_date:"2025-02-13", kev_ransomware:false`. **Sort**: the API returns that **medium**-severity KEV finding at **position 1, above three criticals**. **Badge**: executive report `top_risks[0].impact` = *"⚠ Actively exploited in the wild (CISA KEV)"*. | V1 | KEV outranking raw severity is exactly the claimed behaviour, observed live. |
| 12 | **EPSS scores present, no fabricated zeros** | Aggregated `metadata.epss_score` over all findings | **PASS** | NodeGoat 162/172 CVE findings scored, dvpwa 114/116. Range 0.00150–0.99019. **`exactly_zero = 0` on every repo** — absence is recorded as *absent*, never as a fabricated 0. Live spot-check: `CVE-2021-44228` → `epss_score 0.99999, percentile 1.0`. | V1 | The ~10 unscored CVEs are ones EPSS has no entry for; they are left null rather than zeroed. |
| 13 | **Dependency path for a transitive CVE** | Read `metadata.dependency_path` / `introduced_through` on transitive findings | **PASS** | `CVE-2020-7610` (bson): `["your app","mongodb@2.2.36","mongodb-core@2.1.20","bson@1.0.9"]`, `introduced_through: mongodb@2.2.36`. `CVE-2023-45311` (fsevents): `["your app","forever@2.0.0","forever-monitor@2.0.0","chokidar@2.1.8","fsevents@1.2.9"]`. `CVE-2020-7788` (ini): via `forever@2.0.0 → nconf@0.10.0 → ini@1.3.5`. | V1 | Full chains from "your app" to the vulnerable package, plus the direct dep that introduced it. |
| 14 | **Code ownership — app vs vendored/third-party** | `metadata.code_ownership` distribution | **PASS** | DVWA 440 app / 0 third-party (no deps — correct); NodeGoat 222 / 172; dvpwa 336 / 116; petclinic 146 / 0. Reasons are specific, e.g. `ownership_reason: "vendored library (fingerprint): jQuery 3.2.1"`. | V1 | |
| 15 | **Vendored fingerprinting** — planted old library yields CVEs | Occurred **naturally** on dvpwa, which vendors `jquery-3.2.1.min.js`; no planting needed | **PASS** | Finding carries `detected_via:"fingerprint"`, `vendored:true`, `library:"jQuery"`, `installed_version:"3.2.1"`, `fixed_version:"3.5.0"`, `CVE-2020-11023`, `kev:true`, `epss 0.8383`. | Taaza / T2 | This is also a **live end-to-end proof of the T2 CONDITION-1 guarantee**: the very same file appears in `excluded_bundled` (excluded from SAST) *and* still produced its dependency CVE through fingerprinting. |
| 16 | **Inline snippets on every finding type; secrets redacted** | Snippet coverage by engine; inspection of every gitleaks finding's snippet and metadata | **PASS** | Coverage: gitleaks 8/8 (100%), quality 718/718 (100%), semgrep 394/394 (100%), trivy 292/312 (93.6%). **Redaction visible**: `user-token: ***[32c]`, `Cookie: PHPS…[36c]`, `MIIC…[64c]`, and `metadata.match` = `"user-token: ***[32c]"`. No plaintext secret anywhere. | P1a/P1c | The 20 trivy findings without snippets are SCA rows with no code location — expected, not a gap. |

---

## 5. Honest states

| # | Feature | How tested | Result | Evidence | Last validated | Notes |
|---|---|---|---|---|---|---|
| 17 | **Not measured** — nil end to end, never blank/0/A | Occurred **naturally**: petclinic's trivy hit a Maven 429. Also forced a degradation on a spare dvpwa scan to check the API surface (then restored) | **PASS** *(data + API)* | petclinic: `security_score IS NULL`, `security_rating IS NULL`, quality 84, overall 84/B. In the API the two fields are **omitted entirely** (nil) rather than sent as 0 or "A". Contrast dvpwa: `security_score = 0`, rating `E` — **a real measured zero is preserved as 0**, so the 0-vs-NULL distinction the C1 work introduced is intact. Web renderer covered by 15/15 `display.test.ts` assertions incl. never-blank/0/A. | C1 / D1 | **But see 17b — the executive report violates this.** |
| 17b | *(defect)* **Executive report fabricates a not-measured score** | Read `report/executive.summary` for dvpwa and compared with the DB | **FAIL** | DB: `deployment_score IS NULL` (deployment only runs in CI mode — two-pillar product). Report text: *"scored an overall grade of F (security 0, quality 65, **deployment 0**)"*. | — | A NOT-MEASURED pillar rendered as a measured **0** in a customer-facing narrative — precisely the `return 100` / fabricated-score defect class the honest-state work exists to prevent. The web UI gets this right; the report generator does not. |
| 18 | **Degraded** — surfaced everywhere, never presentable as clean | Natural degradation (petclinic trivy 429) + a forced degradation injected on a spare scan and then restored | **PASS** | Natural: `engines_degraded = [{engine:"trivy", reason:"…429 Too Many Requests…", coverage_lost:"SCA (dependency CVEs)"}]` with security score/rating NULL. Forced: the record surfaced through the API `engines_degraded` **and** SARIF (row 21). Web `scanSummaryState` asserts a degraded scan is never clean-presentable (tested). | D1 | The real-world 429 is better evidence than the forced one: the machinery caught an unplanned failure correctly and refused to score the pillar. |
| 19 | **Partial overall** — carries qualifier + amber, never a bare grade | petclinic is a genuine partial (quality measured, security not) | **PASS** *(data + renderer)* | petclinic overall 84/B derived from quality alone with security NULL. `overallState()` returns `"partial"` for exactly this shape and `partialQualifier()` yields the qualifier text; asserted in `display.test.ts` ("a partially-measured overall is 'partial', never 'full'"). | C1 / P4a | Live UI verification for **this** scan is **BLOCKED** by 5b (petclinic's scan API 500s). Verified at data + renderer level instead. |
| 20 | **`filtered_secrets` + `secret_context` tags render with reasons** | Planted a fixture with placeholder-shaped secrets and an expired JWT, ran the secrets engine; plus real corpus secrets | **PASS** | Filtering: `filtered_secrets = {"expired_jwt": 1}` with **0 findings reported** — suppressed *and counted*, not silently dropped. Context tagging: NodeGoat's `private-key` carries `secret_context:"live-format"`, `secret_context_reason:"matches private-key-pem live format"`, severity **critical** (a real credential is never down-ranked). | S1 / P1 | The corpus itself filtered nothing (`{}` on all 4 repos), so the filtering half needed the planted fixture. |

---

## 6. Outputs

| # | Feature | How tested | Result | Evidence | Last validated | Notes |
|---|---|---|---|---|---|---|
| 21 | **SARIF export** — valid schema, degraded flagged, truncation surfaced | Fetched real SARIF; then re-fetched with a forced degradation | **PASS** | Schema `sarif-schema-2.1.0.json`, `version 2.1.0`, 1 run, `tool.driver.name = Aegis 1.0.0`, 75 rules, 226 results, `versionControlProvenance` present, results carry `ruleId/ruleIndex/level/locations/message/partialFingerprints/properties`. **Degraded flagged (live)**: `invocations:[{executionSuccessful:false, toolExecutionNotifications:[{level:"warning", message:"semgrep degraded: … (coverage lost: SAST (taint + injection))", properties:{engine, coverage_lost}}]}]`. | Pass 5 | On a clean scan `invocations` is absent via `omitempty` — correct, not a gap. Truncation is plumbed (`AllByScanCapped` returns a `truncated` flag) but this corpus never hit the cap, so **truncation surfacing is UNTESTED**. |
| 22 | **SBOM** — valid, complete | Fetched SBOM for dvpwa and reconciled against the manifest | **PASS** | CycloneDX **1.7**, `serialNumber`, `metadata.tools` = trivy 0.71.2, plus `dependencies` and `vulnerabilities` sections. **Completeness reconciled exactly**: `requirements.txt` contains **18** packages; SBOM has **19** components = 18 packages + 1 root application component. 18/19 carry both `version` and `purl` (the root component legitimately has neither). | Pass 5 | |
| 23 | **Compliance reports + mapping spot-check** (Pass 6 was never done) | Generated the SOC 2 report; read the control catalogue; verified 10 control mappings against the actual findings and their CWEs | **DEGRADED** | Report generates: SOC 2 (2017 TSC), 9 controls in scope, 6 need attention, 33% passing, 82% control coverage, HTML + SLA table (critical → 7 days, high → 30, medium → 90). **8 of 10 mappings accurate** — CC6.6←CWE-89 SQLi ✓, CC6.7←CWE-327 MD5 ✓, CC7.2←Dockerfile root user ✓, CC6.8←vulnerable component ✓, CC8.1 correctly *passing* with 0 hard-coded secrets ✓, CC6.1/CC6.2 correctly 0 ✓, CC1.x/CC9.x honestly declared *"requires external evidence"* ✓. | never | **Two real defects — see 23a/23b.** |
| 23a | *(defect)* **CC6.3 false attribution** | Traced the finding behind CC6.3 | **FAIL (mapping)** | CC6.3 is *"Role-based access enforcement"*. Its 2 open findings are `writable-filesystem-service` — *"Service 'redis' is running with a writable root filesystem"*, which carries `CWE-732` + `A05:2021 Security Misconfiguration`. Because **CWE-732 is listed under both CC6.3 and CC7.2**, a container-hardening finding is attributed to an RBAC control. | never | CWE-732 ("Incorrect Permission Assignment for Critical Resource") is too broad to key an RBAC control on. The finding's own OWASP category (A05) already says it is misconfiguration. |
| 23b | *(defect)* **CC6.8 and CC7.1 double-count** | Compared the two controls' finding sets | **DEGRADED** | Both report **exactly the same 58 findings** (every dependency CVE), because CWE-937 is listed under both. | never | Defensible in principle (a CVE is evidence for both "malicious software prevention" and "vulnerability monitoring"), but it means "6 controls need attention" is inflated and the two controls are not independent signals. |
| 24 | **Report rendering** | Fetched `/report` and `/report/executive` | **PASS** *(with 17b)* | `/report` → pillar/severity breakdown + scan record. `/report/executive` → `project, summary, top_risks, trend, priorities, generated_by`. Trend: `previous_grade F → current F, overall_delta 0`. Priorities: *"Remediate 3 critical finding(s) immediately — these are exploitable now."* `top_risks[0]` correctly surfaces the KEV jQuery finding. | Pass 5 | No PDF renderer exists — reports are JSON + embedded HTML. The rendering works; its **content** carries the fabricated "deployment 0" from row 17b. |

---

## 7. Privacy and self-update

| # | Feature | How tested | Result | Evidence | Last validated | Notes |
|---|---|---|---|---|---|---|
| 25 | **Privacy ladder L1–L5** | Searched the entire repo — code, config, migrations, docs — for any graded privacy/data-sharing control | **FAIL (feature absent)** | No match for a privacy ladder, privacy level, tiered data-sharing, or L1–L5 concept anywhere in `services/`, `web/`, `database/` or `docs/`. `config.py` has no privacy/egress/offline/air-gap setting. The only "tier" language in docs is `UI_DATA_AUDIT.md`'s *finding sort order*, which is unrelated. | never | **There is no implemented privacy ladder on this HEAD.** Related privacy properties *do* exist and are real (no customer-code execution, metadata-only ML features, egress redaction, per-project AI opt-in, and the compliance path sending "findings metadata only — never source code"), but they are not organised or exposed as L1–L5. The claim as stated is unsupported. |
| 26 | **AI opt-in is off by default and stays off** | Checked the migration default, the live flag on 4 freshly-created projects, and the service semantics | **PASS** | Migration 000011: `ai_fix_enabled BOOLEAN NOT NULL DEFAULT FALSE`. All four F1 projects created during this pass: `ai_fix_enabled = f`. `ErrAINotEnabled` guards the suggest-fix path. | Pass 5 | ⚠ Presentation caveat: `GET /ai/status` reports `{"enabled": true, "provider": "mock"}`. That is *backend availability* (`s.backend != nil`), **not** per-project opt-in — but the field name invites misreading. |
| 27 | **Self-updating feeds current** — actual timestamps, not "configured to refresh" | Queried the intel status endpoint, the live KEV catalogue, a live EPSS lookup, and the trivy DB metadata | **PASS** | **NVD** last success 2026-09-02 14:41→14:42 (+19 / ~1,981 updated); **GHSA** 14:42 (+20/80); **OSV** 14:42 (481 updated); **semgrep** 14:42. Totals: 17,938 CVEs (nvd 16,573 / ghsa 946 / osv 419). **KEV**: catalogue version **2026.09.02**, 1,694 entries, loaded 18:09:41Z; `is_kev("CVE-2021-44228") = true`. **EPSS**: live `CVE-2021-44228 → 0.99999 (percentile 1.0)`. **Trivy DB**: `UpdatedAt 2026-09-02T07:08:42Z`, `DownloadedAt 09:48:39Z`, `NextUpdate 2026-09-03`. | V1 | KEV and EPSS are **not** in the `intelligence_sources` table — KEV is an in-process cache refreshed every 6 h, EPSS is an on-demand 24 h per-CVE cache. So the admin status endpoint under-reports what is actually being refreshed; both were verified live instead. `kev.status()` reads `entries: 0` until first use (lazy load) — cosmetic. |
| 28 | **Egress chokepoint — parametrized no-plaintext test, on real repos** | Ran the dedicated suite, then inspected real secret findings from the corpus end to end | **PASS** | `tests/test_secret_never_leaks.py` — **18 passed**. On real data every secret is redacted at the egress boundary in both the snippet and the metadata: `user-token: ***[32c]`, `PHPS…[36c]`, `MIIC…[64c]`, `metadata.match = "user-token: ***[32c]"`. | 67e02aa/d96a308 | Redaction is visible in Postgres, i.e. it happened *before* persistence, not just before display. |

---

## 8. ML safety

| # | Feature | How tested | Result | Evidence | Last validated | Notes |
|---|---|---|---|---|---|---|
| 29 | **Per-project memory is advisory-only and NEVER hides** | Marked 3 critical findings as false positives via the real API, re-listed, then ran a **full rescan** and compared probabilities | **PASS** *(safety)* | Findings visible before **20**, after **20** — unchanged. All 3 marked findings **still returned**. **Severity floor held: all three stayed `critical`.** `is_false_positive=true` is recorded as a flag only. Code confirms it can only re-rank: `false_positive_probability` appears **only** in `ORDER BY` (`finding.go:207`) and the web comparator (`findingOrder.ts:30`) — **no `WHERE` clause anywhere filters on it**. | Pass 5 | The safety property is solid. |
| 29b | *(sub-claim)* **the 0.0048 → 0.5024 per-project memory shift** | Same test: 3 FPs marked, then a completed rescan of the same project | **FAIL (does not reproduce)** | Probabilities after the rescan are **byte-identical** to before: `0.0026 → 0.0026`, `0.0093 → 0.0093`, `0.0014 → 0.0014`. | — | Mechanism is absent on this HEAD: the classifier is a **static seeded model** at a fixed path (`/opt/aegis/models/fp_classifier.joblib`, trained from `generate_seed()`), its only project inputs are `project_language` and `project_size_bucket`, and **the orchestrator never passes feedback or FP history to the scanner**. `finding_feedback` rows are written but not consumed by scoring. |
| 30 | **Cross-project learning still OFF** | Inspected model scoping, the feature record, and the feedback path | **PASS** | There is no cross-project learning because there is **no learning from customer data at all**: one static seeded artifact, no per-project or global retraining job, and `finding_feedback` is never read back into scoring. Features are metadata-only (`test_feature_record_is_metadata_only`) — rule id, engine, severity, path *patterns*, LOC bucket, language — never code. | Pass 5 | Passes, but for a stronger reason than "the switch is off": the capability is not wired at all (see 29b). |

---

## FAILs and DEGRADEDs, ranked by severity

| rank | row | severity | issue | why it matters |
|---|---|---|---|---|
| **1** | **5b** | **P0 — critical** | Every scan-scoped read endpoint 500s when `excluded_bundled` is NULL (nullable column vs non-nullable `json.RawMessage`) | **The product's core read path is broken for the majority of scans** — scan detail, findings, all reports, SARIF, SBOM, policy. Any repo without bundled JS is affected: 3 of 4 corpus repos. Shipped in T2 `b27b0b0` and pushed to main. It also blocked five rows of this matrix. |
| **2** | **25** | High | Privacy ladder L1–L5 does not exist | A publicly-claimed capability with **no implementation of any kind**. Related privacy properties are real but are not a graded ladder. |
| **3** | **6** | Medium-high | A `viewer` can `POST /projects` into an org they only have read access to | RBAC boundary violation. Bounded (cannot scan, rename, or even delete afterwards) but it is an unauthorised write that leaves un-removable objects in another tenant's org. |
| **4** | **17b** | Medium-high | Executive report prints "deployment 0" for a pillar that was never measured | A fabricated quantitative claim in a customer-facing report — the exact defect class the honest-state work exists to eliminate. The UI is correct; the report generator is not. |
| **5** | **29b** | Medium | The per-project FP memory does not shift probabilities | A claimed learning behaviour that provably does not happen; `finding_feedback` is collected but never used. (The *safety* half — never hides — passes.) |
| **6** | **1b** | Medium | `rule_pack_version` is not reproducible where sanitiser wrappers are detected | Defeats rule-pack-change detection: identical rules produce a new id every scan, so every re-scan looks like a rule change. |
| **7** | **23a** | Medium | CC6.3 (RBAC) is fed container-hardening findings via the over-broad CWE-732 | Compliance evidence is wrong for a specific control — worse than a gap, because it looks authoritative. |
| **8** | **23b** | Low-medium | CC6.8 and CC7.1 double-count the same 58 CVEs | Inflates "controls needing attention"; the two controls are not independent signals. |
| **9** | **2b** | Low | Ruff yields 0 findings across the entire corpus | Not a defect (Q3 narrowed it deliberately), but it should not be claimed as active quality coverage. |
| **10** | **5a** | Low (cosmetic) | `/projects/{id}/policy` returns 200 where siblings return 404 | No leak and no oracle — foreign and ghost responses are identical — but inconsistent. |
| **11** | **27** | Low (cosmetic) | KEV/EPSS are absent from the intel status endpoint | Both are genuinely fresh and were verified live; the admin surface simply under-reports them. |
| **12** | **26** | Low (cosmetic) | `/ai/status` says `enabled: true` | Means "backend configured", not "opted in". Per-project opt-in is correctly false by default; the field name invites misreading. |

---

## Explicitly NOT tested on this hardware

| item | why |
|---|---|
| **Per-engine wall time** (row 2) | Never persisted — only whole-scan duration is stored. Would need instrumentation, not a query. |
| **SARIF truncation surfacing** (row 21) | The plumbing exists (`AllByScanCapped` → `truncated`) but no corpus repo produced enough findings to hit the cap. Untested, not assumed working. |
| **Live UI rendering of not-measured / degraded / partial** (rows 17, 18, 19) | **Blocked by 5b** — the scan pages 500 for exactly the scans that carry those states. Verified at DB, API and renderer-unit level instead. |
| **Deployment pillar behaviour** | Two-pillar product; deployment runs only in CI mode against a pre-built workspace, which this box does not provide. `deployment_score` is NULL throughout by design. |
| **Deep scan (Joern/CodeQL)** | Not part of the fast-path image (`INCLUDE_JOERN=false`); no deep-scan claims were exercised. |
| **SSO / SCIM / GitHub App / webhooks / notifications** | Require external identity providers and inbound callbacks; out of reach here and out of scope for this matrix. |
| **PDF export** (row 24) | No PDF renderer exists — reports are JSON + embedded HTML. Nothing to test. |

---

## GATE

| check | result |
|---|---|
| Full matrix, every row with real evidence | **done** — 30 numbered claims plus 8 sub-findings, each with the command/output that produced the verdict |
| Explicit FAIL/DEGRADED list, ranked | **done** — 12 entries above |
| Untested stated as untested | **done** — 7 entries above, none assumed working |
| `go build ./...` | **PASS** — orchestrator exit 0, api exit 0 |
| web typecheck | **PASS** — `tsc --noEmit` exit 0 |
| web tests | **PASS** — 15/15 (`display.test.ts` + `findingOrder.test.ts`) |
| scanner suite | **PASS** — `pytest tests/` **150/150 passed**, 0 failures, 0 errors |

**Note on the gate:** the suite is green *and* the product's core read path is broken (row 5b).
That is the important lesson of this pass — 150 passing scanner tests, a clean `go build`, and a
clean typecheck did not catch a nullable-column/`json.RawMessage` mismatch, because nothing in the
suite reads a scan back through the API with that column NULL. The gap is integration coverage of
the API read path, not unit coverage.

---

## Test artifacts left in place (Rule Zero — not cleaned up)

Two tenants (`f1-tenant-a@…`, `f1-tenant-b@…`), 5 F1 projects, 19 scans, one policy on
`F1-dvpwa`, 3 findings marked false-positive on `F1-dvpwa`, and the `viewer-made` project from
row 6 (which the viewer who created it cannot delete). One forced degradation was injected on a
spare dvpwa scan to exercise rows 18/21 and was **restored to its original values** afterwards
(`engines_degraded=[]`, `security_score=0`, `security_rating='E'`).
