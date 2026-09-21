# Pass N1 — removing the Semgrep-licensed rules

**2026-09-19.** Semgrep's head of legal declined a vendor/OEM licence, declined relicensing, and
confirmed that permitted use is limited. There is no route to shipping their rules commercially,
so they are gone. The Semgrep CE **engine** (LGPL-2.1) is not affected and is still used.

The goal was a clean, working product that we fully own, not maximum coverage. Every number
below was re-measured after the cut. Where a before-number is quoted, it was measured **the same
day, with the same harness, on the same checkout**, so the difference is the cut and nothing else.

---

## Gate

| requirement | result |
|---|---|
| Licence table; no restricted rule remains; manifest guard | ✅ §A — 2,677 rule entries removed, **0 remain**; `tools/check_rule_licences.py` caught all **8** violations planted against it |
| CI fully green, all engines running | ⚠ §B.5/§B.7 — every test job green (scanner, Go api + orchestrator with live seams, web typecheck, guards, and the self-scan SAST job, **broken since G2 and now fixed**). **Not green:** four self-scan dependency-audit jobs, red since 2026-08-31 on pre-existing CVEs in our own dependencies — not touched in a licensing pass, listed for decision |
| OWASP sovereign numbers | ✅ §C.1 — **Youden 0.459 → 0.051**, F1 0.775 → 0.247 |
| Ground truth before/after | ✅ §C.2 — **24/45 → 22/45**; juice-shop loses two |
| C1 grade spread | ✅ §B.4 — still spreads (A/B/C), constants **not** touched; one issue raised for decision |
| Compliance not-assessed re-audit | ✅ §B.3 — 71 dead evidence identifiers removed, **2 controls → not-assessed** |
| Rewritten claims | ✅ §D — `ACCURACY.md` CORRECTION 11, README, 7 historical docs bannered, G3 §5 corrected in place |
| Ranked rebuild roadmap | ✅ §E |

**Three things the brief did not anticipate:**

1. **A lifecycle defect the cut would have triggered (§B.6).** On every existing customer's first
   scan after upgrading, each finding raised by a removed rule would have been marked *resolved*,
   and the compliance report lists resolved findings as **"remediation evidence — vulnerabilities
   proven closed."** That is fabricated audit evidence. Fixed, with a new `retired` state. The same
   fix closes a pre-existing defect of the same kind: a timed-out engine resolved everything it had
   previously found.
2. **Precision did not rise (§C.4).** On the ground-truth repos our rules run at 73 % and njsscan at
   27 %. At corpus volume it is worse: Dolibarr's SAST, which used to time out, now completes with
   2,362 `aegis-php-xss` findings that are effectively all false (a WAF our rule cannot see).
3. **The self-scan had not evaluated a rule since G2 (§B.7).** Its SAST job has failed on every push
   since 2026-08-31 on a config error. Fixed; once it ran, it found a bug in our own compose rule.

---

## A. What went and what stayed — per licence

Every licence was read from **each rule's own `metadata.license`**, not from the manifest or the
filename.

| pack | rules | licence (per rule) | decision |
|---|--:|---|---|
| default | 1,056 | Semgrep Rules License v1.0 | **removed** |
| owasp-top-ten | 560 | Semgrep Rules License v1.0 | **removed** |
| r2c-security-audit | 225 | Semgrep Rules License v1.0 | **removed** |
| cwe-top-25 | 216 | Semgrep Rules License v1.0 | **removed** |
| python | 151 | Semgrep Rules License v1.0 | **removed** |
| javascript | 74 | Semgrep Rules License v1.0 | **removed** |
| typescript | 74 | Semgrep Rules License v1.0 | **removed** |
| terraform | 63 | Semgrep Rules License v1.0 | **removed** (Trivy covers Terraform) |
| java | 60 | Semgrep Rules License v1.0 | **removed** |
| secrets | 52 | Semgrep Rules License v1.0 | **removed** (gitleaks covers secrets) |
| ruby | 45 | Semgrep Rules License v1.0 | **removed** |
| golang | 42 | Semgrep Rules License v1.0 | **removed** |
| csharp | 27 | Semgrep Rules License v1.0 | **removed** |
| php | 24 | Semgrep Rules License v1.0 | **removed** |
| dockerfile | 7 | Semgrep Rules License v1.0 | **removed** (Trivy covers Dockerfile) |
| supply-chain | 1 | Semgrep Rules License v1.0 | **removed** |
| *(18 `trailofbits.*` rules)* | 18 | AGPL-3.0 | already excluded at vendor time (G2) — confirmed **0 present** |
| **nodejsscan** | **114** | **LGPL-3.0-or-later** | **kept** — see below |
| **Aegis-authored** | **60** | ours | **kept** — taint 42, bug pack 11, IaC 4, CI/CD 3 |

**Before: 2,791 vendored rule entries (1,256 unique ids). After: 174 rules — 60 ours, 114 njsscan.**
The 2,677 removed entries are 1,142 unique rule ids (packs overlap heavily).

### nodejsscan — kept, and verified from source

- **The licence is LGPL-3.0, not LGPL-2.1** as the brief stated. Upstream `ajinabraham/njsscan`
  `LICENSE` is LGPL v3; every rule's own metadata says `LGPL-3.0-or-later`. (LGPL-2.1 is the
  Semgrep CE *engine's* licence.) LGPL-3.0 is unambiguous for shipping rule YAML as source: we
  ship the licence text (`rules/vendor/LICENSES/`, with the GPL-3.0 text it incorporates).
- **Provenance was the one real ambiguity.** Our copy came through the Semgrep *registry*, and
  carried registry-added metadata (`semgrep.dev` blocks, `sg.run` shortlinks, `semgrep.dev/r`
  source URLs). Compared key by key against upstream @ `b6ade853` — patterns, `pattern-not-sinks`,
  sources, sinks, sanitizers, messages, severities, languages, upstream metadata — **zero
  differences** across all 114 rules. The file was then **rebuilt directly from upstream git**, so
  nothing downloaded from the registry remains. Rule ids are unchanged, so fingerprints and
  lifecycle history carry over. See `rules/vendor/NOTICE.md`.

### Every path that could fetch Semgrep-licensed rules — four found, all closed

| path | what it did | now |
|---|---|---|
| `config.py` default `semgrep_base_configs` | `p/owasp-top-ten,p/r2c-security-audit,p/default,p/secrets,p/supply-chain,p/cwe-top-25` | empty; any non-local config is **refused**, never passed to semgrep (`_local_configs_only`) |
| `semgrep_engine._vendored()` | a missing pack file fell back to the `p/<pack>` registry shortcut | returns `None`; a missing pack is dropped and logged |
| **`routers/rules.py` → `semgrep --validate`** | **downloads `p/semgrep-rule-lints` from the registry on every customer-rule validation** (`semgrep/core_runner.py:1203`) and runs those Semgrep-licensed lint rules | replaced by an offline load check (below) |
| **empty config list** | `semgrep scan` with no `--config` defaults to **`--config auto`** — a registry fetch. After the cut a Python repo's third-party config list *is* empty, and the degraded-retry path would have run exactly that | the engine never invokes semgrep without an explicit local `--config`; with nothing to fall back to it reports FAILED |

Plus two non-product paths: `scripts/vendor_rules.py` fetched from `semgrep.dev/c/` (rewritten to
build from upstream git only), and `self-scan.yml` ran `--config p/security-audit` against this
repository (removed: the self-scan now dogfoods exactly the rules we ship).

**The `--validate` replacement is better, not just cleaner.** Measured in a container with the
network disabled: **the old path rejected a *valid* rule** (rc 2) — customer-rule validation had
silently depended on semgrep.dev being reachable and was broken in any air-gapped deployment. The
new path loads the rule with `semgrep scan` against an empty directory and gets all four cases
right: valid → rc 0; missing pattern/languages → rc 7; unparseable pattern → rc 2; unknown
language → rc 8.

### The guard

`services/scanner/tools/check_rule_licences.py` (self-scan.yml, unconditional) + `tests/test_rule_licences.py`:

1. every vendored pack is in the manifest, its sha256 matches, and **every rule** declares a
   licence in `permitted_licences` (read per rule);
2. no orphan pack file exists;
3. every rule outside `vendor/` is Aegis-authored — `aegis-` id, no registry metadata;
4. no rule carries a restricted licence or the `trailofbits.` prefix, **and no rule's matching logic
   equals any of the 1,141 removed rules** (`restricted_rule_fingerprints.txt` — SHA-256 hashes
   only, no rule content);
5. the default config names no registry pack, and the source contains no fetch construct.

The pytest half drives the real engine with `p/default`, `auto` and a `semgrep.dev` URL in settings
and asserts the command line carries only local files.

**Proven against planted violations** on a copy of the tree — all caught:

| planted | caught by |
|---|---|
| a registry rule pasted into `rules/taint/` | restricted licence + non-`aegis-` id + registry metadata |
| the same rule renamed `aegis-…` | restricted licence + registry metadata |
| the same rule, **metadata stripped** and renamed | **logic fingerprint** |
| a removed pack restored to `vendor/` | orphan pack + restricted licence |
| an AGPL `trailofbits.*` rule appended to njsscan | sha mismatch + rule count + licence |
| the registry-fetched njsscan copy restored, sha re-pinned | registry metadata on a vendored rule |
| config default set back to `p/default` | config check |
| `--validate` reintroduced | fetch-construct check |

**An independent confirmation fell out of the fingerprint list:** none of our 60 rules and none of
njsscan's 114 shares matching logic with any removed rule. Our packs are our own work.

---

## B. Making it work

### B.1 Engines, packs, config

| language / surface | before | after |
|---|---|---|
| JS / TS | `p/javascript`/`p/typescript` + njsscan + ours | **njsscan + ours** |
| Python, Java, Go, PHP | registry pack + ours | **ours only** |
| Ruby, C# | registry pack only | **CI/CD rules only** — no application-code SAST |
| Dockerfile, Terraform | registry pack **and** Trivy | **Trivy** |
| secrets | `p/secrets` **and** gitleaks | **gitleaks** |
| every repo | 6 always-on registry packs | ours (taint, bug, IaC, CI/CD) |

Dead references removed with their rules: the Go/PHP registry-rule exclusions, and a
missing-integrity (SRI) filter for a rule that no longer exists. The njsscan cookie exclusions
stay — all three still point at shipped rules. The ML seed profiles name two registry rule ids;
they are synthetic *training* data, not pack references, and changing them would move the
prioritisation model, so they were deliberately left alone.

The degraded-retry path now retries with the pinned third-party pack when one exists; a Python repo
whose own packs fail to load has nothing else, and reports **FAILED** rather than fetching
(`test_seam_no_fallback_fails_instead_of_fetching`).

### B.2 `rule_pack_version` — still reproducible

Five ground-truth repos scanned twice: **identical `rule_pack_version` and byte-identical findings on
all five** (§C.5). The id changed with the cut, as it should — it hashes rule content — and the
date component now reads the new pin (`rp-20260919-…`).

### B.3 Compliance — the emittable-identifier re-audit

The inventory has two halves, and the cut invalidated both:

- **declared** (identifiers written into shipped rules) — regenerated: **156 → 53 CWEs**.
- **observed** (identifiers seen on real findings) — **the trap.** 2,831 stored findings came from
  rules that no longer ship, and **17 CWEs were observed only on those** (CWE-353 ×449,
  CWE-1357 ×223, CWE-319 ×143, …). The refresh script *preserves* this snapshot when it has no
  database, which would have kept them "emittable" forever. It now counts a semgrep finding only if
  its rule still ships, and **refuses to run without a database when the snapshot predates the
  shipped rule set**; `check_single_framework_tree.py` fails on the same condition.

Result: **emittable CWEs 191 → 111, OWASP categories 28 → 8.** 71 dead identifiers were removed
from framework evidence (a text-level edit, then verified semantically: reloading every framework
proves the only change is those removals). **Two controls had no live evidence left**, and became
`not-assessed` — not "no findings":

| control | why |
|---|---|
| **SOC 2 CC6.3** — access based on roles, least privilege | its only evidence, CWE-269, was emitted only by removed rules (2 findings in the whole corpus) |
| **ISO 27001 A.8.2** — privileged access rights | same |

| framework | scored controls | not-assessed | evidence identifiers |
|---|---|---|---|
| OWASP ASVS | 11 → 11 | 2 → 2 | 59 → 45 |
| SOC 2 | **7 → 6** | **2 → 3** | 58 → 44 |
| ISO 27001 | **8 → 7** | **2 → 3** | 52 → 40 |
| NIST CSF | 7 → 7 | 1 → 1 | 58 → 44 |
| PCI DSS | 7 → 7 | 2 → 2 | 43 → 35 |
| HIPAA | 5 → 5 | 2 → 2 | 45 → 36 |

### B.4 C1 grade spread — still spreads; one issue for decision

C1's harness replayed on the V1 corpus with SAST findings from removed rules dropped. (Semgrep rules
match independently — the sovereign OWASP run is *exactly* the `aegis-*` subset of the full run, 461
of 461 — so this subset replay equals a re-scan for the findings that survive.)

| | A | B | C | D | F | overall range | security range |
|---|--:|--:|--:|--:|--:|---|---|
| full rule set (reproduces C1) | 1 | 8 | 5 | 1 | 0 | 59–90 | 31–92 |
| **sovereign** | **3** | **10** | **2** | 0 | 0 | 65–93 | 42–100 |

Grades still spread across three bands, so per the brief **the constants were not touched.**

**But the reason they moved is the thing to decide on.** The spread compressed upward because the
security score measures findings per KLOC, and on this corpus **60–100 % of each repo's security SAST
findings came from removed rules** (median ~94 %, across the 14 of 15 repos that had any). `macrozheng/mall` (Java) goes from security 73 to
**100 / A** — not because its code improved, but because every security finding it had came from a
removed rule. For languages where our own coverage is thin, the security score now largely measures
*how much of the language we can see*. **Recommendation, not implemented:** the security pillar
should carry the per-language SAST coverage on the report (the C1 "not measured" pattern), so a 100
on a Java repo cannot be read as "secure". That is a product decision.

### B.5 CI

Every CI job was run locally the way the workflow runs it (live Postgres, `CI=true`, seam env):

| check | result |
|---|---|
| scanner suite (in the image) | **259 passed**, 0 failed, 7 skipped — 4 are K1's audited skips; 3 are `ruff binary not available` because the **local** image predates ruff (built 2026-08-07); CI builds fresh |
| Go — api | build + vet clean; all packages pass, **`apiseam` ran** against the live API (1.7 s, not skipped) |
| Go — orchestrator | build + vet clean; all packages pass, incl. `TestAbsenceVerdict`, `TestLifecycleEvidenceFromEngineResults` and the DB-backed `TestLifecycleNeverResolvesWhatDidNotRun` (ran, 0.21 s) |
| web typecheck | `tsc --noEmit`: exit 0, no diagnostics |
| self-scan guards | silent degradation, framework tree, SELECT *, **rule licences** — all pass |
| self-scan SAST job | **passes, 0 findings** — after the fixes in §B.7 |

### B.6 Lifecycle — the cut would have fabricated remediation evidence

`applyLifecycle` marked **every** active finding absent from a scan as `resolved`. On each existing
project's first scan after this release, every finding raised by a removed rule would have been
resolved — and the J3 compliance report lists resolved findings under **"Remediation evidence —
vulnerabilities proven closed."** Nothing was fixed; we stopped looking.

The same code had a pre-existing twin: **a timed-out engine resolved everything it had previously
found.** Semgrep timed out on 6 of 15 V2 repositories, so this was not hypothetical.

**The rule now:** a finding's absence proves it fixed only if the detector that raised it ran.

| situation | before | after |
|---|---|---|
| rule ran, did not fire | resolved | **resolved** |
| rule no longer ships (N1), or a custom rule was deleted | resolved | **`retired`** — neither open nor fixed, excluded from both sides, no `resolved_scan_id` |
| engine failed / timed out / skipped | resolved | **unchanged** |
| rule ships but did not run (pack failed, language not detected) | resolved | **unchanged** |
| retired finding seen again | reopened (new) | **existing** — it was never fixed |

The scanner now reports `rules_executed` and `rules_shipped`; the orchestrator derives per-engine
evidence (`types.LifecycleEvidence`); migration **000031** adds `retired` to the CHECK constraint
(its down-migration returns retired rows to `existing`, never `resolved`). A scanner that predates
N1 sends no evidence and gets the old behaviour, so a mixed-version rollout cannot freeze lifecycle.
Deploy order is migrate-first, which both deploy paths enforce (`docs/DEPLOY_ORDERING.md`).

**Proven, not assumed.** The DB-backed test found a real bug on its first run — a parameter used as
two types (`inconsistent types deduced for parameter $3`), which no unit test could have seen — and,
run against a copy with the old logic planted, **fails all five of its assertions**.

### B.7 `self-scan.yml` has been red on every push since 2026-08-31

Checking the brief's "full CI green" against GitHub's history rather than assuming it:
`tests.yml` has passed on every recent push, but **`self-scan.yml` has failed on every push since
2026-08-31 — five of its seven jobs.** Nobody was watching it, including the passes since.

| job | cause | N1 |
|---|---|---|
| **SAST (Semgrep + Aegis rules)** | `--config services/scanner/rules` also loads `manifest.yaml`, which is not a rule file ("missing keys") — failing since G2 put it there, so **the self-scan has not evaluated a single rule against this repository since G2** | **fixed** — the job names the rule directories. It then found **9 ERROR findings in our own code**, handled below |
| Web dependencies (npm audit) | 5 advisories: Auth.js ×3, Next.js ×2 (2 critical, 2 high) | **not touched** — dependency upgrades are their own risk and do not belong in a licensing cut |
| Scanner dependencies (pip-audit) | 17 known vulnerabilities in 4 packages | not touched |
| Go vulnerabilities (govulncheck) | `cloudflare/circl` < 1.6.1 (fixed upstream) | not touched |
| Filesystem + config (Trivy) | fails with the dependency CVEs above | not touched |

The nine findings the SAST job had been hiding:

| finding | verdict | action |
|---|---|---|
| `aegis-compose-dangerous-capability` ×4, `docker-compose.yml` | **FP, and a bug in our rule**: a bare regex that fires on `cap_drop: [ALL]` — the hardening its own message recommends | **rule fixed** (scoped to `cap_add`), with the missing `cap_drop` negative added to its fixture — which failed on the old rule first. It fired **zero** times in every corpus measured here, so no N1 number moves |
| `aegis-py-sql-string-construction` ×3, `scripts/refresh_emittable_identifiers.py` | FP — code **I wrote in this pass**: an f-string interpolating a constant clause, ids bound as parameters | rewritten as literals; re-run produces identical output |
| `aegis-go-xss` ×2, `exec_report.go`, `scans.go` | FP — downloads served as attachments (an escaped server-rendered report; a JSON SBOM). The over-broad `$W.Write` sink P2 already documented | suppressed inline, with the reason at the line |

**What this leaves:** the four dependency-audit jobs stay red for pre-existing CVEs in our own
dependencies. They are listed for decision below, not fixed here.

---

## C. Re-measured — nothing carried over

### C.1 OWASP Benchmark v1.2 — same harness, same day, same checkout

| | TPR | FPR | F1 | **Youden** | findings | scan time |
|---|--:|--:|--:|--:|--:|--:|
| before (registry + ours) | 0.884 | 0.425 | 0.775 | **0.459** | 2,865 | 215 s |
| **after (sovereign)** | **0.154** | **0.103** | **0.247** | **0.051** | 461 | 32 s |

The before run reproduces the published figures to four decimals on today's code, so the published
number was valid and the drop is the cut alone. The 461 sovereign findings are **exactly** the 461
`aegis-*` findings in the before run.

| category | before TP/FP/FN/TN | after TP/FP/FN/TN |
|---|---|---|
| weakrand | 218/0/0/275 | **0**/0/218/275 |
| crypto | 130/0/0/116 | **0**/0/130/116 |
| hash | 89/0/40/107 | **0**/0/129/107 |
| securecookie | 36/0/0/31 | **0**/0/36/31 |
| trustbound | 43/18/40/25 | **0**/0/83/43 |
| xpathi | 14/13/1/7 | 0/0/15/20 |
| cmdi | 117/109/9/16 | 7/0/119/125 |
| ldapi | 26/28/1/4 | 5/7/22/25 |
| sqli | 253/170/19/62 | 77/55/195/177 |
| xss | 202/112/44/97 | 78/35/168/174 |
| pathtraver | 123/113/10/22 | 51/39/82/96 |

**Five categories go to zero** — weak random, weak crypto, weak hash, insecure cookie, trust
boundary were entirely registry rules. They are also the cheapest to rebuild (§E). Our Java taint
rules hold SQLi, XSS and path traversal at lower recall and much lower FPR.

**What this means for the pitch:** the "leads CodeQL on Youden, 0.459 vs 0.288" claim is withdrawn.
On this benchmark Aegis now scores **below CodeQL (0.288) and below base Semgrep (0.156)**.

### C.2 Ground truth — five repos, one harness

| repo | documented | before | after | lost |
|---|--:|--:|--:|---|
| DVWA | 6 | 3 | 3 | — |
| WebGoat | 6 | 6 | 6 | — |
| NodeGoat | 7 | 5 | 5 | — |
| dvpwa | 1 | 1 | 1 | — |
| juice-shop | 25 | 9 | **7** | directoryListing, accessLogDisclosure — both caught only by `express-check-directory-listing` |
| **total** | **45** | **24** | **22** | |

Definitions: DVWA and WebGoat are G2's, verbatim; NodeGoat is F2 §B.2's item-by-item GT1–GT7;
dvpwa is its README's documented SQLi; juice-shop is **its own** `vuln-code-snippet vuln-line`
markers (25 challenges), a hit being a security finding within ±3 lines.

G2's "not one documented vulnerability is lost" held for its three repositories; it does not hold
for five. **G3 §5, written for counsel, said the same thing and has been corrected in place.**

One generous hit, stated rather than hidden: WebGoat's "PathTrav FileServer" counts because G2's
window is lines 88–100; `aegis-java-path-traversal` actually fires on a `log.debug` at :95, four
lines below the real sink (`resolve()` + `Files.copy` at :91–93). Under a strict line standard it
is a miss, before and after alike.

### C.3 The V2 corpus — paired re-measure

V2 recorded no commit SHAs, so it could not be replayed. Instead each of its 15 repositories was
cloned **once**, its SHA recorded, and that one checkout scanned twice: by a scanner running the
pre-N1 tree (a worktree at `b651c94`, full rule set) and by the N1 tree. SAST is the only engine the
cut touches — the SCA, secrets, quality and deployment engines have no changed line — so SAST is
what was re-measured.

| repo | primary language | commit | before | after | removed | scan s (before / after) |
|---|---|---|--:|--:|--:|---|
| chatwoot | Ruby | `f7f77545` | 426 | 33 | 92 % | 331 / 54 |
| DVWA | PHP | `b496a5d3` | 116 | 32 | 72 % | 50 / 9 |
| **Dolibarr** | PHP | `1348343c` | **timed out** | **2,649** | — | 613 / 543 |
| FreshRSS | PHP | `3f12dcf2` | 101 | 10 | 90 % | 66 / 17 |
| redash | JS + Python | `8f6b15d3` | 145 | 31 | 79 % | 100 / 22 |
| jellyfin | C# | `50866380` | 11 | 1 | 91 % | 102 / 8 |
| juice-shop | TypeScript | `1618a611` | 196 | 123 | 37 % | 126 / 42 |
| librenms | PHP | `4381e1a9` | 205 | 23 | 89 % | 415 / 43 |
| mastodon | Ruby | `2c92a56e` | 406 | 12 | 97 % | 442 / 107 |
| **n8n** | TypeScript | `69b0c527` | **timed out** | **timed out** | — | 622 / 604 |
| **TeamPass** | PHP + JS | `14e7d03b` | **timed out** | **175** | — | 601 / 354 |
| **nocodb** | TypeScript | `28ecd7c2` | **timed out** | **75** | — | 601 / 384 |
| nopCommerce | C# | `3204d843` | 133 | 32 | 76 % | 226 / 88 |
| NodeGoat | JavaScript | `c5cb68a7` | 62 | 29 | 53 % | 59 / 14 |
| WebGoat | Java | `872d6149` | 201 | 14 | 93 % | 68 / 19 |

Security-pillar SAST findings, counted where both runs completed (11 repos): **2,002 → 340, 83 %
removed.** SAST now **completes on 14 of 15 repos, against 11 before**: three of the four timeouts
V2 recorded as its headline operational risk are gone. n8n (3.6 M LOC) still times out.

| language of the finding's file | before | after | kept |
|---|--:|--:|--:|
| Ruby | 582 | 0 | 0 % |
| JavaScript | 323 | 103 | 32 % |
| YAML (CI/CD, k8s, compose) | 311 | 37 | 12 % |
| PHP | 247 | 45 | 18 % |
| TypeScript | 173 | 130 | 75 % |
| HTML | 120 | 0 | 0 % |
| Python | 78 | 19 | 24 % |
| Java | 60 | 6 | 10 % |
| C# | 26 | 0 | 0 % |
| Terraform, Dockerfile, shell, other | 81 | 0 | 0 % (Trivy covers IaC) |

| rule family | before | after |
|---|--:|--:|
| Semgrep registry | 1,671 | **0** |
| Aegis taint | 141 | 141 |
| Aegis CI/CD | 37 | 37 |
| njsscan | 153 | 162 |

Our rules are **exactly** preserved on every repository, as on OWASP. njsscan gains 9, all
`regex_dos` on nopCommerce (18 → 27). The likely cause is semgrep's per-file time budget: with
1,100 more rules competing, some files lose rules under the full set. **Not verified.**

### C.4 Precision — hand-triaged

| repo | triaged | TP | rate |
|---|--:|--:|--:|
| DVWA | 32 of 32 | 26 | 81 % |
| NodeGoat | 29 of 29 | 13 | 45 % |
| WebGoat | 11 of 11 | 10 | 91 % |
| dvpwa | 2 of 2 | 2 | 100 % |
| juice-shop | 40 of 123 (seeded random) | 13 | 32 % |
| **all** | **114** | **64** | **56 %** unweighted · **46 %** with juice-shop scaled to 123 |

| rule family | TP / FP | rate |
|---|---|--:|
| **Aegis taint** | 45 / 17 | **73 %** |
| Aegis CI/CD | 7 / 0 | 100 % |
| **njsscan** | 12 / 33 | **27 %** |

**The TP rate did not rise.** G3 measured the removed rules at 55 %; the sovereign set is 46–56 %.
Our own rules are the precise part. The noise is njsscan's, in five enumerable classes:
`node_username`/`node_password` on message strings ("Invalid password"), `Math.random` in
non-security code (seed data, demo dates, captcha operators), `node_timing_attack` on non-secret
comparisons (`password !== passwordRepeat`), `regex_dos` on a linear regex, and **Sequelize — a SQL
ORM — flagged as NoSQL injection**. That last class also hits our own `aegis-js-nosql-injection`
(6 of its FPs in the juice-shop sample), whose sink matches any `findOne`/`update`. Both are
precision work in rules we can edit; neither needs a licence.

DVWA's 31 `aegis-php` verdicts are M1's (same repo, same rule, same file:line); the rest were made by
reading the source around each line. Verdicts: `n1work/c4_verdicts.json`.

#### Dolibarr: the number above is not the number a customer would see

The 73 % for our rules comes from five small, deliberately vulnerable repositories. At corpus
volume one rule on one repository dominates everything. Dolibarr's SAST **timed out before the
cut, so it had never been seen**. It now completes, with **2,362 `aegis-php-xss` findings, all
rated high**, re-cloned at the measured commit and checked:

| where the taint comes from | findings | verdict |
|---|--:|---|
| `$_SERVER["PHP_SELF"]` on the reported line | 2,074 (88 %) | **FP** — see below |
| a helper argument built from `PHP_SELF` (`$urlsource`, `formconfirm`, `getTitleFieldOfList`, …) | 141 (6 %) | FP, same reason |
| anything else | 147 (6 %) | random 12 checked: **12 FP** (escaped with `dol_escape_js`, translation strings, session values, URLs built from `PHP_SELF` earlier) |
| seeded random 25 of all 2,362 | 25 | **25 FP** |

`main.inc.php:58` loads Dolibarr's WAF (`waf.inc.php`) before every page, and it **rejects any
request whose `PHP_SELF` contains `" ' < > : ; ( ) { } $ % #` or `..`**. With quotes and angle
brackets refused, `PHP_SELF` cannot break out of an HTML attribute. The source is not wrong in
general — M1 found a real `PHP_SELF` XSS in TeamPass — but an application-wide input filter is
invisible to a taint rule.

**So: `aegis-php-xss` is close to 0 % precise on Dolibarr, and Dolibarr is 2,362 of the 3,239
sovereign SAST findings across V2.** Volume-weighted over the corpus, sovereign SAST precision is
low, and it is low because of one rule on one application. This is the most important precision
item the cut exposed, and it is ours to fix. It was deliberately **not** changed in this pass:
altering detection inside the licensing cut would make every before/after number here
unattributable.

### C.5 Invariants

| invariant | result |
|---|---|
| **Determinism** | five repos scanned twice: identical `rule_pack_version`, **byte-identical findings** on all five |
| **Cross-tenant isolation** | unaffected by construction — no query, handler or scoping path changed; the diff touches rules, the semgrep engine, the rules router, lifecycle classification and one CHECK constraint. Still an access-control property, not a rate (`ACCURACY.md`) |
| **Lifecycle** | **broken by the cut, fixed** — §B.6 |

---

## D. Claims rewritten

- `docs/ACCURACY.md` — OWASP section re-measured; per-language table rewritten; **CORRECTION 11**.
- `README.md` — the Security row no longer lists OWASP Top 10 coverage or positions against Snyk and
  Checkmarx on detection; one honest paragraph on what Aegis detects now.
- `docs/RULE_TRIAGE_G3.md` §5 — the counsel paragraph corrected in place (footnote ²).
- Seven historical documents that state the pre-cut OWASP figures carry a dated SUPERSEDED banner
  (`ACCURACY_VALIDATION.md`, `QUALITY_BENCHMARK.md`, `DEEP_SCAN_VALUE.md`, `CVE_RESEARCH.md`,
  `DETERMINISM_VERIFICATION.md`, `PER_ENGINE_ACCURACY.md`, `benchmarks/owasp/README.md`). They are
  records of what was measured then; rewriting them would falsify the history.

---

## E. What it would take to rebuild — ranked by measured loss

Nothing was built. Licences below were read from each project's `LICENSE` file, not assumed.

| # | language / class | measured loss | licence-clean source | effort | priority |
|--:|---|---|---|---|---|
| 1 | **PHP** — file ops, deserialisation, header injection, open redirect, cookie-sourced XSS, `$_SERVER`/`$_FILES` sources | **~79 est. vulns** (G3, largest); 2 classes M1 found we miss | **none.** phpcs-security-audit is **GPL-3.0**; Psalm (MIT) was rejected as an engine in M1, but its taint *stubs* are an MIT catalogue of PHP sinks usable as a specification | M — extend `aegis-php-*` (5 rules) | **high** |
| 2 | **JS/TS** — express misconfiguration (directory listing, CSRF), plus the njsscan/`aegis-js-nosql` precision fixes (§C.4) | **~53 est. vulns** (G3); **2 documented juice-shop challenges** (§C.2) | **eslint-plugin-security — Apache-2.0**; njsscan kept | S–M | **high** |
| 3 | **Java** — weak random, weak crypto, weak hash, insecure cookie, trust boundary (CWE-330/327/328/614/501) | ~5 est. vulns (G3); **473 OWASP true positives, five categories to zero** | CWE definitions + JCA/Servlet API documentation — own-rule work, clean. find-sec-bugs is **LGPL-3.0**: usable as a specification only with counsel's agreement. PMD is **BSD-style** | **S** — pattern rules, no taint | **high** (cheapest recovery of the benchmark) |
| 4 | **Java** — taint breadth (cmdi, xss, sqli recall on OWASP) | cmdi 117 → 7, sqli 253 → 77, xss 202 → 78 TP | own-rule; cross-method flows are an engine limit (Semgrep OSS taint is intraprocedural) | L | medium |
| 5 | **Python** — the rest of Bandit's classes beyond H1's four | ~19 est. vulns (G3); H1 recovered 13 findings | **Bandit — Apache-2.0** (H1 proved the method) | M | medium |
| 6 | **Go** | no Go repository in V2, so no measured loss | **gosec — Apache-2.0** | M | low until a Go loss is measured |
| 7 | **C#** | ~2 est. vulns (G3) | **roslyn-analyzers — MIT** (security CA rules); security-code-scan is LGPL-3.0 | M | low |
| 8 | **Ruby** | ~0 est. vulns (G3: 20 % TP, obsolete-rule dominated) | **none for Rails taint.** Brakeman requires a paid licence for commercial use; RuboCop (MIT) has 7 narrow security cops (eval, open, Marshal/YAML/JSON load) | M for the 7; L for Rails taint | lowest |
| — | Dockerfile, Terraform, secrets | none: Trivy and gitleaks already cover them | — | — | — |

**Where no clean source exists — PHP and Ruby — the work is our own rules, written from the
language and framework documentation.** PHP is also the largest measured loss, so it is first
despite that.

---

## For decision

1. **`aegis-php-xss` on applications with a global input filter (§C.4).** 2,362 high-severity
   findings on Dolibarr, effectively all false. Before the cut its scan timed out and showed
   nothing; after it, a customer would see this flood. Options: de-duplicate findings that share
   one source into one finding per source, recognise a project-level `PHP_SELF` filter the way
   `_php_escaper_wrappers` recognises escapers, or drop `PHP_SELF` as a source (which loses the real
   TeamPass finding). Needs a decision before any Dolibarr-shaped customer is scanned.
2. **Security score vs coverage (§B.4).** Show per-language SAST coverage on the security pillar so a
   thinly-covered language cannot score 100 by being invisible. Constants unchanged pending this.
3. **njsscan precision (§C.4).** Five FP classes, all fixable with exclusions or sanitizers in a pack
   we may edit. The largest precision gain available without writing a single new rule.
4. **The OWASP number in pitch material.** Youden 0.051 is below CodeQL and base Semgrep. Either stop
   citing the benchmark until §E rows 3–4 land, or cite it with this number. It must not be cited
   with the old one.
5. **The dependency CVEs (§B.7).** npm (Auth.js, Next.js — 2 critical), pip (17 in 4 packages),
   Go (`cloudflare/circl`). `self-scan.yml` has been red on them for three weeks. A security
   product failing its own dependency audit is its own finding; this deserves a dedicated pass.
6. **`aegis-go-xss` sink precision.** It flags any `http.ResponseWriter.Write`, including JSON and
   attachment downloads. Two suppressions in our own API are the symptom.
