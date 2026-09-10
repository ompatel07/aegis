# Pass L1 — GitLab's SAST rules as a Semgrep-registry replacement

**Measurement pass. Nothing was adopted.**

**Source:** `gitlab.com/gitlab-org/security-products/sast-rules` @ `7051ea7` (2026-09-01), 195 tags,
latest `v2.10.0` · **Run date:** 2026-09-10 · **Corpus:** F1 ground-truth repos (DVWA, NodeGoat,
juice-shop, WebGoat, dvpwa, spring-petclinic, django-nV)

---

## The short version

**It does not solve the licensing problem, and the measured detection value is close to zero.**

Two independent findings, either of which is decisive on its own:

1. **The repository is not MIT.** It is four licences in one tree, and the parts covering the
   languages we most need — **Ruby and PHP — carry a Commons Clause that forbids selling**. That is
   *more* restrictive than the Semgrep licence we are trying to escape, not less.
2. **The cleanly-licensed subset adds nothing measurable.** Across 7 repositories it produced
   **121 findings: 107 false positives (88%), 8 duplicates of findings our own rules already make,
   and 6 new true positives (4%)**. On documented ground truth it adds **zero** vulnerabilities.

---

## Part A — licence inventory

Built from the `# License:` header on every rule file. GitLab's own `ci/license_header.sh` mandates
one, so this is authoritative rather than inferred. **604 rule files scanned, 0 with no header, 0
ambiguous.**

### By licence

| licence | rules | usable in a sold, self-hosted product? |
|---|--:|---|
| **MIT** (`MIT (c) GitLab Inc.`) | **251** | ✅ yes |
| **LGPL-3.0 / LGPL-2.1** | 157 | ⚠️ workable, with obligations |
| **LGPL-2.1 + Commons Clause** | **102** | ❌ **no — forbids selling** |
| **GPL-2.0** | 62 | ❌ strong copyleft |
| **GitLab EE (proprietary)** | 6 | ❌ requires a GitLab subscription |

The top-level `LICENSE` says the repo is MIT Expat "outside of the above mentioned directories". It
is not that simple: `rules/gitlab/LICENSE` is the **GitLab Enterprise Edition licence**, and
`rules/lgpl-cc/LICENSE` is LGPL-2.1 with a Commons Clause. Reading the repo licence alone and
concluding "MIT" would have been wrong in both directions.

### The Commons Clause, and where it came from

`rules/lgpl-cc/LICENSE` names its own source:

> Software: **semgrep-rules** (https://github.com/returntocorp/semgrep-rules)
> License: LGPL 2.1 · Licensor: **Semgrep, Inc.**

and the condition itself:

> the grant of rights under the License **will not include … the right to Sell the Software** …
> "Sell" means … to provide to third parties, for a fee … a product or service whose value derives,
> entirely or substantially, from the functionality of the Software.

**These 102 rules are Semgrep's own rules, redistributed by GitLab under a no-sell condition.**
Adopting them would re-import the vendor we are trying to leave, under a term that is worse for us
than the original. This is the single most important thing this pass found.

### By language — which languages have a clean subset

| language | MIT | Apache | LGPL | LGPL+CC (no-sell) | GPL | EE |
|---|--:|--:|--:|--:|--:|--:|
| python | 73 | — | 7 | — | — | — |
| scala | 88 | — | — | — | — | — |
| java | 55 | — | 43 | — | — | 2 |
| go | 1 | 26 | — | — | — | — |
| csharp | 22 | — | — | — | — | — |
| javascript | 11 | — | 84 | — | — | 1 |
| kotlin | — | — | 58 | — | — | 1 |
| **ruby** | **0** | **0** | 40 | — | — | — |
| **php** | **0** | **0** | 9 | — | — | — |
| c | — | — | — | — | 62 | — |
| swift / oc / other | — | — | 9 | — | — | — |

*(the LGPL column merges plain LGPL and the Commons-Clause variant per the per-rule header; the
Commons-Clause 102 are concentrated in java, ruby, php, javascript and python — see the mapping
table below, which resolves them exactly)*

### The native-analyzer mappings — the reason this repo looked promising

The brief's hope was that Bandit, Brakeman and gosec being reimplemented here would cover Python,
Ruby and Go, where we have little or nothing. Resolving every mapping to the licences of the rules
it points at:

| mapping | native ids | rules | licences | usable? |
|---|--:|--:|---|:--:|
| **bandit** (Python) | 52 | 71 | **MIT 70**, no-sell 1 | ✅ |
| **gosec** (Go) | 28 | 29 | **Apache 28**, MIT 1 | ✅ |
| **brakeman** (Ruby) | 40 | 40 | **LGPL + Commons Clause 40** | ❌ **no-sell** |
| find_sec_bugs (Java) | 60 | 64 | MIT 64 | ✅ |
| find_sec_bugs_scala | 102 | 108 | MIT 108 | ✅ |
| security_code_scan (C#) | 25 | 25 | MIT 25 | ✅ |
| eslint | 10 | 11 | MIT 11 | ✅ |
| nodejs_scan | 83 | 83 | LGPL 83 | ⚠️ (we already ship p/nodejsscan) |
| flawfinder (C/C++) | 200 | 200 | GPL 200 | ❌ |
| phpcs_security_audit (PHP) | 9 | 9 | LGPL + Commons Clause 9 | ❌ **no-sell** |
| gitlab_lgpl_cc_* | 48 | 48 | LGPL + Commons Clause | ❌ **no-sell** |
| gitlab_ee_* | 5 | 5 | GitLab EE | ❌ |
| mobsf / find_sec_bugs_kotlin | 86 | 89 | LGPL | ⚠️ |

**Two of the three languages the brief named are clean. The third — Ruby — is not, and Ruby is
where we have literally nothing.** Every Brakeman mapping, all 40 rules, carries the no-sell
condition.

**Nothing was ambiguous.** Every rule file carried a parseable header; none needed a judgement call
or a lawyer question.

---

## Part B — what the clean subset actually catches

**The evaluated subset is MIT + Apache only: 276 rules** (251 MIT + 26 Apache gosec, minus qa/spec
fixtures). LGPL rules were held back as a separate bucket per the brief; Commons-Clause, GPL and EE
rules were excluded outright.

### B2. Three-way ground-truth recall — the decider

| repo | documented vulns | (a) current config | (b) sovereign | (c) sovereign + GitLab MIT |
|---|--:|--:|--:|--:|
| NodeGoat (JS) | 7 | 6/7 | 6/7 | **6/7** |
| DVWA (PHP) | 6 | 3/6 | 3/6 | **3/6** |
| WebGoat (Java) | 6 | 6/6 | 6/6 | **6/6** |
| **total** | **19** | **15/19** | **15/19** | **15/19** |

**The GitLab MIT subset adds zero documented vulnerabilities.** Not one line of ground truth moves.
This reproduces G2's finding that (a) and (b) are identical, and settles the new question the same
way.

Raw volume, for context — the subset alone across all 7 repos: DVWA 2, NodeGoat 6, juice-shop 35,
WebGoat 42, dvpwa 7, spring-petclinic 0, django-nV 29. **121 findings, from just 12 of the 276
rules.** 264 rules never fired at all on this corpus.

### B3. Recovery against the ~312 vulnerabilities G3 measured us losing

The recovery is structurally capped, before any precision question:

| language | G3 est. vulns lost | GitLab MIT rules | recovery |
|---|--:|--:|---|
| **PHP** | **~79** | **0** | **0%** — every PHP rule is Commons-Clause |
| JS/TS | ~53 | 19 | 2 new TPs on our corpus |
| **Python** | ~19 | 73 | **0 new** — see B4 |
| Java | ~5 | 57 | 4 new TPs |
| C# | ~2 | 22 | not exercised (no C# repo in corpus) |
| Ruby | ~0 | **0** | 0% — every Ruby rule is Commons-Clause |

**PHP is the largest single block of lost vulnerabilities and the clean subset covers none of it.**
That alone caps recovery well below half, regardless of how good the remaining rules are.

### B4. Overlap — how much duplicates what we already catch

This is where the Python case collapses. Running our own `aegis-*` rules alongside:

| repo | GitLab (non-JS) | our rules | verdict |
|---|---|---|---|
| dvpwa | `hash-md5` @ user.py:41 | `aegis-py-weak-hash-credential` @ **user.py:41** | identical line |
| dvpwa | `hardcoded-sql` @ student.py:45 | `aegis-py-sql-string-construction` @ **student.py:42** | same statement |
| dvpwa | `hardcoded-sql` @ course.py:37, student.py:36 | *(ours correctly silent)* | **both FP — see C** |
| django-nV | `os-popen2` **and** `start-process-partial-path` @ misc.py:33 | `aegis-py-shell-command-construction` @ **misc.py:34** | same statement, and GitLab reports it **twice** |
| django-nV | `hardcoded-sql` @ views.py:183 | `aegis-py-sql-injection` + `aegis-py-sql-string-construction` @ **views.py:184** | same statement |
| WebGoat | `java_ssrf_rule-SSRF` @ SSRFTask2:36 | already ground truth, sovereign HIT | duplicate |

**Every Python true positive GitLab finds, we already find** — and our H1 rules are the more precise
of the two (below).

---

## Part C — precision

**All 121 findings hand-triaged** (the brief asked for 60+; the whole population is 121, so
everything was triaged rather than sampled).

| verdict | n | share |
|---|--:|--:|
| **FP** | **107** | **88%** |
| TP but duplicates one of our own findings | 8 | 6% |
| **TP, genuinely new** | **6** | **4%** |

### Per rule pack

| rule | n | TP | TP-dup | FP | TP rate | verdict |
|---|--:|--:|--:|--:|--:|---|
| `javascript_dos_rule-non-literal-regexp` | 60 | 0 | 0 | 60 | **0%** | **exclude** |
| `javascript_pathtraversal_rule-non-literal-fs-filename` | 26 | 0 | 0 | 26 | **0%** | **exclude** |
| `javascript_timing_rule-possible-timing-attacks` | 10 | 0 | 0 | 10 | **0%** | **exclude** |
| `javascript_require_rule-non-literal-require` | 4 | 0 | 0 | 4 | **0%** | **exclude** |
| `python_sql_rule-hardcoded-sql-expression` | 4 | 0 | 1 | 3 | 25% | **exclude** — ours is better |
| `javascript_eval_rule-eval-with-expression` | 9 | 2 | 3 | 4 | 55% | marginal |
| `java_cookie_rule-CookieInsecure` | 3 | 3 | 0 | 0 | **100%** | **take** |
| `java_crypto_rule-WeakMessageDigest` | 1 | 1 | 0 | 0 | 100% | take, narrow it |
| `java_ssrf_rule-SSRF` | 1 | 0 | 1 | 0 | 100% | duplicate |
| `python_crypto_rule-hash-md5` | 1 | 0 | 1 | 0 | 100% | duplicate |
| `python_exec_rule-os-popen2` | 1 | 0 | 1 | 0 | 100% | duplicate |
| `python_exec_rule-start-process-partial-path` | 1 | 0 | 1 | 0 | 100% | duplicate, double-reports |

Confidence is HIGH on every verdict except the four `eval-with-expression` calls in juice-shop and
DVWA, which are MED — juice-shop is deliberately vulnerable and its `eval` sites are challenge code,
so "is this a finding" depends on whether you count intentional vulnerabilities.

### The context failures we keep hitting — all four are present

1. **Provenance-blind sinks.** `javascript_pathtraversal_rule-non-literal-fs-filename` fires on any
   `fs.*` with a non-literal name. In `vulnCodeFixes.ts:29` the filename comes from
   `fs.readdirSync()` — a directory listing. In `videoHandler.ts:21` it is a constant helper. In
   `scripts/package.mjs` it is a build script. **26 findings, 0 real.**
2. **Same failure, `require`.** `require(path.resolve(__dirname + "/../config/env/" + NODE_ENV))` —
   an environment variable, not remote input. 4 findings, 0 real.
3. **A rule that misreads a framework idiom.** `possible-timing-attacks` fires on
   `if (password !== passwordRepeat)` in registration and change-password forms — comparing two
   values the same user just typed, where there is no secret to leak — and on `if (token === null)`,
   which is a null check. 10 findings, 0 real.
4. **Bound parameters read as string-built SQL.** `python_sql_rule-hardcoded-sql-expression` flags
   `cur.execute(q, params)` where the values travel as bound parameters — the *correct* form. Our
   own `aegis-py-sql-string-construction` declines these, because H1 wrote an explicit negative
   fixture for exactly this shape. **On the one language where GitLab was supposed to help most, our
   rule is measurably more precise than theirs.**

Separately: **60 of 121 findings (50%) landed in vendored or bundled assets** — minified JS inside
Java and Python repositories. T2 already excludes those from SAST, so in our pipeline they would
mostly not appear at all; but it tells you what the ruleset is tuned for.

---

## Part D — practicalities

| question | answer |
|---|---|
| **Do they run on our pinned semgrep 1.97.0?** | **Yes.** `semgrep --validate` reports *"Configuration is valid — found 0 configuration error(s), and 276 rule(s)"*. **This is not coupled to the upgrade pass.** |
| **Rule-id collisions?** | **None.** 276 GitLab ids vs 60 `aegis-*` and 1,256 vendored — zero overlap. Their ids are `language_category_rule-Name`. |
| **Metadata our pipeline needs?** | **cwe 100%**, **owasp 95%**, category 100%, severity 100%. Compliance attribution keys off cwe + owasp, so control mapping would work. `confidence` 5% and `technology` 26% are thin but not load-bearing. |
| **Pinnable release artifact?** | Partly. 195 git tags, latest `v2.10.0`, so a tag is pinnable and G2's manifest+sha256 approach would work directly. There is **no published bundle** — the Makefile has only `test`, `watch` and `benchmark-java` targets; we would assemble the subset ourselves, as this pass did. |
| **Release cadence** | Frequent — 195 tags, actively maintained. |
| **Parser issues** | juice-shop produced **31 errors** (16 syntax, 15 partial-parsing), all on modern TypeScript. Their rules assume a newer semgrep than ours for TS. Java, Python and Go parsed cleanly. |

---

## Part E — recommendation

**This does not solve our licensing problem, and on the evidence it does not solve a detection
problem either.**

On licensing, it partially helps in principle and not at all where it matters. The MIT and Apache
subset — 277 rules covering Python, Java, C#, Go, Scala and a little JavaScript — is genuinely free
of the "internal business purposes only" trap. But **Ruby and PHP, the two languages where we have
no rules of our own and where G3 measured the largest block of lost vulnerabilities (~79 of ~312 in
PHP alone), are covered here only by rules carrying a Commons Clause that forbids selling.** Those
are Semgrep's own rules redistributed under a term strictly worse than the one we are trying to
escape. Adopting the clean subset would leave PHP and Ruby exactly as uncovered as they are today.

On detection, the measured value does not justify the integration. The clean subset changes
documented ground-truth recall by **zero** (15/19 in all three configurations), and across seven
repositories it produced 121 findings of which **107 are false positives, 8 duplicate findings our
own rules already make, and 6 are genuinely new** — three insecure-cookie findings and one MD5 in
WebGoat, and two `eval` calls in juice-shop. Four of its twelve firing rules have a **0% true-positive
rate** on our corpus, and on Python — the language it was most expected to help — our own H1 rules
are the more precise of the two, correctly declining bound-parameter queries that GitLab flags.

**What I would take, if anything:** the four Java rules (`CookieInsecure`, `WeakMessageDigest`,
plus the find_sec_bugs MIT set we did not exercise for lack of a second Java corpus) look like a
small, high-precision addition — 5 findings, 5 true positives, 100%. That is a handful of rules, not
a registry replacement. It would be cheaper to write them ourselves than to take on a second
upstream dependency and its licence-audit burden.

**What remains uncovered either way:** PHP entirely, Ruby entirely, and the long tail of breadth
that G3 measured at ~767 true findings across the corpus. Nothing in this repository closes that.

**Suggested next probe, if the licensing pressure is the driver:** the LGPL bucket (157 rules,
including the 84 LGPL JavaScript rules and 40 LGPL Ruby rules *outside* the Commons-Clause set) was
deliberately not evaluated here. LGPL carries real obligations but is workable for a self-hosted
product, and it is the only place in this repository where Ruby coverage exists at all. That is a
separate measurement pass with a separate legal question attached.

---

## Gate

| requirement | status |
|---|---|
| Licence inventory, nothing inferred | ✅ 604 files, per-rule headers, 0 missing, 0 ambiguous |
| Three-way ground-truth recall | ✅ 15/19 / 15/19 / 15/19 — GitLab adds 0 |
| Recovery number per language | ✅ PHP 0%, Ruby 0%, Python 0 new, Java 4 new, JS 2 new |
| 60+ hand-triaged findings with confidences | ✅ **all 121** triaged, HIGH confidence except 4 MED |
| Practical blockers | ✅ runs on 1.97.0, no id collisions, metadata sufficient, no release bundle, TS parse errors |
| Recommendation | ✅ above |
| **Nothing adopted** | ✅ no rule file was added to the product; the clone lives outside the repo |
