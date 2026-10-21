# Pass N2b — njsscan, measured rule by rule (2026-10-22)

N1 measured njsscan at **27 % TP** on a 33-finding sample. N2 tiered JavaScript STRONG
partly on njsscan's breadth: 114 of its 125 rules and most of its 41 CWE classes. This
pass measured every njsscan finding we have, rule by rule, and pruned what does not hold
up. It writes no new rules.

| gate | result |
|---|---|
| per-rule TP table with confidence and n | §A.2: 30 rules fired, 475 findings, every one read in source |
| FP root-cause groups | §A.3: 8 groups; 3 cover 93 % of all false positives |
| rules before → after | **114 → 89** (25 not shipped, 5 constrained) |
| blended njsscan TP rate before → after | **4.5 % → 59.3 %** on the same files (§B.4) |
| ground truth: NodeGoat, juice-shop, DVWA, WebGoat, dvpwa | **22/45 → 22/45**, no item changed (§B.5) |
| coverage tiers re-measured; test catches a tier change | §C: tiers unchanged; the N2 test **did not** catch tier changes, and now does |
| "41 CWE classes" | §C.3: **withdrawn**. 38 classes remain; 11 (at most 13) are evidenced by a true positive |
| N3 scope | §D |

---

## A. Per-rule TP rate

### A.1 Method

- **Corpus.** Every njsscan finding in V2's sovereign scans (15 repositories) and in F1's
  ground-truth scans (DVWA, NodeGoat, WebGoat, dvpwa, juice-shop), deduplicated on
  (repository, commit, file, line, rule): **475 findings, 30 rules**. 84 of the 114 rules
  never fired.
- **Triage.** All 285 flagged files were fetched at the exact commit that was scanned, and
  each finding was read in context. Verdicts are TP / FP / UNCERTAIN with a confidence of
  high, medium or low. A "TP" is a real weakness of the class the rule names, at that
  location. It need not be a documented one.
- **`regex_dos` was settled by execution, not reading.** A ReDoS TP needs a regex that
  backtracks catastrophically. Every regex literal and `new RegExp('…')` in all 157 files
  flagged by the rule was extracted (1,648 candidates, of which 1,469 compile in V8) and
  run in a `node:vm` sandbox with a 2 s timeout against nine adversarial inputs. **None ran
  longer than 50 ms.** Positive controls `^(a+)+$` and `^(\w+\s?)*$` both hit the 2 s
  timeout, so the harness does detect catastrophic regexes. (The first extractor itself
  backtracked catastrophically on minified Ace. Its alternation overlapped. It was
  rewritten with disjoint alternatives.)
- **The prune was verified by re-running.** The pack was run over the same 285 files in
  the scanner image. The unmodified pack reproduces 466/475 findings; the 9 misses are
  `regex_dos` on minified files where semgrep hit its per-file timeout. The pruned pack
  was then run on the same files, so §B's after-numbers are measured, not projected.
- The working files (`collect.py`, `verdicts.py`, `regex_all.py`, `run_pack.py`) live
  outside the repository. The 475 verdicts, with the rationale for every non-default
  verdict, are in `docs/njsscan_n2b/verdicts.json`, and the rule logic that produced them
  is in `docs/njsscan_n2b/verdicts.py`.

### A.2 The table, ranked

TP rate = TP / (TP + FP); UNCERTAIN is excluded from the rate and listed. **n < 5 is
not evidence either way.** A 100 % on n = 1 means one finding was right.

| # | rule | n | TP | FP | UNC | TP rate | confidence | decision |
|--:|---|--:|--:|--:|--:|--:|---|---|
| 1 | `node_nosqli_js_injection` | 2 | 2 | 0 | 0 | 100 % | high · **n<5** | keep |
| 2 | `cookie_session_default` | 1 | 1 | 0 | 0 | 100 % | high · **n<5** | keep |
| 3 | `cookie_session_no_samesite` | 1 | 1 | 0 | 0 | 100 % | high · **n<5** | keep |
| 4 | `cookie_session_no_secure` | 1 | 1 | 0 | 0 | 100 % | high · **n<5** | keep |
| 5 | `express_cors` | 1 | 1 | 0 | 0 | 100 % | medium · **n<5** | keep |
| 6 | `generic_cors` | 1 | 1 | 0 | 0 | 100 % | medium · **n<5** (same line as #5) | keep |
| 7 | `node_ssrf` | 1 | 1 | 0 | 0 | 100 % | high · **n<5** — the only rule catching NodeGoat GT4 | keep |
| 8 | `express_open_redirect` | 4 | 2 | 2 | 0 | 50 % | high/medium · **n<5** — the only rule catching NodeGoat GT3 | keep |
| 9 | `eval_nodejs` | 9 | 3 | 6 | 0 | 33 % | high | **constrain** |
| 10 | `node_md5` | 3 | 1 | 2 | 0 | 33 % | high/medium · **n<5** | keep |
| 11 | `node_password` | 5 | 1 | 4 | 0 | 20 % | high | **drop** |
| 12 | `node_nosqli_injection` | 17 | 2 | 15 | 0 | 12 % | high | **constrain** |
| 13 | `node_timing_attack` | 13 | 1 | 12 | 0 | 8 % | high/medium | **drop** |
| 14 | `node_insecure_random_generator` | 73 | 3 | 68 | 2 | 4 % | high (FP) / medium (TP) | **drop** |
| 15 | `regex_dos` | 257 | 0 | 257 | 0 | 0 % | high (executed) | **drop** |
| 16 | `node_username` | 27 | 0 | 27 | 0 | 0 % | high | **drop** |
| 17 | `generic_error_disclosure` | 18 | 0 | 18 | 0 | 0 % | high | **drop** |
| 18 | `node_api_key` | 16 | 0 | 16 | 0 | 0 % | high (one source: bootstrap's `DATA_API_KEY`) | **drop** |
| 19 | `regex_injection_dos` | 7 | 0 | 7 | 0 | 0 % | high | **constrain** |
| 20 | `dom_xss` | 5 | 0 | 4 | 1 | 0 % | medium · at the n≈5 line | keep, see §B.3 |
| 21 | `eval_require` | 2 | 0 | 2 | 0 | 0 % | high · **n<5** | **constrain** |
| 22 | `node_secret` | 2 | 0 | 2 | 0 | 0 % | high · **n<5** | **drop** (with its family) |
| 23 | `express_lfr_warning` | 2 | 0 | 2 | 0 | 0 % | high · **n<5** | **constrain** |
| 24 | `node_logic_bypass` | 1 | 0 | 1 | 0 | 0 % | high · **n<5** | keep |
| 25–28 | `helmet_header_{feature_policy,frame_guard,nosniff,x_powered_by}` | 4 | 0 | 4 | 0 | — | high — not detections | **drop** (all 14 `good/` rules) |
| 29 | `express_xss` | 1 | 0 | 0 | 1 | — | low · **n<5** | keep |
| 30 | `handlebars_noescape` | 1 | 0 | 1 | 0 | 0 % | medium · **n<5** | keep |
| | **all** | **475** | **21** | **450** | **4** | **4.5 %** | | |

First-party code only (excluding the 273 findings in vendored/minified third-party paths
such as `htdocs/includes/ace/`, `public/plugins/`, `wwwroot/lib_npm/`): 202 findings,
21 TP / 178 FP / 3 UNC, **10.6 %**.

**Why N1 said 27 %.** N1 triaged a 33-finding sample weighted toward the ground-truth
repositories, where njsscan's best rules (cookies, SSRF, redirect, eval) fire. The noise
lives in the large real applications (Dolibarr, TeamPass, nopCommerce, nocodb) that the
sample under-weighted.

The true positives, for the record: NodeGoat GT1 eval ×3, GT3 redirect, GT4 SSRF, its
session cookie ×3; juice-shop's `$where` NoSQL ×2, marsdb `findOne({_id: req.body.id})`
×2, md5 password hashing, `cors()` allow-all ×2, `Math.random` JWT secret, a hardcoded
`testingPassword`; nocodb's OAuth `state` from `Math.random`, an invite token compared
with `!==`, and a protocol-relative open redirect (`res.redirect(req.path.slice(n))` →
`//evil.com`); FreshRSS's `Math.random` bcrypt-salt fallback.

One prior verdict is revised. COMPETITIVE_F2 called NodeGoat `user-dao.js:51-53`
(`Math.random`) "TP (weak)". It generates a random future date for demo data, so it is
FP here.

### A.3 False positives by root cause

A finding can carry two causes (e.g. vendored code *and* an arity-matched handler).

| group | FPs | root cause | rules |
|---|--:|---|---|
| **RC1 provenance-blind source** | 278 | `$REQ`/`$RES` are unconstrained metavariables: any two-parameter function is a "request handler" and any `a.b` is "request data" (`function _enter(event, context)` → `event.currentTarget`; `fire(tour, source)` → `tour.trigger`; `process.env` in `res.render`). `dom_xss` has the same shape, treating the page's own DOM attributes and text as attacker input | regex_dos, eval_nodejs, eval_require, regex_injection_dos, express_lfr_warning, dom_xss |
| **RC8 vendored third-party code** | 272 | minified Ace inside Dolibarr, TeamPass's `public/plugins/*` (bootstrap, select2, daterangepicker), nopCommerce's `wwwroot/lib_npm/*`. No first-party decision exists to fix | mostly regex_dos, node_api_key |
| **RC2 sink never inspected** | 258 | the property that makes the sink dangerous is never checked: the regex's shape (`^\d+$` flagged as ReDoS); the output context (Handlebars `noEscape` on a webhook JSON body, not HTML) | regex_dos, handlebars_noescape |
| **RC3 API or identifier name, no context** | 132 | `Math.random()` anywhere (UI ids, jitter, colours, demo data, SQL alias suffixes); a string assigned to a variable *named* `*user*`/`*key*`/`*secret*`/`*password*` (error messages, event constants); a comparison involving `password` (`password !== confirmPassword`) or `token === null`, which the rule's own null exclusions miss when they sit in `else if` or lack a semicolon; md5 for a checksum | node_insecure_random_generator, node_username, node_api_key, node_secret, node_password, node_timing_attack, node_md5, node_logic_bypass |
| **RC6 logging is not disclosure** | 18 | `console.error(err)` in a browser `catch`; `console.trace` | generic_error_disclosure |
| **RC4 framework idiom** | 15 | Sequelize `Model.findOne({ where: … })` read as a Mongo query. Upstream *tried* to exclude Sequelize with `pattern-not-sinks`. **That is not a key semgrep implements**, so the exclusion never applied. Verified: a file that imports and calls Sequelize is still flagged | node_nosqli_injection |
| **RC5 not a vulnerability by construction** | 4 | `good/` rules report that helmet's headers **are** set | 14 `good/` rules |
| **RC7 server configuration, not input** | 2 | `request.dashboardUrl` / `req.ncSiteUrl`, set by middleware from configuration | express_open_redirect |

RC1, RC2 and RC3 are the family N1/N2 kept hitting in our own rules: the
`cascadia.Query` / `exec`-use / Flask `from_pyfile` matches flagged an API name, or a
parameter by position, without checking where the data came from.

---

## B. The prune

### B.1 The rule applied to every rule

- **DROP** when the false positives *are* the rule: the matching logic is the heuristic
  (an API name, an identifier name, any function's arity paired with a never-inspected
  sink), so there is no narrow constraint that keeps the rule meaningful.
- **CONSTRAIN** when one identifiable mechanism produces the false positives and a narrow
  fix exists. Each fix was verified on the corpus to remove those false positives and
  keep every true positive.
- **KEEP** when the rule clears the bar, or has n < 5 and no proven structural mechanism.
  The 84 rules that never fired are kept. There is no evidence against them, and none for
  them either (§C.3).

### B.2 Not shipped (25)

| rule(s) | n | TP | why it cannot be constrained |
|---|--:|--:|---|
| `regex_dos` | 257 | 0 | Fixing it means checking the regex's shape: a different rule. We already have one, `aegis-js-redos-nested-quantifier`, which catches NodeGoat GT7 |
| `node_insecure_random_generator` | 73 | 3 | The rule is `Math.random()`. A context constraint (enclosing name matches `token\|secret\|salt\|nonce\|state\|…`) would be a new heuristic rule. Weak random is in N3's scope (§D), with these 3 TPs and 68 FPs as its test corpus |
| `node_timing_attack` | 13 | 1 | Matches comparisons by the variable's *name*; the one TP (an invite token) and the FPs (password vs. its confirmation) are the same shape |
| `node_username`, `node_api_key`, `node_secret`, `node_password` | 50 | 1 | `$X = '<string>'` where `$X`'s name matches. The value is never examined. Hardcoded credentials are the secrets pillar's job (gitleaks: format and entropy, every language). `node_username` is not even a secret |
| `generic_error_disclosure` | 18 | 0 | It flags logging. `node_error_disclosure`, which flags errors written to the **response**, is kept |
| 14 × `good/*` | 4 | — | They report a control that is present. Not detections, no CWE, and they surfaced as findings |
| `cookie_session_no_{domain,path,maxage}` | — | — | The attribute's absence is the safe default. These were excluded at run time (`_DEFAULT_EXCLUDE_RULES`) since before N1 but still shipped, and so were still counted as coverage. Now they are not shipped, and the runtime list is empty |

**True positives lost with dropped rules: 5**, none documented: FreshRSS's bcrypt-salt
fallback, juice-shop's `Math.random` JWT secret and `testingPassword`, nocodb's OAuth
`state` and invite-token comparison. The two TeamPass client-token findings (UNCERTAIN)
go with them. These are the cost of the prune, and N3's weak-random rule should recover
the three random-number ones.

### B.3 Constrained (5), and two constraints reported but not applied

| rule | change | before → after (TP / FP) |
|---|---|---|
| `eval_nodejs` | add `metavariable-regex: $REQ =~ (?i)^(req\|request)$`. This is upstream's own convention: `node_nosqli_injection`'s sources constrain `$REQ` exactly this way | 3 / 6 → **3 / 0** |
| `eval_require` | same | 0 / 2 → 0 / 0 |
| `regex_injection_dos` | same | 0 / 7 → 0 / 0 |
| `express_lfr_warning` | same (it took `process.env` as request data) | 0 / 2 → 0 / 0 |
| `node_nosqli_injection` | sink: `$OBJ.findOne($QUERY, ...)` but **not** `findOne({..., where: $W, ...})`. `where` is the Sequelize/TypeORM key; Mongo's operator is `$where`, a different key, which still matches. Tested on `_id`, `$where` and `where` queries | 2 / 15 → **2 / 1** |

The surviving `node_nosqli_injection` FP is juice-shop `dataErasure.ts:34`, a Sequelize
query whose `where` is nested inside `include: [{…}]`. The constraint is deliberately
narrow, and the FP is left standing rather than widening the pattern.

Three rules that still fire ship with known false positives. Constraints for two of them
are **reported, not applied**:

- `dom_xss` (0 TP / 4 FP / 1 UNC, n = 5). Its sources include `getAttribute`,
  `textContent` and `innerText`, the page's own DOM. Its sanitizer list has
  `$X.escapeHtml(…)` but not bare `escapeHtml(…)`, which is why Dolibarr's escaped output
  was flagged. The fix would drop those three sources and add the bare sanitizer. It is
  not applied because the one plausible TP (librenms `data-popup-content` →
  `innerHTML`: an attribute the server escaped, un-escaped by `getAttribute`) arrives
  through exactly those sources, and afterwards there would be nothing on the corpus to
  verify the rule against. It is DOM XSS's only rule. **Your call.**
- `express_open_redirect` (2 TP / 2 FP, n = 4). The FPs are middleware-set properties
  (`req.ncSiteUrl`). A `$QUERY ∈ {query, body, params, headers, cookies}` constraint
  would remove them. Not applied: n = 4, and this rule is the only one catching NodeGoat
  GT3.
- `node_md5` (1 TP / 2 FP, n = 3) has the same purpose-blind shape as
  `node_insecure_random_generator`. It is kept because n = 3 is not evidence, and MD5 is
  broken for every security purpose, unlike `Math.random()`, which is fine for most of
  its uses. N3's weak-hash work should measure it.

**A latent defect not fixed here.** 42 of the 114 upstream rules use the unconstrained
`$REQ` form (RC1). This pass constrained the four that fired with that mechanism. The
others (`node_sqli_injection`, `generic_os_command_exec`, the `vm*`/`sandbox` code-
injection rules, `generic_path_traversal`, the `*_ssrf` and XXE rules, and more) never
fired on the corpus. Constraining them blind would be the wholesale rewrite this pass
was told not to do. They will produce RC1 false positives on code shaped like
TeamPass's plugins.

### B.4 Before → after

Measured by running each pack over the same 285 files:

| | before (114 rules) | after (89 rules) |
|---|--:|--:|
| njsscan findings on the corpus | 475 | **29** |
| TP / FP / UNC | 21 / 450 / 4 | 16 / 11 / 2 |
| **TP rate (UNC excluded)** | **4.5 %** | **59.3 %** |
| TP rate (UNC counted as FP) | 4.4 % | 55.2 % |

For comparison, N1 measured Aegis's own taint rules at 73 %. The pruned njsscan pack is
now in that range, not a fifth of it.

The 11 FPs that remain: `dom_xss` ×4, `express_open_redirect` ×2, `node_md5` ×2,
`node_nosqli_injection` ×1, `node_logic_bypass` ×1 (juice-shop's own challenge
checker), `handlebars_noescape` ×1.

### B.5 Ground truth — unchanged

The five repositories were re-scanned through the scanner service on the pruned pack (same
checkouts as F1/N1: DVWA `5d5c76c`, NodeGoat `c5cb68a`, WebGoat `38096af`, dvpwa
`a1d8f89`, juice-shop `1618a61`) and scored with N1's `gt_score.py`:

| repo | before | after |
|---|--:|--:|
| DVWA | 3/6 | 3/6 |
| WebGoat | 6/6 | 6/6 |
| NodeGoat | 5/7 | 5/7 |
| dvpwa | 1/1 | 1/1 |
| juice-shop | 7/25 | 7/25 |
| **total** | **22/45** | **22/45** |

No item changed state. njsscan findings on these repositories went 81 → 19 (NodeGoat
24 → 8, juice-shop 57 → 11). NodeGoat GT3 (open redirect) and GT4 (SSRF) are caught only
by njsscan rules (`express_open_redirect`, `node_ssrf`). Both are kept, and both are now
named in `STRONG_EVIDENCE`, so a future prune cannot remove them silently (§C.2).

### B.6 Licence: what modifying LGPL-3.0 rules obliges

njsscan's rules are LGPL-3.0-or-later, which is GPL-3.0 plus additional permissions. The
vendored file was already a modified version: ids are namespaced, and licence and source
metadata are added. Pruning and constraining add to that. The obligations, and how each
is met:

| obligation (GPL-3.0 §5, via LGPL-3.0) | how it is met |
|---|---|
| §5(a) prominent notice that the work was modified, with a relevant date | `rules/vendor/NOTICE.md` lists every rule not shipped and every change, dated 2026-10-22. Each constrained rule carries `metadata.aegis-modified` with the date and the change |
| §5(b)/(c) the modified work stays under the same licence | every rule still declares `LGPL-3.0-or-later`; `tools/check_rule_licences.py` enforces it per rule; licence texts unchanged in `rules/vendor/LICENSES/` |
| §6 corresponding source | the YAML is the source and ships as-is. It is also reproducible: `scripts/vendor_rules.py --refresh --commit b6ade853…` rebuilds it from unmodified upstream (`PRUNED`, `PRUNED_DIRS`, `CONSTRAINED`), and the manifest records the upstream commit, `upstream_rules: 114`, and the 25 excluded and 5 constrained ids |

Removing rules is not a licence problem in itself. The obligation is to say so, which
NOTICE.md now does. A prune that silently stopped applying would be worse: it would ship
the rule again unnoticed. `apply_n2b` therefore fails the vendor build if any pruned or
constrained id disappears upstream.

This is an engineering reading of the licence, not legal advice. G3 goes to counsel, and
this table should go with it.

---

## C. Does JavaScript still earn STRONG?

### C.1 Re-measured

| language | rules (N2) | rules (N2b) | CWE classes (N2 → N2b) | tier |
|---|--:|--:|--:|---|
| javascript | 125 | **100** (taint 11 + njsscan 89) | 41 → **38** | strong |
| typescript | 11 | **100** (taint 11 + njsscan 89) | 9 → **38** | strong |
| python / java / go / php | 12 / 7 / 7 / 5 | unchanged | unchanged | limited / limited / limited / strong |

The classes lost with the prune: CWE-185 (`regex_dos`), CWE-208 (`node_timing_attack`),
CWE-613 (`cookie_session_no_maxage`). `node_insecure_random_generator` was tagged
CWE-327, which other rules still carry, so no class disappears with it. Weak random
(CWE-330/338) has no rule in any language (§D).

**TypeScript's jump is a measurement correction, not new coverage.** Semgrep 1.97 runs a
`languages: [javascript]` rule on `.ts` and `.tsx` (tested: one md5 rule, matched on
`a.ts`, `b.js` and `c.tsx`). A `[typescript]` rule does **not** run on `.js`. So all
114 njsscan rules have always run on TypeScript; juice-shop's njsscan findings are on
`.ts` files. `rule_coverage.rule_index()` counted declared languages and reported 11.
It now counts what runs (`_ALSO_RUNS_ON`).

### C.2 Does the test catch a tier change? It did not; now it does

The brief predicted that the tier table "should move on its own". It could not. `STRONG`
is a declared tuple, and the N2 tests checked only that each tiered language ships more
than zero rules, plus two count floors (`javascript >= 120`, `vendor == 114`). Run against
the pruned pack, the old suite failed on exactly one assertion, `100 >= 120`: a count,
which the person pruning simply edits. A prune that removed `node_ssrf` and added one
unrelated rule would have passed every coverage test. JavaScript would have stayed
STRONG while losing the only rule that catches NodeGoat's SSRF.

Fixed in `utils/rule_coverage.py` and `tests/test_rule_coverage.py`:

- `STRONG_EVIDENCE` names, per STRONG language, the shipped rules its ground-truth proof
  rests on, and what each proves (e.g. `node_ssrf` → "NodeGoat GT4 SSRF — the only rule
  that catches it").
- `test_every_strong_tier_still_ships_its_evidence` fails if any of them stops shipping
  **for that language**, with a message saying to re-measure and re-tier.
- `test_tier_evidence_check_catches_a_prune_that_counts_would_miss` reproduces the case
  above. It removes `node_ssrf`, adds an unrelated rule, asserts the count is unchanged,
  and asserts the evidence check fails naming GT4.

**Verdict: JavaScript still earns STRONG, on the definition STRONG has always had.**
"Proven on documented vulnerabilities across more than one real repository": NodeGoat
5/7 and juice-shop 7/25 are unchanged, and every rule they rest on still ships.
TypeScript and PHP are likewise unchanged. No language is re-tiered.

### C.3 Does "41 CWE classes" survive?

**No. It was mostly noise, and the claim is withdrawn.** The N2 docstring set its own
standard: "STRONG means proven, not broad." Applied to the 38 classes JavaScript has
rules for after the prune:

| evidence on real code (V2 + F1, 20 repositories) | classes |
|---|---|
| **a true positive** | **11**: CWE-95, 601, 918, 943 (eval, redirect, SSRF, NoSQL); 522, 614, 1275 (session cookie); 346 (CORS); 327 (md5); plus CWE-89 and CWE-1333 from Aegis's taint rules on juice-shop and NodeGoat |
| only false or uncertain njsscan findings | 3: CWE-79 (`dom_xss`, `express_xss`), CWE-80 (`handlebars_noescape`), CWE-807 (`node_logic_bypass`) |
| **no njsscan finding at all** | **24**: deserialisation, XXE, XPath, path traversal and zip-slip, `vm`/sandbox code injection, TLS verification, Electron, header injection, JWT, `node_sqli_injection` (njsscan's own, distinct from Aegis's), command injection, LDAP, … |

One caveat on the last two rows: Aegis's own taint rules fired in two of those 27
classes on V2, CWE-79 (`aegis-js-xss`, 6 findings) and CWE-22 (`aegis-js-path-traversal`,
3). They were not re-triaged per class in this pass; N1 measured Aegis's taint rules at
73 % in aggregate. So the count of evidenced classes is **11, possibly 13**, and not more.

Before the prune, the three extra classes were CWE-185, 208 and 613. Their only evidence
was 270 findings with one TP among them. The honest statement is: **JavaScript has rules
for 38 CWE classes and has shown that it finds 11 of them on real code.** For 23 classes,
no rule of ours fired on any of the 20 repositories. That is unmeasured, not proven
precise. It is the same position PHP's five rules are already stated in.

---

## D. What this leaves for N3

N3 was scoped to rebuild five OWASP categories. After the prune, what ships for each,
per language:

| category | JS / TS (njsscan, after prune) | Python | Java | Go | PHP |
|---|---|---|---|---|---|
| **weak random** (CWE-330/338) | **none**. `node_insecure_random_generator` dropped (3/73). N3 should write a context-aware rule and use its 3 TP / 68 FP as the test corpus | **none** | **none** | **none** | **none** |
| **weak crypto** (cipher/mode; CWE-327) | `node_weak_crypto`, `node_aes_ecb`, `node_aes_noiv` **kept, never fired** (unmeasured). Do not duplicate them; measure them | **none** | **none** | **none** | **none** |
| **weak hash** (CWE-328/916) | `node_md5`, `node_sha1` kept, purpose-blind, md5 1/3 (n<5). Do not duplicate; a purpose-aware rule (credential/HMAC/signature context) would *replace* them, not add to them | `aegis-py-weak-hash-credential` (H1, credential-scoped) | **none** | **none** | **none** |
| **insecure cookie** (CWE-614/1004/1275) | `cookie_session_no_secure`, `_no_httponly`, `_no_samesite`, `_default` kept (3 TP on NodeGoat). **Partial**: they match only `require('express-session')` / `require('cookie-session')` **CommonJS** config. They do not fire on `import session from 'express-session'` (the TypeScript/ESM form) or on `res.cookie(name, value, {secure: false})` | **none** | **none** | **none** | **none** |
| **trust boundary** (CWE-501) | **none** | **none** | **none** | **none** | **none** |

**N3's real scope** is therefore:
- weak random: all six languages;
- weak crypto: Python, Java, Go, PHP;
- weak hash: Java, Go and PHP, plus Python beyond credentials;
- insecure cookie: Python, Java, Go and PHP, plus for JS/TS the two forms njsscan does not
  see, `res.cookie()` options and ESM `import`ed session middleware;
- trust boundary: all six languages.

The JS/TS weak-crypto rules and the JS cookie-session rules are kept, so writing those
again would duplicate them. They are unmeasured or n < 5, though, so N3 should put them
on its benchmark rather than assume them.

---

## What changed in the repository

- `scripts/vendor_rules.py` — `PRUNED`, `PRUNED_DIRS`, `CONSTRAINED`, `apply_n2b()`;
  the manifest records `upstream_rules`, `excluded_rules` and `constrained_rules`.
- `services/scanner/rules/vendor/nodejsscan.yaml` — rebuilt at `b6ade853`: 89 rules.
  `rules/manifest.yaml` re-pinned.
- `services/scanner/rules/vendor/NOTICE.md` — LGPL modification notice.
- `services/scanner/engines/semgrep_engine.py` — `_DEFAULT_EXCLUDE_RULES` is empty (the
  three cookie exclusions are now vendor-time prunes).
- `services/scanner/utils/rule_coverage.py` — `_ALSO_RUNS_ON` (javascript → typescript),
  `STRONG_EVIDENCE`, `tier_evidence_gaps()`; docstring table re-measured.
- `services/scanner/tests/test_rule_coverage.py` — evidence and TypeScript tests; floors
  re-measured.
- `services/scanner/compliance/emittable_identifiers.yaml` — refreshed against the new
  rule set (`--dsn`): CWE-185, 208 and 613 are no longer declared. No compliance control
  referenced them. CWE-327 stays emittable through the md5/sha1/cipher rules.
- `docs/ACCURACY.md` (CORRECTION 12, JS/TS row, provenance), `docs/CREDIBILITY_N2.md`
  (superseded note).
