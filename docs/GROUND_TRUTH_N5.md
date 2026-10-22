# Pass N5 — a STRONG bar that can fail, PHP measured, Java/Python gaps closed (2026-10-23)

**Result: no language meets the bar. Every language with rules is LIMITED, and 16 of
the 20 V2/F1 repositories move from a measured security score to "Not measured"; none
moves the other way.** Each language fails a named criterion (§E), and the coverage line
now shows the measured recall next to every tier.

**Headline (held-out recall).** These are the corpora no rule was written from:

| language | held-out recall | 95 % interval | held-out corpora |
|---|--:|---|---|
| **PHP** | **68/160 = 42 %** | 35–50 % | bWAPP, Mutillidae II, XVWA |
| **Python** | **8/38 = 21 %** | 11–36 % | DSVW, django.nV, lets-be-bad-guys |
| **Go** | **4/25 = 16 %** | 6–35 % | damn-vulnerable-golang, go-test-bench, GoVWA, not-going-anywhere |
| **Java** | **5/34 = 15 %** | 6–30 % | java-sec-code, dvja |
| **JavaScript / TypeScript** | none held out | — | their only corpora (NodeGoat, juice-shop) are tuning corpora |

| gate | result |
|---|---|
| bar computed from data, with failing-case tests | `utils/tier_bar.py` evaluates `accuracy/gt_items.json` + `accuracy/triage.json`; no tier is declared anywhere. `tests/test_tier_bar.py` plants evidence on every line and drops each criterion below it (§A) |
| holdout recorded before any rule change | commit `bee2e15`, before the first rule edit (§C) |
| PHP measured on ≥ 2 new corpora | bWAPP, Mutillidae II and XVWA all qualify and are scored item by item (§B) |
| per-language table: tuning vs held-out recall, precision, tier | §E |
| licence guard; both CI workflows | guard green (81 Aegis + 89 njsscan + 9 staged); CI in the commit record |
| ACCURACY.md | measured numbers only, held-out recall as the headline |

---

## A. The uniform STRONG bar

A language is STRONG only if **all** hold, computed from data:

1. **corpora:** its shipped rules caught documented vulnerabilities in **≥ 2 corpora**.
   A detection that a rule was itself promoted on does not count (N4's circularity rule,
   now enforced in code).
2. **recall:** pooled in-scope recall on its **held-out** corpora is **≥ 25 %**. No
   held-out corpus means the criterion fails.
3. **precision:** TP / (TP + FP) over **every triaged finding** of its shipped rules is
   **≥ 70 %**, on real repositories and ground-truth corpora together. UNCERTAIN is
   excluded from the rate (the N2b convention) and reported. Any finding recorded as
   UNTRIAGED fails the criterion.

Only shipped coverage rules are evidence. Silent-clean rules are not, and a pruned rule's
detections and findings stop counting with no hand edit. If the evidence is missing from
the image, the scanner fails **closed**: every language is LIMITED and scores are
withheld, never presented as confident.

**Where the evidence lives.** Both files ship in the scanner image, built by
`docs/ground_truth_n5/build_ledger.py`:
- `services/scanner/accuracy/gt_items.json`: 25 corpora, every documented item, with
  scope, status, the catching rules, role (tuning / held-out) and commit.
- `services/scanner/accuracy/triage.json`: **1,048 security findings, every one with a
  verdict**. The application-language findings are those of the 25 ground-truth corpora
  and the 34-repository real corpus; CI/CD findings on YAML are not any language's
  evidence.

**Tests** (`tests/test_tier_bar.py`):
- Planted evidence exactly on every line is STRONG (25 % recall and 70 % precision pass).
- Each criterion dropped just below its line fails the bar, naming that criterion:
  - one corpus;
  - a promotion's own detection;
  - 23.5 % held-out recall;
  - tuning-only recall, even at 100 %;
  - 69 % precision;
  - one untriaged finding;
  - no triaged finding.
- Removing the catching rule drops the tier with no hand edit.
- The shipped tiers equal the bar evaluated on the shipped evidence.
- No tier constant exists in `rule_coverage`.
- Every rule the evidence names still ships.
- The held-out corpora are exactly the ones drawn in `bee2e15`.
- Java leaves STRONG on recall alone; PHP is measured on its three new corpora.

**The coverage line** carries the measured recall for every language, in every tier. For
example: `Java — limited · 15% held-out recall on 2 corpora`, and
`JS — limited · 71% recall on 1 tuning corpus, none held out`. The per-language detail
in the web adds precision and the failing criteria (`web/lib/display.ts` `evidenceLabel`).

---

## B. PHP corpora

All three candidates publish a located list, so all three qualify. They were measured
for the first time in N5, and N5 wrote no PHP rule, so all three are held out.

| corpus | the published list | commit | documented | in scope | detected | recall | rule gap | ceiling |
|---|---|---|--:|--:|--:|--:|--:|--:|
| **bWAPP** v2.2 (raesene/bWAPP, a docker repackaging of the SourceForge release) | `app/bugs.txt`: every bug mapped to its page | `53bcfdd59c02dcfdbf79e218f0a99c54ff42d799` | 130 | 66 | 37 | 56 % | 20 | 9 |
| **OWASP Mutillidae II** (webpwnized/mutillidae) | `src/documentation/vulnerabilities.php`: a per-page list | `126a1fdb4ff977f87e980d018f0def477afc3d5d` | 156 | 79 | 26 | 33 % | 9 | 44 |
| **XVWA** (s4n7h0/xvwa) | README list of 19 classes, each a `vulnerabilities/<class>/` module | `fb30fa517d288e618b521d252f61107ef6a24797` | 19 | 15 | 5 | 33 % | 7 | 3 |

Method notes (N4's, plus the following):
- bWAPP's AJAX / XML / HREF bugs are a page plus its back end (`sqli_10-1.php` →
  `sqli_10-2.php`); a finding in the back end counts for the item.
- A vulnerability listed under two categories is one item.
- Where a Mutillidae page lists XSS, HTML injection and JS injection for the same input
  and sink, that is one item; the others are recorded as `OUT:duplicate`.
- Detection requires a TRUE-POSITIVE finding of the item's class. Three path-traversal
  findings sit on documented SSRF / upload sinks; they are not counted as detecting them.
- bWAPP is licensed CC BY-NC-ND; only file and line are recorded, never code.

**Misses.**
- **Rule gaps:** no PHP rule for eval / code injection, XPath, XXE, SSRF,
  deserialization, redirects, header or mail injection, SSI or SSTI; `$_FILES` and custom
  request headers are not modelled sources; cookies named `top_security` are not
  session-shaped.
- **Ceilings:** Mutillidae routes its SQL through `SQLQueryHandler` and its logging
  through `LogHandler` (cross-file: 19 of its 44 ceilings); second-order flows; client-side
  code.

**A semgrep 1.97 defect, found here.** In PHP, a `switch` whose `default:` label precedes
other labels of the same fall-through group drops those statements from the analysis:

```php
switch ($level) {
    default:
    case "0":
        $u = $_REQUEST["u"];
        echo "<meta url=" . $u . ">";   // not reported; reported if default: comes after case "0":
    break;
}
```

Mutillidae opens most security-level switches this way (41 pages carry a `default:`
label). Two of its misses are this defect, and it probably hides more, true and false
alike.

**Triage of every PHP finding on the three corpora:** 171 TP / 87 FP / 15 uncertain.
`aegis-php-xss` accounts for 84 of the 87 FPs:
- query, LDAP and XPath **results** printed (30 on bWAPP's SQLi pages alone);
- already-encoded values;
- numbers;
- session values.

Every other PHP rule is at or near 100 % TP there. A finding that prints a value users
can edit (stored XSS) is a TP. A finding that prints static app data, reachable only
through a separate SQLi, is an FP: the SQLi finding is the real defect.

---

## C. Holdout, recorded before any rule change

**Why.** N4's rule-gap list was read off the same corpora N5's rules would be measured
on, so recall on them after the fixes is inflated by construction. Held-out corpora are
fixed here, in a commit made before any N5 rule edit. **N5 writes rules only from the
tuning corpora's gap list. Part A's recall criterion is evaluated on held-out recall.**

**How the corpora were chosen.** I did not pick them. They were drawn by
`services/scanner/tools/draw_holdout.py`, which writes
`services/scanner/accuracy/holdout.json`:

1. **The pool** is every qualifying N4 corpus except those already used to write or change a rule:

   | excluded | why |
   |---|---|
   | Security Shepherd | N4 fixed the Java cookie rule on it; the `aegis-java-xss` precision work comes from its findings |
   | PyGoat | N4 fixed the Python cookie rule on it; the `shell=True` fix comes from it |
   | VulnerableApp | N4 promoted `aegis-java-weak-cipher` on its findings |
   | DVGA (Go) | N4 promoted two Go rules on its findings |
   | dvpwa | F1 ground truth; every pass since F1 gates on it |

2. **The seed** is N4's final commit, `b07254804600f5aa849bdb8d7d574c0d1c85de11`.
3. **The draw** shuffles the pool with that seed and holds corpora out in that order,
   until the held-out set has at least min(20, half the language's in-scope items).

| language | held out (commit) | in scope | tuning | in scope |
|---|---|--:|---|--:|
| **Java** | java-sec-code (`4711f4e186258c6e0dd5c3863e7c9592e7e9026a`) · dvja (`597ece1ab79ffffea7289d49b0c443bb2ebcbd16`) | 34 | VulnerableApp, Security Shepherd, JavaVulnerableLab, Javulna | 175 |
| **Python** | DSVW (`9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908`) · django.nV (`a48901f106da4888417339b7b44b8ed56b64c63f`) · lets-be-bad-guys (`7cbf11014bfc6dc9e199dc0b8a64e4597bc2338f`) | 38 | PyGoat, DVGraphQL, dvpwa | 34 |
| **Go** | damn-vulnerable-golang (`fad5655a69879d37010b40044a5d4f4d305ee916`) · go-test-bench (`92445700823205281369911a72b7127f18c8c9ed`) · GoVWA (`4058f79f31eeb4a36d8f1e64bba1f0c899646e6f`) · not-going-anywhere (`3ea1a49de1c399633e513f0348752b7f0098b7c1`) | 25 | DVGA (Go) | 10 |

**PHP.** N5 writes no PHP rule. The Part B corpora (bWAPP, Mutillidae II, XVWA) are
measured for the first time in N5, so they are held out by construction. DVWA is tuning:
earlier passes gated on it.

**JavaScript / TypeScript.** N5 writes no JS/TS rule. Their only ground-truth corpora,
NodeGoat and juice-shop, are F1/N1 ground truth that every pass since has gated rule
changes on, so they are tuning corpora.

**Baseline before any N5 change** (N4 rules, N4 scans):

| language | held-out recall | tuning recall |
|---|--:|--:|
| Java | 4/34 = 12% | 27/175 = 15% |
| Python | 8/38 = 21% | 10/34 = 29% |
| Go | 4/25 = 16% | 1/10 = 10% |

**What the holdout takes off N5's list.** These N4 rule-gap items sit in held-out
corpora, so N5 writes no rule from them:
- Java: 5 of the 6 *unannotated Spring handler parameter* items (java-sec-code). The
  brief's Part D names this gap, but Part C forbids it.
- Java: redirect (2).
- Python: raw `http.server` sources (DSVW), Django `DEBUG`, `@csrf_exempt`, redirect.

If a rule written from the tuning list catches one of these items, that is
generalisation, and it is counted.

### C.1 What the holdout showed

The rules were frozen before any held-out corpus was scanned with them.

| language | held-out before → after | tuning before → after |
|---|---|---|
| Java | 4/34 → **5/34** | 33/181 → **48/181** |
| Python | 8/38 → **8/38** | 10/34 → **17/34** |
| Go | 4/25 → 4/25 (no Go rule written) | 1/10 → 1/10 |

- **Python: held-out recall did not move. The N5 Python rules fit the corpora they were
  written from.** The `shell=True` fix, the deserialization rule and the Flask debug rule
  caught seven PyGoat items. On DSVW, django.nV and lets-be-bad-guys they caught nothing.
  Those corpora's gaps are sources the rules do not model (raw `http.server`
  parameters), Django settings, `@csrf_exempt` and redirects: the held-out list N5 was not
  allowed to write from.
- **Java: held-out recall moved by one item.** The Spring `@ResponseBody` sink, written
  from VulnerableApp's `ResponseEntity<String>` gap, caught java-sec-code's documented
  stored-XSS endpoint. That is real generalisation, and it is one item. The JdbcTemplate
  sink caught nothing held out. dvja is Struts2, and its gaps are Struts action
  properties as sources.
- The largest held-out Java gap stays open by design: **Spring handler parameters without
  an annotation** (5 items, java-sec-code). Part D named it, but Part C forbids writing it
  from the held-out list. Closing it needs a new held-out corpus first.

---

## D. Gap closing (rules written from the tuning list and the API docs)

### D.1 Java

**`aegis-java-xss` precision: 8 TP / 18 FP / 4 uncertain → 19 TP / 10 FP / 5 uncertain.**
No N4 true positive was lost: Security Shepherd's 7 XSS-challenge TPs and JavaVulnerableLab's
1 remain. The model changes, each from the JDK / Spring API docs:
- **numbers cannot carry markup:** `taint_assume_safe_numbers` / `_booleans`, plus
  `Integer.parseInt` / `Long.parseLong` / `…valueOf` as sanitizers;
- **query results are database rows, not the request:** `executeQuery()` /
  `getResultSet()`, `XPath.evaluate()` and `XPath.compile(…).evaluate()`;
- **Spring's `HtmlUtils.htmlEscape*`** as an encoder.

Removed: 10 Shepherd FPs and 1 JavaVulnerableLab FP. Left:
- **7 Shepherd FPs** carry request taint through a project lookup helper
  (`Getter.getFeedback(root, id)`). That call is indistinguishable, by API shape, from the
  `XssFilter.levelOne(term)` calls that carry the TPs. Only naming would separate them,
  so it was not done.
- **3 VulnerableApp FPs** go through a helper whose lambda escapes.

**New sinks.**
- **XSS:** Spring response bodies. A method declared to return `ResponseEntity<String>`
  (constructor body, `ok(…)`, `body(…)`) and an `@ResponseBody String` return are sinks.
  An object body (JSON) and an explicit JSON `produces` are not.
- **SQL:** `JdbcTemplate` / `NamedParameterJdbcTemplate` (and their interfaces), first
  argument, matched by declared receiver type.

VulnerableApp results:
- **JdbcTemplate:** 7 TP / 2 FP. The FPs are levels VulnerableApp marks `SECURE`: a
  `\d+` check, and quotes stripped inside a quoted literal.
- **Response bodies:** reflected and persistent XSS, 8 TP / 3 FP.

**A semgrep 1.97 quirk, found and recorded:** a sink added as one more branch of a
`pattern-either` with a shared `focus-metavariable` suppressed the `prepareStatement()`
sink nested inside a lambda passed as its argument. VulnerableApp's Error-Based level 4
was lost that way; as a separate sink entry, both report. A fixture holds it.

### D.2 Python

- **`shell=True` anywhere among the keyword arguments**
  (`subprocess.Popen(cmd, shell=True, stdout=…)`); PyGoat's command-injection lab is now
  caught.
- **`aegis-py-unsafe-deserialization`** (new, taint; CWE-502): `pickle`, `marshal`,
  `dill` and `jsonpickle` loads, and `yaml.load` with `Loader` / `UnsafeLoader` or
  `unsafe_load`, from request data, including Flask `request.files` / Django
  `request.FILES`.
- **`aegis-py-flask-debug-enabled`** (new; CWE-489): `app.run(debug=True)`,
  `app.debug = True`, `app.config["DEBUG"] = True` on a `Flask(...)` app. Literal `True`
  only.

### D.3 The 0-FP standard on real repositories

The N5 rules were run on all 34 real repositories (V2's at their recorded commits,
N3's `cmp-*`, spring-petclinic) and compared to a baseline on the old rules. **They added
no finding on any of them: 0 TP / 0 FP.** That meets the standard, and it also means the
N5 rules have no real-code yield yet.

---

## E. Re-measure and re-tier

| language | held-out recall | tuning recall | precision (TP / TP+FP, + uncertain) | corpora with a documented detection | tier | fails |
|---|--:|--:|--:|--:|---|---|
| **PHP** | 68/160 = **42 %** | 3/6 (DVWA) | 240/388 = **62 %** (+16) | 4 | **limited** | **precision** |
| **Java** | 5/34 = **15 %** | 48/181 = 27 % | 76/90 = **84 %** (+5) | 5 | **limited** | **recall** |
| **Python** | 8/38 = **21 %** | 17/34 = 50 % | 51/158 = **32 %** | 6 | **limited** | **recall, precision** |
| **Go** | 4/25 = **16 %** | 1/10 | 11/14 = **79 %** | 1 | **limited** | **corpora, recall** |
| **JavaScript** | none held out | 5/7 (NodeGoat) | 18/48 = **38 %** (+37) | 1 | **limited** | **corpora, recall, precision** |
| **TypeScript** | none held out | 7/12 (juice-shop) | 34/103 = **33 %** (+1) | 1 | **limited** | **corpora, recall, precision** |

Notes on the table:
- Recall is in-scope items, by N4's taxonomy.
- The original five corpora were restated with that taxonomy, which changes no criterion:
  they are all tuning corpora. juice-shop's 25 challenges include 13 out-of-scope ones
  (hidden routes, authorization, chatbot prompts).
- On N1's own definitions those five are **22/45 before and after**.

**Java leaves STRONG through the bar:** on recall alone. It clears both other criteria.

**What drives each precision failure** (from `triage.json`):

| rule | TP / FP / uncertain | mechanism |
|---|---|---|
| `aegis-php-xss` | 112 / **111** / 13 | query / LDAP / XPath results printed; project escapers it does not model (DoliDB, `dol_escape_js`, Mutillidae's `Encoder`); numbers |
| `aegis-py-sql-string-construction` | 6 / **101** / 0 | context-free (it implements what Bandit B608 detects): any formatted SQL. 72 FPs are Django's own backends building DDL from `quote_name()`d identifiers; 10 are shell commands passed to Kafka's `execute()` helper |
| `aegis-js-nosql-injection` | 10 / **39** / 0 | Sequelize `findOne({ where: { id: req.params.id } })` (SQL ORM, no operators: authorization, not injection); `Array.find`; Mirage test mocks |
| `aegis-php-sql-injection` | 36 / **25** / 1 | Dolibarr's `$db->escape()` and int casts |
| njsscan `generic_header_injection`, `dom_xss`, `node_md5` | 1 / 20 / 1 | `Map.set` as a header; vendored minified libraries; cache hashes |
| `aegis-js-redos-nested-quantifier` | 1 / 11 / **36** | the 36 uncertain: catastrophic shapes over the browser's own data (moxie user-agent parsing; minified Ace highlighters) |

These are measured, not fixed. The ones that look fixable by mechanism are:
- PHP query results as sanitizers, as Java now does;
- Sequelize `where` objects not treated as NoSQL;
- an SQL keyword requirement for the inline `execute()` form.

Fixing a false positive on the same corpus that measures precision inflates that
precision, exactly as tuning recall on held-out corpora would. So those fixes need a
real-repository holdout first.

**Repositories that change measured state: 16 of 20.** All move measured → not measured,
none the other way:
- **V2:** 11 of 15 — Dolibarr, FreshRSS, NodeGoat, WebGoat, DVWA, redash, juice-shop,
  librenms, n8n, TeamPass, nocodb;
- **F1:** 5 of 5.

chatwoot, mastodon, jellyfin and nopCommerce were already not measured (Ruby, C#).

**What would move each language**, measured:
- **Java (recall):** 9/34 held-out items are needed, against 5. The largest held-out gap
  is unannotated Spring parameters (5 items), and it can only be closed honestly against a
  new held-out corpus.
- **PHP (precision):** 62 % → 70 % needs 46 fewer FPs (148 → 102), and
  `aegis-php-xss` alone has 111.
- **Python:** both held-out recall (needs 10/38) and precision; the precision failure is
  one rule.
- **Go:** a second corpus with a documented detection, and held-out recall.
- **JS / TS:** a second documented corpus each, a held-out corpus, and precision.
  Counted as one language, JS and TS would have two corpora, but they would still fail
  held-out recall and precision.

### E.1 Determinism

Two unchanged rule families gave different findings on the same commit in two runs:
- Dolibarr's PHP XSS / SQLi: +6 / −1;
- njsscan on vendored minified JS: one finding each in django.nV, DVGraphQL and prisma.

Semgrep's per-file time budget on large files is the likely cause (as in N1); it is not
verified. Every finding of the final runs is triaged, so the evidence matches what was
scanned.

### E.2 OWASP Benchmark

Counted (silent-clean excluded, none present): **Youden 0.2685** (TPR 0.370, FPR 0.101),
against N4's 0.267. The N5 XSS changes remove 2 Benchmark XSS FPs (35 → 33) and no TP.
**Still not a pitch number**, for N3's reason (the weak-random share rests on the
Benchmark's `rememberMe` naming).

---

## What changed in the repository

- **`fix(scoring)`:**
  - `utils/tier_bar.py` (the bar), and `utils/rule_coverage.py` with its declared tiers
    and `STRONG_EVIDENCE` removed;
  - `accuracy/gt_items.json` and `triage.json` (the evidence);
  - the coverage line with measured recall;
  - web: per-language evidence (`evidenceLabel`);
  - `tests/test_tier_bar.py`, and the coverage tests rewritten for computed tiers.
- **`feat(rules)` Java:** XSS precision model, Spring response-body sink, JdbcTemplate
  sink; fixtures for each.
- **`feat(rules)` Python:** `shell=True` position, unsafe deserialization, Flask debug
  mode; fixtures; CWE-489 added to the emittable inventory.
- **`docs(accuracy)`:**
  - this record;
  - `docs/ground_truth_n5/`: PHP items and triage (`php_gt.py`, `score_php.py`), the
    original five restated (`orig5_items.py`), real-repo verdicts, re-scoring decisions,
    the ledger builder, and the measured-state script;
  - ACCURACY.md.

The holdout itself was committed first (`bee2e15`).
