# Pass N4 — ground-truth corpora for Java, Python and Go; re-tier (2026-10-22)

N3 shipped 10 rules and moved no tier, correctly: STRONG requires documented-vulnerability
proof, and outside PHP/JS we had WebGoat (Java), dvpwa (Python) and nothing for Go. This
pass built that evidence: 24 candidates checked, 17 corpora qualified and were scored,
**470 documented items**, and **every one of the 118 findings triaged**.

| gate | result |
|---|---|
| staging policy applied; test proving silent-clean is excluded from coverage | three tiers (§A). `tests/test_rule_validation_tiers.py` proves silent-clean rules run, are labelled, and never count as coverage or STRONG evidence |
| every corpus candidate listed with a verdict and reason | §B: 24 checked, 17 qualify, 7 do not |
| per-corpus, per-language recall tables with full triage | §C: in-scope recall **Python 18/72 (25%), Java 31/209 (15%), Go 5/35 (14%)**. 118 findings: **92 TP / 21 FP / 5 uncertain** |
| rule-gap vs engine-ceiling miss classification | §C.4: Java 89 / 89, Python 38 / 16, Go 15 / 18. The rule-gap list is the next pass's scope |
| tier result, and the count of repos that flip from "Not measured" | §D: **Java and Python move to STRONG; Go stays LIMITED.** Repositories that flip: **0 of V2's 15 and F1's 5** |
| ground truth on the existing 5 corpora unchanged | **22/45 → 22/45**, no item changed |
| licence guard; both CI workflows | guard green (79 shipped + 9 staged Aegis rules); CI in the commit record |
| ACCURACY.md | measured numbers only |

---

## A. The three-tier staging policy

| tier | criterion | runs? | counts toward coverage, tiers, claims, Benchmark? |
|---|---|---|---|
| **PROVEN** | fired on real code, 0 FP after triage | yes | **yes** |
| **SILENT-CLEAN** | matches on API shape only, fixtures pass, ran on the full measured corpus with 0 FP, never fired | yes, findings labelled **"recall unvalidated"** | **no** |
| **STAGED** | any known FP, or matches on naming habits | no (`rules_staging/`) | no |

Plumbing:
- the rule carries `metadata.aegis-validation: silent-clean`;
- the scanner sets `recall_unvalidated` / `validation` on the finding;
- `rule_coverage.counts_as_coverage` excludes the rule from rule counts, CWE breadth and
  `STRONG_EVIDENCE`;
- `benchmarks/owasp/score.py` leaves silent-clean findings out of the counted score;
- the API report (`RiskItem`, compliance payload, AI digest) and the web (`FindingCard`
  and executive report) show a "recall unvalidated" badge.

Tests cover each layer: `tests/test_rule_validation_tiers.py`,
`report_validation_test.go`, `web/lib/validation.test.ts`.

**The audit of N3's 18 staged rules** read each one for what it actually matches on. Seven
were API-shaped and became SILENT-CLEAN: JS ESM `express-session` options, Python weak
cipher and key size, Java weak cipher (JDK standard names) and Java/Go/PHP key size. The
other 11 match on identifier names and stayed STAGED.

**Part C then re-checked every silent-clean and staged rule on the N4 corpora:**

| rule | before | N4 evidence | now |
|---|---|---|---|
| `aegis-java-weak-cipher` | silent-clean | VulnerableApp `AES/ECB/PKCS5Padding` + the LM-hash DES — 3 TP / 0 FP | **PROVEN** |
| `aegis-go-weak-hash-credential` | staged | DVGA (Go) `md5.Sum([]byte(u.Password))` — its documented weak-password module — 1 TP / 0 FP | **PROVEN** |
| `aegis-go-insecure-session-cookie` | staged | DVGA (Go) `session_id` / `signed_session` without `Secure` — 2 TP / 0 FP | **PROVEN** |
| `aegis-py-weak-random-secret` | staged | 4 TP (PyGoat OTP, API key), **1 FP** (DVGraphQL picks from `['changeme']`: the weakness is the list, not the RNG) | staged |
| the other 6 silent-clean, 8 staged | — | never fired on the 17 corpora | unchanged |

**Two FPs in shipped N3 rules, found here and fixed narrowly:**
- `aegis-py-insecure-session-cookie` flagged an empty-value `set_cookie` (a deletion,
  PyGoat).
- `aegis-java-insecure-session-cookie` flagged Security Shepherd's CSRF double-submit
  cookie, named bare `token`. "token" now needs a session/auth qualifier.

N3's own 39-repository corpus still yields exactly its true positives.

---

## B. Corpus candidates — every one checked

A corpus qualifies only if it **publishes its own list of documented vulnerabilities with
locations specific enough to score against**. Full record with commits:
`docs/ground_truth_n4/candidates.json`.

| language | qualifies (what the list is) | does not qualify (why) |
|---|---|---|
| **Go** | **go-test-bench** (route registry in code — an IAST test bench) · **GoVWA** (the app's own menu → `vulnerability/<class>/`) · **DVGA by minhthetroller** (README module table) · **damn-vulnerable-golang** (in-code gosec + CWE annotations — a SAST test target) · **not-going-anywhere** (per-program READMEs; weakly — mostly language pitfalls) | DioCGomes/damn-vulnerable-go-webapp (categories only, no locations) · controlplaneio/very-vulnerable (container/SCA; one unlocated item) · sonatype intentionally-vulnerable-golang-project (SCA only) |
| **Python** | **PyGoat** (per-lab READMEs) · **DSVW** (the attack-case table in `dsvw.py`) · **DVGraphQL** (scenarios + per-scenario solution pages) · **django.nV** (in-app tutorials naming the bug) · **lets-be-bad-guys** (exercise views) · **dvpwa**, full list (F1 scored only its SQLi) | Vulnerable-Flask-App (no list) · vulpy ("some of" the vulnerabilities, no locations) |
| **Java** | **VulnerableApp** (`@AttackVector` annotations — machine-readable; built for benchmarking scanners) · **java-sec-code** (README links each class to its controller) · **dvja** (solution docs naming class + code) · **JavaVulnerableLab** (README inventory; mostly JSP) · **Javulna** (exercises per endpoint) · **Security Shepherd** (module table + solutions) | snyk-labs/java-goof (SCA demos) · ScaleSec/vulnado (repository gone) |

Every language reaches at least two qualifying corpora. Caveats worth carrying:
- Three corpora were built for testing tools rather than for teaching: go-test-bench,
  damn-vulnerable-golang and VulnerableApp.
- PyGoat's "Patched" template-injection lab is still vulnerable: user text is
  interpolated into a template file before rendering.

---

## C. Measurement

Each corpus was scanned through the product (`/scan/sast`, shipped configuration). Each
documented item is IN-SCOPE or OUT-OF-SCOPE (runtime, authentication, authorization,
logic, SCA, secrets, transport). In-scope items are DETECTED, or MISSED with a cause.
Three damn-vulnerable-golang items are documented but have no attacker input in the code
as written (a constant command, a constant query, `md5("test")`). They are counted only
in the strict figure. Every item, with its location, scope, status and catching rule:
`docs/ground_truth_n4/gt_items.json`.

### C.1 Recall per corpus

| corpus | lang | documented | in scope | detected | recall | rule gap | ceiling |
|---|---|--:|--:|--:|--:|--:|--:|
| damn-vulnerable-golang | go | 13 | 8 | 4 | 50% (strict 4/11) | 4 (+3 const) | 0 |
| go-test-bench | go | 10 | 10 | 0 | 0% | 0 | 10 |
| GoVWA | go | 7 | 4 | 0 | 0% | 2 | 2 |
| DVGA (Go) | go | 19 | 10 | 1 | 10% | 3 | 6 |
| not-going-anywhere | go | 6 | 3 | 0 | 0% | 3 | 0 |
| PyGoat | python | 35 | 23 | 7 | 30% | 12 | 4 |
| DSVW | python | 26 | 22 | 5 | 23% | 15 | 2 |
| DVGraphQL | python | 23 | 8 | 1 | 12% | 1 | 6 |
| django.nV | python | 11 | 7 | 1 | 14% | 5 | 1 |
| lets-be-bad-guys | python | 15 | 9 | 2 | 22% | 4 | 3 |
| dvpwa (full list) | python | 4 | 3 | 2 | 67% | 1 | 0 |
| VulnerableApp | java | 168 ¹ | 121 | 9 | 7% | 45 | 67 |
| java-sec-code | java | 35 | 26 | 4 | 15% | 22 | 0 |
| JavaVulnerableLab | java | 45 | 23 | 2 | 9% | 8 | 13 |
| dvja | java | 13 | 8 | 0 | 0% | 5 | 3 |
| Javulna | java | 9 | 6 | 0 | 0% | 1 | 5 |
| Security Shepherd | java | 31 | 25 | 16 | 64% | 8 | 1 |

¹ (level method, vulnerability type) pairs from 147 vulnerable level methods; the 21
levels marked `Variant.SECURE` are excluded. Miss causes were set per vulnerability type
from a read of each type's level code.

### C.2 Recall per language

| language | in-scope recall | corpora where the taint pack caught a documented item |
|---|---|---|
| **Python** | **18/72 = 25%** | 6 of 6 had a documented detection (SQLi in five) |
| **Java** | **31/209 = 15%** (WebGoat F1: 6/6 separately) | Security Shepherd, java-sec-code, VulnerableApp, JavaVulnerableLab (+ WebGoat) |
| **Go** | **5/35 = 14%** (strict 5/38) | damn-vulnerable-golang only (the DVGA detection is the weak-hash rule promoted on that finding) |

For comparison, the existing STRONG languages: JS 5/7 (NodeGoat), TS 7/25 = 28%
(juice-shop), PHP 3/6 (DVWA).

### C.3 Triage of every finding

118 findings on the final scans: **92 TP, 21 FP, 5 uncertain**
(`docs/ground_truth_n4/triage.json`). The FPs cluster in a few rules:

| rule | TP / FP / UNC | the FP mechanism |
|---|---|---|
| `aegis-java-xss` | 8 / **18** / 4 | Security Shepherd: request taint carried through validated values, `Encode.forHtml` output and database-lookup **call results** into `out.write(htmlOutput)`; JavaVulnerableLab: an XPath *result* printed |
| `aegis-go-xss`, `aegis-py-xss` | 0 / 1 each | file **contents** written to the response; taint carried through `os.ReadFile(path)` / `open(path).read()` |
| `aegis-java-ssrf` | 6 / 1 | `new URL(x)` alone is not a request (Shepherd only parses it) |
| `aegis-js-redos-nested-quantifier` | 0 / 0 / 1 | catastrophic shape in vendored `xregexp.js`, but the input is developer regex source |

These are established taint rules, not N3's. `aegis-java-xss` at roughly 31% precision
on these corpora is the most important precision finding of the pass, and it is in a
language this pass moves to STRONG. Every N3/N4 weakness rule's findings were true
positives once the two cookie fixes in §A were made.

### C.4 Misses: rule gap (closeable) vs engine ceiling

**Engine ceiling.** Intraprocedural taint cannot follow these:
- a dispatcher or helper between source and sink (go-test-bench's `GenericHandler`, DVGA's
  `serveX → xEasy`, VulnerableApp's `readFile` / `getCommentsPayload` / ping / upload
  helpers, DVGraphQL's `helpers.run_cmd`);
- template-side escaping bypasses (`|safe`, Jinja templates);
- JSP (not parsed);
- second-order flows (database → page);
- client-side code.

**Rule gaps — the next pass's scope**, ranked by documented items each would reach:

| language | gap | items |
|---|---|--:|
| Java | `ResponseEntity<String>` / `@ResponseBody` return as an XSS sink | 19 |
| Java | Spring `JdbcTemplate.query/update` as SQL sinks | 8 |
| Java | **unannotated** Spring handler parameters as sources (Spring binds them without `@RequestParam`) | 6 |
| Java | deserialization (`ObjectInputStream`, XStream, Fastjson, RMI) | 9 |
| Java | XXE (`DocumentBuilder`, JAXB, ooxml/xlsx) | 9 |
| Java | open redirect / forward (`sendRedirect`, `"redirect:" + url`, `RequestDispatcher.forward`) | 6 |
| Java | frame-options / clickjacking; header and CRLF injection | 7 |
| Python | raw `http.server` (`self.path` → `params`) as a source | 11 |
| Python | Flask/Django debug mode (`DEBUG = True`, `app.run(debug=True)`) | 5 |
| Python | deserialization (`pickle.loads`, `yaml.load(Loader=Loader)`) | 4 |
| Python | open redirect; `@csrf_exempt`; Jinja `autoescape=False`; `MD5PasswordHasher` | 6 |
| Python | `aegis-py-command-injection` sink requires `shell=True` as the **last** argument — a one-token fix | 1 |
| Go | `template.HTML(...)` as an XSS sink | 2 |
| Go | TLS `MinVersion`, integer conversion, decompression bomb, symlink following | 6 |

The full per-item list is in `gt_items.json`.

---

## D. Re-tier

**The bar, as applied.** N2 defines STRONG as the language's **taint pack** proven on
documented vulnerabilities, and the brief requires that across **more than one corpus**.
The re-run of the N2b mechanism therefore names, per STRONG language, the shipped rules
and the documented items they caught (`STRONG_EVIDENCE`).

| language | taint-pack rules with documented detections in more than one corpus | result |
|---|---|---|
| **Java** | `aegis-java-sql-injection` (5 corpora), `aegis-java-ssrf` (3), `aegis-java-path-traversal` (2) | **LIMITED → STRONG** |
| **Python** | `aegis-py-sql-injection` (2), `aegis-py-code-injection` (2), `aegis-py-path-traversal` (2), `aegis-py-sql-string-construction` (3) | **LIMITED → STRONG** |
| **Go** | none: path traversal and SSRF were caught in damn-vulnerable-golang only | **stays LIMITED** |

Counting the DVGA (Go) detection toward Go's tier would be circular: that finding is the
evidence the weak-hash rule was promoted on, in this same pass.

**What STRONG does and does not claim now.** It means proven, not broad. Java's in-scope
recall is 15% and Python's 25%, against TypeScript's 28% on juice-shop: the rules work
where they aim, and they miss most documented vulnerabilities in these corpora. The
re-tier makes a Java- or Python-majority repository's security score *confident*, and that
score is backed by this recall. This is the decision the bar produces. If you want a
recall floor in the bar as well, that is a policy change, and Java would not pass it
today.

**PHP does not meet the bar as N4 states it.** Its STRONG rests on one
documented-vulnerability corpus (DVWA) plus real-code yield on librenms and FreshRSS.
N2 accepted that; N4's bar would not. PHP was not re-tiered in this pass, because that
would turn DVWA, Dolibarr, FreshRSS, librenms and TeamPass to "Not measured". Whether to
build PHP ground truth (bWAPP, Mutillidae and XVWA are candidates) or to re-tier is your
call.

**The commercial number: 0.** Re-tiering Java and Python flips none of V2's 15 or F1's
5 repositories from "Not measured" to a confident score. Every V2/F1 repository that was
not measured is **Ruby** (mastodon, chatwoot) or **C#** (jellyfin, nopCommerce), and
WebGoat was already confident (its JS/TS share). The only flip in the measured workspace
is spring-petclinic, an extra outside F1's five. The number that moves customers is
Ruby and C# SAST, not Java and Python tiers.

**Coverage after N4.** Silent-clean rules are excluded throughout:

| language | rules | CWE classes | tier |
|---|--:|--:|---|
| javascript / typescript | 102 | 39 | strong |
| python | 13 | 12 | **strong** |
| java | 10 | 11 | **strong** |
| php | 9 | 11 | strong |
| go | 10 | 12 | limited |

## E. Unchanged

- **Ground truth on the existing five corpora: 22/45**, no item changed.
- **OWASP Benchmark** (counted, silent-clean excluded): **Youden 0.267** (TPR 0.370, FPR
  0.103), up from N3's 0.175 because `aegis-java-weak-cipher` is now PROVEN (crypto
  130/130). **Still not a pitch number:** the weakrand share rests on the Benchmark's
  `rememberMe` cookie naming (N3 §D), and the cipher rule's real-code proof comes from
  VulnerableApp, itself built for benchmarking scanners. No silent-clean findings appear
  on the Benchmark, so counted equals raw.
- **Licence guard** green: 79 Aegis-authored, 89 njsscan (LGPL-3.0), 9 staged, no
  registry path.

## What changed in the repository

- **Part A, `feat(rules)`:** the three-tier policy across rules, scanner, coverage, the
  Benchmark harness, the API reports and the web.
- **Part C/D, `feat(rules)`:**
  - three promotions and two cookie-FP fixes;
  - `STRONG = php, javascript, typescript, java, python`, with `STRONG_EVIDENCE` for
    java/python;
  - the limited-language gate tests now assert on Go.
- **`docs(accuracy)`:** this record; `docs/ground_truth_n4/` (`candidates.json`,
  `gt_items.json`, `triage.json`, the VulnerableApp annotation parse and the scoring
  scripts); ACCURACY.md.
