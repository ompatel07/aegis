# Pass N6 — two claims, two gates, calibrated against CodeQL

## 0. Decided before recomputing anything (this section is committed first)

Everything in this section was fixed before any number below it was computed: before
any held-out JS/TS corpus was scanned, before CodeQL was run, and before any precision
figure was recomputed under the new split.

### 0.1 Two claims, two gates

A security result makes one of two different claims, and each needs different evidence:

| claim | what the customer reads | what it rests on |
|---|---|---|
| **CLEAN** | "no significant issues" | **recall**: had there been a vulnerability, would we have found it? |
| **PROBLEM** | "these issues exist" | **precision**: when we report one, is it real? |

Each language has a **recall gate** and a **precision gate**, computed independently. A
repository is graded by where its code sits:

| recall gate | precision gate | what is shown |
|---|---|---|
| passes | passes | full score and grade |
| fails | passes | findings, and the score and grade **only if unfavourable** (C or worse). A favourable result (A/B) is never shown: instead, "no issues found in what we check · X% held-out recall" |
| passes | fails | a clean result may be shown (A/B); findings carry a precision caveat; an unfavourable score or grade is not shown |
| fails | fails | withheld, "Not measured" (the N2 contract) |

A repository passes a gate when more than half its application code, by LOC, is in
languages that pass it (the N2 threshold, applied per gate).

### 0.2 Where precision is measured: real repositories

Recall needs documented vulnerabilities, so it comes from ground-truth corpora. Precision
does not, and teaching and tool-test corpora (bWAPP, Security Shepherd, VulnerableApp,
OWASP Benchmark–style apps) are built to trap tools. Their precision is reported as a
**stress figure, not the gate**.

**The real-repository corpus** is production open-source code, not built to be vulnerable.
There are 31 repositories:
- V2's 15, minus the four deliberately vulnerable apps among them (NodeGoat, juice-shop,
  DVWA, WebGoat);
- N3's 19 `cmp-*` repositories;
- spring-petclinic.

dvpwa and django.nV (in N3's 39) are vulnerable by design, so they are stress corpora.

**The precision gate:** precision ≥ 70 % over every triaged finding of the language's
shipped rules on the **held-out** half of the real corpus. Uncertain verdicts are
excluded from the rate, as in N2b. An untriaged finding fails the gate. So does a
language with no triaged finding there: a PROBLEM claim with no evidence is not certified.

### 0.3 The precision holdout

The real corpus was shuffled with a seed (N5's final commit, `65d29f94…`), and the first
half, rounded up, is held out (`services/scanner/accuracy/holdout_n6.json`):

- **held out (16):** Dolibarr, cmp-cobra, cmp-flask, cmp-jackson, cmp-nest, cmp-netty,
  cmp-prisma, cmp-spring, cmp-vault, redash, librenms, mastodon, n8n, TeamPass,
  nopCommerce, spring-petclinic.
- **tuning (15):** FreshRSS, chatwoot, cmp-ansible, cmp-consul, cmp-django, cmp-express,
  cmp-fastapi, cmp-gin, cmp-guava, cmp-kafka, cmp-nextauth, cmp-react, cmp-terraform,
  jellyfin, nocodb.

A precision fix may be written from the tuning half only. Tuning-half precision is
reported, never gated on.

### 0.4 The recall floor, relative to CodeQL

The recall gate for a language passes when both hold:
1. its shipped rules caught documented vulnerabilities in **≥ 2 corpora** (N5's
   criterion; a promotion's own evidence excluded);
2. **Aegis's held-out recall ≥ CodeQL's**, on the same held-out items.

CodeQL is the CodeQL CLI 2.27.3 bundle, `security-extended` suite, default
configuration. Recall uses N4's in-scope taxonomy, and both tools are judged per item by
the same rule.

**Why parity with CodeQL.** A clean result is only as good as the chance we would have
found a vulnerability had there been one. CodeQL `security-extended` is the most widely
deployed taint-based SAST that anyone can run on open-source code. If our held-out recall
is at least CodeQL's on the same documented vulnerabilities, a clean result from Aegis
carries the same evidence as a clean result from that reference. If it is lower, our
clean result promises less than the market's.

**Where CodeQL cannot run** (PHP is unsupported; a corpus without an OSI-approved
license is outside CodeQL's license, below), the comparison uses the corpora where it
did run. With none, the floor stays at N5's absolute **25 %**, labelled
**uncalibrated**.

**CodeQL's license** permits "perform[ing] analysis on the Open Source Codebase" (code
under an OSI-approved license), and forbids any purpose it does not list and use in
automated CI. So CodeQL is run by hand, only on corpora whose repository carries an
OSI-approved license file. A license is never inferred. Corpora without one are NOT RUN:
- java-sec-code: no license file;
- GoVWA: no license file.

### 0.5 JS/TS ground truth

Seven candidates were checked; five qualify and two do not:

| corpus | language | the published list | qualifies? | in scope |
|---|---|---|---|--:|
| appsecco/dvna `9ba473a` | JS | `docs/solution/`: one page per OWASP category, naming files | **yes** | 9 of 19 |
| cr0hn/vulnerable-node `d68f2a3` | JS | `docs/labs/` plus in-code `VULN` markers | **yes** | 14 of 22 |
| snoopysecurity/dvws-node `8e2e9a5` | JS | `CHALLENGES.md`: 50 challenges, each with its endpoint | **yes** | 22 of 50 |
| kOaDT/oss-oopssec-store `faef8cb` | TS | `content/vulnerabilities/`: 36 write-ups with endpoint and code | **yes** | 14 of 36 |
| henning410/VuNAPI `00e26e4` | TS | `Vulnerabilities.md`: endpoints; built to test API fuzzers | **yes** (weakly) | 3 of 7 |
| snyk-labs/nodejs-goof | JS | README lists 8 code vulnerabilities but locates 1; an SCA demo | no | — |
| MGMADev/code-security-demo | JS | clone requires credentials (private or removed) | no | — |

Items and scope: `docs/ground_truth_n6/jsts_items.py`, written before any of these was
scanned.

**Holdout** (N5's rule, same seed, NodeGoat and juice-shop staying tuning):
- **JavaScript held out:** DVNA and vulnerable-node (23 in-scope items).
- **JavaScript tuning:** dvws-node and NodeGoat (29).
- **TypeScript held out:** OopsSec and VuNAPI (17).
- **TypeScript tuning:** juice-shop (12).

---

## Results (computed after §0 was committed in `42413ce`)

**The commercial number.** 6 of V2/F1's 20 repositories now show a security result,
against 0 under N5:
- **V2:** 5 of 15 — Dolibarr, FreshRSS, DVWA, librenms, TeamPass;
- **F1:** 1 of 5 — DVWA.

All six are clean-only: PHP-majority repositories, whose recall is certified and whose
precision is not. Every one has critical or high findings. So each shows its findings
with the precision caveat and **no grade**: a bad grade there would rest on findings we
cannot certify. The other 14 stay withheld. None is full or problem-only.

| quadrant | V2 (15) | F1 (5) |
|---|--:|--:|
| full | 0 | 0 |
| problem-only | 0 | 0 |
| clean-only | 5 | 1 |
| withheld | 10 | 4 |

### E. Per language

| language | held-out recall: Aegis vs CodeQL, same items | real-repo precision (held-out half, the gate) | stress precision (teaching corpora) | quadrant |
|---|---|---|---|---|
| **PHP** | 68/160 = **42 %** (CodeQL has no PHP support: **uncalibrated**, ≥ 25 % floor) | **18/67 = 27 %** (18–39 %) | 221/313 = 71 % | **clean-only** |
| **Python** | **8/38 vs 5/38** | **1/19 = 5 %** (1–25 %) | 49/50 = 98 % | **clean-only** |
| **Go** | **4/21 vs 4/21** (parity); held-out 4/25 | **4/5 = 80 %** (38–96 %) | 7/8 | **problem-only** for Go code (fails corpora: detections in 1 corpus) |
| **Java** | **0/8 vs 3/8** (dvja only); held-out 5/34 | **no finding** on real repositories | 76/90 = 84 % | withheld |
| **JavaScript** | **10/23 vs 18/23** | **0/15** (+36 uncertain) | 73/152 = 48 % | withheld |
| **TypeScript** | **2/17 vs 3/17** | **0/10** | 35/77 = 45 % | withheld |

Intervals are 95 % Wilson. The tuning half of the real corpus (reported, never gated):
PHP 1/8, Python 1/89, JS 5/16, TS 1/20, Go 0/1, Java none.

**Read this before trusting the Python pass.** Python's recall gate passes on DSVW alone.
There, CodeQL raised no alert at all, and Aegis caught 5 of 22 documented items. The
reason is that DSVW serves requests from a raw `http.server` handler, which neither
tool models as a source. Aegis's five come from `aegis-py-sql-string-construction`, a
context-free pattern rule. That rule is also behind Python's precision failure: 6 TP /
101 FP on real code. Without DSVW, Python would be 3/16 against CodeQL's 5/16 and would
fail. So the clean claim it certifies rests on the same rule that sinks its precision.

**Go's precision pass rests on five findings** (four true-positive weak-cipher
findings in vault, and one false positive). The interval is 38–96 %. It is the gate as specified in §0, and
too small to lean on.

### C. CodeQL comparison, per corpus

CodeQL CLI 2.27.3, `security-extended`, default configuration, run by hand per its
license (§0.4). Each item is judged by the rule Aegis is judged by: an alert of the
item's class at the item, or at the helper or route file the corpus documents for it.
Decisions with the query and line are in `docs/ground_truth_n6/codeql_decisions.py`.

| corpus | language | Aegis | CodeQL | notes |
|---|---|--:|--:|---|
| DSVW | Python | 5/22 | **0/22** | CodeQL raised 0 alerts: raw `http.server` source |
| django.nV | Python | 1/7 | 2/7 | CodeQL adds the redirect |
| lets-be-bad-guys | Python | 2/9 | 3/9 | CodeQL adds the redirect |
| DVNA | JS | 5/9 | 6/9 | CodeQL adds reflected XSS in the `.ejs` view |
| vulnerable-node | JS | 5/14 | **12/14** | CodeQL follows SQL across the route → model call (3 items), plus logging, prototype pollution, debug |
| OopsSec Store | TS | 2/14 | 1/14 | both miss the Next.js App Router sources |
| VuNAPI | TS | 0/3 | 2/3 | CodeQL models NestJS decorator parameters |
| dvja | Java | 0/8 | 3/8 | CodeQL with build-free extraction: SQLi in a service, command injection, sensitive log |
| java-sec-code | Java | 5/26 | NOT RUN | no license file |
| damn-vulnerable-golang | Go | 4/8 | 4/8 | different items each: CodeQL TLS + integer conversion; Aegis DES + RC4 |
| go-test-bench | Go | 0/10 | 0/10 | the dispatcher defeats both |
| not-going-anywhere | Go | 0/3 | 0/3 | |
| GoVWA | Go | 0/4 | NOT RUN | no license file |
| bWAPP, Mutillidae II, XVWA | PHP | 68/160 | NOT RUN | CodeQL has no PHP support |

Go needed CodeQL to build the code (autobuild). That is our measurement harness on
licensed test corpora, never customer code.

**The floor, against the data.** CodeQL's own held-out recall ranges from 0 % (DSVW)
to 86 % (vulnerable-node). The reference does not set one absolute bar. It says where a
mainstream tool already does better than us on the same documented vulnerabilities:
- JavaScript, Java and TypeScript: we are below it, so a clean grade there would
  promise more than the market reference delivers.
- Python and Go: we are at or above it, with the Python caveat above.

### B. Precision on real repositories

Measured as §0.2 fixed it. The result is lower than N5's, where teaching-corpus TPs
counted toward precision:
- **PHP:** 62 % under N5 → **27 %** on real code. `aegis-php-xss` and
  `aegis-php-sql-injection` on Dolibarr do not model its escapers.
- **Python:** 5 %; `aegis-py-sql-string-construction` again.
- **JS / TS:** 0 % on the held-out half. The 36 uncertain JS findings are ReDoS
  shapes in vendored client libraries.
- **Java:** no finding on any of the 31 real repositories, so a problem claim has no
  evidence.

No precision fix was made in N6; the holdout is in place for the pass that makes one.

### D. JS/TS ground truth

Five corpora qualify (§0.5): 134 documented items, 62 in scope. Item statuses and the
triage of all 148 findings on them are in `docs/ground_truth_n6/score_jsts.py`.

| corpus | role | in scope | Aegis detected | misses: rule gap / ceiling |
|---|---|--:|--:|---|
| DVNA | held out | 9 | 5 | 1 / 3 (template-side and client-side XSS) |
| vulnerable-node | held out | 14 | 5 | 5 / 4 (SQL built in a model function; template XSS) |
| dvws-node | tuning | 22 | 11 | 11 / 0 (XPath, LDAP, SOAP / XML injection, CORS, log injection, prototype pollution, upload, cookies, GraphQL) |
| OopsSec Store | held out | 14 | 2 | 8 / 4 (Next.js App Router requests and Prisma `$queryRawUnsafe` not modelled) |
| VuNAPI | held out | 3 | 0 | 3 / 0 (NestJS `@Query` / `@Body` parameters not modelled) |

### A. What shipped

- **Scanner:**
  - `utils/tier_bar.py`: two gates per language, the CodeQL reference, and real-repo
    versus stress precision.
  - `utils/rule_coverage.py`: per-gate code fractions, the repository's quadrant, the
    clean label, and the precision caveat.
- **Orchestrator:**
  - `pipeline/aggregator.go` `securityShown`: shows the score or rating only where the
    certified claim backs it.
  - `types.SecurityCoverage`: new quadrant fields.
  - `LanguageCoverage.Evidence`: carried through. **This fixes an N5 defect:** the
    orchestrator dropped the per-language evidence, so it never reached a real scan.
- **API:** the report's coverage sentence names the certified claim.
- **Web:** `securityPresentation`. The Security card shows "No issues found in what we
  check · X% held-out recall" in place of an A or B, and "Findings shown, no grade" with
  the caveat in place of a bad grade.
- **Tests:**
  - scanner: planted evidence for every gate and quadrant, and the measured outcome;
  - orchestrator: one test per quadrant, including **a limited-recall repository with
    zero findings never renders A**;
  - web: the same, on the card.

**Unchanged:** no rule changed. The original five corpora are at **22/45**; the licence
guard is green (81 Aegis + 89 njsscan + 9 staged).
