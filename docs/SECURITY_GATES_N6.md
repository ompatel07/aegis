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
