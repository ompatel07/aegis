# Pass F2 — competitor head-to-head on small repos

**HEAD:** `af57e20` · **Run date:** 2026-09-06 · **Box:** Docker Desktop, 8 CPU, **3.744 GiB total RAM**

Two claims had no evidence behind them: *"competes with SonarQube on quality"* (never run, deferred
twice) and *"beats CodeQL"* (cross-study, synthetic Java only). This pass tests both on the same
checkouts, on one machine, in one sitting.

**Method — same checkout, not just the same repo.** All tools were pointed at the *identical* F1
clones under `/workspaces/_f1/...`, the same trees Aegis scanned in Pass F1. No re-cloning, so no
drift between tools. Aegis's numbers are its F1 pipeline results (API → orchestrator → scanner →
Postgres); the competitors were run afterwards with Aegis stopped.

| part | tool | status |
|---|---|---|
| **A** | SonarQube CE 9.9.8 (quality) | ⚠ **NOT RUN** — server started, analysis could not complete on this box. See §A. |
| **B** | CodeQL CLI 2.26.4 (SAST) | ✅ **RUN** — 3 of 4 repos (PHP unsupported by CodeQL) |
| **C** | Semgrep registry-only (marginal value) | ✅ **RUN** |
| **D** | Aegis-only capability inventory | ✅ compiled |

---

## Corpus

Reused from F1/V2 so results chain to existing data. Two ground-truth repos.

| repo | lang | LOC | ground truth? | why |
|---|---|--:|---|---|
| **NodeGoat** (`OWASP/NodeGoat`) | JS/Node | 3,084 | ✅ **yes** — OWASP teaching app, vulns planted with "the Fix:" comments in source | The three-way repo: Aegis, CodeQL and SonarQube CE all support JS. |
| **DVWA** (`digininja/DVWA`) | PHP | 13,771 | ✅ yes — per-module documented vulns | PHP: **CodeQL cannot scan it at all** (see §B). |
| **dvpwa** (`anxolerd/dvpwa`) | Python | 10,684 | ✅ yes — README §Vulnerabilities lists SQL Injection | Python head-to-head. |
| **spring-petclinic** | Java | 4,214 | ✗ (clean app) | The near-silent control — a well-written app where a good tool should say little. |

---

## §A — vs SonarQube CE: **NOT RUN**

**Status: NOT RUN. No SonarQube numbers are reported, and none are inferred.**

What actually happened, so the next attempt starts informed:

1. `vm.max_map_count` was raised to 262144 (Elasticsearch bootstrap requirement) via a privileged
   `nsenter` into the Docker VM. ✅
2. **SonarQube CE 9.9.8 started successfully and reached `{"status":"UP"}` in ~80 s**, constrained to
   `--memory=2600m` with `-Xmx512m` web / `-Xmx512m` CE / `-Xmx512m` search. Steady-state usage:
   **1.529 GiB**. Admin password rotated, analysis token minted. So *the server half is feasible on
   this box.*
3. The first `sonar-scanner-cli` run (NodeGoat, only 3,084 LOC, `--memory=1200m -Xmx900m`) had not
   finished after **10 minutes**, and shortly afterwards the **Docker engine became unresponsive**.
   The WSL `docker-desktop` distro ended up `Stopped`; two restart attempts and a `wsl --shutdown`
   did not bring the engine back within ~40 minutes, and `docker info` / `wsl -l -v` themselves began
   to hang.

**Why it is NOT RUN rather than "slow":** SonarQube server (1.5 GiB) plus a scanner JVM plus the
Docker VM overhead does not fit in 3.744 GiB with any headroom. The scanner also reads every source
file across a Docker *named volume*, which is pathologically slow on Windows — the same effect made
an 816 MB `tar` extraction exceed 10 minutes earlier in this pass. Under that combination the host
thrashed and the engine died. Reporting a partial or thrash-distorted analysis would be exactly the
"half-run and report noise" failure this pass was told to avoid.

**What is needed to actually run it** (all small, none available on this box today):
- ≥ 8 GiB for the Docker VM (SonarQube's own documented minimum is 4 GiB *for the server alone*), or
- run SonarQube on the host rather than in the constrained VM, and
- copy each repo into the scanner container's local filesystem first, so analysis never reads across
  the named volume.

**Therefore these remain unevidenced and must not be claimed:**
- "competes with SonarQube on quality"
- any ratings/duplication agreement or disagreement with SonarQube
- the **petclinic duplication figure**. Aegis reports **39.33 %** duplicated lines on
  spring-petclinic — implausibly high for a curated Spring sample, and the same shape as the
  `mall 90.5 %` inversion bug. It is *suspicious*, but with SonarQube NOT RUN there is **no
  cross-check**, so it is recorded here as an open question, not as a defect and not as agreement.

---

## §B — vs CodeQL CLI 2.26.4 (SAST): **RUN**

Query suite: `<lang>-security-extended.qls` — deliberately the *broader* security suite rather than
the default `code-scanning` set, to give CodeQL its best recall. Java used
`--build-mode=none`, the fair analogue of Aegis's never-build-customer-code boundary.

### B.1 Coverage and cost

| repo | lang | CodeQL DB create | CodeQL analyze | CodeQL total | CodeQL findings | Aegis total (full pipeline) | Aegis SAST findings |
|---|---|--:|--:|--:|--:|--:|--:|
| NodeGoat | JS | 11 s | 63 s | **74 s** | **17** | 63 s | 60 |
| dvpwa | Python | 12 s | 50 s | **62 s** | **1** | 62 s | 6 |
| spring-petclinic | Java | 84 s | 103 s | **187 s** | **2** | 55 s | 16 |
| DVWA | PHP | — | — | — | — | 66 s | 115 |

**CodeQL cannot scan PHP at all.** Its extractor list is exactly: swift, csv, properties, java, html,
rust, javascript, xml, actions, csharp, ruby, python, cpp, yaml, go. DVWA — 13.8k LOC and the richest
ground truth in the corpus — is simply outside CodeQL's reach. Aegis analysed it in 66 s and produced
115 SAST findings including 31 `aegis-php-*`.

**Memory note (fairness):** CodeQL's Java analysis was **OOM-killed at `--ram=2048`** on this box and
only completed at `--ram=1200 --threads=1`. Aegis analysed the same repo at default settings without
tuning. Confidence: high (reproduced; the failure was a silent mid-query process death).

### B.2 Ground-truth recall — NodeGoat (the number that matters)

Ground truth taken from NodeGoat's **own source**, not from memory: each item below is a vulnerability
the project plants deliberately, most with an explicit `// Fix:` comment next to it.

| # | Documented vulnerability | Location (verified in source) | **Aegis** | **CodeQL** |
|---|---|---|:--:|:--:|
| GT1 | Server-side JS injection — `eval(req.body.*)` | `app/routes/contributions.js:32,33,34` | ✅ `aegis-js-code-injection` (critical) + njsscan + semgrep | ✅ `js/code-injection` ×3 |
| GT2 | **NoSQL injection** — `$where: \`… this.stocks > '${threshold}'\`` | `app/data/allocations-dao.js:78` | ❌ **miss** (only quality findings in that file) | ✅ `js/code-injection` (critical) at :78 |
| GT3 | Unvalidated redirect — `res.redirect(req.query.url)` | `app/routes/index.js:72` | ✅ njsscan + semgrep open-redirect | ✅ `js/server-side-unvalidated-url-redirection` |
| GT4 | SSRF — `needle.get(req.query.url + req.query.symbol)` | `app/routes/research.js:15-16` | ✅ njsscan `node_ssrf` | ✅ `js/request-forgery` (critical) |
| GT5 | Missing CSRF protection (csurf commented out) | `server.js:7,106` | ✅ `express-check-csurf-middleware-usage` | ✅ `js/missing-token-validation` |
| GT6 | Weak crypto — `crypto.createCipheriv(config.cryptoAlgo…)` | `app/data/profile-dao.js:32` | ❌ miss | ❌ miss |
| GT7 | **ReDoS** — `/([0-9]+)+\#/` nested quantifier | `app/routes/profile.js:59` | ❌ **miss** | ✅ `js/redos` + `js/polynomial-redos` |
| | **Recall** | | **4 / 7 = 57 %** | **6 / 7 = 86 %** |

> **On JavaScript SAST recall against documented vulnerabilities, CodeQL beats Aegis, 6/7 vs 4/7.**
> Confidence: **high** — same checkout, same day, ground truth read out of the source file, and both
> misses were confirmed by inspecting Aegis's full finding list for those exact files.

Aegis's two clean misses are not obscure. GT2 is the flagship NoSQL-injection lesson; GT7 is a
textbook catastrophic-backtracking regex. Both are single-file, single-function patterns — not
interprocedural. Aegis *has* a `regex_dos` rule (it fired on `session.js:159`) yet did not fire on
`profile.js:59`.

### B.3 Ground-truth recall — dvpwa (Python): the result reverses

dvpwa's README lists **SQL Injection** as its headline vulnerability.

| Documented vulnerability | Location | **Aegis** | **CodeQL** |
|---|---|:--:|:--:|
| SQL injection — `q = ("INSERT INTO students (name) VALUES ('%(name)s')" % {'name': name})` then `cur.execute(q)` | `sqli/dao/student.py:42-45` | ✅ `sqlalchemy-execute-raw-query` (high) | ❌ **miss** |
| (CodeQL's only finding) weak sensitive-data hashing | `sqli/dao/user.py:41` | — | ✅ |
| | **Recall on the documented SQLi** | **1/1** | **0/1** |

**This is a genuine CodeQL miss, not an extraction failure.** Verified: `sqli/dao/student.py` (1,394
bytes) is present in CodeQL's source archive, the database counted 536 LOC of Python, and the
extraction log reports **0 errors**. CodeQL simply did not report it. The likely cause is source
modelling: the tainted value arrives through an **aiohttp** handler, and if CodeQL does not model
that framework's request parameters as a remote source, its taint path never starts. Aegis's rule is
pattern-based (raw query construction) and therefore fires regardless of framework support.
Confidence: high on the miss; medium on the explanation.

### B.4 Hand-triage — findings each tool has that the other misses

**CodeQL-only (10 sampled, NodeGoat):**

| finding | location | verdict |
|---|---|---|
| `js/code-injection` | allocations-dao.js:78 | **TP** — the documented `$where` NoSQL injection |
| `js/redos` | profile.js:59 | **TP** — planted nested-quantifier ReDoS, with the fix commented out beside it |
| `js/polynomial-redos` | profile.js:61, session.js:181 | **TP (weaker)** — real polynomial backtracking, lower impact |
| `js/sql-injection` ×2 | user-dao.js:91,104 | **TP (weak)** — `findOne({userName: userName})` is NoSQL *operator* injection if the value is an object; real class, modest severity |
| `js/session-fixation`, `js/missing-rate-limiting` | index.js:34 | **TP (advisory)** — genuine hardening gaps, low urgency |
| `js/log-injection` | session.js:64 | **TP (weak)** |
| `js/indirect-command-line-injection` | Gruntfile.js:166 | **TP but low value** — build script, not shipped code |
| `js/clear-text-cookie` | server.js:78 | **TP — overlap**, Aegis flags the same line via cookie-settings rules |

Net: CodeQL's unique findings are **mostly true positives**, and two of them are documented
ground-truth vulnerabilities Aegis missed. That is the strongest single result in this pass.

**Aegis-only (10 sampled, NodeGoat):**

| finding | location | verdict |
|---|---|---|
| 86 dependency CVEs | `package-lock.json` | **TP — entire capability CodeQL lacks.** CodeQL CLI does no SCA. |
| Private key committed | `artifacts/cert/server.key` ×2 | **TP — capability CodeQL lacks.** No secret scanning in CodeQL. |
| Dockerfile / compose misconfig | `docker-compose.yml` ×2 | **TP — capability the JS suite lacks** |
| Mutable GitHub Action tag | `.github/workflows/*.yml` ×6 | **TP** — real supply-chain hygiene finding |
| `node_insecure_random_generator` ×3 | user-dao.js:51-53 | **TP (weak)** — `Math.random()` for non-crypto use; defensible but noisy |
| 12 findings on contributions.js | :32-34 | **TP but redundant** — 4 rules firing on the same 3 eval calls; CodeQL reports 3 |
| tutorial HTML findings ×5 | `app/views/tutorial/a2.html`, `a5.html` | **FP (context)** — these are *teaching pages that display vulnerable examples*, not live code |

Net: Aegis's unique findings are dominated by **whole categories CodeQL does not implement** (SCA,
secrets, IaC), plus some redundancy and a small pocket of context-blind FPs in tutorial content.

---

## §C — vs Semgrep registry-only: **RUN**

Method (as V2 §4): the aegis packs are *additive* over the registry, so their marginal contribution
**is exactly the `aegis-*` finding set**.

| repo | lang | `aegis-*` | registry | total SAST | marginal value |
|---|---|--:|--:|--:|---|
| DVWA | PHP | **31** | 84 | 115 | **+37 % over registry — real.** `aegis-php-sql-injection` ×12, `-path-traversal` ×9, `-command-injection` ×9, `-xss` ×1 |
| NodeGoat | JS | **3** | 57 | 60 | +5 % — small, but all 3 are `aegis-js-code-injection` on the GT1 eval |
| dvpwa | Python | **0** | 6 | 6 | **zero** |
| spring-petclinic | Java | **0** | 16 | 16 | **zero — but correctly so** |

**The V2 §4 per-language table holds after T3.** PHP is where the custom pack earns its keep; JS is
small but real; Python remains zero (consistent with V2's redash result). Java's zero here is *not* a
T3 regression — petclinic is a clean application with no injection sinks to find, and T3's own gate
showed the Java pack producing 6 true positives on WebGoat. A clean app producing zero custom
findings is the 0-FP property working, not the pack being inert.

---

## §D — what only Aegis does

Honest inventory. "Equivalent?" answers whether the competitor offers the same thing **in the
configuration tested here** (CodeQL CLI with security-extended; SonarQube CE).

| capability | Aegis | CodeQL CLI | SonarQube CE | verdict |
|---|---|---|---|---|
| **Dependency CVE scanning (SCA)** | ✅ 86 CVEs on NodeGoat, 65 on dvpwa | ❌ none | ❌ none in CE (Advanced Security is paid) | **Aegis-only here** |
| **Reachability** (is the vulnerable symbol actually called?) | ✅ NodeGoat 30 reachable / 142 not, each with the calling file | ❌ | ❌ | **Aegis-only** |
| **CISA KEV flag + top-of-list sort** | ✅ a *medium* KEV finding sorted above three criticals | ❌ | ❌ | **Aegis-only** |
| **EPSS scores** | ✅ 162/172 CVEs scored, no fabricated zeros | ❌ | ❌ | **Aegis-only** |
| **Transitive dependency path** | ✅ `["your app","mongodb@2.2.36","mongodb-core@2.1.20","bson@1.0.9"]` | ❌ | ❌ | **Aegis-only** |
| **Code ownership (app vs vendored)** | ✅ app/third-party split per finding | ❌ | ~ partial (can exclude paths, not classify) | **Aegis-only in substance** |
| **Vendored-library fingerprinting** | ✅ found jQuery 3.2.1 → CVE-2020-11023 with no manifest entry | ❌ | ❌ | **Aegis-only** |
| **Secret scanning** | ✅ private key in `artifacts/cert/` | ❌ | ~ CE has limited secret rules | **Aegis stronger** |
| **IaC / Dockerfile misconfig** | ✅ DS-0002/0005/0026 etc. | ❌ (separate `actions` extractor, not in the JS suite) | ~ CE has some | **Aegis stronger** |
| **Finding lifecycle** (new/existing/resolved/reopened, line-shift-stable fingerprints) | ✅ proven in F1 | ❌ (SARIF `partialFingerprints` only) | ✅ **SonarQube does this well** — new-code period, issue status | **Not unique — Sonar is a peer** |
| **Honest not-measured / degraded states** | ✅ NULL ≠ 0, `engines_degraded` surfaced through API + SARIF | ❌ n/a | ~ Sonar shows "not computed" in places | **Aegis stronger, but see F1 §17b** |
| **Taint-based SAST depth** | intraprocedural (semgrep OSS) | ✅ **interprocedural, better** | ~ CE is weaker than both | **CodeQL wins** |
| **Language breadth incl. PHP** | ✅ PHP, JS, Python, Java, Go | ❌ **no PHP at all** | ✅ PHP supported | **Aegis + Sonar over CodeQL** |
| **Quality pillar** (smells, duplication, complexity) | ✅ | ❌ | ✅ **Sonar is the category leader** | **Not evidenced — §A NOT RUN** |

---

## Where Aegis actually stands, on this evidence

Written for a skeptical buyer evaluating a small-to-mid repo.

On **JavaScript SAST recall — the one head-to-head with documented ground truth and both tools
running on the same checkout — Aegis lost to CodeQL, 4/7 versus 6/7.** CodeQL found the flagship
NoSQL injection and a planted ReDoS that Aegis missed outright, and its unique findings hand-triaged
as mostly true positives. That result should be taken at face value: for deep taint analysis on a
CodeQL-supported language, CodeQL is the stronger engine, and the previous "beats CodeQL" claim —
which rested on a cross-study of synthetic Java — is not supported and should be withdrawn. The
picture is not one-sided, though: on Python, Aegis caught dvpwa's documented SQL injection and
**CodeQL missed it entirely** (confirmed as a real miss, not an extraction failure), and CodeQL
**cannot analyse PHP at all** — it had nothing to say about the 13.8k-LOC PHP application in this
corpus, where Aegis produced 115 SAST findings. So the honest summary of the SAST comparison is:
CodeQL is deeper where it runs; Aegis runs in more places and is more consistent across languages.
Where Aegis is genuinely differentiated is not raw detection at all — it is everything wrapped around
a finding: dependency CVEs with **reachability**, KEV and EPSS prioritisation, transitive dependency
paths, vendored-library fingerprinting that caught a jQuery CVE with no manifest entry, secret and
IaC coverage, and a finding lifecycle with line-shift-stable fingerprints. CodeQL CLI does none of
those. That is a real and defensible position — *one tool, decent SAST, plus the SCA/secrets/IaC/
prioritisation layer that CodeQL leaves to you to assemble* — but it is a **breadth-and-workflow**
claim, not a depth claim, and it should be sold that way. Finally, the **quality-pillar claim against
SonarQube remains completely unevidenced**: SonarQube CE started fine but could not complete an
analysis on a 3.7 GiB machine, so it is recorded as NOT RUN. Until it runs, "competes with SonarQube
on quality" should not be said out loud — and the unexplained 39.33 % duplication figure on
spring-petclinic is a reason to be actively cautious about the quality metrics rather than confident.

---

## GATE

| requirement | status |
|---|---|
| Both comparisons run, or explicitly NOT RUN with the reason | ✅ CodeQL **run** (§B); SonarQube **NOT RUN** with a precise, reproducible reason and the exact resources needed (§A) |
| Ground-truth recall for all three tools side by side | ⚠ **partial** — Aegis vs CodeQL is complete on two ground-truth repos (§B.2, §B.3). The third tool (SonarQube) is NOT RUN, so a three-way table would be fabrication. |
| Hand-triaged samples both directions | ✅ 10 CodeQL-only + 10 Aegis-only, each with a verdict (§B.4) |
| One-paragraph honest positioning statement | ✅ above |

**Not measured / not claimed:** SonarQube issue counts, its Reliability/Maintainability ratings,
duplication agreement, and any quality-pillar comparison. Aegis's own `spring-petclinic` duplication
figure of 39.33 % is flagged as unverified and suspicious.
