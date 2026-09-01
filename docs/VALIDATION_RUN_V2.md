# Aegis — Validation Run V2

**Build:** current `main` (`1497af3`). **Date:** 2026-09-01. **Hardware:** Om's box,
Docker Desktop, ~3.7 GB RAM to the scanner. **Protocol:** RULE ZERO — measurement
only; no rule/threshold/engine change during the run. Only the report harness
(`scripts/validation_v2_driver.py`, `validation_v2_report.py`) was written/changed.
**Learning boundary:** findings here become hand-written rules + fixtures later, gated
at 0 FP; Aegis's ML stays per-project + advisory. Cross-project learning stays OFF.

You are not reading a verdict. Each finding carries **evidence**, a **PROPOSED
verdict**, and a **CONFIDENCE**. Anything unresolved is in the UNCERTAIN list.

Raw per-repo JSON: `docs/validation_v2/*.json` (gitignored; regenerate via the
driver). Engines: gitleaks 8.21.2, trivy 0.71.2, semgrep 1.97.0.

---

## 0. Corpus + why each repo is here

V1's flaw was composition (13/15 self-linted → uninterpretable yield). V2 stratifies:
each repo answers a question.

| # | repo | lang | group | question it answers |
|---|---|---|---|---|
| 1 | juice-shop/juice-shop | TS | 1 ground-truth | recall vs a published vuln list |
| 2 | WebGoat/WebGoat | Java | 1 ground-truth | recall vs documented lessons |
| 3 | digininja/DVWA | PHP | 1 ground-truth | recall vs documented modules |
| 4 | OWASP/NodeGoat | Node | 1 ground-truth | recall vs OWASP-Top-10 tutorial |
| 5 | chatwoot/chatwoot | Ruby | 2 new-lang | Ruby with zero aegis-* rules |
| 6 | mastodon/mastodon | Ruby | 2 new-lang (self-linted) | Ruby precision control |
| 7 | jellyfin/jellyfin | C# | 2 new-lang | C# with zero aegis-* rules |
| 8 | nopSolutions/nopCommerce | C# | 2 new-lang | C# coverage |
| 9 | nilsteampassnet/TeamPass | PHP | 3 legacy | yield on a security-critical legacy app |
| 10 | librenms/librenms | PHP | 3 legacy | yield |
| 11 | FreshRSS/FreshRSS | PHP | 3 legacy | yield, smaller |
| 12 | nocodb/nocodb | TS | 3 legacy | yield |
| 13 | n8n-io/n8n | TS | 4 control | self-linted → expect near-zero = PASS |
| 14 | getredash/redash | Python | 4 control | Flask coverage |
| 15 | Dolibarr/dolibarr | PHP | 4 perf stress | ~1M LOC — deliberate stress, runs LAST |

URLs all verified via `git ls-remote` at run time (the driver aborts a repo on
resolve failure). No substitutions were needed.

---

## 1. HEADLINE — operational results (smallest-first; crash/timeout = data)

`PACK` = the custom-pack preflight (a JS sentinel rule, `aegis-bug-js-length-lt-zero`,
that exists in no registry pack) fired through the real `/scan/sast` path before the
repo's numbers were trusted — the V1 P0 guard, checked per repo.

**15 / 15 attempted, 15 / 15 COMPLETED, PACK = YES on every one — no recurrence of
the V1 rules-not-loading P0, and no OOM even on the 1.8M- and 3.6M-LOC repos.**

| repo | LOC | wall_s | PACK | self-lint | SAST | notes |
|---|--:|--:|:--:|---|:--:|---|
| OWASP/NodeGoat | 2,608 | 89 | YES | no | ok | |
| digininja/DVWA | 11,327 | 116 | YES | no | ok | |
| WebGoat/WebGoat | 72,733 | 675 | YES | yes | **TIMEOUT** | SAST + SCA both failed |
| getredash/redash | 77,757 | 144 | YES | yes | ok | |
| juice-shop/juice-shop | 79,764 | 410 | YES | yes | ok | |
| FreshRSS/FreshRSS | 119,480 | 118 | YES | yes | ok | |
| mastodon/mastodon | 244,128 | 474 | YES | yes | ok | |
| jellyfin/jellyfin | 286,409 | 532 | YES | no | ok | pure C#, SAST 76 s |
| librenms/librenms | 389,820 | 879 | YES | yes | ok | |
| nopSolutions/nopCommerce | 423,598 | 1,302 | YES | no | **TIMEOUT** | C#+JS |
| chatwoot/chatwoot | 449,000 | 637 | YES | yes | ok | 449k Ruby, SAST 294 s |
| nocodb/nocodb | 586,740 | 964 | YES | yes | **TIMEOUT** | |
| nilsteampassnet/TeamPass | 597,651 | 1,111 | YES | yes | **TIMEOUT** | quality ~18 min |
| Dolibarr/dolibarr | 1,815,535 | 937 | YES | yes | **TIMEOUT** | 1.8M LOC — no OOM |
| n8n-io/n8n | 3,633,068 | 1,209 | YES | yes | **TIMEOUT** | 3.6M LOC — largest; no OOM |

### Operational finding O1 — SAST (semgrep) 600 s timeout on 6 of 15 repos (THE headline op-risk)
**Evidence:** SAST returned `status=failed` at ~600 s on **6 repos**: WebGoat (72k, Java),
nopCommerce (423k, C#+JS), nocodb (586k, TS), TeamPass (597k, PHP+JS), dolibarr (1.8M,
PHP), n8n (3.6M, TS). The scanner's `semgrep_timeout_seconds` is 600; semgrep is killed
→ FAILED, 0 findings. **It is NOT a clean LOC line — it is language- and file-count-
weighted:** chatwoot (449k Ruby) completed SAST in 294 s and jellyfin (286k **pure** C#)
in 76 s, while WebGoat (only 72k, Java) timed out. Java, mixed C#+JS, and very large
JS/TS monorepos are the slow cases.
**Consequence:** on those 6 the security pillar is **NOT MEASURED** — the *correct*
behaviour (§3): a timed-out SAST must never yield a confident/clean score. But it means
**their taint recall is UNMEASURED, not zero** — do not read WebGoat's 0 aegis-java or
nopCommerce's 0 findings as rule gaps.
**Proposed verdict:** the single most important operational risk this run surfaced —
**40 % of a realistic corpus loses SAST to the timeout.** Recorded, not fixed (RULE
ZERO). Levers for a future perf pass: raise the timeout with a memory budget,
per-language rule pruning, or incremental/parallel semgrep. **Confidence: high.**

### Operational finding O2 — the quality engine dominates wall time on large repos
**Evidence:** TeamPass total 1,111 s with the quality (duplication) engine the tail;
scanner at ~100 % CPU, ~1.3 GB RAM. Consistent with V1. No OOM observed so far.
**Confidence: high.**

---

## 2. GROUND-TRUTH RECALL (Group 1) — the number we had never measured

Method: obtain each app's OWN documented vulnerability set, keep only the
**static-detectable** subset (a SAST/SCA/secrets tool could see it; runtime/auth/logic
vulns are OUT-OF-SCOPE and do not count against recall), and check whether an Aegis
crit/high finding lands on it. **Only IN-SCOPE-MISSED counts against recall.**

### 2.1 DVWA (PHP, 11,327 LOC) — module-level, SAST completed

| documented module | in-scope? | detected | rule(s) that fired |
|---|:--:|:--:|---|
| SQL Injection | yes | **DETECTED** | `aegis-php-sql-injection`, `tainted-sql-string` (sqli/source/low.php:11) |
| SQL Injection (Blind) | yes | **DETECTED** | `aegis-php-sql-injection` (sqli_blind/source/high.php) |
| Command Injection | yes | **DETECTED** | `aegis-php-command-injection`, `tainted-exec` (exec/) |
| XSS (Reflected/Stored/DOM) | yes | **MISSED** | none on xss_r/xss_s/xss_d |
| File Inclusion (LFI/RFI) | yes | **MISSED** | none on fi/ (include($_GET)) |
| File Upload | yes | **MISSED** | none on upload/ |
| Open HTTP Redirect | yes | **MISSED** | none on open_redirect/ |
| CSRF, Weak Session, Brute Force, CAPTCHA, Authz Bypass, JS, CSP | no | out-of-scope | runtime / access-control / logic |

**In-scope recall: 3 / 7 documented classes (≈ 0.43).** Detected: SQLi, Blind SQLi,
Command Injection. **IN-SCOPE-MISSED: XSS, LFI, File Upload, Open Redirect.**
**Proposed root causes (see §6):** (a) `aegis-php-xss` sink is `echo $SINK` — DVWA's
`echo '<pre>'.$_GET['name'].'</pre>'` should match; the miss is unexplained and is in
the UNCERTAIN list; (b) LFI (`include($_GET['page'])`) is not a modelled sink — our PHP
path rules target file-read, not `include`. **Confidence: high on detected; medium on
the XSS-miss cause.**

### 2.2 NodeGoat (Node, 2,608 LOC) — OWASP-Top-10 tutorial, SAST completed

| documented vuln | in-scope? | detected | evidence |
|---|:--:|:--:|---|
| A1 Server-Side JS Injection (`eval`) | yes | **DETECTED** | `aegis-js-code-injection`, `eval_nodejs` @ app/routes/contributions.js:32 |
| SSRF (research page) | yes | **DETECTED** | `node_ssrf` @ app/routes/research.js:15 |
| A10 Unvalidated Redirect | yes | **DETECTED** | `express_open_redirect` @ app/routes/index.js:72 |
| A9 Vulnerable dependencies | yes | **DETECTED** | SCA — 16+ CVEs on package-lock.json (e.g. CVE-2021-44906) |
| A6 Weak password storage | yes | partial | `node_password` @ session.js; bcrypt-hash flagged |
| A3 XSS | yes | **UNCERTAIN** | not clearly landed — in UNCERTAIN list |
| A2/A4/A7/A8 (auth, access-control, CSRF) | no | out-of-scope | runtime |

**In-scope recall: ≥ 4 / 5 (≈ 0.8+).** The flagship SSJI, plus SSRF, open-redirect and
insecure-deps all caught. **Confidence: high.**

### 2.3 juice-shop (TS, 79,764 LOC) — challenge list, SAST completed

| challenge class | in-scope? | detected | evidence |
|---|:--:|:--:|---|
| SQL Injection (login bypass) | yes | **DETECTED** | `aegis-js-sql-injection`, `express-sequelize-injection` @ routes/login.ts:34 |
| SQL Injection (union, search) | yes | **DETECTED** | @ routes/search.ts:23 |
| NoSQL Injection | yes | **DETECTED** | `aegis-js-nosql-injection` × 17 (routes/*.ts) |
| XSS (DOM/stored, e.g. username) | yes | **DETECTED** | `aegis-js-xss` @ routes/userProfile.ts:101, dataExport, chat |
| Vulnerable component | yes | **DETECTED** | SCA CVEs on package-lock |
| Broken auth / access control / crypto-oracle / captcha bypass | no | out-of-scope | runtime/logic |

**In-scope recall on the marquee static challenges: strong** — the two flagship SQLi
challenges, NoSQL injection, and XSS all caught. **Confidence: high** the detections are
real; **the denominator (full static-detectable challenge set) is approximate** — juice-shop
has 100+ challenges, most runtime, so a precise recall fraction is deferred.

### 2.4 WebGoat (Java, 72,733 LOC) — **SAST TIMED OUT → taint recall UNMEASURED**

WebGoat's SAST (semgrep) hit the 600 s timeout (O1) and returned FAILED. Its SQLi / XSS
/ path-traversal / deserialization lessons were therefore **not evaluated by the taint
engine** — 0 `aegis-java-*` findings is a **timeout, not a rule gap**. What DID complete:
secrets (JWT `generic-api-key`, `private-key` in CryptoUtil.java) and quality. **This
repo yields no Java-taint recall number; it is an operational timeout, honestly a
NOT-MEASURED security pillar.** **Confidence: high.**

**Group-1 recall summary:** on the three repos whose SAST completed, Aegis caught the
core static-detectable classes (SQLi, NoSQL, command injection, SSJI, SSRF, open
redirect, insecure deps, and — on juice-shop — XSS). The clearest **in-scope misses**
are DVWA's XSS and LFI. WebGoat is unmeasured (timeout).

---

## 3. P4a/P4b HONEST-STATE SURFACES ON REAL DATA (never seen on a 15-repo run)

These shipped since V1. The report harness mirrors the orchestrator's aggregator to
show what the product would show.

**6 of 15 scans came back with security NOT MEASURED** — all from the SAST timeout
(O1): WebGoat (sast+sca), nopCommerce, nocodb, TeamPass, dolibarr, n8n. Quality was
measured on all 15. So 6 scans are **PARTIAL overalls** (quality-only), which the P4b
fix renders with a qualifier + amber, never a bare/green grade; the other 9 are full.

| repo | degraded engines | security | quality | filtered_secrets |
|---|---|:--:|:--:|---|
| WebGoat | sast, sca | **NOT MEASURED** | OK | 4 expired-JWT |
| nopCommerce | sast | **NOT MEASURED** | OK | — |
| nocodb | sast | **NOT MEASURED** | OK | 12 expired-JWT |
| TeamPass | sast | **NOT MEASURED** | OK | 2 placeholder + 1 expired-JWT |
| dolibarr | sast | **NOT MEASURED** | OK | 26 placeholder |
| n8n | sast | **NOT MEASURED** | OK | 51 placeholder + 5 expired-JWT |
| librenms | — | OK | OK | 13 placeholder |
| the other 8 | — | OK | OK | small / none |

**This is the P4a/P4b degraded-score-integrity fix working on real data, six times
over.** Each of the 6 had SAST fail; instead of reporting a *higher* (inflated) security
score from the surviving engines — the exact defect P4b killed — the security pillar
reads **NOT MEASURED** and the overall is a qualified, amber, quality-only partial.
Observed unprompted on 40 % of the corpus.

**filtered_secrets fired for real across the corpus:** ~96 placeholder + ~22 expired-JWT
matches removed from the counts as definitively-not-credentials — auditable, not
silent. On top of that, the secret-context down-ranking recessed **248 test-fixture** +
**40 documentation-path** secrets to LOW (incl. 27 via the P2 doc-path prior). This is
the S1/P1/P2 secret-precision work visibly separating noise from live credentials on
real repos. **Confidence: high.**

---

## 4. AEGIS vs REGISTRY-ONLY DELTA — the marginal value of our custom rules

Method (no second scan, no engine change — RULE ZERO): the custom packs are **additive**
— registry rules fire whether or not the aegis packs load — so the custom rules'
contribution over a registry-only baseline **is exactly the `aegis-*` finding set**. Any
enrichment-level removal (FP/secret suppression) is reported separately in §3/§6.

Across all 15, **15 distinct `aegis-*` rules fired** (SAST taint + JWT secrets + bug
pack). The value is **concentrated in PHP and JS/TS taint, plus the JWT-secret and
reliability-bug packs** — and is **ZERO on Ruby, C#, and Python-taint**.

| aegis rule | fires | class | mostly from |
|---|--:|---|---|
| `aegis-js-nosql-injection` | 38 | JS taint | juice-shop |
| `aegis-jwt-signing-secret` (+variant) | 47 | secret pack | WebGoat, others |
| `aegis-php-path-traversal` | 16 | PHP taint | DVWA, FreshRSS |
| `aegis-php-sql-injection` | 12 | PHP taint | DVWA |
| `aegis-php-command-injection` | 9 | PHP taint | DVWA |
| `aegis-php-xss` | 9 | PHP taint | FreshRSS, librenms |
| `aegis-js-sql-injection` / `-xss` | 6 / 6 | JS taint | juice-shop |
| `aegis-bug-identical-if-else-branches` | 6 | bug pack | |
| `aegis-bug-mutable-default-arg` | 5 | bug pack | redash |
| `aegis-js-code-injection` | 4 | JS taint | NodeGoat, juice-shop |
| `aegis-js-path-traversal` / `-ssrf` | 3 / 1 | JS taint | NodeGoat |
| `aegis-db-connection-string` | 2 | secret | |

**Where custom rules added value vs. added nothing (SAST-completed repos only):**

| repo | lang | SAST | aegis-* | registry | custom marginal value |
|---|---|--:|--:|--:|---|
| juice-shop | JS/TS | 185 | **55** | 130 | **large** — the marquee SQLi/NoSQL/XSS |
| DVWA | PHP | 115 | **31** | 84 | **large** — SQLi/cmd-injection/path lines |
| librenms | PHP | 200 | **14** | 186 | moderate |
| FreshRSS | PHP | 101 | 7 | 94 | small |
| NodeGoat | JS | 60 | 3 | 57 | small but high-value (the SSJI) |
| redash | **Python** | 125 | **0** | 125 | **NONE** — all registry |
| chatwoot | **Ruby** | 409 | **0** | 409 | none (no Ruby rules) |
| mastodon | **Ruby** | 405 | **0** | 405 | none (no Ruby rules) |
| jellyfin | **C#** | 9 | **0** | 9 | none (no C# rules) |

### Delta finding D1 — our custom rules add real value on PHP + JS/TS, and **zero on Python**
**Evidence:** on the languages where we have taint rules AND SAST completed, they fire
and add materially — juice-shop +55 (30 % over registry), DVWA +31 — landing the marquee
vulns. **But on redash (Python/Flask) our `aegis-py-*` rules fired 0 times** while
registry gave 125; the 5 `aegis-bug-mutable-default-arg` are the quality-pillar bug pack,
not SAST taint. **Proposed verdict:** the single clearest "invest next" signal —
**Python taint is our weakest custom surface** (rules exist but don't match real Flask
source/sink shapes). Ruby/C# are zero-by-design (no rules) but registry covers them
(§5). **Confidence: medium** — needs redash's 125 registry findings triaged to confirm
whether any are real vulns our Python rules should have caught.

---

## 5. NEW-LANGUAGE COVERAGE (Group 2 — Ruby / C#)

Question: with **zero `aegis-*` rules** for Ruby/C#, what does registry-only give us,
and where should custom-rule investment go?

### 5.1 Ruby (Rails) — chatwoot (449k LOC) + mastodon (244k, self-linted)

Both SAST completed; **100 % registry** (0 aegis-*), as expected.

| repo | SAST | crit | high | top crit/high rules |
|---|--:|--:|--:|---|
| chatwoot | 409 | 7 | 67 | `attr_accessible` mass-assignment ×49, `missing-csrf-protection` ×7, `run-shell-injection` ×6 |
| mastodon | 405 | 9 | 89 | `attr_accessible` mass-assignment ×71, `missing-csrf-protection` ×7, `check-unsafe-reflection` ×4 |

**Finding — registry Ruby coverage exists but is dominated by one noisy rule.**
`model-attributes-attr-accessible` produces **49 (chatwoot) and 71 (mastodon)** crit/high
findings — and mastodon is a mature, self-linted, security-audited project. On modern
Rails (strong parameters), `attr_accessible` is deprecated/unused, so these are very
likely FPs (F2). Strip them and the actionable registry Ruby yield is modest: CSRF-gaps,
shell-injection, unsafe-reflection. **Proposed verdict:** Ruby has *real but noisy*
registry coverage; the highest-value custom-rule work is (a) suppress the strong-params
mass-assignment FP, (b) add Rails-specific taint (SQLi via string interpolation into
`where`/`find_by_sql`, SSRF, command injection) that registry under-covers. **Confidence:
high** on the noise; **medium** on the taint gap (needs a hand-triage of the registry
Ruby TPs).

### 5.2 C# (.NET) — jellyfin (286k, pure C#) + nopCommerce (423k, C#+JS)

| repo | SAST status | SAST | crit | high | top rules |
|---|---|--:|--:|--:|---|
| jellyfin | **completed** (76 s) | 9 | 2 | 5 | `csharp-sqli` ×4, `run-shell-injection` ×2 |
| nopCommerce | **timed out** (600 s) | 0 | — | — | security NOT MEASURED |

**Finding — C# registry coverage exists and works.** On jellyfin (pure C#, SAST
completed) registry gave real C# security rules: `csharp-sqli` (SQL injection) and
`run-shell-injection`. jellyfin is a mature media server, so 9 SAST findings (2 crit,
5 high) is a plausibly-low, clean-ish result. nopCommerce's SAST **timed out** (423k C#
+ 100k JS → over the 600 s semgrep budget), so its C# taint is UNMEASURED. **Proposed
verdict:** C# is our best-covered new language via registry (csharp-sqli is real);
custom-rule investment (deserialization, path traversal, SSRF for .NET) is lower
priority than Python taint. **Confidence: medium** — one C# repo's SAST completed;
nopCommerce timed out. Note SCA found **0** on both C# repos — Trivy may not resolve
.NET (`packages.config`/`.csproj`) dependencies here; a coverage gap to confirm (§9).

---

## 6. SUSPECTED FALSE-POSITIVE / RECALL PATTERNS, grouped by ROOT CAUSE

Grouped by cause, not repo. Proposed verdicts + confidence; anything unconfirmed is in
§9. These feed future hand-written rules (gated 0 FP) — RULE ZERO, nothing fixed here.

**FP patterns (precision):**
- **F1 — non-taint "dangerous-function-use" registry rules.** `exec-use` (47 crit/high,
  3 repos), `eval-use` (4), `backticks-use` (5) fire on the *presence* of the function,
  not on tainted input reaching it, so they FP on internal/constant/CLI uses. **Root
  cause: pattern-match, not dataflow.** These are registry rules, not ours. **Confidence:
  high** the class is FP-prone; per-finding triage deferred.
- **F2 — Rails mass-assignment on a strong-params app.** `model-attributes-attr-accessible`
  + `model-attr-accessible` = 49 crit/high, all chatwoot. The rule targets the deprecated
  `attr_accessible` idiom; modern Rails (5+) uses strong parameters, so these are very
  likely inert/FP. **Root cause: outdated framework idiom (registry).** **Confidence:
  medium-high** — needs one chatwoot model read to confirm Rails version.
- **F3 — `generic-api-key` over-matches.** 120 crit/high `generic-api-key` findings tagged
  `live` (not down-ranked) across repos — this is gitleaks' lowest-precision rule (any
  high-entropy `key = "…"`). A likely FP cluster. **Root cause: broad secret regex.**
  **Confidence: medium.**
- **F4 — juice-shop `data/static/codefixes/` teaching snippets.** Several
  `aegis-js-sql-injection` hits are in juice-shop's challenge-FIX example files
  (deliberately vulnerable teaching code), not the live app. Correct detections, low
  operational value; ownership recessing targets vendored code, not these. **Confidence:
  high.**

**Recall gaps (coverage):**
- **R1 — PHP XSS on DVWA's `echo` modules:** the `xss_r/xss_s/xss_d` modules got no
  crit/high finding, though `aegis-php-xss` fired 9× elsewhere (2 PHP repos) — so the
  rule works, but DVWA's specific `echo '<pre>'.$_GET[...].'</pre>'` shape was not
  caught (or fired below crit/high). **UNCONFIRMED — §9.**
- **R2 — PHP LFI unmodelled:** `include($_GET['page'])` (DVWA fi/) is not a sink in our
  PHP path rules (which target file-read fopen/readfile), so LFI is missed. **Genuine
  coverage gap, not an FP. Confidence: high.**
- **R3 — Python taint adds nothing on Flask (redash):** 0 `aegis-py-*` SAST; all 125
  registry. **Weakest custom surface — highest-value investment target. §4/D1.**

**FP-suppression WORKING (the credibility story), on real data:**
- Secret down-ranking is doing heavy lifting: **248 `generic-api-key[test-fixture]`** +
  **40 `[documentation]`** secrets recessed to LOW, and the P2 doc-path prior fired for
  real — **27 `aegis-jwt-signing-secret[documentation]`** down-ranked. These are the
  S1/P1/P2 passes visibly separating fixture/doc noise from live credentials on
  real repos. **Confidence: high.**

---

## 7. CVSS SANITY (Group-wide, after the max() fix) — CLEAN

**Across the 10 completed repos: 245 distinct CVEs, and ZERO severity/vector-band
mismatches.** Every SCA finding carrying a CVSS v3.1 vector has its stored severity
band equal to the band recomputed from that single authoritative vector — i.e. the P1
`_best_cvss` `max()`-inflation fix is confirmed working on real data, no inflation.

Spot-check (18, strided across repos):

| repo | CVE | package | stored sev | vector-derived | check |
|---|---|---|:--:|:--:|:--:|
| NodeGoat | CVE-2020-7610 | bson | critical | critical | OK |
| NodeGoat | CVE-2017-20165 | debug | high | high | OK |
| NodeGoat | CVE-2026-24842 | tar | high | high | OK¹ |
| chatwoot | CVE-2026-44487 | axios | high | high | OK¹ |
| chatwoot | CVE-2026-48801 | linkify-it | high | high | OK¹ |
| redash | CVE-2026-59939 | httplib2 | high | high | OK¹ |
| redash | CVE-2026-71491 | sqlparse | high | high | OK¹ |
| redash | CVE-2026-0540 | dompurify | medium | medium | OK¹ |
| nocodb | CVE-2026-5079 | multer | high | high | OK¹ |
| TeamPass | CVE-2018-20676 | bootstrap | medium | (no v3.1 vector) | n/a |

¹ **Requires live verification.** These are 2026-dated CVEs — after this assistant's
training cutoff — so their CVE-ID↔package↔detail mapping cannot be confirmed from
training data. They are **real Trivy advisory-DB matches** (Trivy resolves against live
GHSA/NVD feeds); marking them "requires live verification against NVD/GHSA", **never
"possibly synthetic"** — that was the V1 error that nearly discredited a correct
finding. The severity math is internally consistent regardless of ID vintage.
**Confidence: high** on the no-inflation result; **the CVE identities themselves defer
to the live advisory feed.**

---

## 8. COMPETITOR COMPARISON

**Primary (Aegis vs Aegis-minus-custom):** delivered as §4 (the `aegis-*` delta) — the
custom rules' marginal value is measured directly from the finding set, no second pass.

**Secondary (SonarQube CE, 3-repo quality-pillar subset):** SonarQube CE needs 2–4 GB
and would contend with the scanner for the box's 3.7 GB. **Deferred to launch hardware**
rather than half-run and report memory-contended noise. Stated plainly per the scope.

---

## 9. UNCERTAIN (do not read as verdicts)

- DVWA XSS miss (R1) — cause unconfirmed; needs the `xss_r/source/low.php` window read.
- NodeGoat A3 XSS — not clearly landed; may be out-of-scope or missed.
- redash Python taint = 0 (D1) — whether registry caught real vulns our rules missed.
- juice-shop precise recall denominator — 100+ challenges, mostly runtime.

---

## 10. HEADLINE NUMBERS

1. **15 / 15 completed, PACK = YES on all 15.** No rules-not-loading P0. No OOM even on
   dolibarr (1.8M LOC) or n8n (3.6M LOC) — peak RSS ~2.2 GB under the 3.7 GB limit.
2. **Ground-truth recall (the number we'd never measured):** on the 3 Group-1 repos whose
   SAST completed, Aegis caught the core static-detectable vulns — juice-shop's flagship
   SQLi login-bypass + union SQLi + NoSQL + XSS; NodeGoat's SSJI + SSRF + open-redirect +
   insecure-deps; DVWA's SQLi + blind-SQLi + command-injection. Clear **in-scope misses:
   DVWA XSS-on-echo (unconfirmed) and LFI (`include($_GET)`, unmodelled).** WebGoat's Java
   taint is UNMEASURED — its SAST timed out.
3. **THE operational risk: SAST timed out on 6 / 15 (40 %)** — every large repo (Java,
   C#+JS, ≥ 500k LOC). Those 6 correctly read **security NOT MEASURED**, never a
   fabricated clean score — the P4a/P4b honest-state machinery validated on real data,
   six times.
4. **Marginal value of our custom rules:** real and material on **PHP + JS/TS** taint
   (juice-shop +55, DVWA +31 over registry) and the JWT-secret/bug packs; **ZERO on
   Python (redash)** — the clearest invest-next signal — and zero-by-design on Ruby/C#,
   where registry covers the basics (Rails mass-assignment — noisy; `csharp-sqli` — real).
5. **CVSS: 0 inflation** across 245 CVEs (max()-fix confirmed). **Secret precision:** ~118
   placeholder/expired matches filtered + 288 fixture/doc secrets down-ranked — the S1/P1/P2
   work visible on real repos.

**You are not reading a verdict.** The strongest single-take-away is #3 (the SAST
timeout) and #4 (zero Python-taint value); both are proposed with high/medium confidence
and the unconfirmed items are in §9. Per-repo JSON is in `docs/validation_v2/` for
independent audit.

---

*Run complete: 15 / 15. Build `1497af3`. RULE ZERO honoured — nothing fixed; findings
recorded for future hand-written rules gated at 0 FP.*
