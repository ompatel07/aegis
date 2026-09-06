# Pass G1 — closing the F2 recall gap, and evaluating Opengrep

**HEAD:** `d45aafe` · **Run date:** 2026-09-07 · **Same checkouts as F1/F2** (`/workspaces/_f1/...`),
so every number here chains directly to `COMPETITIVE_F2.md`.

F2 left NodeGoat at **Aegis 4/7 vs CodeQL 6/7**. Part A closes that gap. Part B asks whether a
different engine closes the *structural* gap underneath it.

---

## PART A — the two misses

### A1. `$where` NoSQL injection — NodeGoat `allocations-dao.js:78`

**The premise was wrong in an instructive way.** This is not a pattern gap in our NoSQL taint rule.

Root cause, established by reading the file:

```
grep -n "req\.\|request" app/data/allocations-dao.js   →   (no matches)
```

`threshold` arrives as a **plain function parameter** of `getByUserIdAndThreshold`; the matching
`req.query.threshold` lives in `app/routes/allocations.js` — **a different file**. So no taint rule
can fire here: there is no source in this compilation unit. (Confirmed empirically in Part B —
Opengrep's `--taint-intrafile` does not find it by taint either, because the gap is cross-*file*,
not cross-function.) A second, independent obstacle: the sink is `find(searchCriteria())`, a
function *call*, not the object literal.

What *is* local, and is decisive on its own, is the construct. `$where` hands its argument to
MongoDB to **evaluate as JavaScript**, so building it by interpolation is an injection sink
regardless of where the value came from. The fix is therefore deliberately **not** a taint rule:

**`aegis-js-nosql-where-injection`** (ERROR) — flags `{$where: <template literal>}` and
`{$where: <concatenation>}`; explicitly does *not* flag a constant `$where`.

> Fires at `app/data/allocations-dao.js:77` ✅ (CodeQL reports :78 — same construct, the object
> literal spans both lines.)

### A2. Nested-quantifier ReDoS — NodeGoat `profile.js:59`

**Do we have any ReDoS rule?** Of our own — **no**. `grep -rn "redos|catastrophic|backtrack"
services/scanner/rules/` returns nothing.

**Why didn't the registry rule fire?** It did fire — just elsewhere. njsscan's `regex_dos` hit
`session.js:159` (`USER_RE.test(userName)`), because it is a *"regex tested against user input"*
heuristic. It says nothing about the regex itself. `profile.js:59` needs the **literal analysed**:

```js
const regexPattern = /([0-9]+)+\#/;          // nested quantifier — exponential backtracking
const ok = regexPattern.test(bankRouting);   // bankRouting destructured from req.body above
```

**Decision: write the rule** (silence was not an option, and the boundary argument is weak — this
is statically decidable from the literal alone).

**`aegis-js-redos-nested-quantifier`** (WARNING) — matches regex literals containing a group whose
last element is quantified and which is itself re-quantified: `(X+)+`, `(X*)*`, `(X+)*`, `(X*)+`.
The construct is *redundant as well as dangerous* — `(X+)+` matches exactly what `(X+)` matches —
so its presence is itself the defect, which is what makes flagging it precise rather than noisy.

> Fires at `app/routes/profile.js:59` ✅ — exactly CodeQL's line.

### 0-FP gate (both new rules, all six available repos)

| repo | hits | verdict |
|---|--:|---|
| NodeGoat | 2 | both **TP** — the two documented vulns above |
| django-nV | 1 | **TP** — `/(?:\s+\|#.*)+/` at `xregexp.js:1183`, a genuine nested quantifier in a *vendored* copy of XRegExp |
| DVWA, dvpwa, spring-petclinic, juice-shop | 0 | — |

**3 hits, 3 true positives, 0 false positives.** `semgrep --test` **38/38** (was 36/36).

### NodeGoat recall, re-measured

| # | Documented vulnerability | Aegis (F2) | **Aegis (G1)** | CodeQL |
|---|---|:--:|:--:|:--:|
| GT1 | SSJI `eval(req.body.*)` | ✅ | ✅ | ✅ |
| GT2 | `$where` NoSQL injection | ❌ | ✅ **fixed (A1)** | ✅ |
| GT3 | Unvalidated redirect | ✅ | ✅ | ✅ |
| GT4 | SSRF | ✅ | ✅ | ✅ |
| GT5 | Missing CSRF | ✅ | ✅ | ✅ |
| GT6 | Weak crypto `createCipheriv` | ❌ | ❌ | ❌ *(CodeQL misses it too)* |
| GT7 | Nested-quantifier ReDoS | ❌ | ✅ **fixed (A2)** | ✅ |
| | **Recall** | **4/7 (57 %)** | **6/7 (86 %)** | **6/7 (86 %)** |

**Target met: Aegis now matches CodeQL on NodeGoat.** The one remaining miss (GT6) is missed by
both tools and is cross-file — the weak algorithm is configured in `config/env/all.js`.

### A3. CodeQL's NodeGoat findings — closeable vs. needs-a-better-engine

All 17 CodeQL findings, mapped against Aegis *after* A1/A2. **10 covered, 7 not.**

| CodeQL finding | location | real? | single-file? | status / verdict |
|---|---|---|---|---|
| `js/code-injection` | allocations-dao:78 | TP | construct-local | ✅ **CLOSED (A1)** |
| `js/redos` | profile:59 | TP | yes | ✅ **CLOSED (A2)** |
| `js/polynomial-redos` | profile:61 | TP (same regex as :59) | yes | ✅ **CLOSED (A2)** |
| `js/code-injection` ×3 | contributions:32-34 | TP | yes | ✅ already covered |
| `js/server-side-unvalidated-url-redirection` | index:72 | TP | yes | ✅ already covered |
| `js/request-forgery` | research:16 | TP | yes | ✅ already covered |
| `js/missing-token-validation` | server:78 | TP | yes | ✅ already covered |
| `js/clear-text-cookie` | server:78 | TP | yes | ✅ already covered |
| **`js/log-injection`** | session:64 | **TP — documented NodeGoat "A1-3 Log Injection"** | **yes** (`req.body` destructured in the same function) | **CLOSEABLE — highest-value remaining.** Caveat: a naive rule fires on every `console.log(userInput)`; needs a precision design to hold the 0-FP standard, so deliberately not shipped in this pass |
| `js/sql-injection` ×2 | user-dao:91,104 | TP (weak) — NoSQL *operator* injection | **no — cross-file** (`userName` is a parameter; `req.body` is in session.js) | **needs cross-file taint.** A pattern rule on `findOne({f: var})` would flag ordinary Mongo usage — unacceptable FP cost |
| `js/session-fixation` | index:34 | TP (advisory) | **no — cross-file** (handler lives in session.js) | **needs cross-file taint** |
| `js/missing-rate-limiting` | index:34 | advisory, not a vuln | yes (route table) | closeable in principle; absence-of-middleware rules are FP-prone and low value |
| `js/polynomial-redos` | session:181 | TP (weak) — polynomial, not exponential | yes | closeable only by extending A2 to polynomial shapes, which is materially harder and FP-prone |
| `js/indirect-command-line-injection` | Gruntfile:166 | TP but low value — build script, not shipped code | yes | closeable, low priority |

**The roadmap this produces:** one clearly worthwhile rule remains (**log-injection**, with a
precision design); three are cheap-but-low-value (rate-limiting, Gruntfile, polynomial ReDoS);
and **three genuinely need a cross-file engine** (both `user-dao` NoSQL operator injections and
session-fixation). Note that **cross-file is the boundary — not cross-function**: Part B shows
cross-function is now buyable, cross-file is not.

---

## PART B — Opengrep

**B1.** Opengrep **1.29.0** installed alongside semgrep **1.97.0**. Nothing replaced; both binaries
present and independently invocable.

**B2/B5. A/B on the same checkouts with our own `rules/taint`, unmodified.**

| repo | semgrep | opengrep | opengrep `--taint-intrafile` | sg time | og time | **TI time** | TI slowdown |
|---|--:|--:|--:|--:|--:|--:|--:|
| NodeGoat | 5 | 5 | 5 | 5 s | 5 s | 5 s | 1.0× |
| DVWA | **31** | **27** ⚠ | **30** ⚠ | 5 s | 5 s | 6 s | 1.2× |
| dvpwa | 0 | 0 | 0 | 13 s | 11 s | 29 s | 2.2× |
| spring-petclinic | 0 | 0 | 0 | 4 s | 5 s | 4 s | 1.0× |
| django-nV | 2 | 2 | 2 | 10 s | 12 s | 25 s | 2.5× |
| **WebGoat** | 6 | 6 | **18** ⭐ | 13 s | 17 s | 53 s | **4.1×** |
| juice-shop | 62 | 62 | 63 | 10 s | 16 s | 19 s | 1.9× |

**B3. Ground truth — the decider.**

**WebGoat: `--taint-intrafile` recovers precisely the misses T3 declared out of scope.**

New findings include `SqlInjectionLesson5b.java:49` and `SSRFTask2.java:36` — **the exact two
handler→helper flows T3 documented as unreachable** — plus the whole intro-SQLi family
(Lessons 2, 3, 4, 5a, 6a, 8 ×2, 9, 10) and `ProfileZipSlip.java:79`. **12 new, 0 lost.**

This is the structural gap closing: WebGoat's lessons are written as
`completed(@RequestParam …) → injectableQuery(helper)` **within one file**, which is exactly what
cross-function-intra-file taint buys.

**DVWA: Opengrep is a recall *regression*.** Both Opengrep modes miss **4 `aegis-php-sql-injection`
findings semgrep catches** — the SQLite branch of DVWA's documented SQLi
(`sqli/source/low.php:34`, `medium.php:36`, `sqli_blind/source/high.php:35`, +1):

```php
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$results = $sqlite_db_connection->query( $query );   // semgrep: flagged.  opengrep: silent.
```

These are genuine true positives and DVWA's headline vulnerability class. **NodeGoat**: unchanged
across all three engines — its remaining misses are cross-*file*, which `--taint-intrafile` by
definition cannot reach (this independently confirms the A1 root cause).

**B4. Hand-triage of every new finding.**

| source | new | triage |
|---|--:|---|
| WebGoat (intrafile) | 12 | Sampled 4 in depth — `5b:49` (`"… userid= " + accountName` → `prepareStatement`), `Lesson2:49` (`executeQuery(query)`), `SSRFTask2:36` (`new URL(url).openStream()`), `ProfileZipSlip:79` (`new File(dir, e.getName())` → `Files.copy` = Zip Slip). **4/4 TP.** All 12 sit in deliberately-vulnerable, documented lesson files. **No FPs found.** |
| juice-shop (intrafile) | 1 | `aegis-js-nosql-injection` at `routes/basketItems.ts:86`. 0 lost. |
| DVWA (intrafile) | 3 | `aegis-php-xss` ×3 in `dvwaPage.inc.php`. The dataflow trace is real cross-function taint: `dvwaSecurityLevelGet()` → `dvwaButtonSourceHtmlGet()` → `$systemInfoHtml` → `echo`. **But `dvwaButtonSourceHtmlGet` is one of the wrappers our own pipeline auto-detects as a project sanitizer** (`_augmented_taint_dir`), so production config would likely suppress these — my A/B used the static rules *without* that augmentation. Verdict: plausible TPs, **not** counted as a win, and a reminder that engine A/Bs must be run against the production config. |

**No new FP class was observed from cross-function taint.** That was the main risk and it did not
materialise on this corpus.

**B5. Performance.** The slowdown is real but bounded: 1.0–4.1×, worst case **53 s on WebGoat**,
far inside the 600 s budget T2 established. **However** — the two repos that *already* time out
(dolibarr, n8n; F2 §A/T2) were not re-tested here and a 2–4× multiplier would make them worse, not
better. T2's timeout fix is not endangered for repos that currently pass.

### B6. Recommendation: **do not switch wholesale. Pilot `--taint-intrafile` for Java only.**

Justified by the numbers, in order of weight:

1. **The blocker:** Opengrep **loses 4 documented SQLi true positives on DVWA**, in *both* modes.
   A wholesale switch would silently reduce PHP recall — the exact failure class F1/F2 exist to
   prevent. That alone rules out "switch".
2. **The prize is real but language-specific:** WebGoat **6 → 18 with 0 losses**, recovering the
   two misses T3 explicitly scoped out. On JS/Python/PHP the gain is +1, +0, and *negative*.
   The benefit tracks the handler→helper idiom, which is a **Java/Spring** convention.
3. **Dual-run is not warranted:** running both engines everywhere roughly doubles SAST cost to buy
   +1 finding outside Java. Not a defensible trade.
4. **Staying entirely is also wrong**, because it means knowingly leaving 12 true positives on the
   table for Java — including two we have already documented as misses.

**Concrete next step:** root-cause the DVWA SQLite regression (minimal reproduction, then report
upstream to Opengrep), and run Opengrep `--taint-intrafile` for Java targets **against the
production config** (including `_augmented_taint_dir`) with a 0-FP gate on WebGoat + eladmin +
booklore before enabling it. Do not touch PHP/JS/Python until the regression is understood.

---

## GATE

| requirement | status |
|---|---|
| A: both misses closed or scoped out | ✅ both **closed** with new rules |
| A: NodeGoat recall re-measured | ✅ **4/7 → 6/7**, matching CodeQL |
| A: closeable-vs-engine table for CodeQL's findings | ✅ all 17 classified |
| B: A/B numbers, per-config ground truth, FP triage, timing | ✅ 7 repos × 3 configs |
| B: justified recommendation | ✅ pilot-for-Java-only, with the DVWA blocker stated |
| C: licensing table | ✅ `docs/RULE_LICENSING.md` |
| offline where possible | ✅ all scans local; network used only to fetch Opengrep and to read pack licences |

**Not done / explicitly out of scope:** the log-injection rule (designed, not shipped — needs a
precision design first); polynomial-ReDoS detection; re-testing dolibarr/n8n under intrafile;
evaluating any Opengrep-native rule set.
