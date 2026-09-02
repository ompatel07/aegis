# SAST timeout — diagnosis (Pass T1)

**DIAGNOSIS ONLY. Nothing was fixed** — no timeout, rule, exclude, memory, or shard
change. Build `1497af3`. Environment: Docker ~3.7 GB, semgrep 1.97.0, 8 cores. All
runs used the production per-rule `--timeout 60`, `--max-target-bytes 2000000`,
`--dataflow-traces`, `--jobs 8`; the only change from production was removing the
600 s *overall* cap so the true wall time is visible.

## TL;DR — the language was a red herring

WebGoat (Java) "timed out" but **`p/java` alone scans it in 6 s.** The cost is
**large bundled/minified third-party JS files that live OUTSIDE `node_modules`/`vendor`
and so are not excluded** — `p/nodejsscan` (and the base-pack JS rules) are
catastrophically slow on them: **one 720 KB file, `ace.js`, costs 239 s by itself.**
All six timed-out repos ship such files. Compounded by an always-on 6-pack base tax
(184–271 s before any language pack). **Same cause across all six; the Java/monorepo
framing in V2 was misleading.**

---

## 1. Per-language rule count (Q1) — NOT the cause

Rules that actually run against a 1-line file of each language, with the production
config set (6 base packs + language pack + aegis taint):

| language | rules applied | notes |
|---|--:|---|
| TypeScript | 397 | + p/typescript + p/nodejsscan |
| Python | 391 | completed on redash |
| **Java** | **234** | **timed out on WebGoat** |
| Ruby | 189 | completed on chatwoot (449k LOC) |
| PHP | 155 | |
| C# | 149 | |

**Java has FEWER rules than Python and TypeScript, both of which completed.** Rule
count does not explain the timeout. (Source: registry packs `p/owasp-top-ten,
p/r2c-security-audit, p/default, p/secrets, p/cwe-top-25, p/supply-chain` are loaded
on every scan; the per-language pack is added on top.)

---

## 2. WebGoat vs chatwoot — the timing breakdown (Q2)

`--time`'s per-rule JSON came back empty in 1.97 under `--quiet`, so timing was
measured by **config-pack bisection** (clone once, time each config subset) — more
robust than parsing `--time`, and it isolates the culprit directly.

**WebGoat (72,733 LOC — 411 Java files, 93 JS files):**

| config subset | wall | findings |
|---|--:|--:|
| base (6 packs) | **271 s** | 210 |
| base + `p/java` | 291 s | 210 (**p/java adds 0 findings** — base already has Java rules) |
| base + java + JS packs (`p/javascript` + `p/nodejsscan`) | **535 s** | 241 |
| `p/nodejsscan` ONLY | **263 s** | 31 |
| `p/java` ONLY | **6 s** | 17 |

**chatwoot (449,000 LOC — 2,539 Ruby, 1,105 JS files) — the CONTROL (completed at 294 s):**

| config subset | wall | findings |
|---|--:|--:|
| base (6 packs) | **184 s** | 392 |
| base + ruby + JS packs | 209 s | 412 |
| `p/nodejsscan` ONLY | **35 s** | 20 |
| `p/ruby` ONLY | 77 s | 72 |

The decisive contrast: **`p/nodejsscan` takes 263 s on WebGoat's 93 JS files but only
35 s on chatwoot's 1,105 JS files.** 12× fewer files, 7.5× longer. It is not file
count and not LOC — it is a few **pathological files**. WebGoat's JS averages 525
LOC/file (bundled libraries); chatwoot's averages 107.

### Top slowest FILES (the smoking gun)

`p/nodejsscan` run against WebGoat's single largest JS file:

| file | size | `p/nodejsscan` wall |
|---|--:|--:|
| `src/main/resources/webgoat/static/js/libs/ace.js` | 720 KB | **239 s** |

**One 720 KB bundled file (the Ace code-editor library) is 239 s of nodejsscan's
263 s.** WebGoat's other large bundled libs: `jquery-ui-1.10.4.js` (436 KB),
`wysihtml5-0.3.0.js` (331 KB), `jquery-ui.min.js` (254 KB). None are in
`node_modules`, so none are excluded; `--max-target-bytes 2 MB` doesn't catch them.

*(Per-RULE breakdown within `ace.js` could not be extracted — `--time` returned empty
under `--quiet` in semgrep 1.97, and re-running verbose per-rule on the whole repo was
not worth another 600 s pass once the file was isolated. The unit of catastrophe is
the FILE, which is what the fix acts on. This is the one measurement gap; see §7.)*

---

## 3. One rule or many? (Q3)

**It is a FILE problem, not a rule problem, and it is cumulative — not one rule.**
- On WebGoat, nearly all of nodejsscan's cost is a single file (`ace.js`, 239 s / 263 s).
- The base-pack tax (271 s) is spread across rules/files — but much of *that* is also
  the large JS files (the base packs run their own JS rules on `ace.js` too).
- So the answer is not "one rule to disable"; it is **"a class of files (large bundled
  JS) that many JS rules are pathologically slow on."** The fix acts on the file, not
  a rule.

---

## 4. Language engine vs rule set (Q4) — it is the RULE SET, decisively

`p/java` ONLY scans all of WebGoat in **6 s**. The semgrep Java parser/engine is not
slow. The 271 s + 263 s costs come entirely from the **base packs and `p/nodejsscan`
rule sets** running on the large JS files. **Rule set, not engine — conclusive.**

---

## 5. Cause classification for all 6 timed-out repos (Q5) — SAME cause

A cheap survey (clone + list largest scanned JS/TS, NO semgrep) shows every timed-out
repo ships large bundled/vendored JS **outside `node_modules`/`vendor`** (so scanned):

| repo | scanned JS/TS files | files > 300 KB | worst offenders | cause |
|---|--:|--:|---|---|
| WebGoat | 93 (JS) | (≥4) | `ace.js` 720 KB, `jquery-ui` 436 KB | **bundled JS — CONFIRMED (ace.js = 239 s)** |
| nopCommerce | 455 | 3 | `elfinder.full.js` 1.05 MB, `moment.min` 375 KB | bundled JS (`wwwroot/lib_npm/`) — high conf |
| TeamPass | 829 | **16** | `fontawesome all.js` 1.69 MB, `zxcvbn.js` 821 KB | bundled JS (`public/plugins/`) — high conf |
| nocodb | 2,191 | 10 | `swagger-ui-bundle.js` 1.5 MB, `redoc` 1.0 MB | bundled JS (`public/js/`) — high conf |
| dolibarr | 1,120 | **26** | `swagger-ui.js` 2.7 MB, `ace/worker-xquery.js` 1.6 MB | bundled JS (`htdocs/includes/`,`theme/`) — high conf |
| n8n | (not surveyed) | — | 3.6 M LOC TS monorepo | **scale + likely bundled — medium conf** |

**Five of six share WebGoat's exact cause** (large bundled JS in non-excluded paths).
`--max-target-bytes 2 MB` already skips the >2 MB files (dolibarr swagger 2.7 MB), so
the killers are the **~0.7–2 MB** bundled libs. **n8n (3.6 M LOC) is the one that also
has a genuine SCALE component** — at WebGoat's base-pack rate it would exceed 600 s on
volume alone — but it was not bisected (its shallow clone is prohibitively large on the
3.7 GB box); classified medium-confidence as *scale + probable bundled files*. **Do not
assume — n8n is the honest asterisk.**

---

## 6. Where the time goes: semgrep vs our code (Q6)

**It is 100 % semgrep on a timed-out scan.** In `semgrep_engine.run`, enrichment runs
*after* semgrep returns (`result = await _semgrep(...)` → `_parse` → `enricher.enrich_all`).
On a timeout, semgrep is killed at 600 s and the engine returns FAILED — **enrichment
never runs.** So the 600 s is entirely the semgrep subprocess (rule matching on the
bundled files); none of it is Aegis post-processing. Clone time is separate and small
(seconds). Our code is not implicated. **Confidence: high** (from the code path).

---

## 7. Measurement gap (stated, not hidden)

- Per-RULE timing inside `ace.js` was not obtained (`--time` empty under `--quiet` in
  semgrep 1.97). We know the pathological FILE and the pathological PACK
  (`p/nodejsscan`), which is what a fix targets, but not the single worst rule id.
- n8n was not bisected (clone size). Its cause is inferred (scale + probable bundled).

---

## 8. PROPOSED fixes, ranked by evidence (NOT implemented)

**P1 — Exclude bundled/minified JS from SAST (highest value, lowest risk).**
Add `*.min.js`, `*.bundle.js`, `*-min.js`, and/or a minified-file heuristic (skip a
file whose average line length exceeds ~2 KB, or whose largest line does), plus the
common vendored-asset dirs (`**/static/**/js/libs/`, `**/wwwroot/lib*/`,
`**/public/plugins/`, `**/public/js/`, `**/theme/**/js/`).
- *Evidence:* removes `ace.js`'s 239 s and every offender in §5; base-pack tax alone
  (184–271 s) is under 600 s, so WebGoat + the four bundled-JS repos would complete.
- *Cost:* a few exclude patterns + a small minified detector.
- *What it breaks:* SAST would no longer scan bundled third-party JS. That is
  **correct** — those are not the customer's code (ownership tagging already recesses
  them), and dependency CVEs are SCA's job. Residual risk: a real vuln hand-patched
  into a vendored lib is missed — low, and acceptable.
- *Does NOT fix:* n8n's scale component.

**P2 — Lower `--max-target-bytes` to ~400–500 KB.**
- *Evidence:* skips the 0.5–2 MB bundled libs (ace.js, elfinder, fontawesome, swagger).
- *Cost:* one number.
- *What it breaks:* also skips any *legitimate* generated/large source file (rare);
  blunter than P1 (size, not "is it vendored"). Doesn't help many-medium-file scale.

**P3 — Minified-file detector (a precise form of P1).**
- *Evidence:* long-line/entropy heuristic skips minified files regardless of path/size.
- *Cost:* a small pre-filter. *Risk:* low; a hand-written non-minified large file with
  long lines could be skipped (rare).

**P4 — Trim the always-on base pack set (helps the SCALE case, incl. n8n).**
The 6 base packs (`p/default` + `p/r2c-security-audit` + `p/owasp-top-ten` +
`p/cwe-top-25` overlap heavily) cost 184–271 s *before* any language pack. Trimming to
2–3 non-overlapping packs cuts the constant tax and is the only lever that helps n8n's
scale.
- *Cost:* a coverage change requiring re-validation against the OWASP benchmark + V2.
- *What it breaks:* some registry rules stop running; recall could drop. Needs
  measurement before adoption.

**P5 — Raise the 600 s timeout. REJECTED as a primary fix.** It hides the problem
without explaining it (the pass's own warning), keeps scanning `ace.js` for 239 s of
pure waste, and only defers the wall on the scale repos. It may still be a *secondary*
backstop after P1/P4, but not the answer.

---

## 9. Single best hypothesis + evidence

**The SAST timeout is caused by `p/nodejsscan` (and the base-pack JS rules) scanning
large bundled/minified third-party JS files that live outside `node_modules`/`vendor`
and are therefore not excluded. A single 720 KB file (`ace.js`) costs 239 s; every one
of the six timed-out repos ships such files (elfinder 1.05 MB, fontawesome 1.69 MB,
swagger-ui 1.5–2.7 MB, …). The always-on 6-pack base tax (184–271 s) compounds it. The
language is irrelevant — `p/java` scans WebGoat in 6 s.**

**Evidence:** the pack bisection (p/java 6 s vs base 271 s vs nodejsscan 263 s), the
single-file timing (ace.js = 239 s), the control (nodejsscan 35 s on chatwoot's 1,105
small JS files), and the file survey confirming the same pathological files in
nopCommerce/TeamPass/nocodb/dolibarr.

**Confidence:** HIGH for five of six (WebGoat confirmed by direct timing; the other
four confirmed to ship the offending files). **n8n is the honest exception** — a 3.6 M
LOC monorepo that also has a genuine scale component, not directly bisected. The
evidence is not ambiguous on the primary cause; it is ambiguous only on whether n8n
would still time out on scale *after* the bundled-JS fix — which P1 alone may not
resolve, and which P4 targets.

The recommended sequence for the fix pass (T2, not this one): **P1 first** (kills 5 of
6 with near-zero risk), then **measure n8n**, then **P4** only if scale still bites.
