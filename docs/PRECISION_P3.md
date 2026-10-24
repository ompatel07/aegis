# P3 — Real-code precision: fixed on the tuning half, measured on the held-out half (2026-10-23)

Prerequisite: D2 (`docs/D2_DETERMINISM.md`). Repeat scans of a commit now differ only in
files the scan discloses, and every precision figure here is on findings **stable across
three scans**, counted once per location (rule, file, line).

## A. Both gates on the Wilson 95% lower bound — before any rule edit

A point estimate cannot tell 4/5 from 400/500. From P3 a gate passes only if the
**lower bound of the Wilson 95% interval** clears its floor; there is no minimum-sample
rule (`MIN_CORPORA` is not one: it asks for detections in two independent codebases).

- **precision gate:** lower bound of TP / (TP + FP) on held-out real repositories ≥ 70 %.
- **recall gate, calibrated:** lower bound of Aegis's held-out recall ≥ CodeQL's recall on
  the same items. **Uncalibrated** (no CodeQL reference — PHP): lower bound ≥ 25 %.

`services/scanner/utils/tier_bar.py`; tests in `tests/test_tier_bar.py`, among them
Go's 4/5 failing (lower bound 38 %), a value exactly on its line failing at n = 1,000,
7/7 failing (65 %), 11/11 and 400/420 passing. Re-tier on the shipped evidence, rules
unchanged (`docs/ground_truth_p3/retier.py`):

| language | held-out recall (95 % CI) | CodeQL, same items | real held-out precision (95 % CI) | N6 | **P3 Part A** |
|---|---|---|---|---|---|
| PHP | 68/160 = 42 % [35 %, 50 %] | not run (no PHP) | 18/67 = 27 % [18 %, 39 %] | clean-only | **clean-only** |
| Python | 8/38 = 21 % [11 %, 36 %] | 5/38 = 13 % | 1/19 = 5 % [1 %, 25 %] | clean-only | **withheld** |
| Go | 4/21 = 19 % [8 %, 40 %] | 4/21 = 19 % | 4/5 = 80 % [38 %, 96 %] | problem-only | **withheld** |
| Java | 0/8 = 0 % [0 %, 32 %] | 3/8 = 38 % | none | withheld | withheld |
| JavaScript | 10/23 = 43 % [26 %, 63 %] | 18/23 = 78 % | 0/15 = 0 % [0 %, 20 %] | withheld | withheld |
| TypeScript | 2/17 = 12 % [3 %, 34 %] | 3/17 = 18 % | 0/10 = 0 % [0 %, 28 %] | withheld | withheld |

Two languages lose their claim on the interval alone. **Python's clean claim** rested on
8/38 against CodeQL's 5/38; the lower bound, 11 %, is below 13 %. **Go's problem claim**
rested on five findings. PHP keeps its clean claim (lower bound 35 % ≥ 25 %).

## B. Every false positive on the tuning half, and its root cause

The 31-repository real corpus was split before any fix (N6, `accuracy/holdout_n6.json`):
15 tuning repositories, 16 held out. Fixes were written **only** from the tuning half,
from the weakness each finding was a false instance of; the held-out half was used only
to measure. Stable findings from the D2 scans, by location: 133 tuning-half findings
of shipped coverage rules in application languages, **7 TP, 126 FP**. Every FP is in
this table.

| rule | FP | where | root cause | fix |
|---|--:|---|---|---|
| `aegis-py-sql-string-construction` | 71 | cmp-django | SQL **identifiers** and fragments formatted into statements (table / column names, often through `quote_name()`; values still bound as `%%s`). Many are assignments the rule fired on whether or not they were ever executed | **fixed in part**: reports only where a formatted string reaches `execute*()` / `text()` in the function. Inline identifier formatting that does reach `execute()` stays a FP: a context-free rule cannot tell an identifier from data |
| | 10 | cmp-kafka | a release helper **named** `execute()` running shell commands (`execute(f"git tag -d {tag}")`) | **fixed**: a string reaching `execute()` must show SQL structure (taint label `SQL`); `text()` takes SQL by definition (label `FORMATTED`) |
| | 3 | cmp-ansible | `cursor.execute('DROP TABLE … %s' % name)` with an internal table name | not fixed (identifier, as above) |
| `aegis-php-path-traversal` | 7 | FreshRSS | the key is validated (`ctype_xdigit`) before use, or the path is built from a hash / MIME map — a control-flow guard taint mode cannot see | not fixed |
| `aegis-py-shell-command-construction` | 4 | cmp-ansible | developer tooling (`hacking/`) building commands from its own arguments; no attacker input | not fixed (same limit as SQL identifiers) |
| `generic_header_injection` (njsscan) | 8 | cmp-react 7, cmp-nextauth 1 | `$REQ`/`$RES` bound the parameters of **any** two-parameter function, so a compiler pass's `state.set(id, …)` was a response header | **fixed**: N2b's `$REQ =~ ^(req\|request)$` constraint (`scripts/vendor_rules.py`) |
| `aegis-js-redos-nested-quantifier` | 5 | chatwoot 2, nocodb 2, cmp-react 1 | every regex had a **mandatory separator** inside the repeated group — `(-[a-z]+)*`, `(?:[._][a-z0-9]+)*`, `(?:\\s*)+` — so each repetition is anchored and matching is linear | **fixed**: only a group that *is* one quantified atom, re-quantified (`(X+)+`, `(X*)*`), is reported |
| `aegis-js-nosql-injection` | 3 | nocodb | `Array.prototype.find((j) => j.id === req.params.id)` — a predicate **function**, which no query engine parses | **fixed**: a function argument is not a query document |
| `aegis-js-xss` | 2 | cmp-react | `res.write(JSON.stringify(map))` after `res.set('Content-type', 'application/json')` — the response is not HTML | **fixed**: a sink after an explicit JSON `Content-Type` (set / setHeader / header / type / writeHead) is excluded. `JSON.stringify` is *not* a sanitizer: Express sends a string as `text/html` |
| `express_xss` (njsscan) | 3 | cmp-react 2, cmp-nextauth 1 | a JSON response; a framework adapter writing a body it was handed | not fixed: the rule's source is any property of `req`, with no single mechanism to constrain, and it holds a stress-set TP |
| `node_md5`, `node_sha1` (njsscan) | 4 | cmp-react 3, nocodb 1 | purpose-blind: cache keys and content hashes | not fixed: `node_md5` is the only rule that catches a **held-out** documented item (oopssec-store's MD5 password hash); a purpose-aware rule would replace it, not a constraint |
| `dom_xss` (njsscan) | 2 | FreshRSS | `insertAdjacentHTML` of the page's own template | not fixed |
| `express_open_redirect` (njsscan) | 2 | nocodb | the redirect URL starts with the site's own origin (`${req.ncSiteUrl}/…`) | not fixed: the rule cannot know the prefix is trusted (it also holds a TP here) |
| `handlebars_noescape` (njsscan) | 1 | nocodb | a webhook payload rendered with `noEscape`; not HTML | not fixed |
| `aegis-go-ssrf` | 1 | cmp-terraform | a test mock in a non-test file name | not fixed |

**PHP XSS has no tuning-half finding to root-cause.** Every PHP XSS (and SQL
injection) finding on the real corpus is in a held-out repository — Dolibarr, librenms,
TeamPass. So the split the brief asks for is written from the weakness, not from FPs:
`aegis-php-xss` is now **reflected** XSS (request sources; unchanged matching, its
message no longer claims stored XSS it never modelled), and `aegis-php-stored-xss` is a
new rule with PHP's DB read APIs as sources, WARNING / LOW confidence, **silent-clean**:
labelled findings, no claim, until its own held-out precision clears the gate.

**Ground truth after the edits** (`gt_diff.py`, old vs new rule files with the product's
arguments on every PHP / Python / JS / TS corpus): **no documented item lost**, held-out
or tuning. The edits removed exactly two stress-set findings, both recorded FPs of the
fixed mechanisms (dvws-node's JSON body, oopssec-store's `(?:\/[\w.-]+)*`); dvpwa's SQLi
moved from the assignment to the `execute` line. A first version that required SQL
structure for `text()` too lost dvgraphql's documented `text("title = '%s'" % f)`
injection; taint labels fixed that before anything was measured on the held-out half.

## C.0 Fixed before the stored-XSS sample was drawn

`aegis-php-stored-xss`'s own precision comes from n = 60 stable held-out findings drawn
by `docs/ground_truth_p3/sample_stored_xss.py` (seed: the rule's commit `79b3fa0`),
committed at `8af478b` before the draw. A sampled finding is **TP** if a value some user
can write reaches the HTML output unescaped (by Aegis's reading of the code at the
commit), **FP** if the printed value is an id / number / enum / internally generated
value or is escaped on the way out, **UNCERTAIN** if who can write it cannot be settled
from the code. Decision, on the Wilson 95% interval of TP / (TP + FP):
- lower bound ≥ 70 %: it may be promoted to a coverage rule (it is not, in this pass,
  without a separate review);
- otherwise, upper bound ≥ 50 %: it ships **silent-clean**;
- upper bound < 50 % (most of its findings are false, with 95 % confidence): it does
  **not ship** -- it moves to `rules_staging/`.

## C. Results — held-out before and after, with intervals

Before: the D2 scans (three product scans per repository, N6's rules). After: three
product scans per repository with P3's rules (`/workspaces/_p3after`; n8n left out — it
fails every scan, D2), with `aegis-py-sql-string-construction`'s findings re-measured in
three further runs after its f-string fix (`py_rule_runs.py`; every other rule
unchanged). Stable findings, by location; `p3_ledger.py`. **The gate is the held-out
row.**

| language | held-out before | held-out after | tuning before | tuning after |
|---|---|---|---|---|
| PHP | 17/64 = 27 % [17 %, 38 %] (+3 unstable) | **17/64 = 27 % [17 %, 38 %]** (+3 unstable) | 1/8 | 1/8 |
| Python | 1/19 = 5 % [1 %, 25 %] | **1/5 = 20 % [4 %, 62 %]** | 1/89 | 1/42 |
| JavaScript | 0/14 = 0 % [0 %, 22 %] (+22 uncertain) | **0/11 = 0 % [0 %, 26 %]** (+15 uncertain) | 4/15 | 4/11 |
| TypeScript | 0/8 = 0 % [0 %, 32 %] (+2 unstable) | **0/6 = 0 % [0 %, 39 %]** | 1/20 | 1/6 |
| Go | 4/5 = 80 % [38 %, 96 %] | **4/5 = 80 % [38 %, 96 %]** | 0/1 | 0/1 |
| Java | no finding | no finding | — | — |

**What moved, and what did not.**
- **The fixes removed false positives on the held-out half too**, so they were not
  only fitted to the tuning half: Python 14 fewer (redash and librenms SQL text that is
  never executed, or a `LOAD` that is not SQL), JavaScript 3 fewer and 7 fewer
  uncertain (the separator-anchored ReDoS shape), TypeScript 4 fewer (3 ReDoS, 1 header
  injection; the net is 2 because prisma's two `node_sha1` findings, unstable in the
  before scans, were stable in the after scans — no rule change involved). No held-out
  true positive was lost.
- **But held-out precision did not move to anything a gate can use.** Every language is
  as far below 70 % as before: there is **no held-out true positive at all** in
  JavaScript or TypeScript, Python's single TP over 5 findings has a lower bound of 4 %,
  and PHP is unchanged — its FPs are `aegis-php-xss` and `aegis-php-sql-injection` on
  Dolibarr / librenms / TeamPass, and the tuning half held no finding of either rule to
  learn from. The rates went up because findings went away, not because Aegis found more
  real problems.
- **No quadrant changed** from Part A.

**Recall, re-measured** (`gt_diff.py` over every PHP / Python / JS / TS ground-truth
corpus, old vs new rule files): **no documented item lost**, held-out or tuning.
Held-out recall is unchanged: PHP 68/160, Python 8/38, JavaScript 10/23, TypeScript 2/17,
Go 4/21, Java 0/8. DSVW's recall did not drop: its injections are formatted SQL handed
straight to `cursor.execute()`. Stress precision (teaching corpora, reported only):
JavaScript 73/152 → 73/150, Python 49/50 → 50/51, others unchanged.

**`aegis-php-stored-xss`, measured on its own** (sample fixed in §C.0): 60 of its 2,515
stable held-out findings (Dolibarr 2,514, TeamPass 1), read in source
(`stored_xss_verdicts.py`): **6 TP, 53 FP, 1 uncertain — 6/59 = 10.2 %, [4.7 %, 20.5 %]**.
The upper bound is under 50 %, so it **does not ship** (`rules_staging/php_stored_xss.yaml`).
What it mostly reports is an id, an amount, a date, a status label, or the output of a
helper that already escapes (Dolibarr's `getNomUrl`, `textwithtooltip`). Its 6 TPs are
real stored values printed raw — an accounting code, a project ref, a bank-statement
number, a product label, a country label, a recruitment candidate's name from the public
application form — and even those are an upper bound: Dolibarr's request WAF may refuse
the payload on the way in. Stored XSS is therefore **not covered**, and says so.

**Quadrants on the 20 V2 / F1 repositories** (`docs/ground_truth_n6/quadrant_count.py`,
P3 gates): V2 **5 clean-only, 10 withheld**; F1 **1 clean-only, 4 withheld** — the same as
N6. The PHP repositories keep the clean claim; no V2 / F1 repository is majority Python
or Go, so the two claims Part A withdrew change no repository there.

**Measurement notes.**
- *A rule defect found while confirming verdicts.* The first P3 Python rule tested an
  f-string's SQL structure with a file-wide regex, so `con.execute(f"LOAD {name}")` in a
  file that also held a real SELECT was "SQL" (redash). It was a defect in what the rule
  says, fixed with a fixture that fails on the old version (`68d77a7`), and only that
  rule was re-measured.
- *Unit.* A finding is one location (rule, file, line); N6 counted per-column duplicates
  on minified one-line files (D2 §3).
- *Defaults.* A moved finding takes N5's per-repository verdict for its rule only where
  the source shows the same statement; the four held-out Python FPs were re-read
  (`fix_column_name()`-sanitised identifiers, bound values, an operator's CLI argument).

## D. What changed in `docs/ACCURACY.md`

- A **headline** at the top of § SAST: held-out real-repository precision per language,
  stable findings, Wilson 95 % interval. No language clears the gate.
- **TUNING-SET labels** on every per-rule precision figure measured on the rules' own
  development repositories: N3's 53 / 0, H2's 32 / 32, N2b's 59.3 %, P2's 5 of 7 (H1's
  17 / 17 lives only in its commit message and is addressed in the correction).
- The per-language **status column** moved to P3.
- **CORRECTION 13**, in plain words: the per-rule figures described fit, not accuracy;
  H1's 17 / 17 rested mostly on redash findings later triaged false; Python's clean claim
  and Go's problem claim are withdrawn on the interval.

Evidence files: `p3_before_entries.json`, `p3_after_entries.json` (ledger rows),
`gt_diff.json`, `gt_diff_py2.json` (ground truth, old vs new rules),
`stored_xss_sample.json` + `stored_xss_verdicts.py`.
