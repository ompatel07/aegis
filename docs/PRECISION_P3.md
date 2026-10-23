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
