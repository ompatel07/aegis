# Third-party rules shipped with Aegis

Aegis ships exactly **one** third-party rule pack. Everything else under
`services/scanner/rules/` is written and owned by Aegis.

## nodejsscan — `nodejsscan.yaml`

| | |
|---|---|
| Project | njsscan — <https://github.com/ajinabraham/njsscan> |
| Author | Ajin Abraham |
| Licence | **GNU LGPL-3.0-or-later** — `LICENSES/nodejsscan-LGPL-3.0.txt` (upstream `LICENSE`, verbatim). LGPL-3.0 is a set of additional permissions on top of the GNU GPL-3.0, whose text is included as `LICENSES/GPL-3.0.txt` |
| Built from upstream commit | `b6ade853818a0c2a4fde36a1c5740b663e758ad2` (2026-08-10), `njsscan/rules/semantic_grep/` |
| Rules | **89** of upstream's 114 (25 not shipped, 6 modified — see below) |
| Modifications | **This is a modified version of njsscan's rules** (modified by Aegis, 2026-10-22, Pass N2b, and 2026-10-23, Pass P3). Listed in full below. In addition, on every rule: the id is namespaced `ajinabraham.njsscan.<dir>.<file>.<id>` (the form these rules have always had in Aegis findings), and `metadata.license` / `metadata.source` record the upstream licence and file |

### Modified by Aegis, 2026-10-22 (Pass N2b)

This notice is given under GNU GPL-3.0 §5(a), which LGPL-3.0 incorporates: the
work carries a prominent notice that it was modified, and when. The modified
file is still licensed under the LGPL-3.0-or-later, is shipped as source (the
YAML is the source), and is built reproducibly from the unmodified upstream
commit above by `scripts/vendor_rules.py` (`PRUNED`, `PRUNED_DIRS`,
`CONSTRAINED`). Each modified rule also says what changed in its own
`metadata.aegis-modified`. The measurement behind every change is in
`docs/NJSSCAN_TRIAGE_N2B.md`.

**Not shipped (25 rules).** Each was hand-triaged on real code (475 findings
across 20 repositories). The rule's false positives come from the matching
logic itself, so no narrow constraint fixes them:

| Rule(s) | Measured (TP / findings) | Why not shipped |
|---|---|---|
| `dos.regex_dos.regex_dos` | 0 / 257 | any 2-parameter function is a "handler"; the regex is never inspected — none of the 1,469 regexes in the flagged files backtracks catastrophically |
| `crypto.crypto_node.node_insecure_random_generator` | 3 / 73 | flags every `Math.random()`; whether it is security-relevant is the whole question and the rule cannot see it |
| `crypto.timing_attack_node.node_timing_attack` | 1 / 13 | flags comparisons of variables *named* password/secret/token |
| `generic.hardcoded_secrets.node_username`, `node_api_key`, `node_secret`, `node_password` | 1 / 50 | flags a string assigned to a variable *named* user/api_key/secret/password; the value is never examined |
| `generic.error_disclosure.generic_error_disclosure` | 0 / 18 | flags `console.error`/`console.trace` — logging, not disclosure to a client |
| `good.*` (14 rules: helmet headers, anti-CSRF, rate limiting) | 0 / 4 | report that a security control **is present**; not detections |
| `headers.header_cookie.cookie_session_no_domain`, `no_path`, `no_maxage` | — | the attribute's absence is the safe default; excluded at run time since before N1, now not shipped so coverage counts match what runs |

**Constrained (5 rules).** Each change was checked on the same corpus: every false
positive of that mechanism removed, every true positive kept.

| Rule | Change | Measured |
|---|---|---|
| `eval.eval_node.eval_nodejs` | adds `metavariable-regex: $REQ =~ (?i)^(req\|request)$` — before, any 2-parameter function was a request handler | 3 TP / 6 FP → 3 TP / 0 FP |
| `eval.eval_require.eval_require` | same | 0 TP / 2 FP → 0 / 0 |
| `dos.regex_injection.regex_injection_dos` | same | 0 TP / 7 FP → 0 / 0 |
| `traversal.express_hbs_lfr.express_lfr_warning` | same (it matched `process.env` as request data) | 0 TP / 2 FP → 0 / 0 |
| `database.nosql_find_injection.node_nosqli_injection` | sink becomes `$OBJ.findOne($QUERY, ...)` **not** `findOne({..., where: $W, ...})` — the Sequelize/TypeORM shape. Upstream's `pattern-not-sinks` Sequelize exclusion is not a key semgrep implements, so it never applied | 2 TP / 15 FP → 2 TP / 1 FP |

### Modified by Aegis, 2026-10-23 (Pass P3)

Under the same notice, one more rule is constrained. The measurement is the
real-repository tuning half in `docs/PRECISION_P3.md` §B.

| Rule | Change | Measured |
|---|---|---|
| `headers.header_injection.generic_header_injection` | the N2b constraint above: `$REQ =~ (?i)^(req\|request)$` — before, any 2-parameter function was a request handler, so a compiler pass's `state.set(id, ...)` was a response header | tuning half 0 TP / 8 FP → 0 / 0 |

Logic, messages, severities and upstream metadata of the other 83 rules are
unchanged.

**Provenance.** Before N1 this file was a copy fetched through the Semgrep
registry (`p/nodejsscan`), which carried registry-added annotations
(`semgrep.dev` block, `sg.run` shortlinks, `semgrep.dev/r` source URLs). Pass N1
compared all 114 rules key by key against upstream -- patterns,
`pattern-not-sinks`, sources, sinks, sanitizers, messages, severities, languages
and upstream's own metadata -- and found **no difference at all**, then **rebuilt
the file directly from upstream git** (`scripts/vendor_rules.py`) so nothing
obtained from the registry remains. The rule ids are unchanged, so finding
fingerprints and lifecycle history carry over.

The file is shipped as source with the licence texts above; the rule text is
itself the corresponding source.

## What is NOT shipped (Pass N1, 2026-09-19)

The 16 packs carrying the **Semgrep Rules License v1.0** (2,677 rule entries,
1,142 unique rule ids) were removed, along with any path that could fetch them
again from the Semgrep registry. Semgrep's legal team declined a vendor/OEM
licence and declined relicensing, so there is no route to shipping them
commercially. See `docs/RULE_REMOVAL_N1.md`.

The Semgrep CE **engine** (LGPL-2.1) is unaffected and is still used.

`services/scanner/tools/check_rule_licences.py` fails the build if any rule
with a licence outside the permitted set enters `services/scanner/rules/`.
