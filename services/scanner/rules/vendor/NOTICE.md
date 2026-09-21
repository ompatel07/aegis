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
| Rules | 114 |
| Modifications | none to rule logic, messages, severities or upstream metadata. Two additions: each id is namespaced `ajinabraham.njsscan.<dir>.<file>.<id>` (the form these rules have always had in Aegis findings), and `metadata.license` / `metadata.source` record the upstream licence and file |

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
