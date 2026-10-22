# Staged rules — written, tested, NOT shipped

Rules here are Aegis-authored and pass their fixtures (`semgrep --test`, run by
`tests/test_staged_rules.py`), but have not earned a place in a scan:

- the engine never loads this directory;
- `utils/rule_coverage.py` counts `rules/**` only, so nothing here is coverage;
- `tools/check_rule_licences.py` still checks them, because they are in the image.

## The three-tier policy (Pass N4, 2026-10-22)

| tier | criterion | where | runs? | counts as coverage / tier / claim / Benchmark? |
|---|---|---|---|---|
| **PROVEN** | fired on real code, 0 FP after hand triage | `rules/taint/` | yes | **yes** |
| **SILENT-CLEAN** | matches on **API shape** (no identifier/naming heuristics), fixtures pass, ran on the full measured corpus with 0 FP, never fired | `rules/taint/`, `metadata.aegis-validation: silent-clean` | yes; findings labelled **"recall unvalidated"** in the UI and reports | **no** (`rule_coverage.counts_as_coverage`; Benchmark `score.py` leaves them out) |
| **STAGED** | any known FP, **or** matches on naming habits | here | no | no |

`tests/test_rule_validation_tiers.py` asserts that a silent-clean rule runs, labels
its findings, and is never counted as coverage or STRONG evidence.

## The N4 audit of N3's 18 staged rules

Each rule was read for what it actually matches on.

**Promoted to SILENT-CLEAN (7), API shape only:** `aegis-js-insecure-session-cookie-esm`
(the `express-session` import and its options object), `aegis-py-weak-cipher`,
`aegis-java-weak-cipher` (JDK standard algorithm names; NIST SP 800-131A),
`aegis-py-weak-key-size`, `aegis-java-weak-key-size`, `aegis-go-weak-key-size` and
`aegis-php-weak-key-size` (a numeric bit length below 2048).

**Still STAGED (11):**

| rule | why it stays |
|---|---|
| `aegis-js-weak-random`-family siblings: `aegis-py-weak-random-secret`, `aegis-go-weak-random-secret` | match on the **name** of the receiving variable / function (`$NAME`, `$FN`) |
| `aegis-py-weak-hash-security-use`, `aegis-java-weak-hash-credential`, `aegis-go-weak-hash-credential` | match on credential / digest **names** (`$NAME`, `$ARG`, `$CRED`, `$FN`) |
| `aegis-go-insecure-session-cookie` | matches on the cookie **name**; one real-code FP (a client cookie jar) before its fix |
| `aegis-js-session-trust-boundary`, `aegis-py-session-trust-boundary`, `aegis-go-session-trust-boundary`, `aegis-php-session-trust-boundary` | the privilege branch matches on session-key **names** (`$PRIV`); JS also on the request variable's name (`$REQ`) |
| `aegis-java-session-trust-boundary` | one OWASP Benchmark FP, plus the `$PRIV` name branch |

## Promotion

A staged rule moves to `rules/taint/` as PROVEN when it has true positives on real
code and every one of its real-code findings has been hand-triaged with no false
positive, on a corpus recorded in `docs/ACCURACY.md`. A silent-clean rule becomes
PROVEN the same way, by firing.
