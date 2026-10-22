# Staged rules — written, tested, NOT shipped

Rules here are Aegis-authored and pass their fixtures (`semgrep --test`, run by
`tests/test_staged_rules.py`), but have **not** earned a place in a scan:

- the engine never loads this directory (it loads `rules/taint`, `rules/quality`,
  `rules/iac`, `rules/cicd` and `rules/vendor` only);
- `utils/rule_coverage.py` counts `rules/**` only, so nothing here is reported as
  coverage;
- `tools/check_rule_licences.py` still checks them (Aegis id, no registry
  metadata, no removed-rule logic), because they are in the image.

## Why a rule is here (Pass N3, 2026-10-22)

N3's gate: every rule must fire on **real** repositories at 0 false positives,
not just on the OWASP Benchmark. Measured on V2's 15 repositories, F1's
documented-vulnerability repositories and 21 further real repositories
(`docs/OWASP_CATEGORIES_N3.md`):

| status | rules |
|---|---|
| **benchmark-only**, a gaming risk | `aegis-java-weak-cipher` (130 Benchmark cases, 0 real-repo hits), `aegis-java-session-trust-boundary` (3 TP / 1 FP on the Benchmark, 0 real) |
| **never fired** on real code (unproven) | `aegis-js-insecure-session-cookie-esm`, `aegis-js-session-trust-boundary`, `aegis-py-weak-random-secret`, `aegis-py-weak-hash-security-use`, `aegis-py-weak-cipher`, `aegis-py-weak-key-size`, `aegis-py-session-trust-boundary`, `aegis-java-weak-hash-credential`, `aegis-java-weak-key-size`, `aegis-go-weak-random-secret`, `aegis-go-weak-hash-credential`, `aegis-go-weak-key-size`, `aegis-go-insecure-session-cookie`, `aegis-go-session-trust-boundary`, `aegis-php-weak-key-size`, `aegis-php-session-trust-boundary` |

## Promotion

A rule moves to `rules/taint/` when it has true positives on real code and
every one of its real-code findings has been hand-triaged with no false
positive, on a corpus recorded in `docs/ACCURACY.md`. Fixtures move with it.
