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

Each rule was read for what it actually matches on, then re-checked on the N4 ground-truth corpora.

**SILENT-CLEAN (6), API shape only, ran on every measured corpus with 0 FP and never
fired:** `aegis-js-insecure-session-cookie-esm` (the `express-session` import and its options
object), `aegis-py-weak-cipher`, `aegis-py-weak-key-size`, `aegis-java-weak-key-size`,
`aegis-go-weak-key-size`, `aegis-php-weak-key-size`.

**Promoted to PROVEN in N4 Part C** (fired on the N4 ground-truth corpora, every finding
a true positive -- docs/GROUND_TRUTH_N4.md):

| rule | from | evidence |
|---|---|---|
| `aegis-java-weak-cipher` | silent-clean | VulnerableApp: `AES/ECB/PKCS5Padding` (EncryptionUtils:88) and the LM-hash DES (PasswordHashingUtils:150-151) -- 3 TP / 0 FP |
| `aegis-go-weak-hash-credential` | staged | DVGA (Go): `md5.Sum([]byte(u.Password))`, its documented weak-password module -- 1 TP / 0 FP |
| `aegis-go-insecure-session-cookie` | staged | DVGA (Go): `session_id` and `signed_session` cookies without Secure -- 2 TP / 0 FP |

**Still STAGED (9):**

| rule | why it stays |
|---|---|
| `aegis-py-weak-random-secret` | fired in N4: 4 TP (PyGoat OTP, API key) but **1 FP** (DVGraphQL `random.choice(['changeme'])`, where the weakness is the password list, not the RNG); also name-based |
| `aegis-go-weak-random-secret` | matches on the receiving variable / function **name**; never fired |
| `aegis-py-weak-hash-security-use`, `aegis-java-weak-hash-credential` | match on digest / credential **names**; never fired on real code |
| `aegis-js-session-trust-boundary`, `aegis-py-session-trust-boundary`, `aegis-go-session-trust-boundary`, `aegis-php-session-trust-boundary` | the privilege branch matches on session-key **names** (`$PRIV`); never fired |
| `aegis-java-session-trust-boundary` | one OWASP Benchmark FP, plus the `$PRIV` name branch |

## Staged in P3 (2026-10-24)

| rule | why it stays |
|---|---|
| `aegis-php-stored-xss` (`php_stored_xss.yaml`) | split from `aegis-php-xss` so stored XSS is measured instead of excluded; on a seeded random sample of 60 of its 2,515 stable findings on the held-out real repositories, **6 TP / 53 FP / 1 uncertain (10 %, 95 % interval 4.7–20.5 %)** -- mostly ids, amounts and already-escaped helper output. By the rule fixed before the draw (upper bound < 50 %), it does not ship (`docs/PRECISION_P3.md` §C) |

## Promotion

A staged rule moves to `rules/taint/` as PROVEN when it has true positives on real
code and every one of its real-code findings has been hand-triaged with no false
positive, on a corpus recorded in `docs/ACCURACY.md`. A silent-clean rule becomes
PROVEN the same way, by firing.
