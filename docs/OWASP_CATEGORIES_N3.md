# Pass N3 — the five OWASP pattern categories, real-code-gated (2026-10-22)

N1 removed the Semgrep-licensed rules; OWASP Benchmark Youden fell **0.459 → 0.051**.
Five pattern categories carried much of that drop: weak random, weak crypto, weak hash,
insecure cookie and trust boundary. N2b's Part D scoped what was uncovered per
language. N3 wrote Aegis rules for exactly that scope, then shipped only the ones that
fire on **real** code at **0 false positives**.

| gate | result |
|---|---|
| 1. positive + negative fixture per rule per language; `semgrep --test` | 28 rules written, every one with `ruleid:` and `ok:` fixtures. Shipped 52/52, staged 18/18 pass |
| 2. OWASP Benchmark, before vs after, per category | Youden **0.051 → 0.175** with the shipped rules (30 % of N1's drop recovered). **Not a pitch number**: the whole gain is weakrand, and §D shows it rests on one Benchmark naming convention |
| 3. 0-FP hand triage of every new finding | 39 real repositories. **41 false positives** found in triage, every one removed by a mechanism-level constraint. Final run: **53 findings, 53 true positives** (11 protocol- or format-mandated) |
| 4. benchmark hits vs real-repo hits, per rule | §B. Two rules are **benchmark-only** (Java weak cipher, Java trust boundary) and do not ship. 16 never fired on real code and do not ship either |
| 5. ground truth unchanged or better | **22/45 → 22/45**, no item changed |
| 6. coverage tiers re-measured | counts moved; **no tier changed**. No new rule adds a documented-vulnerability proof (§F) |
| 7. licence guard; full suite; both CI workflows | guard green (70 shipped + 18 staged Aegis rules); suite and CI in the commit record |
| 8. ACCURACY.md, measured numbers only | an N3 section (per-rule real-code TP/FP), the per-language table, the Benchmark paragraph (re-measured, still not a claim) and the provenance row |

**What ships: 10 rules.** `aegis-js-weak-random-secret`,
`aegis-js-insecure-session-cookie`, `aegis-py-insecure-session-cookie`,
`aegis-java-weak-random-secret`, `aegis-java-insecure-session-cookie`,
`aegis-go-weak-cipher`, `aegis-php-weak-random-secret`,
`aegis-php-weak-hash-credential`, `aegis-php-weak-cipher`,
`aegis-php-insecure-session-cookie`.

**What does not: 18 rules**, in `services/scanner/rules_staging/`. They are written and
tested, but the engine does not load them and coverage does not count them (§B).

---

## A. Method

**No copying.** Every rule was written from the CWE definition and the language or
framework API documentation; each records its sources in `metadata.written-from`. No
Semgrep, GitLab, njsscan or registry rule text was used. The N1 licence guard checks
every rule, staged ones included, against the 1,141 logic fingerprints of the removed
Semgrep-licensed rules. Green.

**Frozen before measurement.** The rule files were hash-recorded
(`2026-10-22T07:54:43Z`) before the first Benchmark or corpus run. Every later change
is a constraint motivated by a false positive in a **real** file, listed in §C.
Constraints were checked against the Benchmark afterwards: it moved by **zero** cases,
so none of them was Benchmark-driven.

**Corpora.** All are real code, never built, installed or run.

| corpus | repositories |
|---|---|
| **V2** (15) | Dolibarr `1348343c`, FreshRSS `3f12dcf2`, NodeGoat `c5cb68a7`, WebGoat `872d6149`, chatwoot `f7f77545`, DVWA `b496a5d3`, redash `8f6b15d3`, jellyfin `50866380`, juice-shop `1618a611`, librenms `4381e1a9`, mastodon `2c92a56e`, n8n `69b0c527`, TeamPass `14e7d03b`, nocodb `28ecd7c2`, nopCommerce `3204d843`. Re-cloned at these commits (shallow fetch by SHA) |
| **F1** (the three at commits V2 does not have) | DVWA `5d5c76cc`, WebGoat `38096af4`, dvpwa `a1d8f89f` |
| **extended** (21; every commit in `docs/owasp_n3/verdicts.json` `corpus_commits`) | ansible, cobra, consul, django, express, fastapi, flask, gin, guava, jackson, kafka, nest, netty, next-auth, prisma, react, spring, terraform, vault, django-nV `a48901f1`, spring-petclinic `818c4136` |

V2 has no Go repository and only one Java, one Python and one JS-only
documented-vulnerability repository, so the extended corpus was added to give Go, Java
and Python rules a fair chance to prove themselves. Findings were deduplicated where a
repository appears at two commits with identical lines.

**Harness.** Only the N3 rule files were run, through the engine's own `_build_args`
with its default exclude dirs and the bundled/minified-asset exclusion list. That is
the product's exact semgrep invocation, so a finding here is a finding a customer gets.
Ground truth and the Benchmark were run through the full product (`/scan/sast`).

### A.1 Design: purpose-aware where purpose decides

| category | rule fires only when | why |
|---|---|---|
| weak random | a weak generator's output reaches a value whose **head noun** says it must be unguessable (`csrfToken`, `passwordSalt`, `apiKey`, `otpCode`: not `tokenExpiry`, `saltRounds`), a session/auth cookie, or the return of a generator-named function | `Math.random()` / `java.util.Random` / `random` / `rand` are fine for shuffles, jitter and ids |
| weak hash | MD5/SHA-1 over a **password-family** value (not one that is already a hash), or inside a function named for hashing/verifying passwords; `usedforsecurity=False` respected | MD5 over a cache key or checksum is not a vulnerability |
| weak cipher / key size | DES, 3DES, RC2, RC4, Blowfish/CAST5, ECB, RSA/DSA < 2048, **with no further context** | low ambiguity: there is no safe confidentiality use. Two exceptions found on real code are in §C |
| insecure cookie | Secure/HttpOnly missing or off on a **session/auth-named** cookie written to a response; CSRF cookies excluded | double-submit CSRF tokens must be readable |
| trust boundary | the request chooses **which** session key is written, or writes a **privilege-shaped** key | storing a submitted locale is not a trust decision |

Taint carries the value from generator to sink. One semgrep-specific technique keeps
it honest: **any call that is not a pure value transform sanitises**, with
`exact: true` so only the call's own value is cleaned. So `Math.random().toString(36)`
stays tainted, while `fetchToken('/x?_=' + Math.random())`, a cache-buster, does not
make the fetched token weak. That is N2b's RC2 lesson ("the rule never checks what
makes the code dangerous") turned into rule structure.

Semgrep 1.97 behaviours found and worked around (all fixture-tested):
- `metavariable-regex` is anchored at the start of the text.
- In Java, `$F(...)` binds the qualified name.
- Comprehensions and generator expressions do not carry taint, so
  `"".join(random.choice(...) for ...)` is a source in its own right.
- A non-exact sanitiser clears the whole call range, arguments included.
- Constants are folded (`"rememberMe" + n`), which turns out to matter in §D.
- An invalid rule is dropped **silently** unless a fixture names it. Every rule has
  fixtures for exactly this reason.

---

## B. Per rule: Benchmark hits vs real-repository hits

Real-repo counts are distinct findings on the final run over 39 repositories. Every
one was hand-triaged, and every one is a true positive.

| rule | Benchmark (TP / FP) | real repos (TP / FP) | where | status |
|---|---|---|---|---|
| `aegis-php-weak-hash-credential` | n/a | **26 / 0** | DVWA 17, Dolibarr 4 (LDAP `{MD5}`/`{SHA}` formats), TeamPass 4 (phpseclib PEM KDF), FreshRSS 1 (Fever API key) | **shipped** |
| `aegis-php-insecure-session-cookie` | n/a | **5 / 0** | DVWA 4 (session cookie never Secure; `dvwaSession`), TeamPass 1 (`session.cookie_secure = 0` in the upgrader) | **shipped** |
| `aegis-php-weak-cipher` | n/a | **5 / 0** | DVWA 3 (AES-128-ECB lesson), Dolibarr 2 (NTLM DES, PDF RC4) | **shipped** |
| `aegis-php-weak-random-secret` | n/a | **2 / 0** | DVWA `session_token = md5(uniqid())`, Dolibarr `modGeneratePassPerso` (every character from `mt_rand`) | **shipped** |
| `aegis-java-weak-random-secret` | **175 / 0** | **6 / 0** | WebGoat (secrets and the JWT signing key chosen with `new Random()`) | **shipped**; Benchmark number *not* evidence (§D) |
| `aegis-java-insecure-session-cookie` | 0 / 0 | **1 / 0** | WebGoat `access_token` cookie | **shipped** |
| `aegis-go-weak-cipher` | n/a | **4 / 0** | vault PKCS#7 DES/3DES (format-mandated) | **shipped** |
| `aegis-js-insecure-session-cookie` | n/a | **2 / 0** | juice-shop JWT `token` cookie, no flags | **shipped** |
| `aegis-js-weak-random-secret` | n/a | **1 / 0** | FreshRSS `poormanSalt` (N2b TP #4) | **shipped** |
| `aegis-py-insecure-session-cookie` | n/a | **1 / 0** | django-nV `SESSION_COOKIE_HTTPONLY = False` | **shipped** |
| `aegis-java-weak-cipher` | **130 / 0** (227 findings) | **0** | — | **benchmark-only: gaming risk, not shipped** |
| `aegis-java-session-trust-boundary` | 3 / 1 | **0** | — | **benchmark-only, not shipped** |
| `aegis-java-weak-hash-credential` | 0 / 0 | 0 | one WebGoat TP lost to narrowing (§C) | staged |
| `aegis-java-weak-key-size` | 0 / 0 | 0 | — | staged |
| `aegis-js-insecure-session-cookie-esm`, `aegis-js-session-trust-boundary` | n/a | 0 | — | staged |
| `aegis-py-weak-random-secret`, `-weak-hash-security-use`, `-weak-cipher`, `-weak-key-size`, `-session-trust-boundary` | n/a | 0 | — | staged |
| `aegis-go-weak-random-secret`, `-weak-hash-credential`, `-weak-key-size`, `-insecure-session-cookie`, `-session-trust-boundary` | n/a | 0 | — | staged |
| `aegis-php-weak-key-size`, `aegis-php-session-trust-boundary` | n/a | 0 | — | staged |

The OWASP Benchmark is Java only, so "n/a" means the rule cannot fire there.

**Why "never fired" does not ship.** N3's gate is that a rule *fires on real code at 0
FP*. A rule that has never fired has a vacuous 0-FP record. Shipping it would add
coverage nobody has measured, which is what N2b found 84 njsscan rules to be. These
rules are kept, tested and ready to promote (`rules_staging/README.md`). They are not
counted.

**Trust boundary: none ships, in any language.** The brief expected this to be the
hardest category, and said to drop it if it could not reach 0 FP on real code. It
reached 0 FP only by never firing on real code. It fired only on the Benchmark: 3 TP,
plus 1 FP on a dead-branch case a path-insensitive engine cannot see. That is not
proof, so it does not ship.

---

## C. The false positives real code found, and what removed them

41 false positives across the first two triage rounds, removed by constraints that
each name a mechanism. None was tuned to a file name or a Benchmark shape. Full list
with locations: `docs/owasp_n3/verdicts.json`.

| mechanism (real example) | FPs | constraint |
|---|--:|---|
| a protocol **nonce** only needs uniqueness (OAuth1, HTTP Digest, Yubico, AES-CTR) | 6 | `nonce` removed from the secret-name list |
| a bare **token / sessionId** is often not a secret (redash fetch-race tokens, n8n MCP correlation id, TeamPass temp-dir names) | 10 | `token` needs a security qualifier (`csrf`, `auth`, `reset`, `api`, ...); session-id names removed |
| a **CSPRNG-capability fallback** (`if (function_exists('random_int')) … else mt_rand`, `try { random_bytes } catch`) is dead code | 6 | sources inside such fallbacks are not live |
| **CSPRNG output mixed in** (`hash(uniqid() . random_bytes(32))`) | 1 | expressions containing CSPRNG output are sanitised |
| a function that **verifies** a code returns a verdict (`verifyHOTP`) | 1 | verifier verbs are not generators |
| **protocol-mandated MD5** that the message does not describe: HTTP Digest A1, CRAM-MD5 HMAC key reduction, the Pwned-Passwords SHA-1 prefix, `setCredentials` | 6 | narrowed credential names to the password family; Digest `user:realm:pw` and HIBP 5-char-prefix excluded |
| hashing an **already-hashed** password (FreshRSS API token) | 4 | inputs whose text contains `hash` excluded |
| md5 that **generates** a password (tcpdf owner password) | 1 | the assignment branch accepts only hash-denoting names |
| **ECB as a primitive** to build CFB (phpseclib) | 1 | `mcrypt_module_open(…, ECB)` not flagged; ECB encryption still is |
| **cookie flags via a spread** (n8n), **cleared cookie** (WebGoat), **client cookie jar** (vault CLI), **Django's defaults table** | 6 | spread options not inspected; empty-value cookies excluded; Go cookies only when written to a response; `django/conf/global_settings.py` excluded |

**True positives lost to constraints: 1.** WebGoat `HashingAssignment` hashes a lesson
"secret" word with MD5. It was lost when credential names were narrowed after the
CRAM-MD5 false positive. The rule is staged in any case.

**Protocol- and format-mandated true positives: 11, kept and labelled.** NTLMv1 DES,
PDF RC4, legacy PEM's single-MD5 key derivation, PKCS#7 DES/3DES and the Fever API's
`md5(email:password)` key. The test applied was whether the message's mechanism is the
weakness: for these it is. Where it is not (Digest, CRAM-MD5, HIBP), the finding was
treated as a false positive and constrained away.

---

## D. OWASP Benchmark v1.2: before vs after, and the gaming check

Same harness as N1 (`benchmarks/owasp/scan.py`, `score.py`), through `/scan/sast`. The
"before" run is today's shipped configuration without N3, and it reproduces N1's
0.0514 exactly. CWE-mode and lenient-mode scoring agree.

| category | before (TP/FP/FN/TN) | **after, shipped** | all 28 rules incl. staged (not shipped) |
|---|---|---|---|
| weakrand | 0 / 0 / 218 / 275 | **175 / 0 / 43 / 275** (TPR 0.80, FPR 0) | 175 / 0 / 43 / 275 |
| crypto | 0 / 0 / 130 / 116 | 0 / 0 / 130 / 116 | 130 / 0 / 0 / 116 |
| hash | 0 / 0 / 129 / 107 | 0 / 0 / 129 / 107 | 0 / 0 / 129 / 107 |
| securecookie | 0 / 0 / 36 / 31 | 0 / 0 / 36 / 31 | 0 / 0 / 36 / 31 |
| trustbound | 0 / 0 / 83 / 43 | 0 / 0 / 83 / 43 | 3 / 1 / 80 / 42 |
| **overall** | TPR 0.154 · FPR 0.103 · **Youden 0.051** | TPR 0.278 · FPR 0.103 · **Youden 0.175** | Youden 0.268 |
| share of N1's 0.459 → 0.051 drop recovered | — | **30 %** | 53 % |

**The gaming check is not clean, so 0.175 is not a pitch number.** All 175 weakrand
true positives reach one sink: `new Cookie(cookieName, value)`, where semgrep
constant-folds `cookieName = "rememberMe" + testNumber`, and `remember-me` is on the
secret-name list. The name is in the list on real-world grounds: it is Spring
Security's remember-me cookie and Rails/Laravel's `remember_token`, and the rule was
hash-frozen before the Benchmark ran. But the Benchmark's entire weakrand result
depends on that one naming convention, which **never occurs in the 39 real
repositories**. The same rule's six real true positives come through different sinks.
So the rule ships on its real-code record, and the Benchmark number says nothing about
real-code recall.

What the per-category rows say instead:
- **crypto**: a context-free rule scores 130/130 on the Benchmark and fires on no real
  Java code. That is the brief's definition of a gaming risk, and it does not ship.
- **hash** and **securecookie** stay at 0 *because* the rules are purpose-aware. The
  Benchmark hashes an input called `input` and sets cookies called `SomeCookie`, which
  are not credentials or sessions by any real-code standard. A rule tuned to score
  there would flag every checksum and UI cookie.
- **weakrand misses 43** that use `java.lang.Math.random()` written fully qualified,
  which semgrep does not normalise. It was found through the Benchmark, so it was **not**
  added in this pass.

---

## E. Ground truth: unchanged

Re-scanned through the product with the shipped rules (same checkouts as F1/N1/N2b),
scored with N1's `gt_score.py`:

| repo | N2b | N3 |
|---|--:|--:|
| DVWA | 3/6 | 3/6 |
| WebGoat | 6/6 | 6/6 |
| NodeGoat | 5/7 | 5/7 |
| dvpwa | 1/1 | 1/1 |
| juice-shop | 7/25 | 7/25 |
| **total** | **22/45** | **22/45**, 0 items changed |

NodeGoat GT6 (weak crypto, JavaScript) is still missed. JS weak crypto is the njsscan
rules N2b kept, outside N3's scope.

---

## F. Coverage tiers: re-measured, unchanged

| language | rules N2b → N3 | CWE classes N2b → N3 | tier |
|---|---|---|---|
| javascript / typescript | 100 → **102** | 38 → **39** | strong |
| python | 12 → **13** | 10 → **12** | limited |
| java | 7 → **9** | 7 → **10** | limited |
| php | 5 → **9** | 5 → **11** | strong |
| go | 7 → **8** | 7 → **8** | limited |

Gate 6 asked whether Java, Python or Go now earn STRONG. **No.** STRONG is tied to
documented-vulnerability proof (`STRONG_EVIDENCE`, N2b), and N3 adds none: ground
truth is unchanged. Java's new true positives are WebGoat lessons outside the
documented set, Python's is one settings line in one repository, and Go's is one
library. Each is real yield, but none is the multi-repository documented proof the
tier means. The evidence check (`tier_evidence_gaps()`) is empty, as it should be.

---

## G. Known false negatives

Measured or structural, not fixed here:
- `java.lang.Math.random()` written fully qualified (43 Benchmark cases).
- Generators behind a helper in another function (taint is intraprocedural): a
  `randomString()` helper called as `const token = randomString(32)`.
- JS `Array.from({length}, () => …Math.random…)`.
- Bare `token` and session-id names (dropped for precision; §C).
- commons-lang3 `RandomStringUtils` (version-dependent; only lang 2.x is a source).
- Spring `ResponseCookie` builders and cookie flags set in properties or YAML.
- Weak RNG time sources outside PHP (`Date.now()` tokens).

---

## What changed in the repository

- `services/scanner/rules/taint/{javascript,python,java,go,php}_weakness.yaml` with
  fixtures (`.js`, `.ts`, `.py`, `.java`, `.go`, `.php`): the 10 shipped rules.
- `services/scanner/rules_staging/` (new): the 18 unshipped rules, their fixtures, and
  a README with the promotion criteria. It is not loaded by the engine and not counted
  as coverage.
- `tests/test_staged_rules.py` (new): staged fixtures pass; the engine never loads
  staging; staged ids are never counted.
- `tools/check_rule_licences.py`: also checks staged rules.
- `.github/workflows/self-scan.yml`: excludes `services/scanner/rules_staging`. Its
  fixtures deliberately contain `des.NewCipher`, which the shipped Go rule would flag.
- `utils/rule_coverage.py` (measured table) and `tests/test_rule_coverage.py` (the
  gap-sentence test reads the measured Java count rather than a constant).
- `compliance/emittable_identifiers.yaml`: declared CWE-328/330/338 added.
- `docs/owasp_n3/verdicts.json`: every final finding with its verdict, every removed
  false positive with its mechanism and constraint, and the one lost true positive.
