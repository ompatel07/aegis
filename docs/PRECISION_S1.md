# Precision Pass S1 — make severity honest

Two defects from Validation V1 that corrupt every downstream severity number, plus
a plaintext-secret leak introduced while fixing Defect 1. Build: on `66db94d`.
Engines: gitleaks 8.21.2, trivy 0.71.2, semgrep 1.97.0.

## Headline

**Corpus criticals: 660 → 127 (−533).** Measured LIVE for the 5 biggest-offender
repos (covering 585/630 secrets); offline-valid signals (path prior + v3.1-vector
CVSS) for the other 10. The other-10 secrets after-count is an **upper bound** (V1
stored redacted values — see §Redaction), so the true figure is ≤ 127.

| repo | crit before | crit after | source |
|---|--:|--:|---|
| pocketbase | 413 | **7** | LIVE (392 test-fixture JWTs + 14 expired → LOW) |
| formbricks | 128 | 74 | LIVE (40 placeholder + 14 fixture) |
| documenso | 27 | 22 | LIVE (5 placeholder) |
| mealie | 20 | 2 | LIVE (17 fixture + 1 placeholder → 0 secret crits) |
| snipe-it | 9 | 4 | LIVE (2 fixture secrets + bcrypt→LOW; SCA via CVSS) |
| outline | 14 | 2 | offline |
| usememos | 10 | 0 | offline |
| netbox | 7 | 1 | offline |
| navidrome | 9 | 3 | offline |
| pterodactyl | 11 | 9 | offline |
| paperless | 4 | 1 | offline |
| mall | 5 | 0 | offline |
| eladmin / monica / akaunting | 2 / 1 / 0 | 2 / 0 / 0 | offline |

---

## Defect 1 — test-fixture / placeholder / expired secrets

`enrichment/secret_context.py`, wired into `enricher.enrich_all` (covers gitleaks
secrets + the SAST `detected-bcrypt-hash` rule). **Down-rank to LOW + tag, never
suppress.** Signals:

1. **path prior** — `*_test.*`, `/tests/`, `/spec/`, `/fixtures/`, `/factories/`,
   `/mocks/`, `/testdata/`, `/seeds/`, `*.example`, `.env.example`, … .
2. **placeholder shape** — repeated char, `changeme`/`your-*`/`xxx`/`<…>`/`${…}`/
   `example`/`dummy`/`placeholder`, or Shannon entropy < 3.0.
3. **expired JWT** — decode payload, read `exp`; past ⇒ cannot be live.

Tagged `metadata.secret_context = test-fixture | placeholder | expired |
live-format` + reason. **Mandatory override:** a live-format provider credential
(AWS `AKIA`/`ASIA`, GitHub `ghp_`, Stripe `sk_live_`, Slack `xox*`, Google `AIza`,
OpenAI, Twilio, SendGrid, npm, PyPI, a PEM with a real key body) is **never**
down-ranked, in any path.

### JWT policy (corrected from the original S1 spec)
The path prior applies to **all** secret types, **JWTs included**; expiry is an
*additional* signal, not the only one:
- future-dated JWT **outside** a fixture path → unchanged (critical)
- future-dated JWT **inside** a fixture path → **LOW / test-fixture**
- expired JWT anywhere → **LOW / expired**

This resolves pocketbase, whose 404 test JWTs are future-dated (`exp` year 2050,
so tests never break) — not expired. **Accepted residual risk:** a genuinely live
JWT committed to a test file reads LOW, because JWTs have no live-format signature
the way `AKIA`/`ghp_` do. Acceptable because we down-rank rather than suppress — it
stays in the report, just not in Top Risks.

### Redaction — why offline replay of value-based signals is impossible
gitleaks ran with `--redact` in V1, so the stored `match` is the literal
`"REDACTED"`. The JWT-expiry / placeholder / provider signals cannot be evaluated
on V1 data — only the path prior (from `file_path`) and the bcrypt rule are valid
offline. Value-based signals are validated by the LIVE re-scans.

### Gates
- **Provider override (live):** AWS + GitHub + PEM keys planted in `testdata/` all
  stay **critical / live-format**. ✓
- **JWT (live):** expired `*_test.go` → LOW/expired; future `*_test.go` →
  LOW/test-fixture; future `src/` → critical/unchanged. ✓
- **bcrypt:** seeded hash in `database/factories/*` → HIGH→LOW/test-fixture. ✓
- **Recall (Pass-3 suite):** precision 1.000, **recall 0.917 — unchanged.** The
  suite (`benchmarks/comparative/secrets_bench.py`) scores a detection **regardless
  of severity** (TP = planted file appears in `findings`), so down-ranking (which
  caps severity without removing findings) is mathematically recall-invariant. The
  lone FN (`planted_aws_secret.py`, a bare 40-char key) is a gitleaks limitation,
  not S1; 0.917 is the same 11/12 Pass 3 reported as 0.92.

---

## Defect 1b (BLOCKING) — plaintext secret leak from removing `--redact`

Removing `--redact` let the raw value cross the classification boundary. Fixed as
its own `fix(security)` commit.

**Investigation first:** can gitleaks 8.21.2 give the signals with `--redact` still
on? Verified against real output — with `--redact` the report keeps `Entropy` and
`RuleID` but replaces `Secret`/`Match` with `"REDACTED"`. Entropy alone is not
enough: the **provider-key override and JWT-expiry both require the value**, so
`--redact` cannot stay on. Redact-at-boundary is the approach.

**Trade-off (stated honestly):** we now hold plaintext in memory *during
classification*, where previously we never did. The mitigation is that it never
crosses a persistence, network, or log boundary — proven by a leak test, not a code
reading.

- **Leak 1 — `EngineResult.raw` → Postgres.** `raw={"findings": raw_findings}` held
  gitleaks' plaintext `Secret`/`Match`, persisted to `scans.raw_gitleaks_output` and
  sent over the scanner→orchestrator hop. Fix: `secret_context.redact_raw_findings`
  scrubs `Secret`/`Match`/`Line` (reusing the single `_redact`) before the
  `EngineResult` is built. A third carrier was found and fixed too: `enrich_all`'s
  `_attach_snippets` had filled `code_snippet` with the raw source line — now
  scrubbed in the same pass.
- **Leak 2 — plaintext report file survives a hard kill.** The unredacted report is
  written to disk; `finally` does not run on SIGKILL (OOM). Fix: report lives in a
  private `0700` dir, is created `0600` by `mkstemp`, is **shredded** (zero-overwrite
  + unlink) after use, and the scanner **sweeps stale `gitleaks-*` files on startup**
  — the only crash-safe guarantee, since SIGKILL is uncatchable.

**Leak gate — `tests/test_secret_never_leaks.py`:** plants a unique sentinel, runs a
FULL scan through the real entrypoint, and asserts the sentinel plaintext is absent
from the serialized `EngineResult` (the single payload feeding Postgres / HTTP /
SARIF / compliance / Redis), every finding field, `.raw`, DEBUG logs, a forced
exception traceback inside `annotate`, and `/tmp`. Classification is verified to run
BEFORE redaction (a live scan still tags provider/JWT/fixture correctly).

---

## Defect 1c (SECURITY) — pre-existing snippet leak from Q1 (NOT an S1 regression)

**Correction to follow-up 1:** the `code_snippet` carrier is **not** collateral from
removing `--redact`. `git log --follow` on `utils/snippet.py` shows one commit,
**eb4fc04 (2026-08-12)** — S1 (`0c0d6f0`) never touched it. This leak shipped in
that commit and was live in **every scan from 2026-08-12 to 2026-08-27**.

**Record correction:** our P1 claim "secrets redacted (no plaintext)" was
**inaccurate for semgrep-detected credentials** for that window. Only gitleaks
snippets were redacted; every semgrep credential rule persisted its raw source line.
Do not repeat the claim without this fix in place.

**Hole 1 — `_is_secret` only matched gitleaks.** Semgrep credential rules
(`node_secret`, `node_password`, `detected-bcrypt-hash`, `detected-jwt-token`,
`detected-private-key`, `hardcoded-*`, `python-logger-credential-disclosure`, …,
CWE-798/259) got no snippet redaction. Fixed: `_is_secret` is now a **capability
check** — gitleaks, OR a rule id naming a secret (hints grounded in the actual V1
rule ids), OR CWE-798/259, OR a metadata category of "secret".

**Hole 2 — regex missed non-token-shaped secrets.** `_SECRET_RUN` (base64/hex runs)
can't catch `password = "hunter2"` or the credential in a connection string. Fixed,
layered (both, via the single `secret_context._redact`):
  a) **value-based** — for gitleaks, the exact value (passed transiently, popped
     before serialization) is scrubbed surgically;
  b) **regex** — `_SECRET_RUN` plus assignment-RHS (`password/token/api_key/... =
     "…"`) and URI-credential (`scheme://user:PASS@host`) patterns, for the
     no-value semgrep cases. Only secret-shaped substrings are masked; the rest of
     the line survives (readability gated by test).

**A further carrier found:** semgrep stores the matched line in
`metadata["lines"]` (truncated 2000) — redacted for secret findings in the same
pass (keys: lines/line/code/snippet/matched/context).

**KNOWN REMAINING carrier (out of scope for the snippet fix, flagged):** the raw
semgrep JSON in `EngineResult.raw` (→ `scans.raw_semgrep_output`) still holds
matched lines for semgrep secret findings — the same class as gitleaks Leak 1,
which was fixed for gitleaks only. Recommend a follow-up to redact secret findings'
lines in the raw semgrep output before persistence.

**Blast radius (local Postgres, 78 scans / 12,339 findings):** 9 `code_snippet` +
110 `metadata.lines` rows held plaintext credentials (3 RSA key bodies, bcrypt
hashes, hardcoded passwords). Cleaned with a one-off (`scripts/s1_snippet_cleanup.py`,
same `_redact`) — **0 RSA/bcrypt/token bodies remain** (56 rows still match the
crude rule-name predicate but are false-positive hits like
`"Password must be 8-18 characters"`, no credential). The local V1/S1 audit JSONs
were scrubbed too (`scripts/s1_json_scrub.py`, 198 fields).

**Gate (`tests/test_secret_never_leaks.py`, extended):** non-token secret
(`DB_PASSWORD="summer2024"` + `postgres://admin:hunter2@…`) → absent from
code_snippet; a SEMGREP-caught hardcoded secret → absent from code_snippet +
metadata (Hole-1 guard); the gitleaks sentinel case still green; snippets stay
readable (variable name + comment survive, only the secret masked). Full suite: 110
passed. Pass-3 recall: **0.917 unchanged**.

---

## Defect 2 — CVSS score inflation

`engines/trivy_engine.py`: `_best_cvss` took **`max()` across all CVSS sources**.
Replaced with `_select_cvss` — **precedence NVD → GHSA → vendor**, prefer V3, never
fabricate, record `metadata.cvss_source`; no score ⇒ severity from the advisory's
own label.

**Offline audit (V1 stored real vectors):** re-deriving each score from its v3.1
vector, **29 of 280 auditable findings differ by > 0.5** (10%); 3 flip critical →
lower (snipe jspdf CVE-2026-31938 9.6→6.1, -25940 9.6→8.1, -25755 9.6→8.8); the rest
are mostly high→medium (lodash, axios, dompurify, postcss, brace-expansion,
react-router). Lower bound — the vector audit can't catch same-source inflation; the
live NVD-first re-scan does.

**Historical note:** `_best_cvss` used `max()` for the **entire life of the SCA
engine**, so the *severity* in all prior validations (client1's 5 CVEs, Taaza's 10
PHPMailer CVEs, …) was potentially inflated. This changes **severity only** — the
**TP/FP verdicts and version math are unaffected** (a CVE is still real, the
installed version is still in range). **"SCA 100% precision" survives and should not
be discarded.**

---

## Verification gate summary
| gate | result |
|---|---|
| Leak test (10 sinks) | ✓ sentinel absent everywhere |
| Offline CVSS audit + before/after | ✓ 29 mismatches |
| Live re-scan (5 repos) | ✓ pocketbase 413→7, formbricks 128→74, … |
| Provider-key override (live plant) | ✓ AWS/GitHub/PEM in testdata stay critical |
| JWT policy (live plant) | ✓ expired→LOW, future-in-fixture→LOW, future-in-src→critical |
| Secrets recall (Pass 3) | ✓ 0.917 unchanged (severity-agnostic scoring) |
| Full scanner suite | ✓ 107 passed |
| `go build ./...` + scoring tests | ✓ |
| **Corpus criticals** | **660 → 127** |

Harness: `scripts/validation_v1_replay.py`, `validation_s1_rescan.py`,
`validation_s1_tally.py`.
