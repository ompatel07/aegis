# Precision Pass S1 — make severity honest

Two defects from Validation V1 that corrupt every downstream severity number.
Build: on top of `66db94d`. Engines: gitleaks 8.21.2, trivy 0.71.2, semgrep 1.97.0.

## Headline

**Corpus criticals: 660 → 526 (−134).** Measured LIVE for the 5 biggest-offender
repos (585/630 secrets), offline-valid signals (path prior + v3.1-vector CVSS) for
the other 10. The other-10 secrets are an **upper bound** (see §Redaction).

> ⚠️ **397 of the 526 remaining criticals are pocketbase test JWTs** (see §JWT).
> Excluding pocketbase, the other 14 repos drop **247 → 129 (−48%)**. The pocketbase
> residual is a spec decision left to the reviewer.

| repo | crit before | crit after | source |
|---|--:|--:|---|
| pocketbase | 413 | **397** | LIVE (390 future-dated JWTs remain — see §JWT) |
| formbricks | 128 | 74 | LIVE (40 placeholder + 14 fixture down-ranked) |
| documenso | 27 | 22 | LIVE (5 placeholder) |
| mealie | 20 | 2 | LIVE (17 fixture + 1 placeholder → 0 secret crits) |
| snipe-it | 9 | 4 | LIVE (2 fixture secrets + 1 bcrypt→LOW; SCA via CVSS) |
| outline | 14 | 2 | offline (CVSS-from-vector) |
| netbox | 7 | 1 | offline |
| usememos | 10 | 3 | offline |
| navidrome | 9 | 4 | offline |
| pterodactyl | 11 | 9 | offline |
| paperless | 4 | 1 | offline |
| mall | 5 | 5 | offline |
| eladmin | 2 | 2 | offline |
| akaunting / monica | 0 / 1 | 0 / 0 | offline |

---

## Defect 1 — test-fixture / placeholder / expired secrets

`enrichment/secret_context.py`, wired into `enricher.enrich_all` (covers gitleaks
secrets + the SAST `detected-bcrypt-hash` rule). **Down-rank to LOW + tag, never
suppress.** Three independent signals:

1. **path prior** — `*_test.*`, `/tests/`, `/spec/`, `/fixtures/`, `/factories/`,
   `/mocks/`, `/testdata/`, `/seeds/`, `*.example`, `.env.example`, … .
2. **placeholder shape** — repeated char, `changeme`/`your-*`/`xxx`/`<…>`/`${…}`/
   `example`/`dummy`/`placeholder`, or Shannon entropy < 3.0.
3. **expired JWT** — decode the payload, read `exp`; past ⇒ cannot be live.
   Malformed/undecodable ⇒ unknown, not down-ranked.

Findings tagged `metadata.secret_context = test-fixture | placeholder | expired |
live-format` with a reason. **Mandatory override:** a value matching a live-format
provider credential (AWS `AKIA`/`ASIA`, GitHub `ghp_`, Stripe `sk_live_`, Slack
`xox[baprs]-`, Google `AIza`, OpenAI, Twilio, SendGrid, npm, PyPI, a PEM block with
a real key body) is **never** down-ranked, in any path.

### The redaction discovery (why offline replay is limited)
gitleaks ran with `--redact`, so V1 stored the literal string `"REDACTED"` as the
secret value — the JWT-expiry, placeholder, and provider signals **cannot be
evaluated on V1 data**. Fix: `--redact` removed; `secret_context` re-redacts the
value to a short prefix + length (`AKIA…[20c]`) immediately after classifying, so
no raw secret is stored. Value-based signals are therefore validated by the LIVE
re-scan, not the offline replay.

### JWT reality — the pocketbase caveat (needs a decision)
The spec assumed pocketbase's 404 JWTs are expired. They are **not**: decoding the
actual `apis/*_test.go` tokens shows `exp: 2524604461` (**year 2050**) — future-
dated so the tests never break. Per spec test #4 (*future-dated JWT → unchanged*,
JWTs governed by expiry alone), only the 14 genuinely-expired tokens down-rank; 390
future-dated test JWTs stay critical. **My implementation is correct per spec**, but
it leaves pocketbase at 397 criticals.

**Decision for the reviewer:** if future-dated JWTs that ALSO sit in a fixture path
should down-rank (a one-line change that contradicts test #4 as literally worded),
pocketbase drops ~390 and the corpus lands near **136**. Left unchanged pending your
call, because test #4 is explicit.

### Gates
- **Provider override (live):** AWS + GitHub + PEM keys planted in `testdata/` all
  stay **critical / live-format**. ✓
- **Expired-JWT (live):** expired JWT in `*_test.go` → **LOW/expired**; future-dated
  → **critical/unchanged**. ✓
- **Recall (Pass-3 suite):** precision 1.000, **recall 0.917** — unchanged (the
  down-rank caps severity without removing findings, so recall is mathematically
  invariant; the single FN is a bare-key gitleaks limitation, not S1). 0.917 is the
  same 11/12 Pass 3 reported as 0.92. ✓
- **bcrypt:** seeded hash in `database/factories/*` → HIGH→LOW/test-fixture. ✓

---

## Defect 2 — CVSS score inflation

`engines/trivy_engine.py`: `_best_cvss` took **`max()` across all CVSS sources**
(nvd/ghsa/redhat/…), so any single high vendor score won. Replaced with
`_select_cvss` — **source precedence NVD → GHSA → vendor**, prefer V3, never
fabricate, record `metadata.cvss_source`. When no source has a score, severity
falls back to the advisory's own label (already handled by `cvss_to_severity`).

### Audit (offline, valid — V1 stored real v3.1 vectors)
Re-deriving each SCA finding's base score from its stored vector and comparing to
the stored score: **29 of 280 auditable findings differ by > 0.5** (10%). This is a
lower bound — it catches score-vs-own-vector disagreement but not cases where score
and vector both came from the same inflated source (the live re-scan, NVD-first,
catches those). 3 cases flipped critical → lower:

| repo | CVE | pkg | stored | vector-derived |
|---|---|---|--:|--:|
| snipe | CVE-2026-31938 | jspdf | 9.6 (crit) | **6.1 (med)** |
| snipe | CVE-2026-25940 | jspdf | 9.6 (crit) | **8.1 (high)** |
| snipe | CVE-2026-25755 | jspdf | 9.6 (crit) | **8.8 (high)** |

Most of the other 26 are high→medium inflation (axios, lodash, dompurify, postcss,
brace-expansion, react-router …) — e.g. lodash `CVE-2025-13465` stored 8.2 vs
vector 5.3; axios `CVE-2026-40175` stored 8.1 vs 4.8. This is systemic, not a
one-off, and matters for the scoring pass even where it doesn't cross the critical
line.

---

## Verification gate summary
| gate | result |
|---|---|
| Offline CVSS replay + before/after | ✓ 29 mismatches; CVSS-only corpus 660→657 |
| Live re-scan (5 repos) | ✓ pocketbase/formbricks/documenso/mealie/snipe |
| Provider-key override (live plant) | ✓ AWS/GitHub/PEM in testdata stay critical |
| Expired-JWT (live plant) | ✓ expired→LOW, future→unchanged |
| Secrets recall (Pass 3) | ✓ 0.917 (unchanged), precision 1.000 |
| Full scanner suite | ✓ 103 passed |
| `go build ./...` + scoring tests | ✓ build OK, scoring ok |

Harness: `scripts/validation_v1_replay.py` (CVSS audit), `validation_s1_rescan.py`
(live re-scan), `validation_s1_tally.py` (corpus tally).
