# Pass N2 — stop the product claiming what it cannot see

**2026-10-21.** N1 cut the Semgrep-licensed rules cleanly, and in doing so exposed three
things an evaluator would find in their first session. This pass fixes them.

| # | defect | status |
|--:|---|---|
| A | A Java-only repository could score **Security 100 / grade A** on seven Java rules — not clean, unread | **fixed** — coverage measured, score withheld, gate test asserts it |
| B | `self-scan.yml` red since 2026-08-31; the **Trivy job had never run at all** | **fixed** — 7 of 7 jobs green; Trivy runs (88 findings on its first run), **109 of 112** advisories closed, 3 named and justified |
| C | Dolibarr's first complete scan: **2,362 false XSS findings** | **fixed** — 2,362 → 24, of which **3 are real findings the flood had buried** |
| D | OWASP Benchmark cited as a headline capability number | **withdrawn** from all pitch-facing docs, preserved as labelled history |

---

## A. Per-language coverage, and withholding the score

### A.1 Coverage is counted, not declared

`services/scanner/utils/rule_coverage.py` reads every rule we ship and counts, per
language semgrep would apply it to: rules, families, distinct CWE classes. It moves when
the rule set moves, and `tests/test_rule_coverage.py` fails if the tier table and the
measured rule set disagree.

| language | rules | families | CWE classes | tier |
|---|--:|---|--:|---|
| javascript | 125 | taint 11 + njsscan 114 | 41 | **strong** |
| python | 12 | taint | 10 | limited |
| typescript | 11 | taint | 9 | **strong** |
| java | 7 | taint | 7 | limited |
| go | 7 | taint | 7 | limited |
| php | 5 | taint | 5 | **strong** |
| ruby, csharp, c, cpp, rust, kotlin, scala | **0** | — | 0 | **none** |

### A.2 Where the tiers come from, and the thresholds

Grounded in the N1 per-language measurement (`docs/RULE_REMOVAL_N1.md` §C.3), which ran
before and after the cut on 15 real repositories plus five documented-vulnerability corpora:

- **strong** — php, javascript, typescript. Our packs are proven to fire on the classes
  they target across **more than one** real repository: PHP on DVWA (3/6 documented, +31
  findings), librenms and FreshRSS; JS on NodeGoat (5/7); TS on juice-shop (7/25) and
  nocodb. JavaScript additionally has real class breadth (41 CWE classes) because njsscan
  covers crypto, cookies, headers and DoS on top of taint.
- **limited** — java, python, go. Rules exist and fire, but only for the injection/taint
  families, on thinner evidence: Java 6/6 on WebGoat yet inert on every Java repository
  before T3 and only 10 % of pre-cut finding volume retained; Python 24 % retained;
  **Go has no measured yield on real code at all** — V2 contained no Go repository.
- **none** — everything else. Zero shipped security rules.

> **"Strong" means proven, not broad.** PHP is five rules covering five CWE classes. A PHP
> repository with no findings may still hold deserialisation, XXE, SSRF or file-upload
> flaws we have no rule for. The tier says our rules work where they aim, not that they
> aim everywhere — and the report says so on every scan.

**The confidence threshold is a strict majority of strongly-covered code, by LOC**
(`CONFIDENT_STRONG_FRACTION = 0.5`). Two deliberate choices:

- *A majority of `strong`, not a weighted blend.* The score answers "did we look hard at
  this code?" A blend lets a thinly-covered majority hide behind a well-covered minority —
  exactly the inflation being fixed. Half-strong/half-uncovered is **not** confident.
- *LOC, not file count.* One 5,000-line Java service and fifty one-line JS config files are
  not equal halves of a repository.

Measured against the real corpus shapes:

| repo shape | strong fraction | confident? |
|---|--:|---|
| Java only | 0.00 | **no** — "Java limited" |
| C# only (jellyfin) | 0.00 | **no** — "C# none" |
| Ruby + JS (mastodon) | 0.21 | **no** — 79 % Ruby, no rules |
| Python + JS (redash) | 0.33 | **no** |
| PHP (DVWA, Dolibarr) | 1.00 | yes |
| TS + JS (juice-shop) | 1.00 | yes |

### A.3 How the score is withheld — the existing contract, no new state

When coverage is not confident, `aggregator.go` sets `SecurityScore` and
`SecurityRating` to **nil**, exactly as a degraded engine already does (P4b/C1). The
overall renormalises over the remaining pillars and the web layer renders it **PARTIAL
with a mandatory qualifier**. Nothing new was invented.

Thin coverage is deliberately **not** reported as a degraded engine: nothing
malfunctioned, so claiming an engine failed would be its own small lie. The UI's
`notMeasuredReason()` therefore falls back to the coverage gap, so the pillar never reads
"Not measured" with no reason — the C3 defect.

### A.4 Where it is shown

| surface | what it shows |
|---|---|
| Scan detail page | a card on **every** scan — "Security coverage: PHP strong; Java limited", the LOC split per tier, per-language detail (rules + CWE classes), and what runs regardless of language. Amber, with the gap stated, when not confident |
| Compliance report | a banner above the control table. An auditor reading "no findings" against an injection control is told whether we can read the language, and when we cannot: *"treat an absence of SAST findings against the controls below as unmeasured, not as evidence of compliance"* |
| Executive summary | the caveat in the **first paragraph**, not a field further down |
| AI-written summary | coverage is in the model's digest — without it the model writes confident prose about a clean result on a codebase we never read |
| API | `scans.security_coverage` (migration 000032) |

### A.5 The gate

`TestJavaOnlyRepoWithNoFindingsIsNotAConfidentA` asserts it on real `Aggregate` output,
the way C1 asserted degraded-must-not-outscore-complete. Run against the pre-N2 logic it
fails with precisely the defect:

```
security score is 100 on a Java-only repo we barely cover; it must be nil
security rating is "A"; a worst-severity letter over an unread codebase is a fabricated A
```

Plus: a strongly-covered repo still scores; a pre-N2 scanner (no coverage reported) keeps
the old behaviour rather than withholding everything; a failed engine still withholds
even on strong coverage; and on the scanner side, the tier table cannot drift from the
measured rule set (10 tests).

**One defect found in my own code.** The silent-degradation guard rejected
`_count_lines` returning `0` from an `except` handler: an unreadable Java file would have
counted as zero Java lines and could have flipped the confidence decision *towards*
"covered". It now returns `None`, and unreadable files are counted and reported.

---

## B. Self-scan

### B.1 Trivy — it had never run

`trivy-action@v0.28.0` depended on `setup-trivy@v0.2.1`, which GitHub can no longer
resolve, so the job failed at action-resolution on every push. Pinned to
`trivy-action@v0.36.0` by SHA (which pins `setup-trivy@v0.2.6`).

**Its first real run found 88 issues** — 84 vulnerabilities and 4 misconfigurations. It
had been silent, not clean.

### B.2 Dependencies — 109 of 112 advisories closed

| ecosystem | before | after | what moved |
|---|--:|--:|---|
| Go (both services) | 24 CVEs + 2 govulncheck-only | **0** | go-redis 9.7.0→9.7.3 (GO-2025-3540, found by govulncheck not Trivy), the toolchain to **1.26.10** (GO-2026-6809 in `crypto/x509`), go-git 5.13→5.19.2, go-billy 5.6→5.9.2, x/crypto 0.50→0.55, x/net 0.53→0.58, x/text 0.36→0.41, x/mod 0.34→0.40, golang-jwt 5.2.1→5.2.2, goxmldsig 1.4→1.6 |
| npm | 22 (2 critical) | **1** | next 14.2.35→15.5.28, next-auth patched, postcss → 8.5.31 and postcss-selector-parser → 7.1.7 forced tree-wide via `overrides`, plus `npm audit fix` |
| pip | 22 in 4 packages | **2** | fastapi 0.115.6→0.135.4 with starlette pinned to 1.3.1 (clears all 7 starlette advisories), setuptools 75.6→**80.9.0** (see §B.5), pytest 8.3.4→9.0.3, pytest-asyncio 0.25→1.3 |
| Trivy misconfig | 4 | *(see B.4)* | Helm `readOnlyRootFilesystem` |

Each upgrade was verified, not assumed: `go build`, `go vet` and the full Go suites
**including the live-Postgres API seams** pass; the web typecheck, unit tests and a real
`next build` pass; the scanner suite passes on a rebuilt image.

Two upgrades needed a second step rather than a bigger version number:

- **`x/net` stopped at 0.58.0.** 0.60.0 (which one advisory names) requires Go ≥ 1.26 and
  the project targets 1.25. Raising the toolchain is a separate change.
- **`pytest` 9 needed `pytest-asyncio` 1.3.0** — the old pin capped pytest below 9.

### B.3 The three that remain, each named

`npm audit --audit-level=high` and a bare `pip-audit` are all-or-nothing: either the job
is red on something nobody can act on, or someone raises the threshold and every future
advisory is absorbed silently. Both happened here. So
`scripts/check_dependency_audits.py` gates on a **per-advisory allowlist**: every
tolerated advisory is named with the reason and what would change it, and **anything not
on the list fails the build**.

| advisory | package | why it is tolerated |
|---|---|---|
| GHSA-vfj7-8cjw-p6xm<br>CVE-2026-93687 | braces ≤3.0.3 | **No fixed version exists at any release.** Reaches us only through `tailwindcss@3.4.15`'s build-time file watcher (chokidar) and glob matcher (micromatch) — verified with `npm ls braces`. Tailwind runs at build time over glob patterns *we* author, against paths in our own repository; no attacker-supplied value reaches it. Exploiting it needs write access to the repo or build config, at which point the glob is not the weakness. Fixed by tailwindcss 4.x, a CSS-first-config migration whose result cannot be verified without looking at the rendered UI — deliberately a separate pass, not a blind upgrade inside N2 |
| PYSEC-2026-3447 | setuptools 80.9.0 | Fixed only in 83.0.0, which **cannot be installed**: setuptools 81 removed `pkg_resources`, which semgrep needs at runtime. N2 tried it and CI caught the outage — see §B.5. setuptools is a build/runtime shim, not a request-path component |
| PYSEC-2026-1805 | protobuf 4.25.9 | Blocked by **semgrep 1.97.0**, whose `opentelemetry-exporter-otlp-proto-http` dependency pins protobuf < 5. `pip install semgrep==1.97.0 protobuf==5.29.6` is `ResolutionImpossible`. Bumping semgrep changes findings, and N1's rule is that an engine bump must not land in a pass that also changes rules (this one does, Part C) or the regression is unattributable |

**Nothing Go-related is on this list.** `x/net` initially stopped at 0.58.0 because
0.60.0 requires Go ≥ 1.26; rather than document that advisory, the toolchain moved to
1.26.10 and it is closed. The same applies to the `braces` entry carrying two
identifiers: Trivy keys on the CVE alias and npm on the GHSA id, so one exception is
named twice rather than either gate being widened.

### B.4 Trivy's four misconfigurations

`KSV-0014` — *root filesystem is not read-only* — on `datastores.yaml` (×2),
`orchestrator.yaml` and `scanner.yaml`. See §B.5 for what was done.

### B.5 A P0 I introduced, and CI caught

The setuptools bump in this pass was itself a defect. **setuptools 81 removed
`pkg_resources`**, which semgrep imports at runtime through
`opentelemetry-instrumentation` (pinned by semgrep 1.97.0). Bumping 75.6.0 → 83.0.0 to
clear a CVE made semgrep crash on startup, so **every rule test failed in CI** —
`ModuleNotFoundError: No module named 'pkg_resources'`. That is the scanner's entire SAST
path, not a hardening gap.

`requirements.txt` already carried a comment saying semgrep needs `pkg_resources` from
setuptools. I bumped past it anyway while chasing a version number. It is now a
DO-NOT-BUMP with the boundary, the failure mode, and a pointer to the justification.

Pinned to **80.9.0** — the newest release that still ships `pkg_resources` — which keeps
the PYSEC-2025-49 fix. PYSEC-2026-3447 (fixed only in 83.0.0) joins the named list, with
the same root cause as protobuf: semgrep's OpenTelemetry pin.

This is precisely the risk the brief named — *"dependency bumps are exactly how P0s sneak
in"* — and the reason every upgrade here was re-verified rather than assumed. It is also
an argument for the per-advisory gate over a severity threshold: a threshold would have
let me keep a product-breaking upgrade in exchange for a tidier audit score.

### B.6 Final state

| check | result |
|---|---|
| `aegis-self-scan` | **7 of 7 green** on `d7d58b6` — including a Trivy job that had never run, and govulncheck |
| Scanner suite (in the rebuilt image) | **278 passed, 4 skipped, 0 failed**. The three "ruff binary not available" skips are gone with the rebuild, leaving K1's four audited skips |
| Go suites + API seams (live Postgres) | green on Go 1.26.10, both services |
| Web | `tsc --noEmit` clean, 22 unit tests pass, real `next build` succeeds on Next 15 |
| `semgrep --test` | 4/4 compose rules, 42/42 taint pack |

Two findings only govulncheck caught, which Trivy missed — proof the two jobs are not
redundant:

- **GO-2025-3540**, `redis/go-redis` 9.7.0 → 9.7.3, reachable from
  `ProgressHandler.Stream` → `redis.Client.Subscribe`.
- **GO-2026-6809** in the **toolchain**, not a dependency: `crypto/x509` in go1.26.9,
  fixed in go1.26.10. `setup-go` with `"1.26"` resolved to `.9`, so both workflows now
  pin the patch.

---

## C. The Dolibarr false-positive flood

### C.1 How Dolibarr actually sanitises PHP_SELF

`htdocs/main.inc.php:58` loads `htdocs/waf.inc.php` on every page. At **file scope** —
not inside a function anything has to remember to call — it does:

```php
if (!defined('NOSCANPHPSELFFORINJECTION') && !empty($_SERVER["PHP_SELF"])) {
    $morevaltochecklikepost = array($_SERVER["PHP_SELF"]);
    analyseVarsForSqlAndScriptsInjection($morevaltochecklikepost, 2);
}
```

and for `$type == 2` rejects any request whose `PHP_SELF` matches
`/[:;"\'<>\?\(\){}\$%#]/` or contains `..`, then dies. Nothing in the tree defines
`NOSCANPHPSELFFORINJECTION`. With quotes and angle brackets refused, `PHP_SELF` cannot
break out of an HTML attribute or open a tag.

**Is it expressible as a sanitizer?** No. Semgrep's taint is per-file and
intraprocedural, so a guard in an included file is invisible at the sink — there is no
local expression to match.

**It is expressible as a source constraint**, which is what was done, reusing the
mechanism `_php_escaper_wrappers` already established: read the project, and if the
guard is there, drop `$_SERVER['PHP_SELF']` from `aegis-php-xss`'s sources **for that
scan only**. Every other source is untouched, so a `$_GET`-sourced XSS in the same file
still fires.

The detector is deliberately narrow, because a wrong positive here *silences* a real
vulnerability class. All three must hold in one file: it reads `$_SERVER['PHP_SELF']`; it
applies a `preg_match` character class rejecting **both** angle brackets and a quote; and
that file also calls something at file scope, so the guard is reached rather than merely
defined.

### C.2 Before and after

| repo | `aegis-php-xss` before | after | total SAST before → after |
|---|--:|--:|---|
| **Dolibarr** | **2,362** | **24** | 2,652 → 317 |
| DVWA | 1 | **1** | 32 → 32 |
| TeamPass | 2 | **2** | — → 153 |
| FreshRSS | 0 | 0 | — |

The detector fires on Dolibarr (`htdocs/waf.inc.php`) and on **none** of DVWA, TeamPass
or FreshRSS. The PHP_SELF true positives the brief required to survive both do:

- TeamPass `public/install/upgrade.php:281` and `:553` — reflected XSS via
  `$_SERVER['PHP_SELF']` + `HTTP_HOST`. **Kept.**
- DVWA `vulnerabilities/csp/source/jsonp.php:12` — `$_GET['callback']`, unaffected by
  construction. **Kept.**

Neither repo had any adjustment applied (`project_adjustments: None`), which is the point:
the suppression is not a global softening of the rule, it is specific to a project that
demonstrably filters the source.

### C.3 Hand-triage of the 24 that remain

| verdict | n | detail |
|---|--:|---|
| **TP** | **3** | `adherents/card.php:1064` — `$_SERVER['HTTP_REFERER']` into an `<input value="…">` unescaped; `core/lib/website.lib.php:565` and `install/inc.php:666` — `$_SERVER['REQUEST_URI']` printed into HTML. **The WAF filters `QUERY_STRING` and `PHP_SELF`; it does not filter `REQUEST_URI` or `HTTP_REFERER`** |
| UNCERTAIN | 1 | `openid_connect/callback.php:89` — a cookie value through `dol_escape_js` into a JS string literal. Quotes are escaped; `</script>` is **not**, so a breakout is conceivable |
| FP | 20 | 11 are `dol_escape_js`-escaped values sourced from app config (`getDolGlobalInt/String`) or `$_SESSION`, not request data; 9 are DB/menu/literal values (`$menu['style']`, `$websitepage->pageurl`, `$warehouseid`, translation strings) |

**The flood was burying real bugs.** Three genuine findings were invisible inside 2,362,
and the two REQUEST_URI ones are the same class as the PHP_SELF class Dolibarr took care
to filter — it simply filters the wrong two `$_SERVER` keys.

`dol_escape_js` was deliberately **not** added as a sanitizer. It escapes quotes but not
`<`, so it does not make a value safe inside a `<script>` block; treating it as an
escaper would have converted a real class into silence.

### C.4 Not fixed here, and why

A repository with the same idiom but **no** filter would still produce thousands of
findings for one source repeated across thousands of files. That is a presentation
problem, not a detection one, and the fix is to collapse findings that share a single
source into one finding with N occurrences — which changes fingerprints and therefore
lifecycle history. It belongs in its own pass, and is recorded as such.

---

## D. The OWASP Benchmark claim

Removed from the headline of `docs/ACCURACY.md` and from `README.md`. Neither number may
be cited as a current capability:

- **pre-N1 (F1 0.775 / Youden 0.459)** — produced by rules we no longer ship;
- **post-N1 (F1 0.247 / Youden 0.051)** — real, but it scores *synthetic Java*, the one
  language where our coverage is thinnest. Citing it would be as misleading in the
  pessimistic direction as the old number was in the optimistic one.

Both are preserved with their method, source and dates under **"Superseded benchmark
history"** at the end of `ACCURACY.md`, labelled as history and not for citation. The
seven historical documents that quote the pre-N1 figures keep their N1 SUPERSEDED
banners.

What replaces it: per-language coverage (§A), ground-truth recall (22 of 45 documented
vulnerabilities, `RULE_REMOVAL_N1.md` §C.2), and hand-triaged precision (§C.4 there).
Rebuilding a benchmark claim needs the Java rules in §E of that document first.
