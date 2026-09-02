# SAST Timeout Fix — Pass T2 (exclude bundled/minified JS from SAST)

Implements **P1** from `SAST_TIMEOUT_DIAGNOSIS.md` (T1): exclude large bundled / minified
third-party JS/TS from semgrep. Not P5 (raising the timeout — that hides the cause).

Commits:
- `c2cef17` fix(performance): exclude bundled/minified third-party JS from SAST
- `b27b0b0` fix(performance): surface the SAST bundled-asset exclusion through to the scan record + UI
- `cf8f9fa` fix(performance): keep excluded_bundled visible when SAST times out

## The detector (`services/scanner/utils/bundled_assets.py`)

Principled, content-based — the T1 offenders were OUTSIDE node_modules/vendor, so a path
list would miss them. Two signals, calibrated on the real files:

| signal | threshold | catches |
|---|---|---|
| minified | mean line ≥ 300 B **or** newline/byte < 0.005 (files ≥ 20 KB) | jquery.min.js and friends |
| large-bundled | single JS/TS file ≥ 300 KB | ace.js (720 KB, *formatted*, mean line 32 — only size separates it), swagger-ui, fontawesome, ckeditor |

Across the V2 corpus no hand-written source exceeded ~40 KB; every scanned JS/TS ≥ 300 KB
was a vendored library. The **load-bearing** unit test is the negative one: a 200 KB
genuinely hand-written, normally-formatted TS file is NOT excluded. 7 unit tests pass.

## CONDITION 1 — SAST-only; fingerprinting still runs (verified)

The exclusion adds `--exclude <path>` to semgrep only. SCA (Trivy) and vendored-library
fingerprinting (`utils/vendored_fingerprint`) walk the tree independently and still scan
these files. Verified end to end: a planted `jquery-1.7.1.min.js` (92 KB) is excluded from
SAST **and** fingerprinted as jquery@1.7.1 → OSV returns its 5 CVEs (CVE-2012-6708,
-2015-9251, -2019-11358, -2020-11023, -2020-7656).

**Gap (pre-existing, non-regressing):** fingerprinting covers a curated set
(jQuery/Bootstrap/PHPMailer/FPDF). Libraries like ace/three.js/dat.gui get no CVE
coverage — but they never did, and their SAST findings were third-party noise. T2 removes
noise, not coverage.

## CONDITION 2 — counted + surfaced, never silent

`excluded_bundled` ({files, bytes, reasons, sample}) flows scanner → orchestrator
(types + aggregator) → `scans.excluded_bundled` JSONB (migration 000029) → API → scan
detail page, modelled on `filtered_secrets`. Shown as a neutral notice
("N bundled/minified files excluded from SAST (M MB) — still scanned by SCA + vendored
fingerprinting") with the file list. **NOT a degradation** — it is correct behaviour, not
lost coverage, so it does not enter `engines_degraded`. `cf8f9fa` also carries the field
on the timeout path, so a scan that excludes and then times out is not silent.

## THE GATE

### No true-positive lost (before/after on the same scanner, `AEGIS_DISABLE_BUNDLED_EXCLUDE`)

Every one of the 9 repos whose SAST completes shows **0 disappeared findings** and 0
disappearances outside the excluded files:

| repo | before | after | Δ | excluded |
|---|---|---|---|---|
| DVWA (ground-truth) | 115 | 115 | 0 | none |
| NodeGoat (ground-truth) | 60 | 60 | 0 | none |
| juice-shop (ground-truth) | 185 (296 s) | 185 (90 s) | 0 | 2 files / 0.9 MB |
| FreshRSS | 101 | 101 | 0 | none |
| redash | 125 | 125 | 0 | none |
| chatwoot | = | = | 0 | none |
| jellyfin | = | = | 0 | none |
| mastodon | 405 | 405 | 0 | none |
| librenms | **timeout / 0** | 199 (342 s) | 0 | 43 files / 6.6 MB |

### Timing for the 6 previously-timed-out repos

| repo | before | after T2 | excluded |
|---|---|---|---|
| WebGoat | timeout | **45 s ✅** | 10 files / 2.3 MB |
| nopCommerce | timeout | **161 s ✅** | (js excluded) |
| nocodb | timeout | **410 s ✅** | (js excluded) |
| TeamPass | timeout | **456 s ✅** | (js excluded) |
| dolibarr | timeout | **still times out ❌** | 168 files / 25.3 MB |
| n8n | timeout | **still times out ❌** | none |

**4 of 6 now complete** (+ librenms, a 7th, rescued). Two remain:

- **dolibarr** excludes 25.3 MB of bundled JS and *still* times out — its residual cost is
  the 77 MB PHP tree (4223 files) under `p/php`, not the JS. T1 over-attributed dolibarr
  to bundled JS. Needs a separate PHP-scope fix, not P1.
- **n8n** excludes nothing (source-only clone; its bundles live in uncloned
  node_modules/dist). Its timeout is genuine TS-monorepo scale, as T1 noted. **Reported
  and stopped — P4 (trimming base packs) not attempted; it needs its own recall gate.**

### WebGoat Java taint recall (V2 gap: was UNMEASURED/timeout — now measured)

WebGoat completes → its Java lessons are now evaluated. Static-detectable classes ARE
caught:

- **SQLi** — across 8 real lesson files (SqlInjectionLesson5a/5b/8/9/10, advanced
  Challenge, mitigation/Servers, challenge5): 8 `formatted-sql-string` + 3
  `tainted-sql-string`.
- **Path traversal** — `httpservlet-path-traversal` in ProfileUploadRetrieval (the
  path-traversal lesson) + `tainted-file-path` in FileServer.
- **SSRF** — `tainted-url-host` in the JWT JKU endpoint.

**But these are REGISTRY (p/java, OWASP) rules.** The Aegis custom Java taint pack
(`aegis-java-sql-injection`, `aegis-java-path-traversal`, …) fired **0** taint findings on
WebGoat (only 1 quality rule, `aegis-bug-java-string-literal-equality`). So suite-level
Java recall is good, but the custom pack contributes nothing on WebGoat's idioms
(`@RequestParam`/`@PathVariable` sources, JDBC Statement sinks) — a **recall gap in the
Aegis java-taint pack** to follow up, separate from T2. Clearest suite miss: Java
command-injection in the lesson source (only caught in a CI workflow yml).

## Suite health

- Detector unit tests: 7/7 pass. Web display tests (incl. never-silent assertions): pass.
- `go build ./...` green (orchestrator + api); web `tsc --noEmit` green.
- Pre-existing, unrelated: `api/internal/services` **test** package fails to build (stale
  refs to removed `AIGeneratedPct`/`InAIGeneratedCode`/`AICodeSafetyScore` fields) —
  present before T2, untouched by it; production code and all other packages build/test green.
