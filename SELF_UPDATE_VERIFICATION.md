# Self-Update & P1/P2 Integration Verification

Honest, evidence-based verification (real feed timestamps + real scans, no
inflation) of two things before launch:

1. **Does Aegis stay current on the LATEST KNOWN vulnerabilities automatically?**
   (Part 1 — it must never miss what's already published/known; it does not, and
   does not claim to, invent zero-days.)
2. **Do all the recent P1/P2 changes work together end-to-end with no regression?**
   (Part 2.)

Verified **2026-08-13**. Where a mechanism is *not* automatic or depends on
something (e.g. network at scan time), it is called out plainly.

---

# PART 1 — Self-updating for new/current vulnerabilities

## A) CVE / dependency updates (KNOWN vulns in libraries) — automatic

### 1–2. Intelligence feeds are live and current (real timestamps)

`intelligence_sync_log`, last successful sync per source (queried 2026-08-13 ~11:04 UTC):

| Source | Last sync (UTC) | Ago | Status | This run |
|--------|-----------------|-----|--------|----------|
| **NVD** | 2026-08-13 10:21 | ~43 min | success | +0 added / +1000 updated (an earlier run **today** added **+63**; a prior-day run **+104**) |
| **OSV** | 2026-08-13 10:16 | ~48 min | success | **+7 added** / +350 updated |
| **GHSA** | 2026-08-13 10:15 | ~48 min | success | +0 / +100 updated (earlier runs +5, +12) |
| **Semgrep (catalog)** | 2026-08-13 10:16 | ~48 min | success | rule catalog refresh |

`cve_database`: **12,697 CVEs** (NVD 11,897 + OSV 318 + GHSA 482). Newest CVE
`modified_date` = **2026-08-13 09:17** (today); newest `published_date` =
2026-08-12. **Genuinely fresh, not a stale snapshot.**

**CISA KEV** (`utils/kev.py`, live refresh): catalog version **2026.08.11**,
**1,665 entries** — current (KEV publishes every few days). Refreshed on scanner
boot and every 6 h (scanner logs show repeated `kev.refreshed … version=2026.08.11`).

### 3. Trivy vuln DB auto-updates (not pinned)

Trivy DB `metadata.json` in the live cache:
`{"UpdatedAt":"2026-08-13T07:15:41Z","DownloadedAt":"2026-08-13T09:59:53Z","NextUpdate":"2026-08-14T07:15:41Z"}`
— built today, downloaded today ~1 h ago, next update tomorrow. The scan-time
`trivy fs` command carries **no `--skip-db-update`**, and a boot + 6 h loop runs
`trivy image --download-db-only` (scanner logs: `rulepack.trivy_db_refreshed`).
**Trivy's own DB is the primary scan-time CVE source and it auto-updates on a
24 h cycle** — independent of the NVD/OSV/GHSA feeds above (which drive retroactive
re-flagging + display).

### 4. Retroactive re-scoring — re-proven live

Exercised the **real** `FlagAffectedScans` query against a real recent scan
(`7065ae0f…`, uses `minimist`):

1. Reset it to `needs_reeval = FALSE` (baseline: not flagged).
2. Simulated a newly-published CVE affecting `minimist` via the exact
   `FlagAffectedScans` UPDATE → the scan flipped to **`needs_reeval = TRUE`** with
   reason *"New vulnerability CVE-RETRO-2026-TEST affects a dependency in this scan."*
3. Negative control: a package **not** in the scan matched **0** rows (no false flag).
4. Restored original state.

**A newly-published CVE for a library a customer already scanned retroactively
flags that past scan.** ✅

### 5. Cadences actually fire on schedule (not just manual)

`intelligence/syncer.go` `Scheduler.loop`: a staggered first run on boot, then a
`time.NewTicker(src.Interval())` fires each source **continuously**. Wired in
`orchestrator/cmd/main.go` (`NewScheduler(...).Start(intelCtx)`) with intervals
**NVD 24 h, OSV 6 h, GHSA 24 h, Semgrep 7 d**. The sync-log history shows multiple
independent runs today (10:15, 09:58) and on prior days — evidence the loop fires,
not just a one-off manual trigger. Scanner-side, the KEV + Trivy-DB refresh loop
(`main.py _rulepack_refresh_loop`) runs on boot + every 6 h.

### 6. "A CVE published today for a library a customer uses" — will it get flagged?

**Yes, by two independent paths, proven:**

- **Next scan (primary).** Trivy's DB auto-updates (≤24 h), so a scan run **today**
  already flags **2026-published CVEs** — the integration scan below flagged
  `CVE-2026-25639`, `CVE-2026-34477`, `CVE-2026-34480`, `CVE-2026-40175`, plus a
  KEV Log4Shell `CVE-2021-44228`. A CVE lands on the next scan once Trivy's DB
  carries it (within its 24 h cycle; immediately if already present).
- **Retroactive (past scans).** The feed scheduler ingests new CVEs (OSV ≤6 h,
  NVD/GHSA ≤24 h) and `FlagAffectedScans` marks affected past scans
  `needs_reeval = TRUE` (proven in §4).

**Honest boundary / dependencies:** scan-time freshness depends on the scanner
having **network access** to fetch Trivy DB updates; the retroactive path depends
on the orchestrator running continuously so the tickers fire. Both hold in a
normal always-on deployment. Latency is bounded by the cadences above (worst case
~24 h from publication to detection), not instant.

## B) SAST rule updates (new vulnerability PATTERNS)

### 1–2. How registry rules stay current — they are fetched, not pinned

The scanner runs `semgrep scan --config p/owasp-top-ten --config p/python …` per
scan. Verified live:

- The semgrep registry is **reachable at scan time** (`https://semgrep.dev/api/registry/rules`
  → **HTTP 200**).
- The configured `SEMGREP_RULES_CACHE_DIR` (`/opt/aegis/cache/semgrep`) is **empty**
  and `~/.semgrep` holds only a log + settings (no persisted rule cache).

⇒ **`p/*` registry rulesets are pulled from the semgrep.dev registry at scan
time, not pinned to the image.** A **new registry rule for a new pattern reaches
Aegis automatically on the next scan — no image rebuild required.** The Semgrep
`SemgrepSource` (7 d) does **not** gate this; it only catalogues the current rule
list into `rule_registry` for display.

**Honest dependency:** this requires **network access at scan time**. If the
scanner is offline, semgrep cannot fetch `p/*` and SAST degrades to whatever it
can resolve (the custom `aegis-*` rules, which are bundled, still run).

### 3. Custom `aegis-*` rules all load + fire in the current build

**52 bundled custom rules**, all green on `semgrep --test` in the running image:

| Pack | Count | `--test` |
|------|------:|----------|
| `rules/taint` (Py/JS/TS/Go/Java/**PHP**) | **36** | 36/36 ✓ |
| `rules/ai_code_taint` (JS + Python) | 12 | 12/12 ✓ |
| `rules/iac` (docker-compose) | 4 | 4/4 ✓ |

(52 = 36 + 12 + 4. The earlier "48" counted taint + AI-code only, excluding the 4
IaC compose rules.) The 5 new `aegis-php-*` rules are included and fire (see Part 2).

### 4. Honest boundary — new PATTERNS

For a genuinely new vulnerability **pattern**, detection reaches Aegis by exactly
two paths:

1. **Semgrep publishes a registry rule** for it → **automatic** on the next scan
   (registry is live-fetched, §B.1).
2. **We write a custom `aegis-*` rule** → requires a code change + image rebuild.

**Aegis does NOT auto-learn or infer new patterns it has no rule for.** There is
no ML that invents detections for novel patterns; the ML classifier only scores
*existing* findings' false-positive likelihood. So the honest claim is: *Aegis
stays current on known vulnerability patterns published to the Semgrep registry
(automatically) and on our curated custom rules (on release) — it does not detect
a brand-new pattern that neither the registry nor a custom rule covers.*

---

# PART 2 — All recent P1/P2 changes work together (single real scan)

One comprehensive upload (PHP + Python + `pom.xml` with log4j + `package-lock.json`
with a transitive vuln + a private key + a complex module + a docker-compose),
scanned **twice**. **51 findings** each run.

| # | Feature | Result |
|---|---------|--------|
| 1 | **P1a lifecycle** | Every finding carries a `fingerprint` + `lifecycle_status`; scan 1 = all `existing` (baseline), scan 2 (unchanged) = all `existing` — no phantom new. |
| 2 | **P1b CISA KEV** | `CVE-2021-44228` + `CVE-2021-45046` (Log4Shell) flagged `kev=true`; all non-KEV CVEs clean. |
| 3 | **P1c inline snippets** | 44/51 findings carry a code snippet; the private-key secret snippet is **redacted** (`MIIE…REDACTED`). The 7 without are `pom.xml` CVE findings whose exact Maven line isn't located (best-effort locator; `package-lock.json`/`requirements.txt` CVEs do get snippets) — pre-existing, not a P1/P2 regression. |
| 4 | **P2a PHP taint** | `aegis-php-sql-injection` fired on `vuln.php`. |
| 5 | **P2b EPSS + dep path** | 37 CVEs carry `epss_score`; the transitive lodash vuln shows `your app → wrapper@1.0.0 → lodash@4.17.11`. |
| 6 | **P2c typing + ratings** | issue types `{vulnerability: 49, code_smell: 2}`; scan rated **Reliability A / Security E / Maintainability E**. |
| 7 | **No engine regression** | SAST (semgrep + aegis-php), SCA (trivy), secrets (gitleaks), IaC (`aegis-compose-privileged`), quality all fired correctly. (Deployment engine N/A for an upload with no deploy target.) |
| 8 | **Determinism** | Same repo scanned 2× → **51 = 51** findings and a **byte-identical fingerprint set**. The P1/P2 additions did not break determinism. |

**All P1/P2 changes are live and consistent, with no regression.**

---

## Honest flags for launch

- **Scan-time freshness needs network.** Trivy DB updates and Semgrep registry
  rules are both fetched over the network; an offline scanner degrades (Trivy uses
  its last-downloaded DB; semgrep falls back to bundled custom rules).
- **Detection latency is bounded by cadence, not instant** — worst case ~24 h from
  a CVE's publication to it appearing (Trivy 24 h / NVD-GHSA 24 h / OSV 6 h).
- **New *patterns* are not auto-learned** — only registry rules (automatic) or new
  custom rules (on release) add pattern coverage. No overclaim of zero-day/novel-
  pattern detection.
- **Custom rules + the semgrep binary version update only on image rebuild** (the
  *registry rules* they run alongside do not).
- **Minor:** SCA inline snippets aren't located for `pom.xml` (Maven XML) targets;
  other lockfile formats are fine.
