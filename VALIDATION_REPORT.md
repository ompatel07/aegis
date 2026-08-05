# Validation Report — Real Unseen Repo (`github.com/ompatel07/client1`)

A real user scanned an unseen Next.js static-export site (`client1`) and manually
confirmed everything Aegis **found** is true: all 5 CVEs (postcss ×4, sharp ×1) are
true positives with correct version math, 0 false positives, valid CycloneDX 1.7
SBOM, real quality metrics. This report closes the validation loop on three points:
**(1) reachability presentation, (2) false-negative accounting, (3) a SARIF
location polish.** No inflation — where Aegis misses something, it's stated plainly.

Reproduced through the **real-user path** (connect → scan): overall **76 / B**,
security 72, quality 63, deployment 100, 87 findings (5 CVEs + 82 quality).

---

## 1. Reachability presentation — ✅ Aegis distinguishes "present" from "reachable"

The concern was right to raise: the postcss CVEs are real but **low-reachability**
in this app (postcss runs at build time on trusted Tailwind CSS, not on
attacker-controlled input). Aegis's Pass-3 reachability analysis applies here and
**is surfaced to the user** — it does *not* present all CVEs as equally urgent.

| Package | CVEs | `reachable` | `is_direct` | How it's shown |
|---------|:----:|:-----------:|:-----------:|----------------|
| **postcss** 8.4.31 | 4 | **False** | False (transitive) | green **"Not reachable"** badge |
| **sharp** 0.34.5 | 1 | **True** | True (direct) | amber **"Reachable · direct dep"** badge |

**Import/usage-level reachability** (`utils/reachability.py`): postcss is a
**transitive, build-time** dependency — no first-party source imports it — so it's
marked **not reachable**; sharp is a **direct** dependency actually used, so it's
escalated. Build/output dirs (`.next`, `out`, `node_modules`) are excluded from the
"first-party source" that grants reachability.

**Surfaced three ways:**
- **Per-finding badge** (`ReachabilityBadge`): green *"Not reachable"* vs amber
  *"Reachable · direct dep"* on every SCA finding card.
- **Finding detail** (`ReachabilityDetail`): *"Imported / used in code: No · Direct
  dependency: No"* for postcss.
- **Score weighting** (`security_scorer.go`): unreachable **×0.5**, reachable ×1.0,
  reachable+direct **×1.2**. This is why the security score is **72, not lower** —
  the 4 unreachable postcss CVEs are de-weighted; the reachable sharp CVE carries
  full+direct weight. The prioritization signal is real, not cosmetic.

**Verdict:** ✅ **No prioritization gap.** Aegis correctly separates "vulnerable
dependency present" (postcss, de-prioritized) from "vulnerability reachable"
(sharp, escalated) and shows it to the user. The honest limitation is stated in the
code itself: this is **module-level** reachability (is the vulnerable *package*
wired in), not a proof the vulnerable *function* executes on untrusted input — a
strong, honest static approximation, not a runtime taint proof.

---

## 2. False-negative accounting — one real gap, everything else correctly clean

I reviewed `client1` for the common issues a security tool should catch and checked
each against what Aegis flagged. **Aegis's SAST + secrets returned 0 findings**;
here is whether that's accurate, item by item:

| Class | Present in client1? | Aegis | Correct? |
|-------|---------------------|-------|----------|
| **Exposed secrets / env vars** | **No** — no `.env` committed, no hardcoded keys/tokens (only `process.env.QA_ROUTES` in a QA script) | 0 | ✅ correct (nothing to miss) |
| **SSRF in `fetch`** | **No** — 2 fetches, both static/relative URLs (`/search-index.json`, Netlify `/`); no user-controlled URL | 0 | ✅ correct |
| **Insecure form handling / Netlify / honeypot** | **No** — `EnquiryForm` is secure: `data-netlify-honeypot` + hidden honeypot input + client-side validation; submits urlencoded POST to Netlify | 0 | ✅ correct |
| **`dangerouslySetInnerHTML` XSS** | **5 uses** (all JSON-LD `JSON.stringify(schema)` of static product data — low-risk here) | **0** | ✅ **FIXED** — new taint rule catches tainted uses; client1's 5 safe uses stay 0 (see below) |

### The one real false negative — found, then FIXED: React `dangerouslySetInnerHTML` XSS

- client1's 5 instances are the **canonical low-risk pattern** — JSON-LD structured
  data built from **static** product data. Not exploitable, exactly as assessed.
- **But the sink was not covered at all.** A planted **tainted** case —
  `searchParams.q → dangerouslySetInnerHTML={{__html: q}}` (a real Next.js XSS) —
  was flagged **0**. Aegis's JS/TS rulesets (`p/typescript`/`p/javascript`/
  `p/nodejsscan` + Aegis taint rules targeting Express `res.send`) had no React
  `dangerouslySetInnerHTML` rule (even stock `p/react`/`p/xss` returned 0 in test).

**Fix — new taint rule `aegis-react-xss`** (`rules/taint/javascript.yaml`),
precision-safe by construction (taint-mode: fires only when the `__html` value
traces to a user-controlled source; the safe static JSON-LD pattern has no source):

- **Sources:** `useSearchParams()`, `searchParams`/`.get()`, `router.query`,
  `window.location.*` / `location.*`, `$E.target.value` (form input).
- **Sink:** the React `{__html: …}` payload (element-agnostic; that key is used for
  nothing else).
- **Sanitizers:** `DOMPurify.sanitize`, `sanitizeHtml`, `he.encode`,
  `validator.escape`, `escapeHtml`.

**Before → after (verified):**

| Test | Before | After |
|------|:------:|:-----:|
| planted `searchParams.q → __html` (real XSS) | ❌ missed | ✅ **caught** (aegis-react-xss, high) |
| `useSearchParams` / server `searchParams` prop / `location.hash` / `router.query` → `__html` | — | ✅ all fire |
| **client1's 5 real uses** (static JSON-LD) | 0 | ✅ **still 0 (0 FP)** |
| static const, `JSON.stringify(const)`, DOMPurify-sanitized, prop→JSON.stringify | — | ✅ 0 (clean) |
| `vercel/next-learn` (4 files using `dangerouslySetInnerHTML`) | — | ✅ **0 false positives** |

Verified via direct fixtures, `semgrep --test` (**31/31 pass**), the scanner test
suite (**51/51 pass**), and live scans. **Precision-safe: catches real React XSS,
leaves safe patterns clean.**

**Everything else Aegis reported "nothing" on is genuinely accurate** — client1 is a
static export with no secrets, no server-side input handling, and a hardened form.
The 0 SAST / 0 secrets result is correct on the merits, with the single
`dangerouslySetInnerHTML` capability gap noted above.

---

## 3. SARIF CVE location — ✅ FIXED (now points to the exact lockfile line)

**Before:** SCA/CVE findings showed `package-lock.json:` with **no line** — Trivy
does not emit a line/location for dependency-file vulnerabilities (`Locations=None`,
`PkgPath=None`).

**Fix** (`trivy_engine.py`, `_locate_in_lockfile`): a defensive best-effort locator
sets the finding's line by searching the lockfile for the package — **preferring a
line that names both the package and the flagged version**, which disambiguates the
two postcss versions in this lockfile (`8.4.31` transitive at L5305 vs a resolved
`8.5.25` at L6289). Any failure returns no line (no regression to the accurate SCA
engine).

**Result — verified end-to-end in the SARIF export of the real-user client1 scan:**

| Finding | SARIF location (after) |
|---------|------------------------|
| sharp `GHSA-f88m-g3jw-g9cj` | `package-lock.json:5323` |
| postcss `CVE-2026-45623` / `-69153` / `-41305` / `GHSA-r28c-9q8g-f849` | `package-lock.json:5305` |

**Honest note:** `package-lock.json` is machine-generated — the practical fix for a
dependency CVE is `npm update <pkg>` / a version override, not editing that line —
but the exact line now anchors SARIF/IDE navigation, and the finding already
identified the dependency precisely (`package@version` + CVE id).

---

## Summary

| Validation point | Result |
|------------------|--------|
| CVEs found are true positives (user-confirmed) | ✅ (5/5, correct version math) |
| Reachability distinguishes present vs reachable, surfaced to user | ✅ postcss "Not reachable" / sharp "Reachable · direct" + score weight |
| False-negative accounting | ✅ secrets / SSRF / forms correctly clean; the one gap (**React `dangerouslySetInnerHTML` XSS**) is now **FIXED** — new `aegis-react-xss` taint rule, precision-safe |
| SARIF CVE location | ✅ **fixed** — exact lockfile line |

**Bottom line:** on this real unseen repo Aegis is accurate about what it finds
**and** honest about priority (reachability de-weights the build-time postcss CVEs).
The one missed class — React `dangerouslySetInnerHTML` XSS — has been **fixed with a
precision-safe taint rule** (catches tainted uses, leaves the safe static pattern
clean: client1's 5 uses and next-learn's 4 stay at 0 FP). The SARIF location gap is
also fixed. Both the reachability presentation and the accuracy are validated on
real code.
