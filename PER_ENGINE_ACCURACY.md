# Per-Engine Real-World Accuracy + False-Negative Report

**Phase 2F pre-launch hardening, Pass 3 of 6.** Engine-by-engine confirmation that
each performs in **real-world use** as its scorecard claims, with a specific focus
on **false negatives** (missed real vulnerabilities) — the highest-stakes error
type for a security tool.

Every result below is a **live run** against the running scanner (semgrep 1.97.0,
trivy 0.71.2, gitleaks 8.21.2), using real known-vulnerability test sets, not
synthetic-only. Where a real gap was found it is stated plainly; where a probe
turned out to be a false alarm, that is stated too (no inflation either way).

Scorecard cross-referenced: [ACCURACY_VALIDATION.md](ACCURACY_VALIDATION.md).

---

## Verdicts at a glance

| # | Engine | Claim | This pass (real runs) | Verdict |
|---|--------|-------|-----------------------|---------|
| 1 | **SAST** (Semgrep + Aegis taint) | F1 0.775 / recall 88.4% | **10/10** canonical CWEs caught across Py/JS/Go/Java, 0 FN | ✅ **PASS** |
| 2 | **SCA** (Trivy) | 100% precision | **6/6** pinned known-CVE packages flagged (40 CVEs); reachability correct | ✅ **PASS** |
| 3 | **Secrets** (Gitleaks) | precision 1.00 / recall 0.92 | reproduced exactly; **new FN: DB connection strings + JWT signing secrets missed** | ⚠️ **CONCERN** |
| 4 | **IaC** (Trivy + Aegis compose) | 9/9 recall, 0 hi-FP | 9/9 + S3 public buckets + K8s host/root all caught | ✅ **PASS** |
| 5 | **Taint / dataflow + SoR** | 144/144 nodes | intra-fn taint + **SoR 6/6 nodes match real code**; cross-fn/file benign-sink missed | ✅ **PASS** (scope) |
| 6 | **Deployment** | 4/4 builds | 4/4 + missing-dependency build correctly failed | ✅ **PASS** |
| 7 | **Code Quality** | metrics exact | CC/params integer-exact; suggestions specific + actionable | ✅ **PASS** |
| 8 | **CVE Intelligence** | live + retro re-score | 4 feeds synced today; retro re-score proven; no false flags | ✅ **PASS** |

**One CONCERN (Engine 3)** — a real, common, fixable secret false-negative beyond
the already-documented bare-AWS gap. Everything else passes on real-world code.

---

## Engine 1 — SAST (Semgrep + Aegis taint) — ✅ PASS

- **OWASP recall 88.4% / F1 0.775** — cross-referenced from Pass 1 (determinism +
  regression: the saved OWASP TP/FP/FN/TN did not move). The Phase-2D recall-safe
  FP tuning is byte-identical on the OWASP corpus (§2 of the scorecard), so it
  introduced **no** false negatives — recall is still 88.4%.
- **Cross-language false-negative probe (the new work).** Planted canonical,
  clearly-vulnerable source→sink code — one file per language:

  | Language | Planted CWEs | Result |
  |----------|--------------|--------|
  | Python | SQLi, command-injection, path-traversal | **all 3 caught** |
  | JavaScript | SQLi, command-injection, reflected XSS | **all 3 caught** |
  | Go | SQLi, command-injection | **both caught** |
  | Java | SQLi, command-injection | **both caught** |

  **10/10 planted real vulnerabilities detected, 0 false negatives.** The Aegis
  custom **taint-mode** rules (`aegis-py/js/go/java-sql-injection`,
  `aegis-*-command-injection`, `aegis-js-xss`) fired cross-language alongside the
  registry rules — corroborating detection, not single-rule reliance.

---

## Engine 2 — SCA (Trivy) — ✅ PASS

- **100% precision** — cross-referenced (40/40 OSV-verified on the scorecard).
- **Known-CVE false-negative probe.** Pinned six packages to specific
  **known-vulnerable versions** and confirmed every one is flagged:

  | Package@version | CVEs flagged | A named CVE present |
  |-----------------|-------------:|---------------------|
  | Jinja2 2.10 | 6 | CVE-2019-10906 ✓ |
  | PyYAML 5.1 | 3 | CVE-2020-1747 ✓ |
  | urllib3 1.24.1 | 12 | CVE-2019-11236 ✓ |
  | Flask 0.12.2 | 4 | CVE-2018-1000656 ✓ |
  | requests 2.19.1 | 5 | CVE-2018-18074 ✓ |
  | cryptography 2.3 | 10 | CVE-2020-25659 ✓ |

  **6/6 known-vulnerable packages flagged (40 CVEs), no known CVE missed.**
- **Reachability works.** The app imported `yaml` + `requests` but only *declared*
  the other four. Findings carried `reachable=True` for the imported packages and
  `reachable=False` for the declared-but-unused ones — exactly the discrimination
  the scorer needs to prioritize reachable, direct-dependency CVEs.

---

## Engine 3 — Secrets (Gitleaks) — ⚠️ CONCERN

- **Precision 1.00 / recall 0.92 reproduced exactly** on the 12-planted + 8-decoy
  corpus (11/12 TP, 0/8 FP). All decoys (AWS docs example key, placeholders,
  UUID, git SHA, MD5, base64, env lookups) correctly ignored.
- **The one documented miss reproduced:** the bare **AWS secret access key**
  (40-char blob with no paired `AKIA…` id) — inherent, information-theoretically
  indistinguishable from any base64 string.
- **New false-negative found (the concern).** A supplemental probe of formats the
  original corpus didn't cover:

  | Format | Detected? |
  |--------|-----------|
  | `postgres://user:pass@host/db` connection string | ❌ **missed** |
  | `mysql://…`, `mongodb+srv://…`, `redis://…:pass@…` | ❌ **missed** |
  | JWT **signing secret** (named var, secret value) | ❌ **missed** |
  | Azure AccountKey, SendGrid, Twilio | ✅ detected (generic/provider rule) |

  **Database connection strings with embedded credentials are a common, high-value
  real-world leak vector — and none of the four URI schemes were detected.** This
  is *beyond* the known bare-AWS gap. It is **fixable now** with a targeted,
  high-precision Gitleaks custom rule (`scheme://user:password@host` where the
  password is not a placeholder) — the `://…:…@` shape is a strong signal that
  won't hurt the 0-FP precision. **Reported, not fixed** (per the "report before
  fixing" rule); recommended for a fast follow-up.

---

## Engine 4 — IaC (Trivy + Aegis compose rules) — ✅ PASS

- **9/9 recall reproduced** across Dockerfile / Terraform / Kubernetes /
  docker-compose (latest-tag, root user, unencrypted/public, open security group,
  privileged, hostPath, exposed 0.0.0.0 port, SYS_ADMIN), **0 high/critical FP**
  on hardened files, example-dir scoping intact.
- **Supplemental FN probe.** Explicit **S3 public-read bucket** (AVD-AWS-0086/87/88
  + public-access ACL) → **8 findings, 6 HIGH, caught**; **K8s hostNetwork,
  hostPID, allowPrivilegeEscalation, runAsNonRoot=false** → **all caught** (19
  findings on the pod).
- **Honest note (a false alarm I chased down, not a gap).** An initial S3 probe
  reported 0 findings — that was **my own malformed, compressed one-liner HCL**
  which Trivy's HCL parser silently parses to nothing. Re-tested with
  conventionally-formatted HCL (what `terraform fmt` produces, i.e. every real
  repo), the scanner catches all 8. So: **no S3 gap** — verified before reporting.
  The only residual is Trivy's parser being formatting-sensitive on unusual HCL,
  which real-world Terraform doesn't trigger.

---

## Engine 5 — Taint / dataflow + Steps-of-Reproduction — ✅ PASS (on claimed scope)

- **SoR is real and accurate.** Scanned the `vulnerable_app` fixture: 6 taint
  findings carried steps-to-reproduce (source / flow / sink / cwe / why_exploitable
  / example_input, built from Semgrep's `--dataflow-traces`). Every SoR **source
  node's `file:line:code` matched the actual fixture code — 6/6.** E.g.
  `aegis-py-command-injection` source = `host = request.args.get("host")` (L35) →
  sink `os.system(...)` (L37). Not fabricated; omitted entirely on non-dataflow
  findings.
- **Intra-function taint caught with SoR** (source + sink in one function):
  `aegis-py-sql-injection` fires, SoR present. ✓
- **The honest false-negative boundary.** A **cross-function** flow into a sink
  that is **benign in isolation** (`cur.execute(v)` where `v` is a bare parameter,
  tainted only via another function) was **NOT caught** (0 findings). The fast
  (Semgrep-OSS) taint engine is **intra-procedural**: it does not track taint
  across function/file boundaries. This is the **shelved-Joern deep-scan gap**,
  already documented. Mitigation in practice: vulnerabilities whose sink is
  independently suspicious (string-concat in a query, `os.system` on a variable)
  are still caught by pattern rules — just without a SoR flow. What's missed is the
  narrow case where the sink looks safe on its own and only a cross-procedural
  dataflow reveals the taint.

---

## Engine 6 — Deployment testing — ✅ PASS

- **4/4 reproduced** — good Go/Node builds pass (no `build-failed`), broken
  (syntax-error) Go/Node builds emit a **CRITICAL `build-failed`** with the real
  compiler message.
- **Missing-dependency FN probe (new).** A Go module importing a nonexistent
  package → **CRITICAL build-failed** finding carrying the real `go build ./...`
  output (`main.go:2:8: …`). So both broken-build classes tested — **syntax error
  and missing dependency — correctly fail.** Builds actually execute; this is not a
  heuristic.
- **False-negative risk (honest).** Verification only covers build systems the
  engine recognizes and can invoke (Go, Node, …). A project whose build it cannot
  determine gets **no** build-failed signal even if genuinely broken — inherent to
  build-based verification, not a detection defect.

---

## Engine 7 — Code Quality — ✅ PASS

- **Metrics integer-exact vs hand-computed:** cyclomatic complexity 13→13 and
  25→25, parameter count 7→7, Type-2 (token-normalized) duplication detected.
- **Suggestions are specific + actionable, not filler.** Example real finding:
  *"'process' takes 8 parameters (threshold 6). Consider grouping related arguments
  into an object."* — names the function, the measured value, the threshold, and a
  concrete refactor. Deterministic measurements: "accuracy" here is arithmetic
  correctness, and it is exact.

---

## Engine 8 — CVE Intelligence — ✅ PASS

- **Feeds live and current** — all four sources synced **today (2026-07-30)** with
  `status=success`: NVD (6,781 CVEs, newest modified today; +4 added / 1,996
  updated), GHSA (192, +17/83), OSV (268), Semgrep rules. Genuinely fresh, not a
  stale snapshot.
- **Retroactive re-scoring proven end-to-end.** On a real recent scan (had a `bson`
  dependency finding): reset `needs_reeval=FALSE`, ran the exact `FlagAffectedScans`
  UPDATE for a new CVE affecting `bson` → flipped to **`TRUE`** with the reason
  *"New vulnerability CVE-RETRO-P3-0001 affects a dependency in this scan."* Original
  value restored afterward.
- **No false CVE flags.** The same flag query for a package **not** present in any
  recent scan flagged **0 scans** — a CVE only re-flags a scan that actually
  contains the affected package. Combined with SCA's version-precise matching
  (Engine 2), a CVE is never attached to a package it doesn't affect.

---

## Consolidated false-negative summary (brutally honest)

What classes of real issues does Aegis miss, and why?

| Gap | Engine | Status | Notes |
|-----|--------|--------|-------|
| **DB connection strings + JWT signing secrets** | Secrets | 🔧 **FIXABLE NOW** | `scheme://user:pass@host` URIs + named JWT secrets not detected. Common, high-value. Targeted Gitleaks rule, precision-safe. **The one action item from this pass.** |
| **Bare AWS secret key** (no `AKIA` id) | Secrets | ⛔ **INHERENT** | Indistinguishable from any base64 string; flagging all would destroy precision. The access-key id (which identifies the account) *is* caught. |
| **Cross-function / cross-file taint into a benign-looking sink** | Taint | ⏸️ **DEFERRED** | Fast engine is intra-procedural (shelved-Joern deep scan). Vulns with independently-suspicious sinks still caught (no SoR). |
| **Architectural / business-logic / broken-auth-logic bugs** | SAST | ⛔ **INHERENT** | No static analyzer catches logic bugs that require understanding intended behavior. Industry-wide SAST limitation. |
| **Broken builds in unrecognized build systems** | Deployment | ⛔ **INHERENT** | Can't verify a build it can't invoke. Recognized systems (Go/Node/…) verified for real. |
| ~~S3 public buckets~~ | IaC | ✅ **NOT A GAP** | Initial probe was my malformed HCL; well-formatted HCL is caught (8 findings). |

**Bottom line:** across all eight engines on real-world code, detection matches the
scorecard, with **one genuine, fixable false-negative to close (DB connection-string
secrets)** and a small set of **inherent/known-deferred limitations** that are
honestly disclosed rather than hidden. No engine was found to silently
underperform its claimed accuracy on the vulnerabilities it claims to catch.

**Reproduce:** planted-corpus probes were run in-container against `/scan/{sast,
sca,secrets,quality,deployment}`; existing harnesses in
[`benchmarks/comparative/`](benchmarks/comparative/) and
[`benchmarks/iac/`](benchmarks/iac/); intelligence checks are DB queries against
`intelligence_sync_log` / `cve_database` / `scans.needs_reeval`.
