# What Aegis Finds That SAST-Only Tools Miss — Dependency-CVE Detection Coverage

> **Honest framing up front.** This document is about **detection coverage**, not
> vulnerability *discovery*. Every CVE below is a **known, publicly-catalogued
> advisory** (NVD / OSV / GitHub Security Advisories) that Aegis's SCA engine
> **detected in a real project's dependency tree**. These are **not** novel or
> zero-day vulnerabilities Aegis found through original research — they are already
> published, and Aegis's contribution is *catching them in your dependencies and
> telling you which ones are reachable*. We say this plainly because the honest
> framing is the credible one.

## The gap: a SAST-only tool is blind to your dependencies

Static Application Security Testing (CodeQL, SonarQube, stock Semgrep) analyzes
**the code you wrote** for dangerous patterns — SQL injection, XSS, hardcoded
secrets. That is valuable, and Aegis does it well (F1 0.775 on OWASP Benchmark,
beating CodeQL's 0.744 — see [ACCURACY_VALIDATION.md](ACCURACY_VALIDATION.md)).

But modern applications are **mostly other people's code**: a typical service is
5–20% first-party and 80–95% third-party dependencies. The most impactful
real-world breaches of the last few years — Log4Shell, the `event-stream`
compromise, countless prototype-pollution and ReDoS advisories — live in
**dependencies**, not in the application's own source. **A SAST-only tool has
structurally zero visibility into these.** It can read your `import` statement; it
cannot know the imported version carries a critical CVE.

Aegis is **multi-engine** — SAST **+** SCA (dependency CVEs) **+** secrets **+**
IaC **+** reachability — so it catches the dependency vulnerabilities a pure-SAST
tool cannot, and then tells you which are actually reachable in your code.

## What Aegis detected — verified real

Across the 19-repo comparative benchmark ([COMPARATIVE_ANALYSIS.md](COMPARATIVE_ANALYSIS.md)),
Aegis's bundled SCA surfaced dependency CVEs that the SAST-only tools in the
comparison (Semgrep-CE) reported **zero** of:

| Project | Dependency findings (Trivy) | of which critical/high |
| --- | --- | --- |
| HashiCorp Vault | 175 | 5 critical |
| Terraform | 1,174 | many high |
| Prisma | 714 | 3 critical / 249 high |
| NextAuth.js | 62 | 21 high |

**Are these real? Yes — measured, not asserted.** In the SCA accuracy validation
([ACCURACY_VALIDATION.md §3](ACCURACY_VALIDATION.md)) a random sample of **40**
flagged advisories was cross-referenced against the **OSV API** (which is
package-precise): **40 / 40 = 100%** were independently confirmed as genuinely
affecting the exact installed `package@version`. Zero false positives.

### Concrete examples (each independently OSV-verified)

Real dependency CVEs Aegis caught in **NextAuth.js**, each confirmed against OSV at
the exact pinned version:

| Package @ version | CVE | Class |
| --- | --- | --- |
| `tough-cookie` @ 2.5.0 | CVE-2023-26136 | Prototype pollution |
| `undici` @ 6.24.0 | CVE-2026-12151 | HTTP client flaw |
| `form-data` @ 2.5.4 | CVE-2026-12143 | Unsafe multipart boundary generation |
| `tmp` @ 0.2.6 | CVE-2026-49982 | Arbitrary file write via symlink |

Every one is a published advisory in a dependency the project pulls in — and every
one is **invisible to a tool that only scans first-party source**. (Severity is
shown in-product as flagged by the advisory feeds; because feeds sometimes
disagree on CVSS, consult the CVE for the authoritative score rather than trusting
a single vendor's rating — Aegis surfaces the source URL on every finding.)

## The differentiator: reachability, not just a list

A raw dependency scan produces a wall of CVEs, most of which don't matter (the
vulnerable code path is never called). Aegis annotates each dependency finding
with **reachability** — whether the vulnerable package is actually imported/used
in the codebase — so teams fix the CVEs that are genuinely exploitable first
instead of drowning in noise. This is the difference between "you have 714 CVEs"
and "these are the 30 reachable ones that matter."

## Scrupulous caveats (the honest part)

- **Detection, not discovery.** Restated because it matters: these are known CVEs
  from public advisory databases. Aegis's value is *coverage + reachability + a
  clean workflow*, not finding new vulnerabilities.
- **Raw counts include dev/test/example dependencies.** The headline numbers above
  (Vault 175, Terraform 1,174, …) are **raw** and include non-production
  dependencies — a dev tool, a test fixture, an `examples/` demo pinning an old
  package. We documented this inflation openly in COMPARATIVE_ANALYSIS.md, and the
  shipping scanner now **scopes out demo/sample directories by default**, so a
  production scan reports the smaller, production-relevant set. (Concrete example:
  Flask's only dependency CVEs lived in `examples/celery/requirements.txt`; the
  production-scoped scan correctly reports **0** for Flask's actual runtime deps.)
- **SBOM completeness needs a committed lockfile.** Dependency detection resolves
  from lockfiles (requirements.txt, go.sum, package-lock.json). A repo that commits
  no lockfile yields fewer/no components — Trivy (correctly) will not fabricate a
  dependency tree it cannot resolve.

## Reproduce it

```bash
# Dependency CVEs for any repo, cross-referenced against OSV for truth:
python benchmarks/comparative/sca_verify.py     # runs inside the scanner image
```

The SCA engine is Trivy (Apache-2.0), matched against the NVD/OSV/GHSA advisory
feeds Aegis syncs continuously ([INTELLIGENCE_VERIFICATION.md](INTELLIGENCE_VERIFICATION.md)).
Everything here is self-hosted — the source never leaves your infrastructure
([PRIVACY.md](PRIVACY.md)).

---

*Bottom line: Aegis catches real, verified dependency CVEs that SAST-only tools
structurally cannot see, and — via reachability — tells you which ones actually
matter. It does not claim to discover new vulnerabilities, and the honest scoping
(production vs. dev/example dependencies) is stated plainly. Accurate coverage,
honestly framed.*
