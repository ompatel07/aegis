# Comparative Analysis — Aegis vs. Community Tools

Track 2c: Aegis on real, mid-sized public codebases alongside the free tools
teams actually reach for. Committed **per repo** as each completes.

## Method

For each repo (shallow clone, tests/vendor/node_modules excluded):

- **Semgrep Community** — `semgrep --config p/default` (the bare community
  security ruleset).
- **Aegis SAST** — Aegis's fuller Semgrep config (`p/owasp-top-ten`,
  `p/r2c-security-audit`, `p/cwe-top-25`, `p/default`, `p/secrets`) **plus**
  Aegis's own taint rules. Same engine family as Semgrep-CE, so findings are
  directly comparable (shared vs. unique).
- **Trivy** — `trivy fs` (dependency CVEs + secrets + IaC misconfig): a
  *different scope* (supply-chain/secrets/config, not code patterns), included to
  show coverage Aegis's SCA/secret engines also provide.

Reported: total findings, severity split, per-KLOC density, and Aegis-vs-CE
overlap. KLOC counts non-blank source lines. Harness:
[`benchmarks/comparative/compare.py`](benchmarks/comparative/compare.py).

**Honest scope notes.** SonarQube Community needs a persistent server + per-repo
scanner run; it's attempted opportunistically and noted where run, but never
blocks a per-repo commit. Trivy `fs` reports `0` where a repo pins no
known-vulnerable dependencies. Per the Track 2d discipline, none of these rules
were tuned to any repo — this is Aegis's stock configuration.

## Summary (running)

| Repo | Lang | KLOC | Semgrep-CE | Aegis SAST | Trivy | Aegis Δ vs CE |
| --- | --- | --- | --- | --- | --- | --- |
| Express | JS | 4.1 | 45 | **49** | 0 | +4 high (superset) |
| Cobra | Go | 14.4 | 13 | 13 | 0 | 0 (agree — clean lib) |

## Per-repo detail

### Express (JS, expressjs/express)

| Tool | Total | High | Medium | Low | /KLOC |
| --- | --- | --- | --- | --- | --- |
| Semgrep-CE | 45 | 0 | 42 | 3 | 11.1 |
| **Aegis SAST** | **49** | **4** | 42 | 3 | 12.1 |
| Trivy (fs) | 0 | — | — | — | 0 |

Aegis is a **strict superset** of Semgrep-CE here: all 45 CE findings plus 4
additional **high**-severity findings surfaced by the OWASP/CWE packs + Aegis
taint rules that the bare community ruleset misses. Trivy found no dependency
CVEs (Express pins no known-vulnerable deps). The +4 high findings are the
concrete value Aegis adds over stock Semgrep on this codebase.

### Cobra (Go, spf13/cobra)

| Tool | Total | High | Medium | Low | /KLOC |
| --- | --- | --- | --- | --- | --- |
| Semgrep-CE | 13 | 0 | 11 | 2 | 0.9 |
| **Aegis SAST** | 13 | 0 | 11 | 2 | 0.9 |
| Trivy (fs) | 0 | — | — | — | 0 |

Aegis and Semgrep-CE **agree exactly** (13 findings, 0 unique). Cobra is a mature
CLI library with no web/injection attack surface, so the OWASP/CWE/taint packs
correctly add nothing — Aegis introduces **no extra noise** where there's nothing
to add. Low density (0.9/KLOC) reflects clean, well-reviewed code.
