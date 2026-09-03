# Pass F2 — competitor head-to-head on small repos

**Run date:** 2026-09-03 · **HEAD:** `af57e20` (F2-pre) · **Corpus:** the F1 clones, unchanged.

Two claims came into this pass with no evidence: *"competes with SonarQube on quality"*
(never run, deferred twice) and *"beats CodeQL"* (a cross-study comparison against a
published paper, on synthetic Java only). The plan was to make both testable for the first
time by using small repos.

> ## ⛔ Both head-to-heads are NOT RUN. The box ran out of disk.
>
> `C:` has **207 MB free** of 208 GB, and the Docker VHDX is already **59.5 GB** and cannot
> grow. Any large write makes the Docker VM's filesystem go read-only and takes the daemon
> down with it — which happened repeatedly during this pass and is also the cause of the
> Docker crashes seen throughout the preceding sessions.
>
> Neither competitor fits: **CodeQL** needs an 816 MB bundle that unpacks to >2 GB, and
> **SonarQube CE** needs a ~1 GB image plus 2–4 GB RAM against a **3.744 GiB** Docker
> memory ceiling. Per this pass's own instruction — *"if a comparison cannot be run
> cleanly, report it as NOT RUN — do not half-run it and report noise"* — nothing was
> approximated, inferred, or substituted. **No competitor number appears anywhere in this
> document.**
>
> Parts C and D needed no new resources and did run, on real data, and are reported in full.

---

## Environment — the blocker, precisely

| fact | value | consequence |
|---|---|---|
| `C:` free space | **207 MB** (207.9 GB used) | the Docker VHDX cannot grow; the VM goes read-only under load |
| Docker VHDX size | **59.5 GB** (`docker_data.vhdx`) | already at the ceiling the host can back |
| Docker memory ceiling | **3.744 GiB** | below SonarQube CE's 2–4 GB working set once a scanner JVM is added |
| CodeQL bundle | 816 MB compressed, >2 GB extracted | does not fit |
| SonarQube CE image | ~1 GB | does not fit |

The CodeQL attempt is worth recording exactly, because it is the disk failure caught in the
act rather than an assumption:

```
tar: codeql/cpp/tools/linux64/trap-cache-reader: Cannot write: Read-only file system
level=error msg="error waiting for container: unexpected EOF"
```

The download succeeded (816 MB). Extraction filled the VHDX, the filesystem flipped to
read-only mid-tar, and the daemon died. Docker did not recover for the remainder of the
pass despite a full restart (`Stop-Process` → `wsl --shutdown` → relaunch).

**To unblock:** free space on `C:` (tens of GB — the VHDX will still be 59.5 GB), and raise
Docker Desktop's memory to ≥ 6 GB before attempting SonarQube. Neither is something this
pass should do to a developer's machine unilaterally.

---

## Corpus

The F1 clones, byte-identical and unmoved, so every number chains to F1 and V2. Using the
*same checkout* for every tool was the point of reusing them.

| repo | lang | LOC | ground truth? | CodeQL-capable? | SonarQube CE-capable? |
|---|---|--:|---|---|---|
| **DVWA** | PHP | 13,771 | **yes** — documented per-module vulns | **no** — CodeQL has no PHP analyzer | yes |
| **NodeGoat** | JS | 3,084 | **yes** — OWASP Top 10 tutorial app | yes | yes |
| **dvpwa** | Python | 10,684 | partial — deliberately vulnerable | yes | yes |
| **spring-petclinic** | Java | 4,214 | no — clean control | needs a build (or `--build-mode=none`) | yes |

Worth noting for whenever this is re-run: **DVWA can never be part of a CodeQL comparison**
— CodeQL does not analyse PHP at all. The three-way ground-truth repo is **NodeGoat**.

---

## Part A — vs SonarQube CE (quality pillar): **NOT RUN**

Nothing was measured. No issue counts, no rating comparison, no duplication cross-check, no
overlap triage. The SonarQube claim therefore remains **exactly as unevidenced as it was
before this pass** and must not be made.

One thing this pass *did* surface that makes the duplication cross-check more urgent, from
Aegis's own numbers:

| repo | Aegis duplicated-line % |
|---|--:|
| spring-petclinic | **39.33 %** |
| DVWA | 22.24 % |
| NodeGoat | 10.47 % |
| dvpwa | 8.15 % |

**39.33 % duplication on spring-petclinic is not credible.** It is a small, curated,
heavily-reviewed Spring sample app; published SonarQube analyses of it report low single
digits. This has the same smell as the mall 90.5 % inversion bug. It is **unverified** —
confirming it needs exactly the Sonar cross-check that could not run — but it is a concrete,
falsifiable hypothesis for whoever runs Part A: *if Sonar reports petclinic in the low single
digits, our duplication metric is still wrong.*

---

## Part B — vs CodeQL CLI (SAST): **NOT RUN**

Attempted and failed on disk, as documented above. No CodeQL findings, no recall number, no
overlap triage, no wall-time or memory comparison.

Consequence for `docs/ACCURACY.md`: the OWASP Benchmark section's stated limitation —
*"this is a cross-study comparison, not a same-harness head-to-head"* — **stands unchanged**.
It was to be replaced by a same-harness result in this pass; it was not. The "beats CodeQL"
claim still rests on Xiong & Zhang's published figures for CodeQL against our own harness
figures for Aegis, on synthetic Java, and must keep carrying that caveat.

---

## Part C — vs Semgrep registry-only: **RUN** ✅

This one needed no new tooling. The Aegis custom packs are *additive* — registry rules fire
whether or not the `aegis-*` packs load — so the marginal value of our rules over a
registry-only Semgrep **is exactly the `aegis-*` finding set** (the V2 §4 method). Measured
on the F1 scans, i.e. the same checkouts, same day.

| repo | lang | registry-only SAST | `aegis-*` SAST | total | marginal value |
|---|---|--:|--:|--:|---|
| **DVWA** | PHP | 84 | **31** | 115 | **+31 (27 % of total)** — SQLi, command injection, path traversal |
| **NodeGoat** | JS | 57 | **3** | 60 | **+3** — the SSJI/`eval` code-injection at `contributions.js:32-34` |
| **dvpwa** | Python | 6 | **0** | 6 | **none** |
| **spring-petclinic** | Java | 16 | **0** | 16 | **none** |

**The V2 §4 per-language table holds on this corpus, post-T3.** DVWA +31 and NodeGoat +3
match V2's figures exactly. Two readings worth stating plainly:

- **Python still contributes nothing.** `aegis-py-*` fired 0 on a deliberately vulnerable
  Python app. dvpwa's headline SQL injection *was* caught — `sqlalchemy-execute-raw-query`
  (high) and `formatted-sql-query` at `sqli/dao/student.py:45` — but by **registry** rules.
  This is the third corpus in a row where the Python taint pack yields zero.
- **Java contributing 0 here is correct, not a regression.** spring-petclinic is a clean app;
  T3 demonstrated the repaired Java pack finding 6 true positives on WebGoat. Zero on clean
  code is the 0-FP property working, and it is why a clean repo cannot evidence a taint pack.

**Confidence: high** (mechanical counts, no triage judgement involved).

---

## Ground-truth recall — **one column of three**

The GATE asks for ground-truth recall for all three tools side by side. **Only Aegis ran**,
so this is one third of that table and must not be read as a comparison. It is included
because it is real evidence about Aegis and because it is the exact shape the missing
columns would slot into.

### NodeGoat (OWASP Top 10 tutorial app) — Aegis

| documented class | Aegis | evidence |
|---|---|---|
| **A1 Injection — server-side JS injection** | **DETECTED** | `aegis-js-code-injection` (critical) ×3 at `app/routes/contributions.js:32-34`, corroborated by `eval_nodejs`, `eval-detected`, `code-string-concat`. This is NodeGoat's canonical vulnerability. |
| **A10 Unvalidated redirect** | **DETECTED** | `express_open_redirect` (high) + `express-open-redirect` at `app/routes/index.js:72` |
| **A6 Sensitive data / weak crypto** | **DETECTED** | `node_insecure_random_generator` at `app/data/user-dao.js:51-53`, `detected-bcrypt-hash` |
| **A2 Broken auth / session** | **DETECTED (adjacent)** | `node_password` (hardcoded creds, `session.js:61,172`), `node_timing_attack` (`session.js:176`), insecure randomness in `session.js:16-17` |
| **A8 CSRF** | **DETECTED** | missing-CSRF-token on `benefits.html:54`, `login.html:107`, `memos.html:15` |
| **A9 Vulnerable components** | **DETECTED** | 87 dependency CVEs (SCA), incl. transitive chains with dependency paths |
| **A3 XSS** | **CANDIDATE MISS** | no XSS finding was produced on NodeGoat's views, though the views *were* analysed (they carry the CSRF findings). Marked candidate rather than confirmed: hand-verifying the sink needs the working tree, and Docker was down. **Confidence: medium.** |
| **A4 IDOR** | **OUT OF SCOPE** | authorization-by-object-id is not statically decidable without app semantics |
| **A7 Missing function-level access control** | **OUT OF SCOPE** | same |
| **A5 Security misconfiguration** | **PARTIAL** | mutable GitHub-Actions tags, plaintext HTTP links; no app-level misconfig rule fired |

Aegis additionally flagged two things not on the tutorial list: `node_ssrf`
(`app/routes/research.js:15`) and a local-file-read warning (`app/routes/tutorial.js`).

**Aegis recall on the statically-detectable NodeGoat classes: 6 of 7 detected, 1 candidate
miss (XSS), 2 classes out of scope for any SAST tool.** Confidence: medium-high — the
detections are unambiguous; the single miss is unverified.

### dvpwa (Python) — Aegis

SQL injection **DETECTED** (`sqli/dao/student.py:45`, two rules) and MD5-as-password
**DETECTED** (`sqli/dao/user.py:41`). Its documented XSS, CSRF and session-fixation issues
produced no SAST finding — candidate misses, **unverified**, same reason as above.

### DVWA — see F1

F1 measured DVWA in-scope recall at **3/7** and explained the misses as the cross-file
boundary (source in `source/low.php`, sink in the includer). Not re-derived here.

---

## Part D — what only Aegis does: **RUN** ✅ (inventory, not a benchmark)

An honest inventory. Competitor columns are assessed from product knowledge, **not measured
in this pass** — they say what the tool offers, not how well it does it.

| capability | SonarQube CE | CodeQL | verdict |
|---|---|---|---|
| **Reachability** — is this CVE actually reachable from your code? | **No** — CE has no dependency analysis at all (SCA is a separate paid product) | **No** — CodeQL is SAST; Dependabot does SCA separately and offers no reachability for most ecosystems | **genuine differentiator** |
| **CISA KEV flagging + sort** | No | No | **genuine differentiator** |
| **EPSS scores** | No | No | **genuine differentiator** (though EPSS is FIRST's model, not ours — we attach it) |
| **Dependency path for a transitive CVE** | No (no SCA in CE) | Not in CodeQL; Dependabot does show paths in the GitHub product | **differentiator vs both CLIs**, not vs the wider GitHub platform |
| **Vendored-library fingerprinting** (copied-in lib → its CVEs) | No | No | **genuine differentiator** — rare outside commercial SCA (Snyk, Black Duck) |
| **Code ownership** (app vs vendored/third-party tagging on each finding) | Partial — exclusions and third-party handling exist, but findings are not *tagged* with ownership | No | **modest differentiator** |
| **Finding lifecycle** (new / existing / resolved / reopened) | **YES — this is SonarQube's home turf.** New-code periods and issue states have been core for years | Partial — code-scanning alerts have open/fixed/dismissed states across runs | **NOT a differentiator.** Be honest: we match a long-standing SonarQube feature |
| **Line-shift-resilient fingerprints** | **YES** — hash-based issue tracking | Yes — alert fingerprints | **NOT a differentiator** |
| **Honest not-measured / degraded states** | Partial — some metrics show as not computed, but a rating is generally always produced | No explicit concept | **modest differentiator**, and mostly a discipline rather than a feature |
| **Never executes your code** | Sonar CE analysis is also static (though some languages want build output) | Same for JS/Python; Java historically needs a build | **not a differentiator** for these languages |

**Reading this honestly:** the real differentiation is concentrated in the **SCA enrichment
stack** — reachability, KEV, EPSS, dependency path and vendored fingerprinting, none of which
SonarQube CE or the CodeQL CLI offers. Lifecycle tracking and stable fingerprints, which are
easy to present as differentiators, are **not** — SonarQube has done both well for years, and
claiming them would not survive a buyer's first demo of Sonar.

---

## GATE

| requirement | status |
|---|---|
| Both comparisons run, **or explicitly NOT RUN with the reason** | **met, by the second branch** — Parts A and B are NOT RUN, with the disk/RAM ceiling and the verbatim failure recorded |
| Ground-truth recall for all three tools side by side | **NOT MET** — only Aegis ran. One column of three is provided and labelled as such; the other two are absent, not estimated |
| Hand-triaged samples both directions | **NOT MET** — impossible without competitor findings. Nothing was invented to fill it |
| The one-paragraph honest positioning statement | **met** — below |

---

## Where Aegis actually stands, on this evidence

Written for a buyer who will check.

On this pass's evidence, the only defensible statement is a narrow one. Against a
**registry-only Semgrep** — which is what most teams actually have — Aegis measurably adds
detection on PHP (+31 findings on DVWA, 27 % of its SAST total) and adds the specific
server-side-JS-injection catch on NodeGoat, while adding nothing at all on Python and nothing
on clean Java; that is a real but *language-lopsided* advantage, and we now say so per
language rather than in aggregate. Against **SonarQube** and **CodeQL** we have, as of today,
**no head-to-head evidence at all** — the SonarQube claim has now been deferred three times
and the CodeQL claim still rests on comparing our own harness numbers to a published paper's,
on synthetic Java; a skeptical buyer should discount both entirely until a same-harness run
exists, and we should stop making them in the meantime. What Aegis does appear to hold alone
is the dependency-risk enrichment stack — reachability, KEV, EPSS, transitive dependency
paths and vendored-library fingerprinting — which neither SonarQube CE nor the CodeQL CLI
offers, and which on NodeGoat turned 87 raw dependency CVEs into a ranked, reachability-
filtered list; that, plus the honest not-measured/degraded discipline, is the honest pitch.
The things it would be easiest to oversell — finding lifecycle and stable fingerprints — are
precisely the things SonarQube has done well for a decade, and one unverified number in our
own quality pillar (39 % duplication on spring-petclinic) is a live reason not to lead with
the quality story until Part A actually runs.

---

*Aegis numbers are from the F1 scans of the same checkouts (2026-09-03). No competitor was
executed. Nothing in this document is inferred from a tool that did not run.*
