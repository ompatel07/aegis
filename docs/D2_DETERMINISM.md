# D2 — Why repeat scans of one commit differ, and what Aegis does about it (2026-10-23)

**In plain language.** Scanning the same code twice should give the same answer. It did
not: N5 saw Dolibarr's PHP findings move by +6 / −1 between two scans of one commit, and
a precision measured on findings that move is not a measurement. D2 found the cause. It
is inside Semgrep, it is a time limit, and **it cannot be switched off** — so a scan
cannot be made fully repeatable. What D2 does instead is (1) stop the one cause we
control (a whole-scan time limit Dolibarr sat right on), (2) detect the rest on every
scan and **name the affected files** on the scan page, and (3) measure precision only on
findings that are stable across repeat scans.

## 1. The cause

Semgrep's taint analysis computes, for every function, how untrusted data flows through
it — an iterative "fixpoint". Semgrep bounds that computation by **wall-clock time**:
0.2 s per function (`Limits_semgrep.taint_FIXPOINT_TIMEOUT`; 0.15 s for constant
propagation), checked after 100 iterations, and on expiry it **keeps the partial
result**. A partial result is a subset of the full one, so findings go missing. Whether a
function finishes in 0.2 s depends on how busy the machine is — Semgrep's own source
comment notes that garbage-collector pressure alone triggers it. In Semgrep 1.97 the
timeout is reported nowhere except its debug log; nothing in the JSON output says the
analysis was cut short. The limit is a compile-time constant: no flag, environment
variable or rule option moves it (checked against `semgrep-core -help` and the 1.97
source), and Semgrep's current development branch has the same 0.2 s.

### Evidence (scripts in `docs/d2/`)

| test | result |
|---|---|
| Dolibarr, 3 product scans of one commit, idle machine (`d2_run.py`) | 81 / 79 / 81 findings: `aegis-php-xss` at `adherents/card.php:1064` and `:1388` (both triaged TP) present in runs 1 and 3, absent in run 2 — and **no error reported** for that file in run 2 |
| `card.php`, the product's rule set, run alone ×3 (`d2_load.py`) | the same findings every run, no fixpoint timeout |
| `card.php`, 4 / 8 / 12 concurrent copies on 8 CPUs | a fixpoint timeout on **every** run; the shipped XSS rule's 22 findings fall to between 0 and 7 |
| `--timeout 0` vs `--timeout 600` (`d2_load.py`) | no change: the per-rule file timeout is a different limit |
| rule cost: plain vs project-augmented vs collapsed sanitizers (`d2_variants.py`) | all three time out under load: the cost is the file's top-level function, not our sanitizer list |
| one full Dolibarr pass with detection on (`d2_detect.py`) | 572 fixpoint timeouts in 145 files — Dolibarr's own pages and classes as well as vendored jQuery / tcpdf / nusoap |
| re-analysing the affected files one at a time (`d2_retry.py`) | 1,542 s for one retry pass, and 53 of 141 files still timed out alone: a retry does not converge |

A second, separate cause: Dolibarr's whole SAST pass took 410–620 s against a **600 s**
limit, so the same commit completed on one scan and failed outright on the next (it did
in this pass: 618 s, FAILED, no findings).

## 2. What changed (`fix(sast)`)

1. **Whole-scan limit.** `SEMGREP_TIMEOUT_SECONDS` 600 → 1200; the orchestrator's
   per-call `SCANNER_TIMEOUT_SECONDS` 900 → 1500 so it never cuts the scanner off first.
2. **Detection.** Semgrep runs with `--debug` while its core log is held at warning
   level (`SEMGREP_LOG_LEVEL=warning`) — about 370 KB of log on Dolibarr — and the
   scanner reads back every `Fixpoint timeout` warning plus every per-file rule timeout
   from the JSON errors (`semgrep_engine.partial_analysis`).
3. **Disclosure.** `security_coverage.partially_analysed` carries the count and the
   first 25 files; the scan page says "N files were only partially analysed (…): the
   analysis hit a time limit, so findings in them can differ between scans of the same
   commit and some may be missed". It is a disclosure, not a degradation: the score
   and quadrant are unchanged (a degraded engine withholds security, and every large
   repository would then be "Not measured" for an engine limit it shares with every
   Semgrep user).
4. **No leak.** The debug log carries matched code (`match_key = (...)`), which for a
   hardcoded-secret rule is the secret. A failed scan's error is now built from
   Semgrep's JSON errors, else from plain error lines with no matched code, else from
   the exit code — never from the raw log (`tests/test_partial_analysis.py` plants one).

## 3. Repeat scans after the change

The 31-repository real corpus (`docs/d2/real_commits.txt`, the V2 / N3 / spring-petclinic
repositories at their recorded commits), each scanned **three times** through the
product's engine on the new code, one repository at a time, the three rounds
interleaved so a repository's runs are hours apart (`d2_run.py`, `d2_record.py`; the
per-repository table is `docs/d2/d2_record.json`):

| | |
|---|---|
| repositories identical on all three scans | **28 of 31** |
| repositories whose findings moved | 2 — Dolibarr (78 stable, 3 unstable), prisma (56 stable, 2 unstable) |
| unstable findings in a file the scan disclosed | **5 of 5** |
| unstable findings anywhere else | **0** |
| repositories that fail | n8n, on **every** scan (1,214–1,221 s against 1,200 s) |
| scans that would have failed under the old 600 s limit | Dolibarr run 2 (614 s), TeamPass run 1 (603 s) |

The five unstable findings: Dolibarr `aegis-php-xss` at `adherents/card.php:1388` (a
triaged TP) and `takepos/invoice.php:1016`, `aegis-php-sql-injection` at
`takepos/invoice.php:1252`; prisma `node_sha1` twice in a test file. Each was present in
runs 1 and 3 and absent in run 2 — the run that disclosed the most partially analysed
files (Dolibarr 150, against 106 and 120). Files disclosed per scan: Dolibarr 106–150,
TeamPass 19–30, cmp-react 7–11, nocodb 1–6, FreshRSS 2–3, and 0–2 elsewhere.

**Verdict: bounded, not eliminated.** Repeat scans of a commit differ only in files the
scan names as partially analysed, and they now complete (or fail) the same way every
time. They are not identical, and cannot be on this engine.

One unit note for every precision figure that follows: a finding is counted once per
**location** (rule, file, line). N6's triage counted per-column duplicates separately —
15 on minified one-line vendored files in Dolibarr (`ace/src/mode-*.js`,
`highlight.*.pack.js`) and one librenms line holding two sinks — so N6's held-out
JavaScript 0/15 (+36 uncertain) is 0/14 (+22) by location, and PHP's 18/67 is 18/66.

## 4. How precision is measured from now on

A precision figure is computed on **stable** findings: present in all three scans of
the commit. An unstable finding is reported separately with its count, and it always
lies in a file the scan disclosed (§3). This is the rule P3 follows.

## 5. What this does not fix

- The variance itself. It is a property of Semgrep's engine; the only levers left are
  fewer timeouts (cheaper rules — the heaviest, `aegis-php-weak-random-secret`, caused
  206 of Dolibarr's 572) or a different engine. Neither is in D2.
- Repositories beyond 1,200 s. n8n's SAST pass exceeds it on every scan, so n8n fails
  every time — repeatably, but without findings. It has no triaged finding in the
  precision corpus, so no figure depends on it.
- The detection depends on a Semgrep debug-log line. A Semgrep upgrade must re-check it
  (later versions also report `FixpointTimeout` in the JSON errors, which
  `partial_analysis` already reads).
