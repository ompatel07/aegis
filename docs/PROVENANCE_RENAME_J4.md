# Pass J4 — commit provenance and rename-aware lifecycle

**HEAD:** `c4be1a4` + this change · **Run date:** 2026-09-09
**Evidence base:** the real stack with rebuilt images; a live scan of `OWASP/NodeGoat`; two uploaded
archives differing only by a moved directory; the real fingerprint code path.

**Headline: a moved file no longer produces a wave of fake regressions and fake fixes.** Measured on
a real directory move: **every one of 8 fingerprints changed, and 0 findings resolved or opened**.
Before this change the same move produced 8 resolved + 8 new — 16 phantom transitions in a document
whose entire value is open-vs-closed.

Along the way this pass reproduced, and then fixed, a P0 of exactly the class F1 found in T2.

---

## 1. Part A — record which commit was scanned

`commit_sha` was populated on **3 of 136 scans**. It was written only when an API caller happened to
supply one; the orchestrator cloned a specific revision and never recorded which.

`adapters.Checkout` now carries `CommitSHA`, resolved from `repo.Head()` after the clone —
`git.PlainCloneContext` already returned the repository handle and it was being discarded. The worker
persists it via `Store.SetCommitSHA` immediately after checkout.

Best-effort by design: an unresolvable HEAD leaves the field empty and logs, rather than failing a
scan that would otherwise succeed. Provenance is valuable, but not more valuable than the scan.

### Verified on a real scan

```
scan status : completed
commit_sha  : c5cb68a7084e4ae7dcc60e6a98768720a81841e8   (40 chars)
github says : c5cb68a7084e4ae7dcc60e6a98768720a81841e8   ← OWASP/NodeGoat master HEAD
```

SARIF `versionControlProvenance`, previously empty:

```json
{"repositoryUri": "https://github.com/OWASP/NodeGoat",
 "revisionId": "c5cb68a7084e4ae7dcc60e6a98768720a81841e8",
 "branch": "master"}
```

**Backfill is not possible and was not attempted.** The 133 historical scans cloned a revision that
was never recorded and whose working copy is long deleted; the branch may have moved many times
since. Those scans stay unattributed, and any remediation evidence drawn from them can cite a date
and a scan id but not a commit. Stated rather than papered over with a guess.

---

## 2. Part B — rename-aware lifecycle

### 2.1 Why not git's rename detection

The brief's design was: with Part A landed we know both commits, so run `git diff --find-renames`
between them. That does not work here, for a reason worth recording.

**`GIT_CLONE_DEPTH` defaults to 1.** The working copy contains the current commit and nothing else,
so the previous scan's commit is simply not present and no diff between the two revisions can run.
Making it work would need a second network fetch of a specific SHA on every scan, which fails
whenever the branch was force-pushed, the commit was garbage-collected, the previous scan was of a
different branch, or the scan came from an uploaded archive with no git history at all. It would also
be the only part of the pipeline that reaches back to the git host after the clone.

There is a second, better reason. Git answers *"was this file renamed, at ≥50% similarity"*. What the
lifecycle actually needs is *"is this the same finding"* — and a file can be 60% similar while the
vulnerable line itself was deleted and a different one introduced. Matching on the finding's own
content answers the real question directly.

### 2.2 What was built instead

The scanner now emits a second identity alongside the fingerprint:

| key | basis | purpose |
|---|---|---|
| `fingerprint` | rule + **file_path** + cve + normalized code + ordinal | exact identity — unchanged |
| `code_key` | rule + cve + normalized code + ordinal | the same identity **without the path** |

`file_path` stays in the fingerprint deliberately: identical code in two files is two findings, and
dropping the path would collide them. `code_key` is never used alone.

The lifecycle matches in two phases. Phase one is today's exact-fingerprint comparison, untouched.
Phase two considers only what phase one left over — prior findings that appear to have vanished, and
current findings that appear to be new — and pairs them when **all four** hold:

1. the content keys are equal,
2. the rule ids are equal,
3. the pairing is **strictly 1:1** — exactly one unmatched prior and exactly one unmatched current
   finding carry that key,
4. the prior fingerprint is genuinely absent from this scan.

Anything ambiguous leaves both sides alone and falls back to today's behaviour. A file copied, one
file split into two, or the same vulnerable line duplicated elsewhere all produce more than one
candidate, and the rule declines. **Guessing here would fabricate remediation evidence, which is
worse than reporting a move as a resolve plus a new finding.**

### 2.3 The similarity threshold, and why it is not 50 %

Git's default rename threshold is 50 %: half the file's content must match. That is a reasonable
default for *"did a file move"* and a poor one for *"is this the same vulnerability"* — a file can
cross that bar while the flagged line is gone.

**Our threshold is effectively 100 %, on the flagged code rather than the file.** The content key is
equal only when the normalized flagged line(s), the rule and the CVE are all identical. A file that
was rewritten as it moved does not migrate: its findings resolve and new ones open, which is the
correct reading, because the code that was vulnerable is no longer there.

This is strictly more conservative than git's default. It gives up some recall — a rename that also
edited the vulnerable line reads as resolve + new — in exchange for never asserting that a finding
survived a move when it did not.

### 2.4 The cases

| case | behaviour | why |
|---|---|---|
| Pure rename / directory move | **migrated**, stays EXISTING | content key equal, 1:1 |
| Rename + edit elsewhere in the file | **migrated** | the flagged line is unchanged |
| Rename + edit *of the flagged line* | resolve + new | the vulnerable code changed; that is a different finding |
| Copy (file duplicated) | falls back | two current candidates — declines |
| Split (one file into two) | falls back | ambiguous pairing — declines |
| Identical code already in two files | falls back | two prior candidates — declines |
| No prior commit recorded | **unaffected** | the mechanism never needed the commit |
| Findings first seen before this change | falls back once | `code_key` is NULL until their next scan re-establishes it |

The last row is a real, temporary limitation. `code_key` cannot be backfilled: it is derived from the
source line the finding sat on, and that line is not stored. Existing rows are left NULL and the
upsert backfills them on the next scan, so a project becomes rename-aware one scan after upgrading.

### 2.5 The gate: a real directory move between two scans

Two uploaded archives, identical content, `src/handlers/` → `src/api/handlers/`.

| | scan 1 (before) | scan 2 (after the move) |
|---|---|---|
| `src/handlers/db.py` | 3 findings, existing | — |
| `src/handlers/tasks.py` | 5 findings, existing | — |
| `src/api/handlers/db.py` | — | **3 findings, existing** |
| `src/api/handlers/tasks.py` | — | **5 findings, existing** |

Project lifecycle state after the move:

```
 status   | count
----------+-------
 existing |     8      ← 0 resolved, 0 new
```

State rows followed the file, and kept their history:

```
 file_path                 | status   | times_seen | count
---------------------------+----------+------------+-------
 src/api/handlers/db.py    | existing |          2 |     3
 src/api/handlers/tasks.py | existing |          2 |     5
```

That the migration genuinely fired, rather than the move being a no-op:

```
 fingerprints_shared | fingerprints_only_before | code_keys_shared
---------------------+--------------------------+------------------
                   0 |                        8 |                8
```

**Every fingerprint changed. Nothing resolved.** Under the previous behaviour this was 8 resolved +
8 new = 16 phantom transitions on a day when no code changed at all.

### 2.6 Line-shift resilience unchanged

The F1 checks (5→25, 6→26, 11→31, 12→32 — the same finding after 20 lines are inserted above):

```
fingerprint survives 20-line shift: True
code_key    survives 20-line shift: True
```

Both keys exclude the line number, so the new key inherits the property rather than weakening it.
Pinned by `tests/test_code_key.py::test_code_key_survives_a_line_shift`.

---

## 3. Part C — the churn table, re-measured

Measured through the real `utils.snippet.attach()`. The lifecycle column is the one that matters:
`code_key` is only decisive when the fingerprint has already failed to match.

| operation | fingerprint | code_key | lifecycle outcome |
|---|---|---|---|
| 200 lines inserted above | same | same | EXISTING (exact) |
| Reformat surrounding code | same | same | EXISTING (exact) |
| Rename the enclosing function | same | same | EXISTING (exact) |
| Re-indent the flagged line | same | same | EXISTING (exact) |
| **File move to a new directory** | CHANGED | same | **EXISTING (migrated)** ← was resolve + new |
| **File rename** | CHANGED | same | **EXISTING (migrated)** ← was resolve + new |
| **Deep directory move** | CHANGED | same | **EXISTING (migrated)** ← was resolve + new |
| Intra-line token spacing (`black`/`gofmt`) | CHANGED | CHANGED | resolve + new |
| The flagged code itself changes | CHANGED | CHANGED | resolve + new — *correct* |

**Three of the four previously-breaking operations are fixed.** One still breaks, and it is
documented rather than hidden:

> **Known limitation — a formatter that changes token spacing on the flagged line resolves that
> finding and opens a new one.** Whitespace *runs* are collapsed, so re-indentation is safe; what
> breaks it is `black` removing the spaces around an operator, or `gofmt` realigning, *on the flagged
> line itself*. It is a one-off per file — formatters are idempotent, so the first run over
> unformatted code causes it and subsequent runs do not. Running a formatter across a repository for
> the first time will show a burst of resolve+new on the lines it touched.

Fixing that would mean normalizing the flagged code more aggressively (stripping all whitespace, or
tokenizing), which would start colliding findings that differ only by spacing. Not worth it for a
one-off event; stated so a customer is not surprised by it.

The ambiguity guard, verified: two files containing identical vulnerable code share a `code_key`, so
a move involving either produces two candidates and the 1:1 rule declines.

---

## 4. A P0 this pass caused, caught, and fixed

Adding `code_key` to the `findings` table broke **every scan-read endpoint**. `FindingRepository`
reads with `SELECT * FROM findings`, so sqlx failed with `missing destination name code_key` and the
API returned 500 for SARIF export, the findings list and the compliance report.

This is the same defect as T2's `excluded_bundled`, which F1 found: add a column, forget the struct
field, and every read path dies. `go build`, `go vet` and the entire unit suite stayed green
throughout, because nothing in them scans a findings row into the model. Only calling the real
endpoint surfaced it.

Fixed by adding the field, and pinned by a new seam test that performs exactly the failing operation:

```go
{"findings", &[]models.Finding{}, "SELECT * FROM findings LIMIT 1"}
```

`LIMIT 1` is enough — sqlx resolves the column set before it touches a row, so it fails on a
schema/struct mismatch even against an empty table.

Writing that test also showed why `scans` is *not* in it: `repository/scan.go` enumerates its columns
explicitly, with a comment saying it avoids `SELECT *` precisely because the table carries `raw_*`
columns. Adding `scans` to the test would assert something the code deliberately does not do. The
explicit column list is the better pattern; `findings` is the one that needs the guard.

---

## 5. Part D — the pack refresh is now scheduled

`rules/manifest.yaml` declared `refresh_cadence: monthly, reviewed` and `scripts/vendor_rules.py`
existed to do it, but nothing ran it: `self-scan.yml` was the only workflow and it has no `schedule:`
trigger. The pins were current only because a human refreshed them during G2.

`.github/workflows/rule-pack-drift.yml` runs monthly (`0 7 1 * *`) plus on demand, and:

1. **Verifies** the vendored files still match the manifest — a hard failure, because a mismatch
   breaks the reproducibility G2 established.
2. **Reports** drift against upstream via `--refresh`, and writes the diff to the job summary.
3. **Never re-pins.** No `--write` in CI. Silently adopting upstream rule changes would alter a
   customer's results between two scans of unchanged code with no signal — the exact failure
   vendoring was introduced to prevent. The summary tells a human what to run to adopt them, and
   reminds them to re-run the 0-FP gates first.

### Dry run

```
$ python scripts/vendor_rules.py --verify
  pinned 2026-09-07  packs=17  rules=2791  mismatches=0
      2677  Semgrep Rules License v1.0
       114  LGPL-3.0-or-later

$ python scripts/vendor_rules.py --refresh
  fetching p/owasp-top-ten ... (17 packs)
  excluded 18 rule(s) by policy (prefixes=['trailofbits.'], ids=0)

  no change vs current pin
```

---

## Gate

| requirement | status |
|---|---|
| `commit_sha` on a real scan, and in SARIF `revisionId` | ✅ §1 — present, 40 chars, **matches GitHub's master HEAD exactly**; SARIF provenance populated |
| Directory moved between scans: findings stay EXISTING, no phantom wave | ✅ §2.5 — **8 existing, 0 resolved, 0 new**; 0 fingerprints shared, 8 code keys shared |
| Line-shift resilience unchanged | ✅ §2.6 — both keys survive a 20-line shift; pinned by test |
| Re-measured churn table | ✅ §3 — 3 of 4 breaks fixed; the formatter case documented as a known limitation |
| Scheduled refresh with a dry run | ✅ §5 — monthly, verify-hard/report-only, never re-pins; dry run shown |
| Full suite + `go build ./...` | ✅ **255 passed, 0 failed, 4 skipped** (was 247); orchestrator and api build, vet and test clean; `tsc --noEmit` clean |

**Semgrep was not touched**, as instructed — an engine upgrade landing beside a fingerprint change
would make any regression unattributable.
