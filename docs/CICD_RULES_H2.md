# Pass H2 — CI/CD supply-chain rules, language-independent

**HEAD:** `d8c3438` + this change · **Run date:** 2026-09-08
**Corpus:** 99 workflow files across 11 repositories — chatwoot, jellyfin, mastodon (sparse-cloned
`.github` only), juice-shop, DVWA, NodeGoat, WebGoat, spring-petclinic (F1), redash, flask, requests
(H1) — **plus this repository**.

**Headline: three rules shipped, five candidate classes skipped, and the most useful result is a
negative one — two of the four *critical* CI/CD rule families in the G3 loss list produce no true
positive at that severity anywhere in the corpus.**

The pack is the only detection we own that fires on a repository in **any** language, including the
two (Ruby, C#) where our language packs contribute nothing at all.

---

## 1. Part A — what the loss list actually contains

G3 measured 238 CI/CD-family findings that disappear when the Semgrep-licensed rules are removed.
Starting from our own data rather than from a checklist:

| rule family in the loss set | count | severity claimed | shipped? | why |
|---|--:|---|:--:|---|
| `github-actions-mutable-action-tag` | 138 | medium | ✅ **partly** | Shipped as `aegis-cicd-action-unpinned-ref`, scoped to **third-party** publishers — see §4 |
| `no-new-privileges` | 27 | medium | ❌ | docker-compose hardening advisory, not a vulnerability — §3 |
| `writable-filesystem-service` | 27 | medium | ❌ | Same; most real services cannot run a read-only root filesystem |
| `run-shell-injection` | 17 | **critical** | ✅ **rewritten** | Shipped far narrower as `aegis-cicd-workflow-script-injection`. **0 of 17 survived triage at critical** — §2 |
| `aws-*` (various) | 17 | mixed | ❌ | Terraform — **Trivy already covers this**, measured 82 findings — §3 |
| `secrets-inherit` | 8 | **critical** | ❌ | **0 of 8 are true positives.** All eight call a *local* reusable workflow — §2 |
| `missing-user` | 2 | high | ❌ | Dockerfile — **Trivy covers it** (DS-0001) — §3 |
| `gha-workflow-env-secret` | 1 | medium | ❌ | Single instance; not enough evidence to hold a 0-FP bar — §3 |
| `gha-curl-pipe-shell` | 1 | **critical** | ✅ | Shipped as `aegis-cicd-curl-pipe-shell`. Genuine |

### Shipped

| rule | severity | corpus (11 repos) | this repo | TP | FP |
|---|---|--:|--:|--:|--:|
| `aegis-cicd-action-unpinned-ref` | WARNING | 31 | 2 | 33 | **0** |
| `aegis-cicd-curl-pipe-shell` | ERROR | 1 | 0 | 1 | **0** |
| `aegis-cicd-workflow-script-injection` | ERROR | 0 | 0 | — | **0** |
| **total** | | **32** | **2** | **34** | **0** |

The 32 corpus findings fall in **6 of the 11 repositories** — chatwoot 13, redash 7, WebGoat 5,
juice-shop 4, spring-petclinic 2, DVWA 1. The other five (jellyfin, mastodon, NodeGoat, flask,
requests) return **zero**.

All route to the **SECURITY** pillar (they carry no `metadata.pillar`, and the engine defaults there).

---

## 2. The two critical families that did not survive triage

This is the substantive finding of the pass, and it corrects G3.

### `secrets: inherit` — 8 reported critical, 0 true positives

All eight instances are in mastodon, and all eight look like this:

```yaml
build-image:
  uses: ./.github/workflows/build-container-image.yml   # ← LOCAL, same repository
  secrets: inherit
```

`secrets: inherit` forwards the caller's secrets to the called workflow. When the callee is a
**remote, third-party** reusable workflow that is a serious exposure. When it is a local file in the
same repository — as in all eight cases — the secrets never leave a trust boundary they were not
already inside, and this is the ordinary, documented way to factor a workflow. Reporting it as
*critical* is wrong.

The narrow form (`secrets: inherit` to a `owner/repo/.github/workflows/x.yml@ref` callee) **is**
worth detecting, but there is **not one instance of it in 99 workflow files**, so we would be
shipping a rule we have never seen fire. Skipped, and recorded here so it can be revisited when the
corpus contains one.

### `pull_request_target` — 3 instances, 0 true positives

Not a separate line in the loss table, but it is the canonical "critical CI/CD" pattern, so it was
prototyped. All three corpus instances are the **safe** use:

| repo | file | what it does | verdict |
|---|---|---|:--:|
| juice-shop | `pr-compliance.yml` | Reads PR metadata via `actions/github-script`, SHA-pinned. No checkout. | safe |
| jellyfin | `pull-request-conflict.yml` | Applies a label via a SHA-pinned action. No checkout. | safe |
| chatwoot | `lint_pr.yml` | Validates the PR title. No checkout. | safe |

`pull_request_target` is dangerous specifically when it is **combined with checking out the pull
request's head**, because that runs attacker code in a context that holds write permissions and
secrets. None of the three does. A bare `pull_request_target` rule would have been 3 findings and 3
false positives; the constrained rule has no corpus instance to validate against. Skipped.

### `run-shell-injection` — 17 reported critical, 0 exploitable

Every `${{ }}` expression that lands inside a `run:` block anywhere in the corpus was enumerated —
44 matches, 40 distinct expressions. Sorted by who can control the value:

| class | examples | count | injectable? |
|---|---|--:|:--:|
| Structurally constrained | `pull_request.number` (integer), `pull_request.head.sha` (hex), `issue.comments_url` (server-generated), `base_ref`, `base.repo.full_name` | 11 | **no** |
| Repository-internal | `github.ref_name`, `github.sha`, `runner.temp`, `env.*`, `matrix.*`, `steps.*.outputs.*`, `needs.*.outputs.*` | 24 | no |
| Write-access gated | `github.event.inputs.*` (workflow_dispatch), `github.event.release.*` | 9 | only by a maintainer |
| **Free text, any GitHub user** | PR/issue title or body, comment body, `head_ref`, commit message | **0** | — |

**There is not one genuinely attacker-controlled free-text expression inside a `run:` block in the
entire corpus.** The shipped rule is scoped to exactly that set, so it reports nothing here — which
is the correct answer, not a gap.

One case is worth stating explicitly because G3 got it backwards. jellyfin `ci-compat.yml` was
recorded as an exploitable `${{ github.head_ref }}` injection. It is not:

```yaml
- name: Checkout common ancestor
  env:
    HEAD_REF: ${{ github.head_ref }}      # ← bound to env
  run: |
    ANCESTOR_REF=$(git merge-base upstream/${{ github.base_ref }} origin/$HEAD_REF)
```

The workflow already applies **the exact remediation our own rule message recommends**. The registry
rule fired on hardened code. `docs/RULE_TRIAGE_G3.md` items 21, 28, 30 and 34 have been corrected in
place; the report's exploitable-vulnerability rate moves from 32 % to 23 %.

---

## 3. Part B — what Trivy already covers

Measured, not assumed. Trivy 0.71.2 `--scanners vuln,misconfig` on juice-shop:

| target class | Trivy results | our rules | outcome |
|---|--:|---|---|
| Dockerfile | **7** (DS-0026, DS-0001 root user, …) | none | **skip** — `missing-user` in the loss list is Trivy's DS-0001 |
| Terraform | **82** (AWS-0124, AWS-0104, …) | none | **skip** — the `aws-*` losses are Trivy's |
| Kubernetes | covered by the same misconfig engine | none | **skip** |
| **`.github/workflows`** | **0** | **3 rules** | **ship** — this is the gap |
| docker-compose | 0 (Trivy does not parse compose) | 4 `aegis-compose-*` rules | already ours, pre-existing |

Trivy returns **zero** results targeting `.github/workflows`. GitHub Actions is the genuine hole,
and it is the only thing this pack touches. No rule in the pack can double-report with Trivy,
because no rule in the pack looks at a file Trivy scans — the path scoping is what enforces that,
and `test_cicd_rules_are_scoped_and_routed` asserts every rule keeps it.

### Deliberately not shipped

| candidate | why not |
|---|---|
| Dockerfile / Terraform / Kubernetes rules | Trivy covers them. A double-reported finding is worse than a missing one |
| `secrets: inherit` (remote callee) | Real class, **0 instances** in 99 files — no way to validate it |
| `pull_request_target` + PR-head checkout | Real class, **0 instances** — same reason |
| `no-new-privileges`, read-only root filesystem | Hardening defaults most services legitimately cannot meet; 54 findings of advice, not defects |
| Secret in a job-level `env:` | 1 instance; not enough to hold a 0-FP bar |
| `workflow_dispatch` inputs into `run:` | Requires write access to exploit. Would have added 3 corpus findings and blurred the rule's meaning |

---

## 4. The one scoping decision worth arguing about

`aegis-cicd-action-unpinned-ref` **excludes** `actions/`, `github/` and `docker/`.

Counted across the corpus: **401 action references — 247 already pinned to a full SHA, 154 on a
movable ref. Of those 154, 121 are first-party and 33 are third-party.** The rule reports exactly
those 33. Including first-party would take the pack from 33 findings to 154 and bury the ones a
reader can act on.

That 65 of the 247 SHA-pinned refs are **third-party** is the useful part: pinning third-party
actions is not a counsel of perfection, it is what these projects already mostly do.

The argument against our choice is legitimate and is written into the rule file: a GitHub-owned tag
is movable too. The argument for it is that repointing `actions/checkout@v4` requires compromising
the same organisation that operates the runner the job executes on, which is not a threat the pin
mitigates. Teams wanting the stricter posture can pin all 401; the rule text says so.

The detection itself is stated as a **property, not a list**: a ref is acceptable only if it is a
40–64 character hex SHA. Anything else — `@v4`, `@main`, `@1.2.3`, or a ref shape nobody has
invented yet — is movable by default. That is why `actions-rs/toolchain@v1` is reported while
`actions/checkout@v4` is not, and the fixture asserts exactly that distinction.

**Precision evidence:** jellyfin and mastodon SHA-pin everything, and the rule returns **zero** on
both. A rule that fires on 6 repositories and stays silent on the 2 that did the work is measuring
the property it claims to measure.

---

## 5. Part C — the gate

| requirement | status |
|---|---|
| Positive **and** negative fixture per rule; `semgrep --test` green | ✅ **3/3 rules pass** — 10 positives, 11 negatives. Fixture at `tests/fixtures/cicd/.github/workflows/` |
| 0-FP triage across the corpus | ✅ **32 findings, 32 hand-triaged TP, 0 FP** across 11 repos (6 of them yield; 5 are clean) |
| …plus this repo — dogfood it | ✅ **2 findings, both real, both fixed** — see below |
| Coverage delta vs. the CI/CD portion of the G3 loss | ✅ §1 table — 3 families covered, 5 skipped with reasons |
| No Trivy overlap | ✅ §3 — measured 0 Trivy results on `.github/workflows`; enforced by path scoping + a test |
| Full suite + `go build ./...` | ✅ **154 passed, 0 failed**; both Go services build clean |
| Language-independent row in the ACCURACY table | ✅ added, with a paragraph on why it does not fit the table's shape |

### Dogfooding — what our own repository was doing wrong

Two findings, both genuine:

1. `gitleaks/gitleaks-action@v2` — movable major tag. **Pinned** to
   `ff98106e4c7b2bc287b24eaf42907196329070c7`.
2. `aquasecurity/trivy-action@0.28.0` — movable tag, **and it does not exist**. The project renamed
   its tags to a `v` prefix; `0.28.0` now 404s. **Pinned** to
   `915b19bbe73b92a6cf82a1bc12b087c9a19a5fe2` (`v0.28.0`).

The second one was not just hygiene. Our `self-scan.yml` Trivy job has been failing at **"Set up
job"** — the step that resolves the action reference — on every recent run, so **our own CI has not
actually been running Trivy against this repository**. A rule about movable refs found a broken ref
in the workflow that runs our own security scan. That is the argument for the rule, made by
accident.

After the pins, our repository returns **0 findings** from the pack.

One self-inflicted problem was caught in the same pass: the fixture file is a deliberately vulnerable
workflow at a real `.github/workflows/` path, so `self-scan.yml` scanned it and produced 6 ERROR
findings against our own build. `--exclude services/scanner/tests/fixtures` was added.

### Verification

| check | result |
|---|---|
| `semgrep --test` (cicd pack) | **3/3 rules pass** — 10 positives fire, 11 negatives stay silent |
| Pack across 11 repos + self | **34 findings** (32 corpus + 2 ours), **0 semgrep errors**, **0 FP** |
| Our own `.github` after pins | **0 findings** |
| Scanner test suite | **154 passed, 0 failed** (was 150 at G2; +4 from `test_cicd_rules.py`) |
| `go build ./...` | **clean** — orchestrator and api both OK (no Go code changed this pass) |

---

## 6. Honest limits

- **The script-injection rule has no corpus true positive.** It is shipped because the class is the
  one CI/CD failure that is straightforwardly catastrophic, the rule is precise, and it costs
  nothing when it does not fire. But its recall against real attacks is **unvalidated** — fixtures
  are not evidence, and this document should not be read as claiming otherwise.
- **GitHub Actions only.** Not GitLab CI, Jenkins, CircleCI or Azure Pipelines. "Language
  independent" does not mean "CI-platform independent".
- **The unpinned-ref rule is hygiene, not exploitation.** It is WARNING for that reason. It tells
  you a supply-chain door is unlocked, not that anyone has walked through it.
- **Three of the eleven repositories were sparse-cloned** (`.github` only) because the full V2
  clones were removed during a disk reclamation. That is sufficient for this pack — every rule reads
  only `.github` — but those three contributed no evidence to anything else.
- **`writable-filesystem-service` and `no-new-privileges` remain genuinely uncovered** on
  docker-compose: Trivy does not parse compose and our compose pack does not check them. They were
  skipped as advisory-grade, not because they are duplicated. That is a judgement call, and it is
  reversible.
