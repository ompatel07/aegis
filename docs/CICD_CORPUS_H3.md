# Pass H3 Part A — CI-system corpus census, and why H3 does not proceed

**HEAD:** `543a106` · **Run date:** 2026-09-08
**Scope of census:** every repository Aegis has ever validated against — V1 + V2 (30 repos, via the
GitHub API where the local clones were reclaimed), F1 (7), H1 (3), H2 (3) — **plus this repository**.

**Recommendation: NO-GO on H3 as specified. Do not write GitLab CI or Jenkins rules yet.**

The corpus contains **one** GitLab CI pipeline file — seven lines, exercising none of the candidate
rule classes — and **zero** Jenkinsfiles. Rules written against that cannot be false-positive gated
and cannot be recall-checked. That is precisely the condition that let `aegis-java-*` sit inert for
months, and it is the thing H2 avoided by having 99 files to triage against.

---

## 1. The census

Counted by walking the local clones, and by querying the GitHub tree API for the V1/V2 repositories
whose clones were removed during the disk reclamation. 30 distinct repositories in all.

| CI system | pipeline files | repos | which |
|---|--:|--:|---|
| **GitHub Actions** | **99** | **11** | DVWA, NodeGoat, WebGoat, chatwoot, flask, jellyfin, juice-shop, mastodon, redash, requests, spring-petclinic |
| **CircleCI** | 1 | 1 | chatwoot (`.circleci/config.yml`, 11.8 KB — a real pipeline) |
| **GitLab CI** | 1 | 1 | juice-shop (`.gitlab-ci.yml`, **7 lines**) |
| **Jenkins** | **0** | **0** | — |
| **Azure Pipelines** | **0** | **0** | — |
| Bitbucket Pipelines | 0 | 0 | — |
| Drone / Woodpecker | 0 | 0 | — |
| Travis CI (obsolete) | 1 | 1 | NodeGoat |

This repository has **GitHub Actions only** — no `.gitlab-ci.yml`, no `Jenkinsfile`, nothing else.
So gate item 5 (dogfood) has no target for H3 either.

### The single GitLab file, in full

```yaml
include:
  - template: Auto-DevOps.gitlab-ci.yml

variables:
  SAST_EXCLUDED_PATHS: "frontend/src/assets/private/**"
  TEST_DISABLED: "true"
  DAST_DISABLED: "true"
```

Measured against the Part C candidate list, this file contains:

| candidate rule class | present here? |
|---|:--:|
| untrusted `CI_*` variable interpolated into `script:` | **no** — there is no `script:` block |
| unpinned `image:` tag | **no** — there is no `image:` |
| secret echoed in `script:` / unmasked variable | **no** |
| `include: remote:` from an unpinned external URL | **no** — it is `include: template:`, a first-party GitLab template |
| `curl \| bash` install | **no** |

**Every candidate class scores zero.** The second file the glob found,
`.gitlab/auto-deploy-values.yaml`, is 50 bytes of Helm values — not a pipeline definition at all.

So the usable GitLab corpus is not "1 file, thin". It is **1 file that exercises nothing we would
write**, which is operationally the same as zero.

---

## 2. Why the count is this low, and why that matters

This is **not** an accident of which 30 repositories we picked. Every repository in the corpus is
hosted on GitHub, and a GitHub-hosted project overwhelmingly uses GitHub Actions. A corpus sourced
from GitHub will **structurally** under-represent GitLab CI, and will contain Jenkinsfiles only for
the minority of projects that mirror an enterprise build.

That has two consequences worth stating plainly:

1. **The census cannot be fixed by adding more GitHub repositories.** Sampling more of the same
   population returns more of the same answer. A GitLab corpus has to come from GitLab.
2. **It says nothing about market share.** GitLab CI and Jenkins are widely used; our corpus is
   simply blind to them. The business rationale in the H3 brief — clients arrive on unpredictable
   stacks — is sound. What is missing is evidence, not motivation.

---

## 3. A second, independent blocker for the Jenkins half

Even with a corpus, the Jenkins rules could not be built the way the H2 rules were.

**Semgrep 1.97.0 does not support Groovy.** Its supported-language list runs to 60-plus entries and
includes several genuinely obscure ones (`move_on_aptos`, `circom`, `promql`, `jsonnet`, `hack`) —
but there is no `groovy`, and no Jenkins-specific mode:

```
apex bash c c# c++ cairo circom clojure cpp csharp dart docker dockerfile elixir generic go
golang hack hcl html java javascript js json jsonnet julia kotlin lisp lua move_on_aptos
move_on_sui ocaml php promql proto protobuf python r ql regex ruby rust scala scheme sh sol
solidity swift terraform ts typescript vue xml yaml
```

A `Jenkinsfile` would therefore have to be matched with `languages: [generic]` or `[regex]` — no
parse tree, no metavariable binding over real syntax. That directly undermines the specific bug
class the brief names as the interesting one:

> `sh "..."` with string interpolation of params/env rather than single-quoted — the Groovy
> interpolation-vs-shell distinction is the real bug class

That distinction is exactly what an AST would settle and what a regex handles badly. `"${params.X}"`
inside a `sh` step is interpolated by Groovy before the shell sees it; `'${params.X}'` is not. In
generic mode we would be pattern-matching quote characters across line continuations, heredocs and
nested string escapes, on a file type we have no parser for and no corpus to check against.

This is not fatal forever — the H2 `curl | sh` and script-injection rules are regex-driven inside a
YAML pattern and hold a 0-FP bar — but combining *no parser* with *no corpus* means neither of the
two things that normally keep a rule honest would be available.

---

## 4. Options, and what I would do

The brief offered three. Assessed against the evidence above:

| option | assessment |
|---|---|
| **(a) source a dedicated corpus first**, then decide on rules | **Viable, and my recommendation** — but it must be scoped as its own deliverable, not smuggled into a rule pass |
| **(b) pivot to whichever CI system the corpus contains** | **Weak.** The only other system present is CircleCI: 1 file, 1 repo. That is thinner than the GitLab evidence, not better |
| **(c) skip and report no-go** | Acceptable, and strictly better than shipping unvalidated rules — but it leaves a real coverage gap unexamined |

### Recommendation

**Take (a), as a separate corpus-building task, and split it by system — they are not equally
tractable.**

**GitLab CI — do this one first.** It is YAML, so it lands in exactly the machinery H2 already
proved out: `languages: [yaml]`, path-scoped, pattern + `metavariable-regex`, fixtures, `semgrep
--test`. The attacker-controlled-field discipline transfers directly — the work is enumerating which
`CI_*` variables an outsider can set (`CI_COMMIT_TITLE`, `CI_COMMIT_BRANCH`,
`CI_MERGE_REQUEST_TITLE`, `CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`) versus which are server-generated
(`CI_COMMIT_SHA`, `CI_PIPELINE_ID`, `CI_JOB_ID`). Corpus must come **from gitlab.com**, not GitHub;
20–30 `.gitlab-ci.yml` files from active GitLab-hosted projects is a realistic target.

**Jenkins — defer, and reconsider the tool.** Two blockers, not one: no corpus *and* no parser. If
Jenkins coverage is commercially important, the honest options are to accept regex-grade rules and
say so, or to look at a Groovy-aware engine for that file type specifically. Deciding that is a
scoping question for you, not something to settle inside a rule pass.

**What I would not do:** write the rules now against fixtures alone. Three rules with fixtures and
no corpus would pass a `semgrep --test` gate and tell us nothing about false positives on real
pipelines. H2's shipped `aegis-cicd-workflow-script-injection` is already carrying one unvalidated-
recall caveat; a whole pack of them would make the caveat the product.

---

## 5. What this pass did deliver

- The census above, now on record, so the question does not get re-litigated from memory.
- The Groovy finding, which is a hard constraint on any future Jenkins work.
- The outstanding H2 gate item (item 8): the exact passed-vs-skipped test breakdown. **154 passed,
  0 failed, 0 skipped** — so the H2 report's figure was correct and needed no correction. It had
  been asserted from an exit code plus a collected count, which does not by itself exclude skips;
  it is now measured with `-rs`. The reason the summary line was invisible on earlier attempts is
  that `pyproject.toml` already sets `addopts = "-q"`, so passing `-q` again silently made it
  `-qq` and suppressed the totals.

Nothing was shipped into `rules/cicd/`. The H2 pack is unchanged.
