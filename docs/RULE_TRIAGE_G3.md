# Pass G3 — what the Semgrep-licensed rules actually contribute

**HEAD:** `3a40814` · **Run date:** 2026-09-07 · **Corpus:** V2 (15 repos) + F1 Java.

G2 showed that stripping every Semgrep-licensed rule leaves ground-truth recall unchanged
(NodeGoat 6/7, DVWA 3/6, WebGoat 6/6) while volume drops 73–95 %. **That result was not usable
as stated.** The documented lists are narrow — 7, 6 and 6 vulnerabilities — so "no documented vuln
lost" says nothing about the 1,387 findings that vanish. This pass triages them.

**Headline: the dropped findings are ~61 % true positives, but only ~32 % are exploitable
vulnerabilities, and the value is distributed almost inversely to the volume.**

---

## 1. The 40-item triage

**Population:** 1,387 findings disappear when Semgrep-licensed rules are removed. **Sample:** 40,
stratified by language and weighted toward critical/high (8 critical, 19 high, 11 medium/low).

| verdict | meaning |
|---|---|
| **TP** | the rule is right about this code |
| **FP** | the rule is wrong here |
| **UNC** | undecidable without context I do not have |

`kind` separates **vuln** (an exploitable weakness) from **advisory** (true, but hardening/hygiene).
`covered` = the same location is still flagged by a *surviving* rule (ours or LGPL njsscan), so the
**vulnerability** is not lost even though that finding row is. Only checkable for the 7 repos held
locally; `—` elsewhere.

| # | lang | rule | location | verdict | kind | cov | conf | basis |
|--:|---|---|---|:--:|---|:--:|:--:|---|
| 1 | Ruby | `model-attributes-attr-accessible` | chatwoot `ContactPolicy.rb:1` | **FP** | — | — | H | `attr_accessible` was **removed in Rails 4 (2013)**; rule is obsolete. Fired on a *Policy*, not a model |
| 2 | Ruby | `model-attributes-attr-accessible` | chatwoot `message.rb:41` | **FP** | — | — | H | Obsolete; modern Rails uses strong parameters |
| 3 | Ruby | `model-attributes-attr-accessible` | mastodon `familiar_followers_presenter.rb:4` | **FP** | — | — | H | Fired on a *Presenter*, not an AR model |
| 4 | Ruby | `model-attributes-attr-accessible` | chatwoot `webhook.rb:21` | **FP** | — | — | H | Obsolete rule |
| 5 | Ruby | `model-attributes-attr-accessible` | mastodon `cli/maintenance.rb:39` | **FP** | — | — | H | Fired on inline maintenance helper classes |
| 6 | Ruby | `missing-user` | chatwoot `vite.Dockerfile:9` | **TP** | advisory | — | H | No `USER` → container runs as root |
| 7 | Ruby | `model-attributes-attr-accessible` | mastodon `migrate/2017….rb:4` | **FP** | — | — | H | Fired on a migration-local class |
| 8 | Ruby | `no-new-privileges` | chatwoot `docker-compose.test.yaml:17` | **TP** | advisory | — | M | Real hardening, but a *test* compose file |
| 9 | Ruby | `avoid-html-safe` | mastodon `text_formatter.rb:34` | **FP** | — | — | M | Carries an explicit `rubocop:disable Rails/OutputSafety`; formatter escapes internally |
| 10 | Ruby | `var-in-script-tag` | chatwoot `_portal_analytics.html.erb:30` | **FP** | — | — | H | `<%= @portal.hotjar_site_id.to_i %>` — `.to_i` coerces to integer, not injectable |
| 11 | PHP | `tainted-sql-string` | DVWA `bac/source/low.php:35` | **TP** | **vuln** | **no** | H | **Verified in source**: `$id` interpolated into `SELECT`. **Genuinely lost** |
| 12 | PHP | `tainted-exec` | DVWA `exec/source/low.php:10` | **TP** | **vuln** | yes | H | **Verified**: `shell_exec('ping '.$target)`. Covered by `aegis-php-command-injection` |
| 13 | PHP | `exec-use` | DVWA `exec/source/impossible.php:22` | **FP** | — | — | H | `impossible.php` is DVWA's **hardened** version; rule flags any `exec()` |
| 14 | PHP | `exec-use` | librenms `removespikes.php:430` | **TP** | advisory | — | M | Real `shell_exec` with interpolation; sources appear internal |
| 15 | PHP | `exec-use` | librenms `VminfoLibvirt.php:67` | **TP** | advisory | — | M | Same class |
| 16 | PHP | `detected-private-key` | librenms `mibs/linksys/LINKSYS-SSL:444` | **FP** | — | — | H | A MIB **documentation** file describing PEM format — not a key |
| 17 | PHP | `eval-detected` | librenms `overlib_mini.js:293` | **FP** | — | — | H | Vendored third-party JS; `eval` over its own constants. T2 would now exclude this file |
| 18 | PHP | `eval-detected` | librenms `overlib_mini.js:165` | **FP** | — | — | H | Same vendored library |
| 19 | PHP | `dependabot-missing-cooldown` | FreshRSS `.github/dependabot.yml:22` | **FP** | — | — | H | A dependabot config preference, not a security finding |
| 20 | JS/TS | `express-sequelize-injection` | juice-shop `routes/search.ts:23` | **TP** | **vuln** | yes | H | **Verified**: repo's own `vuln-code-snippet vuln-line` annotation. Covered by our rules |
| 21 | JS/TS | `run-shell-injection` | juice-shop `update-challenges-www.yml:27` | **TP** | **vuln** | — | H | `${{ github.ref_name }}` into a `run:` block = GHA script injection |
| 22 | JS/TS | `code-string-concat` | NodeGoat `contributions.js:32` | **TP** | **vuln** | yes | H | Documented SSJI. Covered by `aegis-js-code-injection` |
| 23 | JS/TS | `gha-curl-pipe-shell` | juice-shop `ci.yml:359` | **TP** | advisory | — | H | `curl \| sh` in CI — supply-chain exposure |
| 24 | JS/TS | `remote-property-injection` | juice-shop `routes/currentUser.ts:31` | **TP** | **vuln** | **no** | M | `baseUser[field]` with request-controlled `field`. **Genuinely lost** |
| 25 | JS/TS | `code-string-concat` | NodeGoat `contributions.js:33` | **TP** | **vuln** | yes | H | Same SSJI, adjacent line. Covered |
| 26 | JS/TS | `plaintext-http-link` | NodeGoat `tutorial/a2.html:209` | **FP** | — | — | H | An `http://` hyperlink inside a tutorial page |
| 27 | JS/TS | `github-actions-mutable-action-tag` | NodeGoat `lint.yml:16` | **TP** | advisory | — | H | `actions/checkout@v2` unpinned — supply-chain hygiene |
| 28 | Python | `run-shell-injection` | redash `preview-image.yml:136` | **TP** | **vuln** | — | H | `github.event.inputs` interpolated into a `run:` block |
| 29 | Python | `run-shell-injection` | redash `periodic-snapshot.yml:33` | **TP** | advisory | — | M | Uses secrets + git config; injection path less clear |
| 30 | Python | `nan-injection` | redash `authentication/__init__.py:81` | **TP** | **vuln** | — | H | `float(request.args['expires'])` accepts `"nan"`; NaN comparisons are always False → **expiry check bypass** |
| 31 | Python | `sqlalchemy-execute-raw-query` | redash `snowflake.py:170` | **TP** | **vuln** | — | M | `"USE {}".format(config['database'])` — data-source config is admin-supplied |
| 32 | Python | `python-logger-credential-disclosure` | redash `authentication.py:38` | **FP** | — | — | M | Logs user_id/org identifiers, not credentials |
| 33 | Python | `formatted-sql-query` | redash `cli/database.py:43` | **TP** | advisory | — | M | f-string `CREATE EXTENSION` from settings; CLI + admin-controlled |
| 34 | C# | `run-shell-injection` | jellyfin `ci-compat.yml:57` | **TP** | **vuln** | — | H | `${{ github.head_ref }}` — PR branch names are attacker-controlled |
| 35 | C# | `detected-generic-api-key` | jellyfin `TmdbUtils.cs:34` | **TP** | **vuln** | — | H | Hardcoded TMDB API key as a public `const` in source |
| 36 | C# | `csharp-sqli` | jellyfin `SqliteExtensions.cs:267` | **UNC** | — | — | M | `command.CommandText = sql` in a generic helper; verdict depends on callers. Repo not held locally |
| 37 | C# | `unsafe-path-combine` | jellyfin `PluginManager.cs:377` | **UNC** | — | — | M | `Path.Combine` on a plugin path; depends on manifest trust. Repo not held locally |
| 38 | Java | `spring-actuator-fully-enabled` | petclinic `application.properties:21` | **TP** | **vuln** | **no** | H | `exposure.include=*`; the file's own comment says *"Don't do this in production"*. **Genuinely lost** |
| 39 | Java | `run-as-non-root` | petclinic `k8s/petclinic.yml:30` | **TP** | advisory | no | H | K8s container without `runAsNonRoot` |
| 40 | Java | `no-sudo-in-dockerfile` | petclinic `.devcontainer/Dockerfile:10` | **TP** | advisory | no | M | `sudo` in a Dockerfile; devcontainer only, not shipped |

### Rates

| metric | value |
|---|--:|
| **TP** | **23 / 40 (58 %)** — 13 vuln + 10 advisory |
| **FP** | 15 / 40 (38 %) |
| **UNC** | 2 / 40 (5 %) |
| **TP rate** (excluding uncertain) | **61 %** |
| **Exploitable-vulnerability rate** | **32 %** (13/40) |

**Of the 13 sampled exploitable vulnerabilities, 4 are still caught by a surviving rule of ours**
(DVWA cmdi, juice-shop SQLi, NodeGoat SSJI ×2). Only **3 were confirmed genuinely lost** with no
surviving coverage — DVWA `bac` SQLi, juice-shop property injection, petclinic actuator exposure.
The rest sit in repos not held locally, so overlap could not be checked.

---

## 2. By rule pack — where the value actually sits

| attributed pack | lost findings | sampled TP | sampled FP | TP rate |
|---|--:|--:|--:|--:|
| **`p/default`** | **1,008 (73 %)** | 9 | 7 | **56 %** |
| `p/ruby` | 196 | 1 | 0 | 100 % |
| `p/php` | 65 | 1 | 0 | 100 % |
| `p/javascript` | 38 | 2 | 0 | 100 % |
| `p/python` | 21 | 1 | 1 | 50 % |
| `p/cwe-top-25` | 18 | 2 | 0 | 100 % |
| `p/r2c-security-audit` | 13 | — | — | n/a |
| `p/terraform` | 10 | — | — | n/a |
| `p/owasp-top-ten` | 7 | — | — | n/a |
| `p/csharp` | 6 | 0 | 0 (2 UNC) | n/a |
| `p/dockerfile` | 3 | 2 | 0 | 100 % |
| `p/secrets` | 2 | — | — | n/a |

**`p/default` is the whole ballgame** — 73 % of everything lost, at a 56 % TP rate. If only one pack
could be replaced, it is that one. The small language packs are high-precision but low-volume.

**A cross-cutting finding the language view hides:** the **GitHub-Actions / container rules**
(`run-shell-injection`, `github-actions-mutable-action-tag`, `gha-curl-pipe-shell`, `missing-user`,
`no-new-privileges`, `run-as-non-root`, `no-sudo-in-dockerfile`) fire in **every language**
— `github-actions-mutable-action-tag` alone is 145 findings across all six — and scored **9 TP / 0 FP**
in the sample. They are language-independent CI/CD and container rules. A small set of replacements
there recovers real value across the entire corpus at once, which no per-language plan captures.

---

## 3. Per language — lost volume vs. real value

Extrapolating each language's sampled TP and vuln rate to its full lost volume:

| language | lost | sampled | TP rate | vuln rate | est. real TPs | est. vulns | our coverage today | what closing it needs |
|---|--:|--:|--:|--:|--:|--:|---|---|
| **Ruby** | **785** | 10 | **20 %** | **0 %** | ~157 | **~0** | none | Mostly *not worth replacing*. Dominated by one obsolete rule (`attr_accessible`, removed in Rails 4) and `check-unscoped-find` (148). Real Rails taint (mass assignment, `html_safe`, unscoped find with genuine IDOR) would be new work with **no usable prior art** — Brakeman is commercially restricted (G2 Part D) |
| **PHP** | 357 | 9 | 44 % | 22 % | ~159 | ~79 | `aegis-php-*` (15.6 % of PHP findings) | Extend the existing pack: file ops, deserialisation, LDAP, header injection. `exec-use`/`unlink-use` are advisory-grade and cheap to reproduce |
| **JS/TS** | 106 | 8 | **88 %** | **62 %** | ~93 | ~66 | strongest (ours + LGPL njsscan) | Highest precision of any language. Specific gaps: sequelize/ORM injection, remote property injection, GHA injection |
| **Python** | 114 | 6 | **83 %** | 50 % | ~95 | ~57 | **none** | **Best value-per-effort.** High TP rate, zero coverage of our own, and Bandit (Apache-2.0) is a legally clean specification to reimplement. Notable classes: NaN injection, raw SQLAlchemy execute, f-string SQL |
| **Java** | 16 | 3 | 100 % | 33 % | ~16 | ~5 | `aegis-java-*` (T3) | Small observed volume, but Spring misconfiguration (actuator exposure) is a class our taint pack does not cover at all |
| **C#** | 9 | 4 | 100 %* | 50 % | ~9 | ~4 | none | *2 of 4 undecidable. Lowest volume; revisit if a C# customer appears |
| **TOTAL** | **1,387** | 40 | 61 % | 32 % | **~840** | **~451** | | |

> **Read the estimates as order-of-magnitude, not precision.** Per-language samples are 3–10 items;
> Java (n=3) and C# (n=4) cannot support a percentage. Ruby's "~0 vulns" means *none observed in 10*,
> not that the true rate is zero.

---

## 4. Corpus weighting — Ruby's 57 % is composition, not market signal

| repo | lost findings | language | code LOC |
|---|--:|---|--:|
| mastodon | 393 | Ruby | 244,128 (150k Ruby) |
| chatwoot | 392 | Ruby | 449,000 (189k Ruby) |
| librenms | 182 | PHP | — |
| redash | 114 | Python | 77,757 |
| FreshRSS | 91 | PHP | — |
| DVWA | 84 | PHP | 11,327 |
| juice-shop | 73 | JS/TS | 79,764 |

**Ruby is 785/1,387 = 57 % of all lost findings, and it comes from exactly 2 repos out of 15.**
Those two are the largest in the corpus — 339k Ruby LOC between them, against DVWA's 11k. Ruby's
dominance is an artefact of **which repos V2 happened to include**, not evidence that Ruby matters
most to our market.

**The roadmap must not be ranked by that number**, and G2's Part C — which put Ruby third largely on
volume — was mis-ranked by exactly this bias. Corrected below.

### Re-ranked replacement roadmap

| G2 rank | **G3 rank** | language | why it moved |
|:--:|:--:|---|---|
| 2 | **1** | **Python** | 83 % TP, ~57 est. vulns, **zero** coverage of our own, and Bandit is a free legal specification. Best value-per-effort |
| 6 | **2** | **JS/TS** | Highest precision (88 %) and 62 % vuln rate. We are strongest here, but the residual gaps are real vulnerabilities, not noise |
| 4 | **3** | **PHP** | Largest *real* TP volume after Ruby's discount (~159), and we already have a pack to extend |
| 1 | **4** | **Java** | 100 % TP but only 16 observed findings. Pack exists; Spring misconfiguration is a genuine uncovered class. Market importance keeps it here |
| 5 | **5** | **C#** | Unchanged — lowest volume, half the sample undecidable |
| 3 | **6** | **Ruby** | **Biggest drop.** 57 % of lost volume but 20 % TP and no exploitable vulns observed; dominated by an obsolete rule. Replacing it would largely reproduce noise, and Brakeman is unusable |
| — | **cross-cutting** | **CI/CD + container rules** | **New entry, arguably first.** 9 TP / 0 FP in the sample, fires in all six languages, ~200+ findings. Language-independent and cheap |

---

## 5. For counsel — what we cover and what we would genuinely lose

*Written to be accurate, not favourable.*

> Aegis's own rules, plus the LGPL-licensed njsscan pack, detect **every documented vulnerability we
> currently detect** on our ground-truth corpora — removing all 2,677 Semgrep-licensed rules changes
> ground-truth recall not at all (NodeGoat 6/7, DVWA 3/6, WebGoat 6/6 either way). What those rules
> supply is **breadth**: 1,387 additional findings across a 15-repository corpus, of which hand-triage
> of a 40-item weighted sample indicates roughly **61 % are true positives and roughly 32 % are
> exploitable vulnerabilities** — an estimated ~840 true findings and ~451 real vulnerabilities we
> would no longer report. That loss is real and would be visible to customers, but it is **not
> evenly distributed and not what our detection claims rest on**: the largest single block (Ruby,
> 57 % of the total) triaged at only 20 % true-positive with no exploitable vulnerabilities observed
> and is dominated by a rule that checks for an API Rails removed in 2013, while a meaningful share
> of the genuine vulnerabilities in the remainder are **already caught by our own rules at the same
> code location** (4 of the 13 sampled vulnerabilities). Our honest position is therefore that these
> rules currently provide substantial *coverage breadth and report completeness* that we would need
> months of rule-writing to reproduce, that we could continue to detect the vulnerability classes we
> today claim and demonstrate without them, and that we have not yet written our own rules for
> Python, Ruby or C# at all.

---

## Gate

| requirement | status |
|---|---|
| 40-item triage table with confidences | ✅ above — 23 TP / 15 FP / 2 UNC, each with basis and confidence |
| TP rate reported | ✅ 61 % (excl. uncertain); 32 % exploitable-vulnerability rate |
| per-pack TP rates | ✅ `p/default` = 73 % of losses at 56 % TP; small language packs high-precision/low-volume |
| re-ranked replacement roadmap | ✅ Ruby 3 → 6; Python → 1; CI/CD rules added as a cross-cutting entry |
| corpus-weighting sanity check | ✅ Ruby = 57 % of losses from 2/15 repos, 339k LOC — composition, not market importance |
| honest statement for counsel | ✅ §5 |

**Method limits, stated:** V2 findings were triaged from rule semantics plus the stored code
snippet, since only 7 of the 15 repositories are held locally; those 7 were verified against real
source. Per-language samples of 3–10 cannot carry a percentage on their own. Two C# findings were
left undecided rather than guessed. Java's lost volume (16) comes only from F1 spring-petclinic
because WebGoat's V2 SAST run timed out.
