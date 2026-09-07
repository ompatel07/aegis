# Rule licensing — what Aegis consumes, and under which licence

**Compiled:** 2026-09-07 (Pass G1, Part C) · **Method:** every pack Aegis actually loads was
fetched from the registry and its rules' `metadata.license` field was tallied programmatically.
The counts below are measured, not estimated.

> **This document contains no legal opinion and is not legal advice.** It exists so Om can put
> accurate facts in front of a lawyer. Nothing here says whether our usage is permitted; it says
> what we consume, how many rules, under which declared licence, and which questions follow.

---

## How Aegis consumes rules

Aegis does **not** vendor the registry. At scan time `semgrep_engine.py` passes registry
shortcuts (`--config p/...`) and semgrep **fetches them live from `semgrep.dev`** on every scan,
alongside our own bundled rules in `/app/rules/{taint,iac,quality}`.

Two configuration sites decide what is fetched:

| where | packs |
|---|---|
| `services/scanner/config.py:48` (always-on) | `p/owasp-top-ten`, `p/r2c-security-audit`, `p/default`, `p/secrets`, `p/supply-chain`, `p/cwe-top-25` |
| `semgrep_engine.py` `_LANGUAGE_RULESETS` (per detected language) | `p/python`, `p/javascript`, `p/typescript`, `p/nodejsscan`, `p/java`, `p/golang`, `p/ruby`, `p/php`, `p/csharp` |
| `semgrep_engine.py` `_IAC_RULESETS` (when the files exist) | `p/dockerfile`, `p/terraform` |

---

## Measured licence inventory

| source | rules | declared `metadata.license` | who publishes it |
|---|--:|---|---|
| `p/owasp-top-ten` | 560 | **Semgrep Rules License v1.0** (100 %) | Semgrep, Inc. |
| `p/r2c-security-audit` | 225 | **Semgrep Rules License v1.0** (100 %) | Semgrep, Inc. |
| `p/default` | 1,074 | **Semgrep Rules License v1.0** ×1,056 · **AGPL-3.0** ×18 | Semgrep, Inc. (+ AGPL contributions) |
| `p/secrets` | 52 | **Semgrep Rules License v1.0** (100 %) | Semgrep, Inc. |
| `p/supply-chain` | 1 | **Semgrep Rules License v1.0** | Semgrep, Inc. |
| `p/cwe-top-25` | 216 | **Semgrep Rules License v1.0** (100 %) | Semgrep, Inc. |
| `p/python` | 151 | **Semgrep Rules License v1.0** (100 %) | Semgrep, Inc. |
| `p/javascript` | 74 | **Semgrep Rules License v1.0** (100 %) | Semgrep, Inc. |
| `p/typescript` | 74 | **Semgrep Rules License v1.0** (100 %) | Semgrep, Inc. |
| `p/java` | 60 | **Semgrep Rules License v1.0** (100 %) | Semgrep, Inc. |
| `p/golang` | 42 | **Semgrep Rules License v1.0** (100 %) | Semgrep, Inc. |
| `p/ruby` | 45 | **Semgrep Rules License v1.0** (100 %) | Semgrep, Inc. |
| `p/php` | 24 | **Semgrep Rules License v1.0** (100 %) | Semgrep, Inc. |
| `p/csharp` | 27 | **Semgrep Rules License v1.0** (100 %) | Semgrep, Inc. |
| `p/dockerfile` | 7 | **Semgrep Rules License v1.0** (100 %) | Semgrep, Inc. |
| `p/terraform` | 63 | **Semgrep Rules License v1.0** (100 %) | Semgrep, Inc. |
| **`p/nodejsscan`** | **114** | **LGPL-3.0-or-later** (100 %) | njsscan / Ajin Abraham (third party, not Semgrep) |
| **Aegis `rules/taint`, `rules/iac`, `rules/quality`** | ~40 | **ours — we author them** | Aegis |

### Totals across everything we fetch

| declared licence | rule count |
|---|--:|
| **Semgrep Rules License v1.0** | **2,677** |
| LGPL-3.0-or-later (`p/nodejsscan`) | 114 |
| AGPL-3.0 (inside `p/default`) | 18 |
| Authored by us | ~40 |

The licence string embedded in every one of those 2,677 rules is verbatim:
`Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license`

---

## Where the exposure sits, factually

1. **Volume.** 2,677 of the ~2,850 rules we run are Semgrep-published under the Semgrep Rules
   License v1.0. Per V2 §4 and F2 §C, the **registry does most of the detection work** — on this
   corpus our own `aegis-*` rules contribute 0–37 % of SAST findings depending on language, and
   0 % on Python, Java (clean code) and Ruby/C#. Aegis's SAST output is therefore substantially
   produced by Semgrep-licensed rules.
2. **Live fetch, per scan.** We do not ship these rules; we retrieve them from `semgrep.dev` at
   scan time. Whether "use" is distribution, or a service dependency, is a question for counsel —
   and it also means the terms in force are whatever is current at fetch time, not the terms on
   the day we built the image.
3. **We intend to sell Aegis.** That is the commercial-use trigger the Semgrep Rules License is
   reported to bear on (Dec 2024). **We have not read or interpreted the licence text here** —
   it is at `semgrep.dev/legal/rules-license`.
4. **`p/nodejsscan` is a different animal.** Its 114 rules are LGPL-3.0-or-later and come from
   the njsscan project, not Semgrep. Different obligations, different author.
5. **18 AGPL-3.0 rules sit inside `p/default`.** AGPL is a strong network-copyleft licence and
   they are mixed into a pack we load on every scan; they are not separable through the `p/`
   shortcut.

---

## Does Opengrep change the picture?

**Tested, and the answer is essentially no — with one caveat.**

- Opengrep 1.29.0's `--config` accepts *"Semgrep registry entry name"*, and we verified live that
  `opengrep scan --config p/nodejsscan` **fetches from `semgrep.dev` and returns rules carrying
  the same `metadata.license` values**. Swapping the *engine* does not change where the rules come
  from or how they are licensed.
- **The engine licence is a separate axis from the rule licence.** Opengrep is LGPL-2.1 (a fork of
  Semgrep CE, which moved to a stricter licence); Semgrep CE's current engine terms are its own
  question. Changing engine may affect *engine* obligations while leaving all 2,677 rule licences
  untouched.
- **Caveat / open item:** Opengrep also accepts rules from arbitrary git repositories
  (`--config git+https://github.com/org/rules#tag`). The consortium has stated an intent to
  maintain a permissively-licensed rule ecosystem. **We did not evaluate the coverage or quality
  of any Opengrep-native rule set in this pass** — if replacing Semgrep-licensed rules ever
  becomes necessary, that evaluation is unstarted work, and F2/G1 evidence says the registry is
  doing most of the detecting, so the replacement cost would be substantial.

---

## Questions for counsel

Stated as questions, deliberately unanswered here:

1. Does running Semgrep-licensed rules inside a commercial SaaS/self-hosted product constitute
   permitted use under Semgrep Rules License v1.0?
2. Does fetching rules at scan time rather than redistributing them change the analysis?
3. Do the 18 AGPL-3.0 rules inside `p/default` create obligations distinct from the rest of that
   pack, given we cannot exclude them via the `p/` shortcut?
4. What are our obligations for the 114 LGPL-3.0-or-later njsscan rules?
5. Does swapping the engine to Opengrep (LGPL-2.1) alter any of the above, given the rules would
   still be fetched from the Semgrep registry?
6. If the answer to (1) is unfavourable, what is the minimum change — pinning a pre-Dec-2024 rule
   snapshot, moving to an Opengrep-native/permissive rule set, or authoring replacements?

---

## Reproducing this table

```
python3 - <<'PY'
import urllib.request, yaml, collections
for p in ["p/owasp-top-ten","p/r2c-security-audit","p/default","p/secrets","p/supply-chain",
          "p/cwe-top-25","p/python","p/javascript","p/typescript","p/nodejsscan","p/java",
          "p/golang","p/ruby","p/php","p/csharp","p/dockerfile","p/terraform"]:
    doc = yaml.safe_load(urllib.request.urlopen("https://semgrep.dev/c/"+p, timeout=90).read())
    lic = collections.Counter((r.get("metadata") or {}).get("license","(none)") for r in doc["rules"])
    print(p, len(doc["rules"]), dict(lic))
PY
```

---

## UPDATE — Pass G2 (2026-09-07): the picture has changed materially

Three facts in this document were superseded by G2 (`docs/RULE_SOVEREIGNTY_G2.md`). The licence
*question* is unchanged and still for counsel; the *exposure* is now smaller and measurable.

**1. We no longer live-fetch. The rules are pinned and vendored.**
`scripts/vendor_rules.py` pins all 17 packs into `services/scanner/rules/vendor/` with a manifest
recording each pack's sha256, rule count and licence histogram. Question 2 below ("does fetching at
scan time rather than redistributing change the analysis?") now has a concrete answer for counsel to
work from: **we hold a pinned local copy**, refreshed monthly under review. That is a different — and
more clearly bounded — posture than an unreviewed per-scan download, and counsel should be told
which one they are advising on.

**2. The 18 AGPL-3.0 rules are gone.**
Question 3 asked what obligations they create *given we cannot exclude them via the `p/` shortcut*.
Vendoring removed that constraint: they are dropped at pin time
(`EXCLUDE_PREFIXES = ("trailofbits.",)`), taking `p/default` from 1,074 to 1,056 rules. **The
question is now moot** unless we choose to re-include them.

**3. Two counts, both true — use the right one.**
This document counts **per-pack rule instances** (2,677 under the Semgrep licence), which is what the
manifest ships. G2's index counts **distinct rule ids** (1,142 under the Semgrep licence), because
packs overlap heavily — `p/default` re-includes much of `p/owasp-top-ten`. For "how many distinct
rules do we depend on", the distinct number is the honest one.

**4. What our findings actually depend on** (G2 Part A, 1,810 findings across V2 + F1):
**83.5 %** come from Semgrep-licensed rules — but **ground-truth recall is identical without them**
(NodeGoat 6/7, DVWA 3/6, WebGoat 6/6 in both configurations). They supply breadth and volume, not
the documented-vulnerability detection our recall claims rest on. That distinction matters
commercially and should be stated to counsel alongside the percentage.

**5. Opengrep does not change the picture — now confirmed, not assumed.**
The open item above ("we did not evaluate any Opengrep-native rule set") is closed: the
`opengrep/opengrep-rules` repository is **archived with 6 stars**. There is no alternative ecosystem
there. Separately, **Brakeman — the obvious open-source answer for Ruby, our single largest exposure
at 45 % of all findings — is published under the Brakeman Public Use License (Synopsys, Inc.), which
states that commercial use requires a paid licence.** It is not an escape route.
