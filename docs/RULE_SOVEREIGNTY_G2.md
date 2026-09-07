# Pass G2 — rule-set sovereignty: measuring the dependency and building the option to reduce it

**HEAD:** `d5cfaa5` · **Run date:** 2026-09-07 · **Corpora:** V2 (15 repos) + F1 (4 repos) for the
dependency measurement; 7 live checkouts for the scans.

G1 established that we run 2,677 rule instances under the Semgrep Rules License v1.0, live-fetched
per scan, in a product we intend to sell. **This pass does not resolve the legal question — that is
for counsel.** It answers the two engineering questions underneath it: *how dependent are we,
exactly?* and *what would it take not to be?*

---

## PART A — the dependency, measured

### A1. Where our findings actually come from

Every SAST finding in both corpora was joined against an exact rule-id → pack → licence index built
by fetching all 17 packs we load (1,274 distinct rule ids). **No finding was unclassifiable.**

| language | findings | Semgrep-licensed | % | LGPL (njsscan) | **ours (`aegis-*`)** | % ours |
|---|--:|--:|--:|--:|--:|--:|
| **Ruby** | 814 | 785 | **96.4 %** | 29 | 0 | 0.0 % |
| **PHP** | 531 | 441 | 83.1 % | 7 | **83** | 15.6 % |
| **JS/TS** | 305 | 139 | **45.6 %** | **105** | **61** | 20.0 % |
| **Python** | 131 | 120 | 91.6 % | 11 | 0 | 0.0 % |
| **Java** | 16 | 16 | 100 % | 0 | 0 | 0.0 % |
| **C#** | 9 | 9 | 100 % | 0 | 0 | 0.0 % |
| **ALL** | **1,810** | **1,512** | **83.5 %** | 152 | 146 | 8.1 % |

**83.5 % of every SAST finding Aegis has ever produced comes from a Semgrep-licensed rule.**

Two things stand out. **Ruby alone is 45 % of all findings we have ever produced** and is 96.4 %
Semgrep-licensed with nothing of our own — the single largest concentration of exposure. And
**JS/TS is our strongest position (45.6 %)** precisely because LGPL njsscan carries 105 findings
there; it is the one language where a permissive third-party source is already doing heavy lifting.

> **Sample caveat:** Java (n=16) and C# (n=9) are small — WebGoat timed out during V2 and
> spring-petclinic is deliberately clean. Their *100 %* is directionally right (we shipped no Java
> findings of our own until T3, and none for C# at all) but rests on few observations.

### A2. "If every Semgrep-licensed rule vanished tomorrow" — we ran it

Config: **our `aegis-*` packs + LGPL `p/nodejsscan` only.** The 18 AGPL-3.0 rules were deliberately
*excluded* rather than kept — strong network copyleft is not a safer place to stand.

| repo | full config | **sovereign** | retained |
|---|--:|--:|--:|
| DVWA (PHP) | 115 | 31 | 27 % |
| NodeGoat (JS) | 62 | 32 | 52 % |
| juice-shop (TS) | 192 | 121 | 63 % |
| WebGoat (Java) | 197 | 10 | 5 % |
| dvpwa (Python) | 6 | 0 | 0 % |
| spring-petclinic (Java) | 16 | 0 | 0 % |
| django-nV (Python) | 68 | 11 | 16 % |

Raw volume collapses by 73–95 % on most repos. **But volume is the wrong metric**, and the
ground-truth measurement says so:

### A3. Ground-truth recall is IDENTICAL under both configurations

| repo | full config | **sovereign** |
|---|--:|--:|
| NodeGoat (7 documented vulns) | **6/7** | **6/7** |
| DVWA (6 documented, in-scope) | **3/6** | **3/6** |
| WebGoat (6 documented Java flows) | **6/6** | **6/6** |

**Not one documented vulnerability is lost.** Every ground-truth finding we catch, we catch with our
own rules or with LGPL njsscan. (`node_ssrf`, which covers NodeGoat's SSRF, is an njsscan rule —
it survives.)

**This is the most important number in the pass.** The Semgrep-licensed rules contribute
*breadth and volume* — the long tail of advisory findings that makes a report look thorough — not
the documented-vulnerability detection our recall claims rest on. Losing them would be a severe
product-quality regression and a marketing problem. It would **not**, on this evidence, be a
detection-capability catastrophe.

---

## PART B — pinned and vendored

Live-fetching was wrong for three reasons that have nothing to do with the legal question:
licence exposure we cannot inventory, a `rule_pack_version` that cannot be pinned (F1 row 1b), and a
registry that can silently change a customer's results between two scans of unchanged code.

**What now exists**

- `scripts/vendor_rules.py` — `--refresh` (fetch + rule-level diff against the pin), `--refresh
  --write` (re-pin, after review), `--verify` (sha256 check of every vendored file).
- `services/scanner/rules/vendor/*.yaml` — 17 packs, **2,791 rules, 6.8 MB**, deterministically
  serialised (rules sorted by id, `newline=""`) so an unchanged pack hashes identically.
- `services/scanner/rules/manifest.yaml` — per pack: source URL, **sha256**, rule count, rules
  excluded, and the full licence histogram. `--verify` reports **0 mismatches**.
- The engine resolves `p/<pack>` to its pinned copy, **falling back to the registry shortcut with a
  warning** if a vendored file is missing, so a partial checkout degrades rather than losing coverage.

**Refresh cadence:** monthly, and on demand when a CVE class requires it. `--refresh` prints the
rule-level diff, a human reads it, and only then is `--write` run. **The review is the point** — an
unreviewed auto-fetch would put us back exactly where we started.

### The AGPL exclusion — now possible

The `p/` shortcut gave no way to drop the 18 AGPL-3.0 Trail of Bits rules bundled inside
`p/default`; they arrived on every scan whether we wanted them or not. Vendoring removes that
constraint: `EXCLUDE_PREFIXES = ("trailofbits.",)` drops them at pin time. **`p/default`
1,074 → 1,056 rules; the manifest licence histogram now shows 2,677 Semgrep + 114 LGPL and no AGPL.**

### `rule_pack_version` — F1 row 1b fixed

The id now hashes rule **content**, never paths, with the date coming from the manifest's `pinned_at`
rather than `now()` (a wall-clock date would break reproducibility across midnight for an unchanged
rule set). Verified on **DVWA — the exact repo where the bug fired**, because its project sanitiser
wrappers trigger the `mkdtemp` augmented-taint path:

```
run 1: rule_pack_version=rp-20260907-600d94e92e  findings=114
run 2: rule_pack_version=rp-20260907-600d94e92e  findings=114
REPRODUCIBLE: True      IDENTICAL findings: True
```

### Two regressions the "no detection lost" gate caught

Pinning is not a no-op, and the T2-standard diff earned its keep twice:

1. **Rule ids were silently rewritten.** Loading a pack from a file makes semgrep derive ids from
   that path: `php.lang.security.exec-use.exec-use` became
   `app.rules.vendor.php.lang.security.exec-use.exec-use`. Left alone this changes every finding's
   fingerprint, so an unchanged codebase would have reported its **entire backlog as NEW** and broken
   lifecycle continuity. Fixed by normalising the id back to its canonical form on parse.
2. **`--exclude-rule` stopped matching.** It compares ids exactly, so every suppression silently
   lapsed and a rule we deliberately suppress (`echoed-request`) reappeared. Fixed by emitting both
   the bare and vendored spellings.

Neither would have been visible from finding *counts* alone.

---

## PART C — the replacement roadmap (plan only; no rules written this pass)

Ranked by **exposure × market importance**, informed by Part D's licence findings.

| # | language | Semgrep-licensed findings | our coverage today | what replacement needs | effort |
|---|---|--:|---|---|---|
| **1** | **Java** | 16 (100 %) | `aegis-java-*` exists (T3) but yields 0 on clean code | Extend the T3 Spring/servlet taint pack beyond injection into the classes registry covers: deserialisation, XXE, weak crypto, SSRF variants, path traversal. G1 showed cross-function taint is buyable via Opengrep for Java specifically. | **medium** — a pack exists to build on |
| **2** | **Python** | 120 (91.6 %) | none | **Bandit is Apache-2.0** — its ~35 check *designs* (B1xx–B7xx) are a legally clean specification to reimplement as semgrep rules. Not a conversion (Bandit is AST-plugin based), but the hard part — knowing what to check — is free. | **medium** |
| **3** | **Ruby** | 785 (96.4 %) | **none** | The largest single exposure and the hardest to close: **Brakeman is commercially restricted** (Part D), so there is no free reference implementation to work from. Rails-specific taint (mass assignment, unsafe `render`/`send`, SQL via `where("...#{}")`, `html_safe`) written from scratch. V2 also flagged the registry's Rails rules as noisy, so this is a quality opportunity as well as a licence one. | **high** |
| **4** | **PHP** | 441 (83.1 %) | `aegis-php-*` = 15.6 % of PHP findings | Extend the existing pack — it already carries DVWA's ground truth. Broaden sinks (file ops, deserialisation, LDAP, header injection) rather than starting over. | **low–medium** |
| **5** | **C#** | 9 (100 %) | none | Lowest volume observed and lowest priority; revisit if a C# customer appears. | **medium** (greenfield) |
| **6** | **JS/TS** | 139 (45.6 %) | `aegis-js-*` = 20 %, plus LGPL njsscan 34 % | **Already our best position.** njsscan is LGPL and directly usable; our own pack covers the ground truth. Targeted top-ups only. | **low** |

**The strategic read:** our exposure is *inverted* against our differentiation. We are least exposed
where we are strongest (JS/TS) and most exposed where we ship nothing (Ruby, Python, Java, C#).
Sovereignty work should start at **Java and Python** — Java because a pack already exists and the
market matters, Python because Bandit hands us a legally clean specification — while **Ruby is the
biggest number and the worst-supported path**, and should be scoped as a real project rather than a
top-up.

---

## PART D — what else exists (researched, not adopted)

Licences below were **fetched from each project's repository**, not recalled.

| source | licence (verified) | language | semgrep format? | usable by a commercial product? |
|---|---|---|---|---|
| **njsscan rules** (`p/nodejsscan`) | **LGPL-3.0-or-later** | JS/Node | **yes — already semgrep rules** | **Yes, and we already do.** 114 rules; carries 105 of our 305 JS/TS findings |
| nodejsscan (the web app) | GPL-3.0 | — | n/a | Not relevant; the rules, not the app, are what we use |
| **gosec** | **Apache-2.0** | Go | no — Go AST analyser | Yes. Reimplementation, not conversion; rule *designs* are freely reusable |
| **bandit** | **Apache-2.0** | Python | no — Python AST plugins | Yes. Same: the check catalogue is a clean specification |
| **brakeman** | **Brakeman Public Use License (Synopsys, Inc.)** — *"Commercial Uses of the Software for commercial purposes require a commercial, non-free license"* | Ruby | no | **No.** The obvious answer for our biggest gap is licensed exactly the way we are trying to avoid |
| PHP_CodeSniffer | BSD-3-Clause | PHP | no — "sniffs" | Yes (permissive), but it is a style engine; security value is in the add-on below |
| phpcs-security-audit | GPL-3.0 | PHP | no | Copyleft — needs the same counsel review as any GPL dependency |
| semgrep-rules (upstream repo) | NOASSERTION → Semgrep Rules License | many | yes | This *is* the thing we are trying to reduce dependence on |
| Opengrep (engine) | **LGPL-2.1** | — | n/a | Engine licence only; changes nothing about rule licensing (G1) |
| **`opengrep/opengrep-rules`** | NOASSERTION — **ARCHIVED, 6 stars** | — | — | **There is no Opengrep rule ecosystem.** G1 left this as an open item; it is now closed, negatively |

**Three conclusions.**

1. **Opengrep does not help here.** G1 speculated the consortium might offer a permissively-licensed
   rule ecosystem. Its rules repository is **archived with 6 stars**. Opengrep is an engine story, not
   a rules story — and G1 already showed it resolves the *same* Semgrep registry.
2. **Brakeman is a trap for exactly our situation.** Ruby is 45 % of our findings and 96.4 %
   Semgrep-licensed, and the standard open-source Rails scanner is Synopsys-owned with an explicit
   commercial-use restriction. Ruby sovereignty means writing rules, not adopting a project.
3. **Apache-2.0 tools are a specification, not a shortcut.** gosec and bandit cannot be converted —
   they are AST analysers, not pattern rules — but their check catalogues are permissively licensed
   prior art we can reimplement without licence risk. That is the cheapest legitimate path for Python
   and Go.

---

## GATE

| requirement | status |
|---|---|
| A: per-language dependency table | ✅ 1,810 findings classified, 0 unclassifiable |
| A: "without them" scan + ground-truth recall | ✅ 7 repos scanned; **GT recall identical** (6/7, 3/6, 6/6) |
| B: pinned manifest in place | ✅ 17 packs, 2,791 rules, `--verify` 0 mismatches |
| B: `rule_pack_version` reproducible | ✅ verified twice on DVWA — the repo that exhibited the bug |
| B: AGPL rules excludable | ✅ 18 excluded at pin time; `p/default` 1,074 → 1,056 |
| C: ranked replacement roadmap | ✅ 6 languages ranked by exposure × market importance |
| D: alternative-source inventory | ✅ 10 sources, licences verified from source |
| no detection lost vs main | ✅ **LOST=0, NEW=0 across all 7 repos** (T2-standard diff, below) |
| full suite + `go build ./...` | ✅ pytest **150 passed, 0 failed**; `semgrep --test` **38/38**; go build clean ×2; web typecheck clean |

**Not done / deliberately out of scope:** writing any replacement rules (Part C is a plan, as
instructed); resolving the licensing question (counsel); evaluating rule *quality* of gosec/bandit
catalogues beyond licence.

### The before/after gate in full

Pinned vendored packs vs the live-fetch baseline, plus `rule_pack_version` stability (two scans each):

| repo | before | after | LOST | NEW | id stable | rule_pack_version |
|---|--:|--:|--:|--:|:--:|---|
| DVWA | 114 | 114 | **0** | **0** | ✅ | `rp-20260907-600d94e92e` |
| NodeGoat | 62 | 62 | **0** | **0** | ✅ | `rp-20260907-db2bca5656` |
| juice-shop | 191 | 191 | **0** | **0** | ✅ | `rp-20260907-456b3c1b08` |
| WebGoat | 193 | 193 | **0** | **0** | ✅ | `rp-20260907-81b4d325c7` |
| dvpwa | 6 | 6 | **0** | **0** | ✅ | `rp-20260907-b84c4e8bbe` |
| spring-petclinic | 16 | 16 | **0** | **0** | ✅ | `rp-20260907-ccdaa16c5b` |
| django-nV | 61 | 61 | **0** | **0** | ✅ | `rp-20260907-b84c4e8bbe` |
| **TOTAL** | | | **0** | **0** | | |

Pinning is behaviour-identical to live fetch — *after* the two regressions above were fixed. Ids
differ per repo because different language packs load, which is the field working as intended;
dvpwa and django-nV share an id because both resolve to the same Python + IaC pack set.
