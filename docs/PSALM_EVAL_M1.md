# Pass M1 — Psalm as a licence-clean PHP engine

**Measurement pass. Nothing was adopted.** Psalm was cloned and run entirely outside
this repository (`E:\m1work`), as in L1. No file under `services/` changed.

Two questions were asked, and they are answered **separately** below, because a good
answer to one would otherwise hide a bad answer to the other.

| | question | answer |
|---|---|---|
| **Q1** | Is Psalm licence-clean, and does it cover the PHP detection we would lose? | **Licence: yes, with one flagged dependency.** Coverage: it replaces roughly *none* of it. |
| **Q2** | Is it better, equal, or worse than what we have now? | **Equal on a synthetic benchmark. Substantially worse on real code.** |

**Recommendation: REJECT** as a detection engine. Detail and reasoning in §7.

---

## 1. Method

| | |
|---|---|
| Psalm | 6.16.1, installed by Composer into `E:\m1work\psalmbin` (never into this repo) |
| Runtime | `composer:2` image (PHP 8.4), `--memory=2g`/`3g`, `--no-cache` on every run |
| Mode | `--taint-analysis` only, `errorLevel="8"` so no type issues are reported |
| Our baseline | `services/scanner/rules/taint/php.yaml` (`aegis-php-*`, 5 rules) under semgrep 1.97.0, invoked with the same flags `semgrep_engine.py` uses in production |
| Corpus | DVWA, FreshRSS, TeamPass — cloned at fixed commits outside the repo |

Every finding quoted below was triaged by **reading the source at the reported
location**, applying one standard to both engines: *is the reported dataflow
exploitable?* A finding on a line that happens to contain a real bug reachable by a
**different** path is counted as a false positive, and is called out where it occurs.

Triage scripts are reproducible: `triage_dvwa.py`, `triage_freshrss.py`, `gt_recall.py`.

### Corpus size

| repo | first-party `.php` | lines | notes |
|---|--:|--:|---|
| DVWA | 169 | 12,934 | deliberately vulnerable |
| FreshRSS | 592 | 125,466 | real application |
| TeamPass | 457 | 368,309 | real application; **also vendors 4,487 more `.php` in-tree** |

---

## 2. Q1 — Licensing

### 2.1 Psalm itself

`vendor/vimeo/psalm/LICENSE` is the **MIT License**, Copyright (c) 2016 Vimeo. It
carries the standard grant including the right to *"use, copy, modify, merge, publish,
distribute, sublicense, and/or **sell** copies"*. No Commons Clause, no field-of-use
restriction. This is the clean result L1 failed to find in GitLab's ruleset.

### 2.2 Dependencies — read from each package's own manifest, never inferred

49 runtime packages (`composer.lock` has **zero** dev packages in the shipped set):

| licence | packages |
|--:|---|
| 44 | MIT |
| 2 | BSD-3-Clause (`nikic/php-parser`, `sebastian/diff`) |
| 2 | ISC (`danog/advanced-json-rpc`, `felixfbecker/language-server-protocol`) |
| **1** | **OSL-3.0 — `netresearch/jsonmapper`** |

The licence for every package was read from `vendor/<name>/composer.json`, and
cross-checked against `composer.lock`. **Zero mismatches.**

### 2.3 The OSL-3.0 package — a lawyer question, with the technical facts pinned down

`netresearch/jsonmapper` is **OSL-3.0**, a copyleft licence whose §5 "External
Deployment" clause treats making the software available over a network as
distribution. That is exactly our deployment model, so it cannot be waved through.

What is technically true, each verified by execution rather than by reading:

1. **It is pulled in transitively**, not chosen: `vimeo/psalm` → `danog/advanced-json-rpc`
   (which requires `netresearch/jsonmapper: ^5`) → the package. It exists to
   deserialise JSON-RPC for Psalm's **language server**, which we would never run.
2. **Its code IS loaded during an ordinary taint run.** Probed with
   `get_included_files()` after a real DVWA scan: `JsonMapper.php` is in the list.
   The mechanism is `Preloader::preload()`, which calls `class_exists()` over a
   JIT-warm-up list (`PreloaderList::CLASSES`) that includes `\JsonMapper`.
3. **No `JsonMapper` object is ever constructed** outside the language server —
   grepping for `new JsonMapper` across `vendor/vimeo/psalm/src/` returns nothing.
4. **Correction to an earlier reading of mine:** the `require_once` of
   `JsonMapper.php` at `CliUtils.php:80-82` is *not* unconditional — it sits inside
   `if ($in_phar)`. It is dead code in a Composer install. The loading in (2) happens
   through the preloader instead.
5. **Deleting the package outright leaves Psalm fully functional.** With
   `vendor/netresearch/` removed, DVWA produced **35 findings, an identical set** to
   the 35 with it present.

**Point 5 is the practical answer.** If Psalm were ever adopted, the OSL-3.0 code can
simply not be shipped. This is a packaging step, not a legal risk we would have to
carry — but the decision that it is *sufficient* is counsel's, not mine.

### 2.4 Q1 verdict

**Licence: clean, with one removable OSL-3.0 dependency.** There is no Commons
Clause and nothing that forbids selling. On the licence question alone, Psalm is a
better answer than anything L1 found.

**But Q1 also asked whether Psalm covers the PHP detection we would lose.** It does
not — see §4 and §5. The licence being clean does not make it a replacement.

---

## 3. Practicality

### 3.1 The `vendor/` boundary question — much weaker than assumed

Aegis never builds, installs dependencies for, or runs scanned customer code. Psalm's
type inference wants `vendor/` present, and `composer install` executes composer
scripts, so this looked like a blocker. Measured on FreshRSS:

| | with `vendor/` (after `composer install --ignore-platform-reqs`) | without `composer.json` at all |
|---|--:|--:|
| findings | 194 | 194 |
| finding **sets** | **byte-identical** | **0 differences either way** |
| type inference | 92.94 % | 93.44 % |
| wall time | 70.6 s | 108.5 s |
| peak memory | 396 MB | 546 MB |

**The boundary objection is not the problem here.** Running Psalm with no
dependencies installed costs nothing in accuracy on this corpus — it is slightly
*slower* and hungrier, because unresolved types widen, but it finds exactly the same
things.

One hard edge: Psalm **fails outright** if `composer.json` exists and `vendor/` does
not (`Could not find any composer autoloaders`). The workaround is to move
`composer.json` aside before the run — mechanical, but it means Psalm cannot simply be
pointed at a customer checkout as-is.

### 3.2 Determinism — a Pass-1 invariant

**Deterministic.** DVWA run twice: 35/35 identical findings, identical order. Re-run
again for this write-up on a rebuilt Docker environment: **35 findings, identical set,
16.12 s / 79.3 MB** against the recorded 16.6 s / 79 MB baseline. Psalm clears this bar.

### 3.3 Resource cost — and this one is disqualifying on its own

| repo | wall time | peak memory | type inference |
|---|--:|--:|--:|
| DVWA (169 files) | 16.1 s | 79 MB | 75.2 % |
| FreshRSS (592 files) | 70.6 s | 396 MB | 92.9 % |
| **TeamPass (457 files, 368 k lines)** | **1,365 s (22.8 min)** | **594 MB** | 79.4 % |

`config.py` sets `semgrep_timeout_seconds = 600`. **TeamPass exceeds our SAST budget
by 2.3×** — and that is *after* excluding its in-tree vendored libraries. Pointed at
the repository as it actually ships (4,944 `.php` files, because `vendor/`,
`app/includes/libraries/` and `public/plugins/` are all committed), the run **did not
complete in 25 minutes** and was killed.

Scaling is superlinear and driven by lines, not file count: TeamPass has *fewer*
first-party files than FreshRSS and takes **19× longer**.

The PHP runtime itself is cheap by comparison: the `composer:2` image is 324 MB.

---

## 4. Q2 — Accuracy, three ways

### 4.1 Ground-truth recall on DVWA (G2's definitions, reused verbatim)

| documented vulnerability | `aegis-php-*` | Psalm | Psalm + custom sources (§6) |
|---|:--:|:--:|:--:|
| SQL injection | HIT | HIT | HIT |
| SQL injection blind | HIT | HIT | HIT |
| Command injection | HIT | HIT | HIT |
| File inclusion | miss | miss | miss |
| XSS reflected | miss | miss | miss |
| XSS stored | miss | miss | miss |
| **recall** | **3/6** | **3/6** | **3/6** |

**Psalm hits exactly what we hit and misses exactly what we miss.** It recovers none
of G2's known gap.

The three misses share one root cause, and it is *not* the one the brief anticipated.
They are not cross-function taint failures. In `fi/source/low.php` the entire file is
`$file = $_GET['page'];`, and the `include($file)` lives in `fi/index.php:36`; in
`xss_r/source/low.php` the code appends to `$html`, which is echoed at
`xss_r/index.php:51`. **The taint crosses via `include`-shared variable scope, not via
a call.** Neither engine models that, and no source or sanitizer configuration fixes it.

### 4.2 Volume and precision, per corpus

| repo | | `aegis-php-*` | Psalm |
|---|---|--:|--:|
| **DVWA** | findings | 31 | 35 |
| | distinct locations | 31 | 31 |
| | true positives | 25 | 29 |
| | **TP rate** | **80.6 %** | **82.9 %** |
| **FreshRSS** | findings | 7 | 194 |
| | true positives | 0 | 0 |
| | **TP rate** | **0 %** | **0 %** |
| **TeamPass** | findings | 2 | 1,036 |
| | distinct locations | 2 | 518 |
| | true positives | **2** | **0** |
| | **TP rate** | **100 %** | **0 %** |
| **All three** | findings | **40** | **1,265** |
| | true positives | **27** | **29** |
| | **TP rate** | **67.5 %** | **2.3 %** |

**Better, equal, or worse — plainly: equal on the synthetic benchmark, decisively
worse on real code.** On DVWA the two engines are within two points of each other. On
the two real applications Psalm emits **1,230 findings and not one of them is a real
vulnerability**, while our five rules emit 9 and get 2 right.

### 4.3 What each engine finds that the other does not (DVWA, exact file:line)

19 true positives are shared. Six are unique to each side:

| Psalm only | `aegis-php-*` only |
|---|---|
| `dvwaPage.inc.php:389,461,497` — cookie-sourced XSS via `dvwaThemeGet()` | `api/src/HealthController.php:88` — `php://input` into `exec()` |
| `open_redirect/source/{low,medium,high}.php` — all three, incl. high's bypassable `strpos(…,"info.php")` guard | `authbypass/change_user_details.php:48` — `json_decode(php://input)` into a raw `UPDATE` |
| | `sqli/source/low.php:34`, `sqli_blind/source/{low:34,high:35,medium:36}` — SQLite `$conn->query()` |

This is genuinely complementary, and it is the one real argument for Psalm: open
redirect and cookie-sourced XSS are classes our pack does not cover at all. Both are
cheap to add as `aegis-php-*` rules — far cheaper than adopting an engine.

### 4.4 Shared false positives

Five of the six DVWA false positives are **identical across both engines**:

- `exec/source/impossible.php:22,26` — `is_numeric()` on all four octets is not
  recognised as a validator. This is G3 item 13, reproduced exactly.
- `bac/source/medium.php:22,29,73` — an anchored digits-only `preg_match` guards
  the branch that assigns `$id`.

`bac/source/medium.php:73` deserves a note: **both engines report the right line for
the wrong reason.** The reported path (`$_GET['user_id']` → `$id` → `$target_id`) is
digit-validated and inert. The line *does* contain a real SQL injection — via
`$ip = $_SERVER['HTTP_X_FORWARDED_FOR']` — which **both engines miss**, because
neither treats `$_SERVER` as a source (§6).

---

## 5. Why Psalm's real-world precision collapses

Three mechanisms, each verified against Psalm's own source.

### 5.1 Call-site merging is the dominant driver

Psalm computes a taint summary per function and **applies it to every call site**.
Once any one caller passes tainted data into a parameter, that function's return value
is treated as tainted *everywhere*.

- **FreshRSS: 125 of 194** findings (64 %) are one instance of this. A single flow —
  `$_GET['rid']` → `Minz_Request::requestId()` → `Minz_Url::display#1` →
  `FreshRSS_Feed::$name` → `_t#2` → `vsprintf` — taints the return of the translation
  function `_t()`. Psalm then reports **every** `echo _t('gen.short.ok')` in the
  codebase, with hardcoded literal keys, as tainted output.
- **TeamPass: 515 of 518** locations (99.4 %) collapse to **one** merge point,
  `json_decode#1`.

Median taint-trail length on FreshRSS is **36 hops**; 179 of 194 exceed ten. A trail
that long is not reviewable by a human, which is the practical cost on top of the
statistical one.

### 5.2 Psalm ships 14 escaper functions, and none of the ones that matter here

Extracted from every `@psalm-taint-escape` annotation in Psalm's stubs:

```
cubrid_real_escape_string, db2_escape_string, escape_string, filter_var, ldap_escape,
mysqli_escape_string, mysqli_real_escape_string, pg_escape_bytea, pg_escape_identifier,
pg_escape_literal, pg_escape_string, real_escape_string, strip_tags, urlencode
```

(`htmlspecialchars` is handled separately by an internal plugin — its stub says so.)

Crucially, **`json_encode` is annotated to *propagate* taint** (`@psalm-flow ($value) -> return`).
All 518 TeamPass locations sink into `prepareExchangedData()`, which is:

```php
$data = json_encode($data, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
```

— the maximal HTML-safe JSON encoding, hex-escaping `<`, `>`, `'`, `"` and `&`,
optionally followed by AES encryption. Nothing can survive it. **Our `aegis-php-xss`
rule already lists `json_encode(...)` as a sanitizer, with a comment explaining why.**
That single line of our rule is the difference between 2 findings and 1,036.

### 5.3 No notion of a validator

Psalm's escapers are *transformers*. A boolean guard removes no taint. Every FreshRSS
false-positive cluster outside the `_t()` merge is this:

| guard used by FreshRSS | findings it fails to suppress |
|---|--:|
| `ctype_xdigit($key)` / `ctype_xdigit($id)` | 7 |
| `ctype_alnum($token)` | 3 |
| anchored `preg_match` on the username | 12 |
| `is_numeric()` (DVWA) | 2 |

Our rules have the same blind spot — it is why we share five of six DVWA false
positives — so this is not a point of difference. It is a point about **taint analysis
in general**, and worth recording as such.

### 5.4 The full FreshRSS triage

All 194 were triaged by hand — no sampling was needed, because they collapse into
eleven clusters. **0 true positives.**

| n | cluster | why it is a false positive |
|--:|---|---|
| 122 | `_t(…)` / `Minz_Url::display(…)` | §5.1 summary merge; reported sinks are literal keys |
| 18 | installer / CLI | `Themes::icon('key')` and friends are literals |
| 15 + 3 | CSP `header(…)` | `csp.frame-ancestors` is read-only config; grepped every writer, there is no request path to it, and `header()` has rejected CRLF since PHP 5.1.2 |
| 12 | username into a config path | `checkUsername()` runs first in the same `&&` chain |
| 7 | `ctype_xdigit`-guarded paths | §5.3 |
| 6 | `exit($_REQUEST['hub_challenge'])` | `Content-Type: text/plain` + `X-Content-Type-Options: nosniff`, set at `p/api/pshb.php:8-10` |
| 3 | `ctype_alnum`-guarded token path | §5.3 |
| 3 | server-generated values | `$_FILES[…]['tmp_name']`, self-issued login token |
| 3 | plain-text email body | `.txt.php` template, not HTML |
| 2 | vendored PHPMailer debug echo | only live when `SMTPDebug` is on |

### 5.5 Double-reporting

Psalm reports `TaintedHtml` and `TaintedTextWithQuotes` at the same location. On
TeamPass this is **100 % duplication — 1,036 findings for 518 locations, every single
one doubled.** On DVWA it affects 4 locations (8 findings). Any adoption would need
de-duplication before findings reached a customer; our fingerprint scheme would
otherwise create two lifecycle entries per issue.

---

## 6. Part D — custom sources: measured, not speculated

Part D was gated on Part C looking viable. **It does not** — 0 true positives across
1,230 real-world findings. But the diagnostic question ("what is missing, and would
adding it help?") is cheap to answer with a measurement, so it was answered.

### 6.1 What Psalm ships

From `VariableFetchAnalyzer.php:526-534`, Psalm's built-in taint sources are **exactly
four superglobals**:

```php
if ($var_name === '$_GET' || $var_name === '$_POST'
    || $var_name === '$_COOKIE' || $var_name === '$_REQUEST') {
    $taints = TaintKindGroup::ALL_INPUT;
}
```

**`$_SERVER`, `$_FILES`, `php://input` and `getenv()` are not sources.** That single
fact explains every unique miss in §4.3 and the `bac/medium.php:73` near-miss in §4.4.

### 6.2 A plugin fixes the gap — and does not improve recall

A ~30-line plugin implementing `AddTaintsInterface` (`plugin/ServerTaintPlugin.php`)
adds `$_SERVER` and `$_FILES`. Re-measured on DVWA:

| | baseline | + plugin |
|---|--:|--:|
| findings | 35 | 58 |
| distinct locations | 31 | 45 |
| locations gained | — | **14** |
| locations lost | — | **0** |
| wall time | 16.1 s | 45.7 s (**2.8×**) |
| peak memory | 79 MB | 127 MB |
| **DVWA ground-truth recall** | **3/6** | **3/6** |

Of the 14 new locations, **6 are true positives** — the whole `upload` module
(`low`, `medium`, `high`×2), `bac/source/low.php:81` (the `HTTP_X_FORWARDED_FOR` SQLi
that both engines missed), and `api/help/help.php:39` (`SERVER_NAME` reflected into an
href). The other 8 are false positives: `upload/source/impossible.php` ×3 (hardened
with an extension whitelist, size limit, MIME check, `getimagesize()` and a re-encode),
`sqli_blind/source/*` ×3 (`header($_SERVER['SERVER_PROTOCOL'] . ' 404 Not Found')` —
`header()` blocks CRLF), plus the DB setup script and a generic redirect helper.

So the increment is **43 % precise, costs 2.8× runtime, and moves ground-truth recall
by zero.** No sanitizer or sink work was attempted, because §5.1 shows the dominant
error is architectural — a call-site-merged summary is not fixable from a plugin that
adds sources or escapers.

**Answer to the brief's Part D question: no, DVWA recall does not exceed 3/6, and it
cannot be made to by configuration.** The three misses are `include`-scope flows (§4.1).

---

## 7. Recommendation

### REJECT — do not adopt Psalm as a detection engine.

Not on licensing. Psalm is MIT and, unlike anything L1 examined, explicitly permits
selling; its one OSL-3.0 dependency is transitive, unused at runtime, and can be
deleted with byte-identical results. **Q1 is a pass.**

It fails on Q2, and on cost, for four independent reasons — any one of which would be
sufficient:

1. **It replaces none of what we would lose.** Ground-truth recall is 3/6 — identical
   to our own rules, with identical hits and identical misses. The reason G2's PHP gap
   exists is `include`-shared variable scope, which Psalm does not model either.
2. **Precision on real code is 0 %.** 1,230 findings across FreshRSS and TeamPass, zero
   true positives, against 9 findings and 2 true positives from our five rules. That is
   not a tuning problem; 99.4 % of the TeamPass findings descend from a single merged
   `json_decode` summary.
3. **It breaks the scan budget.** 22.8 minutes on TeamPass against a 600 s SAST
   timeout, and that is with vendored code excluded; unexcluded it did not finish in 25.
   Time scales with lines, and our corpus contains much larger PHP repos than TeamPass.
4. **Every finding is double-reported.** 100 % duplication on TeamPass. J1's principle
   applies: a double-reported finding is worse than a missing one.

### What to do instead

The measurement produced two concrete, cheap wins that need no new engine:

- **Add open-redirect and cookie-sourced-XSS rules to `aegis-php-*`.** These are
  the only two classes Psalm found that we do not cover (§4.3), and both are ordinary
  semgrep taint rules.
- **Add `$_SERVER['HTTP_HOST' | 'PHP_SELF' | 'SERVER_NAME' | 'HTTP_X_FORWARDED_FOR']`
  and `$_FILES[…]['name']` as sources to the existing rules.** §6.2 shows this class is
  real: it is the actual bug at `bac/source/low.php:81` and the confirmed reflected XSS
  at TeamPass `public/install/upgrade.php:295,553`, which our `aegis-php-xss` rule
  already catches via `PHP_SELF` and which **Psalm misses entirely**.

Both are ordinary rule work in the pack we already own, under a licence we already
control. Neither carries an engine's runtime, memory, packaging or determinism risk.

### If it were adopted anyway

For completeness, since the brief asked: it would have to run **alongside**
`aegis-php-*`, not replace it — §4.3 shows our rules find six DVWA true positives Psalm
does not. That means the overlap (19 shared true positives on DVWA) would have to be
de-duplicated across two engines with different location semantics, **on top of**
Psalm's own internal 2× duplication. And it would be CI-only at best, not part of a
customer scan, because of §3.3.

---

## 8. Answers to the brief, in one place

| question | answer |
|---|---|
| Psalm's licence | **MIT**, explicitly permits selling |
| Dependency licences | 44 MIT, 2 BSD-3-Clause, 2 ISC, **1 OSL-3.0** (`netresearch/jsonmapper`) |
| Is the OSL-3.0 code loaded? | **Yes**, by `Preloader::preload()`; never instantiated; **deleting the package gives identical results** — a lawyer question, but a removable one |
| `vendor/` — shippable or CI-only? | **Neither is required.** With and without `vendor/` produced byte-identical findings on FreshRSS. Psalm does need `composer.json` moved aside when `vendor/` is absent |
| Three-way recall | `aegis-php-*` **3/6**, Psalm **3/6**, Psalm+plugin **3/6** on DVWA |
| G3's ~79 PHP losses | **Not enumerable** — the 79 is a *projection* in `RULE_TRIAGE_G3.md:160` (357 findings × a sampled 22 %), not a list. Of the 3 hand-triaged G3 PHP items that live in this corpus: row 12 (`exec/source/low.php:10`) **recovered**; row 11 (`bac/source/low.php:35`) **not recovered by either engine**; row 13 (`exec/source/impossible.php:22`) — Psalm **reproduces the false positive** |
| TP rate vs ours | DVWA **82.9 % vs 80.6 %** (equal). Real code **0 % vs 67.5 %** (much worse) |
| Determinism | **Yes** — 35/35 identical across runs and across a rebuilt environment |
| Resource cost | 16 s / 79 MB (DVWA) → 71 s / 396 MB (FreshRSS) → **1,365 s / 594 MB (TeamPass, 2.3× over budget)** |
| Verdict | **REJECT** |
