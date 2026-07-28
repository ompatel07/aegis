# Deep-Scan Value Proposition — Joern Interprocedural Taint (Track 2f)

Does Aegis's optional **deep-scan tier** (Joern's Code Property Graph +
interprocedural taint analysis) find real vulnerabilities that the **fast pass**
(Semgrep, largely intra-file) structurally cannot? This is the honest answer,
measured on real code — reported with the same discipline as the Consul/Vault
"Ember flood" catch in [COMPARATIVE_ANALYSIS.md](COMPARATIVE_ANALYSIS.md): real
value where it exists, and a raw number called a mirage where it is one.

**Headline:** on a corpus of 10 mature OSS frameworks/libraries (the Track 2c
set), Joern's deep scan surfaced **zero genuine net-new vulnerabilities** beyond
the fast pass. The capability is real — a planted cross-function flow is detected
end-to-end — but this corpus is the wrong place for it to shine, and the two repos
where it "fired" were raw-count mirages that dedupe to false positives
(next-auth SSRF) or non-production demo code (netty). One repo (django) exceeded
Joern's memory envelope on the test VM and did not complete.

---

## 0. First, an honest prerequisite: the deep scan was broken

Before any measurement: **the Joern taint query did not run at all** on the
pinned engine. `engines/joern/taint.sc` was written against an older Joern API
(`.file.name` on `CfgNode`) and **fails to compile against the bundled Joern
4.0.570** — a flow's path elements are `AstNode`, so the query threw a
`Type Mismatch` and wrote empty output every time. The deep-scanner image also
failed to build: its base moved to Debian 13 (trixie), which dropped
`openjdk-17-jre-headless`.

Both were fixed in this track (JDK 21; `.location`-based file/line accessors that
are stable across Joern versions), so **this is the first time the deep-scan tier
has actually executed end-to-end.** Any prior claim about its value was untested.
The fix is verified: a planted two-file app (below) now yields a correct
14-step interprocedural flow.

---

## 1. The capability is real (planted-vulnerability proof)

A deliberately vulnerable two-file app — HTTP input in `handler.js` crossing a
function boundary into a sink reached via `db.js`:

```js
// handler.js
function handler(req, res) {
  const name = req.query.name;   // SOURCE: HTTP input
  const r = lookup(name);        // crosses function boundary
  res.send(r);                   // SINK (reached after interprocedural hops)
}
function lookup(userInput) { return db.run(userInput); }
```

Joern reports a **14-step interprocedural flow** `req.query.name → lookup(name)
→ userInput → db.run(userInput) → … → res.send(r)`. Semgrep's fast pass does
**not** connect this across the `handler → lookup` boundary. So the deep tier
genuinely does something the fast tier cannot. The question is whether that
capability *pays off on real codebases* — measured next.

---

## 2. Method

For each repo (shallow clone; `tests/vendor/node_modules` excluded), inside the
deep-scanner image (Semgrep **and** Joern present):

- **Fast pass** — Aegis's Semgrep config (`p/owasp-top-ten`,
  `p/r2c-security-audit`, `p/cwe-top-25`, `p/default`, `p/secrets`) + Aegis taint
  rules. Same config as Track 2c (fast-SAST totals match Track 2c per repo,
  validating the harness).
- **Deep pass** — `joern-parse` builds a CPG; `engines/joern/taint.sc` queries it
  for SQLi / command-injection / XSS / SSRF / path-traversal interprocedural
  flows.
- **Merge** — a deep flow **corroborates** a fast finding when they share CWE +
  file within a 2-line window (this mirrors the product's real
  `pipeline/deepmerge.go`); otherwise it is **net-new**.

Two counts are reported, and the distinction is the whole story:

- **raw paths** — every taint path Joern enumerates. Joern emits one "flow" per
  *path*, and many paths can reach the **same** sink.
- **unique sinks** — distinct `(CWE, file, line)` after dedup. This is the honest
  "how many distinct issues" number.

Harness: [`benchmarks/comparative/deep_compare.py`](benchmarks/comparative/deep_compare.py).
Raw data + sampled source→sink flows:
[`benchmarks/comparative/deep_scan_data/`](benchmarks/comparative/deep_scan_data/).
Environment: Joern 4.0.570 / JDK 21, 3.7 GiB VM, JVM capped at `-Xmx3g`.

---

## 3. Results — all 10 repos

| Repo | Lang | KLOC | Fast SAST | Joern | Parse+Query | Raw paths | Unique sinks | Genuine net-new |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| spring-petclinic | Java | 1.6 | 16 | ✅ | 6s + 10s | 0 | 0 | 0 |
| express | JS | 4.1 | 49 | ✅ | 14s + 16s | 0 | 0 | 0 |
| flask | Py | 8.0 | 17 | ✅ | 13s + 16s | 0 | 0 | 0 |
| cobra | Go | 14.4 | 13 | ✅ | 19s + 14s | 0 | 0 | 0 |
| gin | Go | 20.2 | 43 | ✅ | 23s + 16s | 0 | 0 | 0 |
| fastapi | Py | 28.5 | 23 | ✅ | 85s + 48s | 0 | 0 | 0 |
| **next-auth** | TS | 42.9 | 63 | ✅ | 28s + 24s | **110** | **16** | **0** (all FP) |
| jackson-databind | Java | 125.0 | 8 | ✅ | 74s + 18s | 0 | 0 | 0 |
| **django** | Py | 144.6 | — | ⚠️ **OOM** | — | — | — | — |
| **netty** | Java | 322.6 | 325 | ✅ | 159s + 55s | **150** | **4** | **0** (demo code) |

**7 of 9 completed repos: zero flows.** 2 repos fired; both dissected below. 1
repo OOM'd. **Genuine net-new vulnerabilities across the whole corpus: 0.**

Why zero on the clean 7 is *correct*, not a miss: these are frameworks and
libraries. They **define** the request objects (`req.query`, `request.headers`)
rather than **consuming** untrusted input in application-handler style, so there
is no unsanitized source→sink to follow. jackson is the sharpest case — its famous
CVEs are **polymorphic-deserialization gadget chains**, which are architectural,
not taint-visible to any CPG/pattern tool (Track 2c predicted exactly this).

---

## 4. The two "hits", dissected

### 4a. next-auth — 110 raw → 16 unique → **0 real** (SSRF pattern over-fires)

All 110 paths are **SSRF (CWE-918)** and collapse onto **16 unique sinks** (top
sinks each absorb 5–15 duplicate paths). Sampling the actual source→sink of six
distinct sinks shows **every one is a false positive**:

| Sink | What Joern flagged | Why it's not SSRF |
| --- | --- | --- |
| `next-auth/src/lib/index.ts:275-276` | `new URL(redirect).pathname` | `new URL()` **parses** a string; it makes **no request**. The SSRF sink regex matches `new url(` literally. |
| `core/src/lib/client.ts:159` | `fetch(url, {body: req.body})` | The **body** is user-supplied (expected — it's a POST to the auth API); the **URL** is trusted config. SSRF needs attacker-controlled **destination**, not body. |
| `core/src/lib/utils/web.ts:27`, `frameworks-*/index.ts` | `req.headers → toInternalRequest(req)` / `getSessionData(req)` | The "sink" is a **function declaration**; the flow is normal request-object plumbing. |

Root cause: the SSRF sink pattern treats `new URL(...)` (parsing) and any
body-carrying `fetch(...)` as request sinks, and the query has **no
sanitizer/validation awareness** — next-auth validates redirect URLs, but Joern
can't see that. So an auth library that builds URLs on every request lights up
end to end. **Honest count of real SSRF in next-auth: 0.** The raw 110 is a
mirage; even the deduped 16 are noise.

### 4b. netty — 150 raw → 4 unique → all in `example/` demo code

150 paths collapse onto **4 unique sinks**, and **147 of the 150 pile onto a
single sink** — one XSS line in a benchmark page. All 4 are in netty's
`example/` directory, **not the shipped library**:

- **1× XSS** — `example/.../WebSocketServerBenchmarkPage.java:31`: the HTTP `Host`
  header is reflected into the returned HTML (`getWebSocketLocation()`). This is a
  **genuine cross-file flow** (`WebSocketServerHandler → WebSocketServerBenchmarkPage`,
  2 files) that the fast pass missed — but it is low-severity Host-header
  reflection in **benchmark demo code**, and it is inflated 147× by path
  enumeration.
- **3× path-traversal** — `example/.../HttpStaticFileServerHandler.java:199/204/208`:
  request headers flow (across 5 files of netty's internal request machinery) to
  file-send sinks. But this example ships a `sanitizeUri()` guard that rejects
  `../`, which Joern **doesn't model**, and the sinks are the file **write**, not
  the path-controlled **open**. Over-reported.

**A production scan scoping out `example/` finds 0 in netty.** Same discipline as
Consul/Vault: the impressive 150 is 147 duplicate paths to one demo-code sink.

---

## 5. Cost & operational envelope

- **CPG build dominates cost** and scales with size **and language**. Joern's
  **Java** frontend is efficient — jackson (125 KLOC) parsed in 74s, netty
  (322 KLOC) in 159s. Joern's **Python** frontend is far heavier: fastapi
  (28 KLOC) took 85s, and **django (144 KLOC) OOM-killed the container** at the
  3.7 GiB cgroup limit (confirmed docker `oom` event at 23:32:05) — the deep scan
  did not complete. This validates the product's `deep_scan_max_repo_mb` gate and
  argues for a **language-aware** limit (Python needs a lower ceiling / more RAM).
- **Query time is cheap** relative to parse (10–55s). The expense is the CPG.
- Deep scan is therefore correctly an **opt-in sidecar** (`--profile deep`,
  ~6.9 GB image), not a default — the ~1–4 min/repo cost only pays off where
  there are real interprocedural flows to find.

---

## 6. Honest verdict

**On this corpus, the deep-scan tier did not earn its cost.** Zero genuine
net-new vulnerabilities across 10 mature OSS repos; its two firings were a
false-positive SSRF flood (next-auth) and non-production demo-code findings
(netty), both massively inflated by path-duplication.

That is **not** the same as "Joern is worthless":

1. **The capability is real and unique** — proven on a planted cross-function
   flow the fast pass cannot connect. Interprocedural CPG taint is a genuine
   analysis the fast tier structurally lacks.
2. **The corpus is the wrong target.** Frameworks/libraries either don't consume
   untrusted input as app handlers, sanitize it (netty), or have architectural
   (non-taint) vulns (jackson). The deep tier's value lands on **application
   code** with real unsanitized source→sink chains — which this Track 2c set, by
   design, does not contain. Testing it here is the honest stress test; it is not
   where a customer would run it.
3. **The current `taint.sc` has fixable precision problems** that this run
   surfaced concretely:
   - **Counts paths, not unique sinks** → 150 and 110 headline numbers that are
     really 4 and 16. *Fix: dedupe by `(cwe,file,line)` before reporting (the
     product's `deepmerge.go` dedupes deep-vs-fast but not deep-internal
     path-duplication).* 
   - **SSRF sink over-matches** `new URL()` (parsing, not a request) and
     body-carrying `fetch()`. *Fix: require the tainted value to reach the URL/host
     argument, not the body; drop `new URL()` as a standalone sink.*
   - **No sanitizer/validator modeling** → flags flows through `sanitizeUri()`.
     *Fix: add sanitizer definitions so guarded paths are pruned.*
   - **Scans `example/`/demo trees** → netty's only "findings". *Fix: exclude
     example/sample/benchmark directories, as the fast pass's `code_relevant`
     logic already does for generic noise.*

### Recommendation

Keep the deep-scan tier **opt-in and honest**: (a) report **unique sinks**, never
raw path counts, in any UI/marketing; (b) land the four `taint.sc` precision
fixes above before promoting deep-scan findings to the same weight as fast
findings; (c) make the size gate **language-aware** (lower ceiling for Python);
and (d) re-benchmark on an **application** corpus (e.g. deliberately vulnerable
apps / real product code with known interprocedural CVEs), where the capability
proven in §1 can actually demonstrate value. **Until then, the deep tier's
measured value on real mature codebases is ~0, and the docs should say so.**

*Integrity note: fast-SAST totals here match Track 2c per repo; no rule was tuned
to any repo; the two unflattering firings were dissected to the exact sink and
attributed to specific pattern defects rather than reported as wins.*
