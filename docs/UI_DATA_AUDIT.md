# UI data audit (P4a) — what the API returns vs. what the web renders

Grounded in the Go API models (`services/api/internal/models/scan.go`,
`finding.go`) and the finding repository/handlers, not guesses. This is the spec for
the rest of P4a and for the visual pass P4b. "Rendered where?" is the state **before**
P4a; the → notes what P4a adds.

Legend for states: a field that is a Go pointer (`*int`, `*string`, `*time.Time`) or
JSON `omitempty` can be **null/absent**; the "null renders as" column is the honest
state the UI must show. **NOT MEASURED** (null) must never render as blank, `0`,
`A`, `-`, or a grey placeholder that reads as fine.

## Scan (`GET /scans/:id` → `models.Scan`)

| field | type | in web types? | rendered where (pre-P4a) | states incl. null | null renders as |
|---|---|---|---|---|---|
| id, project_id, trigger | string | yes | routing/labels | — | — |
| status | string | yes | ScanStatusBadge (list, detail, dashboard) | queued/running/completed/failed | badge |
| branch, commit_sha | *string | yes | detail subheader | string / absent | omitted |
| **overall_grade** | *string | yes | list `?? "—"`, dashboard `?? "—"`, detail | A–F / **null** | ~~"—"~~ → **"Not measured"** (B1) |
| **overall_score** | *int | yes | detail ScoreCard | 0–100 / null | ScoreCard "Not measured" ✓ |
| **security_score** | *int | yes | detail ScoreCard | 0–100 / null | "Not measured" ✓ |
| **quality_score** | *int | yes | detail ScoreCard | 0–100 / null | "Not measured" ✓ |
| **deployment_score** | *int | yes | detail card, list col, dashboard col, trend line | 0–100 / **null (web scan)** | ~~"—"~~ → **not shown at all** (B2 — CI-only) |
| **reliability_rating** | *string | yes | **nowhere** | A–E / null | → detail summary, "Not measured" (E) |
| **security_rating** | *string | yes | **nowhere** | A–E / null | → detail summary + score (E) |
| **maintainability_rating** | *string | yes | **nowhere** | A–E / null | → detail summary (E) |
| **engines_degraded** | JSON `[{engine,reason,coverage_lost}]` | yes | detail + report banner only | `[]` / non-empty | → **badge on list, dashboard, trend, report** (B3) |
| **filtered_secrets** | (NOT YET IN API) | no | nowhere | `{placeholder,expired_jwt}` counts | → plumbed + count note (D) |
| quality_issues_total, security_issues_total | int | yes | detail subtitles | 0..n | number |
| secrets_found, vulnerabilities_found | int | yes | detail subtitles | 0..n | number |
| duration_seconds | *int | yes | detail | seconds / null | formatDuration |
| error_message | *string | yes | detail failed card | string / null | shown on failed |
| stage | *string | yes | ScanProgress | pipeline stage / null | live progress |
| needs_reeval, reeval_reason | bool/*string | partial | — | — | internal (not surfaced) |
| rule_pack_version | *string | yes | — | string / null | internal (provenance) |

## Finding (`GET /scans/:id/findings` → `models.Finding`)

| field | in web types? | rendered where (pre-P4a) | states | P4a |
|---|---|---|---|---|
| severity | yes | SeverityBadge | critical…info | — |
| risk_level | yes | RiskBadge | informational…critical / null | — |
| engine, rule_id, rule_name | yes | badges + dialog | — | — |
| title / title_human | yes | heading | — | — |
| impact, description | yes | dialog | string / null | — |
| file_path, line_start/end | yes | location line | — | — |
| cwe_id, cve_id, owasp_category | yes | dialog rows | string / null | — |
| is_new | yes | "new" badge | bool | — |
| **lifecycle_status** | yes | **nowhere** | new/existing/reopened / null | → badge (C) |
| **code_snippet + snippet_start_line** | yes | **nowhere** | code / null (secrets redacted at egress) | → line-numbered block (C) |
| **issue_type** | **NO (missing from TS)** | nowhere | bug/vulnerability/code_smell / null | → TS field + badge (C) |
| is_suppressed | yes | "suppressed" badge | bool | — |
| is_false_positive | yes | (triage) | bool | — |
| false_positive_probability | yes | LikelyFP badge (>0.5, not on crit/KEV) | 0–1 / null | — |
| fix_suggestion, remediation_* | yes | dialog | string / null | — |
| context_metadata.steps_to_reproduce | yes | Steps-to-reproduce | object / null | — |
| context_metadata.cvss_* | yes | ContextMetadata | — | — |
| metadata.code_ownership | yes | third-party badge | app/third_party | — |
| metadata.reachable / reachable_file_count | yes | ReachabilityBadge | true/false/null | — |
| **metadata.kev** | yes (sort/FP-suppress) | **no badge** | true/absent | → "actively exploited" badge (C) |
| **metadata.epss_score / epss_percentile** | in metadata | **nowhere** | 0–1 / null | → dialog row (C) |
| **metadata.dependency_path / introduced_through / is_transitive** | in metadata | **nowhere** | array / null | → transitive-dep block (C) |
| **metadata.secret_context / secret_context_reason** | in metadata | **nowhere** | test-fixture/placeholder/expired/documentation/live-format / null | → tag + reason (C) |

## Internal / not surfaced (deliberately)

- `needs_reeval`, `reeval_reason`, `rule_pack_version`, `fingerprint` — provenance and
  lifecycle plumbing; no screen needs them (fingerprint drives is_new/lifecycle).
- `column_start/end` — used for precise anchoring, not shown.
- `metadata.match`, `metadata.entropy` — secret internals; **match is redacted at
  egress and must never reach the UI** (see snippet path confirmation).

## Part D — default ordering (the product decision)

A V1 repo yields hundreds–thousands of findings; a flat list is worthless.
Prioritization is the differentiator, so the default order answers "what first".

**Order (each tier breaks ties into the next):**
1. **KEV** — CISA "actively exploited". A CVE with a real-world exploit campaign is
   the only thing that outranks severity; nothing is more urgent.
2. **Severity band** — critical → info. The base risk axis.
3. **Reachable** — a reachable vuln (user input can hit it) above a same-severity
   unreachable one. Reachability is our SCA differentiator; it belongs in the sort,
   not just a badge.
4. **New since last scan** — a regression you just introduced ranks above pre-existing
   debt of equal severity; it is the thing you can still cheaply fix in this PR.
5. **Likely-FP down** — the ML FP estimate pushes probable noise *down within* its
   band (never hides, never crosses a band, never applied to critical/KEV).
6. **Stable fingerprint** — deterministic tiebreak so identical scans order identically.

**Defence of the starting position** (KEV → reachable+high → new → rest): I keep it,
with two refinements. (a) Reachability is promoted into the sort key (tier 3), because
"reachable + high" beating "unreachable + high" is exactly the prioritization claim —
leaving it a badge only would let an unreachable critical sit above a reachable one.
(b) "new" sits *below* reachability (tier 4): a reachable exploited path you shipped
last year still beats a new-but-unreachable smell. This matches the server SQL
(`kevFirstSQL, severityRankSQL, reachable, is_new, fp, fingerprint`) so pagination and
the client agree.

**Below the fold, never hidden.** Down-ranked secrets (secret_context = fixture /
placeholder / expired / documentation) are LOW severity, so they naturally sort to the
bottom — but they stay in the list and reachable via the severity/`secret_context`
filters. S1 chose down-rank over suppress deliberately; the UI honours that. Suppressed
findings are hidden by default but one toggle away.

**Filtered secrets are counted, not silent.** Placeholder/expired matches that P1
*removed* from the findings never appear as findings, but the scan shows
"N placeholder / M expired-JWT matches filtered" (from `filtered_secrets`). Silent
filtering is indistinguishable from missing them.
