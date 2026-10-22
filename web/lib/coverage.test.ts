// N2 — per-language SAST coverage must be visible, and a thin-coverage scan must
// never present as a confident security result.
//   node --test --experimental-strip-types lib/*.test.ts

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  notMeasuredReason,
  coverageLabel,
  coverageBreakdown,
  evidenceLabel,
  overallState,
  partialQualifier,
  NOT_MEASURED,
  ratingDisplay,
  scoreDisplay,
} from "./display.ts";

const javaOnly = {
  total_code_lines: 5000,
  strong_fraction: 0,
  limited_fraction: 1,
  uncovered_fraction: 0,
  confident: false,
  threshold: 0.5,
  languages: [
    { language: "java", tier: "limited" as const, loc: 5000, share: 1, rules: 7, cwe_classes: 7 },
  ],
  summary: "Java limited",
  gap: "most of this repository is in languages Aegis covers thinly or not at all (Java 100% (7 rules)), so an absence of findings is not evidence of safety",
  always_on: ["dependency CVEs (trivy)"],
};

const phpOnly = { ...javaOnly, strong_fraction: 1, limited_fraction: 0, confident: true,
  summary: "PHP strong", gap: null,
  languages: [{ language: "php", tier: "strong" as const, loc: 11000, share: 1, rules: 5, cwe_classes: 5 }] };

// THE GATE: the UI half. A Java-only repo scanned clean has security_score/rating
// null (the orchestrator withheld them) — the page must say WHY, not show a blank.
test("a thin-coverage security pillar states the coverage gap as its reason", () => {
  const scan = { engines_degraded: [], security_coverage: javaOnly };
  const reason = notMeasuredReason(scan, "security");
  assert.ok(reason, "security read Not measured with no reason — the C3 defect");
  assert.match(reason!, /covers thinly or not at all/);
  assert.match(reason!, /Java 100%/);
});

test("a thin-coverage scan renders Not measured, never a bare A or 100", () => {
  // What the RatingCard receives when the orchestrator withholds the pillar.
  assert.equal(ratingDisplay(null).text, NOT_MEASURED);
  assert.equal(scoreDisplay(null).text, NOT_MEASURED);
  for (const forbidden of ["A", "100", "", "—"]) {
    assert.notEqual(ratingDisplay(null).text, forbidden);
  }
});

test("the overall of a thin-coverage scan is partial with a qualifier, not a bare grade", () => {
  const scan = { overall_grade: "A" as const, security_score: undefined, quality_score: 88 };
  assert.equal(overallState(scan), "partial");
  assert.notEqual(overallState(scan), "full");
  assert.equal(partialQualifier(scan), "Quality only");
});

test("strong coverage does not fabricate a reason to withhold", () => {
  assert.equal(notMeasuredReason({ engines_degraded: [], security_coverage: phpOnly }, "security"), null);
});

test("a degraded engine's reason still wins over the coverage gap", () => {
  const scan = {
    engines_degraded: [{ engine: "trivy", reason: "engine failed", coverage_lost: "SCA" }],
    security_coverage: javaOnly,
  };
  assert.match(notMeasuredReason(scan, "security")!, /trivy: engine failed/);
});

test("coverage is labelled and broken down for display", () => {
  assert.equal(coverageLabel(phpOnly), "Security coverage: PHP strong");
  assert.equal(coverageLabel(null), null);
  assert.deepEqual(coverageBreakdown(javaOnly), [{ label: "thinly covered", pct: 100 }]);
  assert.deepEqual(coverageBreakdown(null), []);
  // a mixed repo shows every non-zero tier
  const mixed = { ...javaOnly, strong_fraction: 0.2, limited_fraction: 0.3, uncovered_fraction: 0.5 };
  assert.deepEqual(coverageBreakdown(mixed).map((r) => r.pct), [20, 30, 50]);
});

test("a pre-N2 scan without coverage is unchanged", () => {
  assert.equal(notMeasuredReason({ engines_degraded: [] }, "security"), null);
  assert.equal(coverageLabel(undefined), null);
});


// N5 — the tier is computed from measured evidence, and the numbers travel with it.
test("the per-language detail states held-out recall, precision and the failing criterion", () => {
  const ev = {
    tier: "limited" as const, failed: ["recall: held-out 4/34 = 12%, needs 25%"], corpora: 6,
    held_out_corpora: 2, held_out_recall: 0.1176, held_out_detected: 4, held_out_in_scope: 34,
    tuning_recall: 0.15, precision: 0.81, tp: 100, fp: 23, uncertain: 2,
  };
  assert.equal(
    evidenceLabel(ev),
    "held-out recall 12% (4/34, 2 corpora) · precision 81% (100/123) · fails recall",
  );
  assert.equal(
    evidenceLabel({ ...ev, held_out_recall: null, held_out_corpora: 0, failed: [] }),
    "no held-out corpus (6 tuning) · precision 81% (100/123)",
  );
  assert.equal(evidenceLabel(null), null, "pre-N5 scans carry no evidence and show none");
});
