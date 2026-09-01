// Honest-state tests (P4a GATE 3 + 4). Run with the zero-dependency Node runner:
//   node --test --experimental-strip-types lib/*.test.ts
// (wired as `npm test` in web/package.json).

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  gradeDisplay,
  ratingDisplay,
  scoreDisplay,
  scanSummaryState,
  isCleanPresentable,
  overallState,
  partialQualifier,
  NOT_MEASURED,
} from "./display.ts";

const FORBIDDEN_NULL_RENDERS = ["", "-", "—", "0", "A", "N/A", "n/a"];

// GATE 3 — a null rating/grade renders "Not measured", never blank, 0, A, or a dash.
test("null grade renders Not measured, never blank/0/A/dash", () => {
  for (const v of [null, undefined, ""]) {
    const d = gradeDisplay(v as string | null);
    assert.equal(d.measured, false);
    assert.equal(d.text, NOT_MEASURED);
    assert.ok(!FORBIDDEN_NULL_RENDERS.includes(d.text), `grade null rendered as ${d.text}`);
  }
});

test("null rating renders Not measured, never blank/0/A/dash", () => {
  for (const v of [null, undefined, ""]) {
    const d = ratingDisplay(v as string | null);
    assert.equal(d.measured, false);
    assert.equal(d.text, NOT_MEASURED);
    assert.ok(!FORBIDDEN_NULL_RENDERS.includes(d.text));
  }
});

test("null score renders Not measured, but a real 0 stays 0", () => {
  assert.equal(scoreDisplay(null).text, NOT_MEASURED);
  assert.equal(scoreDisplay(undefined).text, NOT_MEASURED);
  // 0 is a measured score — it must NOT collapse into not-measured.
  assert.equal(scoreDisplay(0).measured, true);
  assert.equal(scoreDisplay(0).text, "0");
});

test("a measured A grade still renders A", () => {
  const d = gradeDisplay("A");
  assert.equal(d.measured, true);
  assert.equal(d.text, "A");
});

// GATE 4 — a degraded scan can never render as clean on any summary surface. Every
// surface derives its badge from scanSummaryState, so testing it covers all of them.
test("a degraded scan is never clean-presentable, even with a grade", () => {
  const degradedButGraded = {
    status: "completed" as const,
    overall_grade: "A" as const, // looks clean...
    engines_degraded: [{ engine: "semgrep", reason: "SAST timed out", coverage_lost: "SAST" }],
  };
  assert.equal(scanSummaryState(degradedButGraded), "degraded");
  assert.equal(isCleanPresentable(degradedButGraded), false);
});

test("a completed scan with no degradation and a grade is clean-presentable", () => {
  const clean = { status: "completed" as const, overall_grade: "B" as const, engines_degraded: [] };
  assert.equal(scanSummaryState(clean), "graded");
  assert.equal(isCleanPresentable(clean), true);
});

test("a completed scan with a null grade is not-measured, not clean", () => {
  const noGrade = { status: "completed" as const, overall_grade: undefined, engines_degraded: [] };
  assert.equal(scanSummaryState(noGrade), "not-measured");
  assert.equal(isCleanPresentable(noGrade), false);
});

// Follow-up: a partially-measured scan's grade must never render as a bare letter or
// bare number, and must not be styled as a passing/green value. The grade cell keys
// entirely off overallState — "partial" forces the amber, qualifier-bearing branch;
// only "full" reaches the coloured (green-capable) bare grade — so asserting the
// state is asserting the render.
test("a partially-measured overall is 'partial', never 'full'", () => {
  const partial = { overall_grade: "C" as const, security_score: undefined, quality_score: 74 };
  assert.equal(overallState(partial), "partial"); // -> amber qualifier branch, not bare/green
  assert.notEqual(overallState(partial), "full"); // -> never the coloured bare-grade branch
  assert.equal(partialQualifier(partial), "Quality only"); // qualifier travels with the number
});

test("a fully-measured overall is 'full'; a null-grade overall is 'not-measured'", () => {
  assert.equal(overallState({ overall_grade: "B" as const, security_score: 80, quality_score: 74 }), "full");
  assert.equal(overallState({ overall_grade: undefined, security_score: undefined, quality_score: undefined }), "not-measured");
});

test("failed outranks degradation and grade", () => {
  const failed = {
    status: "failed" as const,
    overall_grade: "A" as const,
    engines_degraded: [{ engine: "trivy", reason: "x", coverage_lost: "SCA" }],
  };
  assert.equal(scanSummaryState(failed), "failed");
  assert.equal(isCleanPresentable(failed), false);
});
