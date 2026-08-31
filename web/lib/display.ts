// Honest-state display helpers (P4a). The three states that are the product's
// thesis — NOT MEASURED, NOT OFFERED, and DEGRADED — are decided HERE, once, so
// every summary surface (scan list, dashboard, trend, report, detail) renders them
// identically. A null rating/score/grade must NEVER read as blank, 0, "A", "-", or
// a grey "fine" placeholder; a degraded scan must NEVER render as clean anywhere.

import type { Scan } from "./types";

// A value that may be "not measured". `measured=false` carries the mandatory
// "Not measured" label so no caller can accidentally render null as blank/0/A.
export interface Measured {
  measured: boolean;
  text: string;
}

export const NOT_MEASURED = "Not measured";

// Grade cell (A–F) for scan summaries. null/"" -> "Not measured", never "—"/blank.
export function gradeDisplay(grade?: string | null): Measured {
  if (grade == null || grade === "") return { measured: false, text: NOT_MEASURED };
  return { measured: true, text: grade };
}

// A–E pillar rating. Same contract as a grade.
export function ratingDisplay(letter?: string | null): Measured {
  if (letter == null || letter === "") return { measured: false, text: NOT_MEASURED };
  return { measured: true, text: letter };
}

// Numeric 0–100 score. null -> "Not measured" (0 is a real, measured score and must
// stay "0", never collapse to not-measured).
export function scoreDisplay(score?: number | null): Measured {
  if (score == null) return { measured: false, text: NOT_MEASURED };
  return { measured: true, text: String(score) };
}

// DEGRADED: any engine ran without full coverage, or failed. Fed by engines_degraded.
export function isDegraded(scan: Pick<Scan, "engines_degraded">): boolean {
  return Array.isArray(scan.engines_degraded) && scan.engines_degraded.length > 0;
}

export function degradedCount(scan: Pick<Scan, "engines_degraded">): number {
  return Array.isArray(scan.engines_degraded) ? scan.engines_degraded.length : 0;
}

// The single summary state for a scan, used by EVERY surface. "degraded" is returned
// even when the scan has a grade, so a degraded scan can never be presented as a
// clean/graded result on one surface while another flags it. Order matters:
// failed > degraded > (graded | not-measured).
export type ScanSummaryState =
  | "queued"
  | "running"
  | "failed"
  | "degraded"
  | "not-measured"
  | "graded";

export function scanSummaryState(
  scan: Pick<Scan, "status" | "overall_grade" | "engines_degraded">,
): ScanSummaryState {
  if (scan.status === "queued") return "queued";
  if (scan.status === "running") return "running";
  if (scan.status === "failed") return "failed";
  if (isDegraded(scan)) return "degraded"; // wins over a grade — never "clean"
  if (scan.overall_grade == null) return "not-measured";
  return "graded";
}

// True only when a scan is safe to present as a finished, fully-covered result.
// If this is false, a green/graded-looking summary is a bug.
export function isCleanPresentable(
  scan: Pick<Scan, "status" | "overall_grade" | "engines_degraded">,
): boolean {
  return scanSummaryState(scan) === "graded";
}

// filtered_secrets -> a human sentence, or null when nothing was filtered. Silent
// filtering is indistinguishable from missing them, so a non-zero count is stated.
export function filteredSecretsLabel(
  filtered?: { placeholder?: number; expired_jwt?: number } | null,
): string | null {
  if (!filtered) return null;
  const parts: string[] = [];
  if (filtered.placeholder) parts.push(`${filtered.placeholder} placeholder`);
  if (filtered.expired_jwt) parts.push(`${filtered.expired_jwt} expired-JWT`);
  if (parts.length === 0) return null;
  return `${parts.join(" and ")} secret match${
    (filtered.placeholder ?? 0) + (filtered.expired_jwt ?? 0) === 1 ? "" : "es"
  } filtered (definitively not credentials)`;
}
