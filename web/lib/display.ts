// Honest-state display helpers (P4a). The three states that are the product's
// thesis — NOT MEASURED, NOT OFFERED, and DEGRADED — are decided HERE, once, so
// every summary surface (scan list, dashboard, trend, report, detail) renders them
// identically. A null rating/score/grade must NEVER read as blank, 0, "A", "-", or
// a grey "fine" placeholder; a degraded scan must NEVER render as clean anywhere.

import type { Scan, CoverageEvidence } from "./types";

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

// The OVERALL's measurement state. An overall computed from a SUBSET of pillars
// (e.g. quality only, because a degraded/failed security engine was excluded) is NOT
// comparable to one computed from all pillars, so it must never render as a bare
// grade — the qualifier is mandatory and travels with the number everywhere.
export type OverallState = "not-measured" | "partial" | "full";

export function overallState(
  scan: Pick<Scan, "overall_grade" | "security_score" | "quality_score">,
): OverallState {
  if (scan.overall_grade == null) return "not-measured";
  // security + quality are the two offered pillars; either being nil while an overall
  // exists means the overall was renormalized over a subset (partial).
  if (scan.security_score == null || scan.quality_score == null) return "partial";
  return "full";
}

// The qualifier that must accompany a partial overall — names which pillar carried
// it when it is only one, else "partial".
export function partialQualifier(
  scan: Pick<Scan, "security_score" | "quality_score">,
): string {
  const sec = scan.security_score != null;
  const qual = scan.quality_score != null;
  if (qual && !sec) return "Quality only";
  if (sec && !qual) return "Security only";
  return "partial";
}

// True only when a scan is safe to present as a finished, fully-covered result.
// If this is false, a green/graded-looking summary is a bug.
export function isCleanPresentable(
  scan: Pick<Scan, "status" | "overall_grade" | "engines_degraded">,
): boolean {
  return scanSummaryState(scan) === "graded";
}

// The engines that feed each pillar's score/rating (mirrors the orchestrator's
// per-pillar confidence in aggregator.go).
const PILLAR_ENGINES: Record<string, string[]> = {
  security: ["semgrep", "trivy", "gitleaks"],
  reliability: ["semgrep", "quality"],
  maintainability: ["quality"],
  quality: ["quality"],
};

// Why a pillar reads "Not measured" — the degraded/failed engine's reason, so the
// UI shows the REASON (C3), not the method that never ran. null when we have none.
export function notMeasuredReason(
  scan: Pick<Scan, "engines_degraded" | "security_coverage">,
  pillar: "security" | "reliability" | "maintainability" | "quality",
): string | null {
  const engines = PILLAR_ENGINES[pillar] ?? [];
  for (const d of scan.engines_degraded ?? []) {
    if (engines.includes(d.engine)) return `${d.engine}: ${d.reason}`;
  }
  // N2: thin per-language coverage withholds the security score too, and it is not a
  // degraded engine — nothing malfunctioned, we simply cannot read most of this code.
  // Without this the pillar would read "Not measured" with no reason at all.
  if (pillar === "security" && scan.security_coverage && !scan.security_coverage.confident) {
    return scan.security_coverage.gap ?? coverageLabel(scan.security_coverage);
  }
  return null;
}

// "Security coverage: PHP strong; Java limited" — what a customer is and is not
// getting from SAST. Shown on the scan page and every report (N2).
export function coverageLabel(
  coverage?: Pick<Scan["security_coverage"] & object, "summary"> | null,
): string | null {
  if (!coverage?.summary) return null;
  return `Security coverage: ${coverage.summary}`;
}

// N5: the measured evidence behind one language's tier, for the per-language detail:
// "held-out recall 12% (4/34, 2 corpora) · precision 81% (100/124) · fails recall".
// A tier name alone hides 15% against 50%, so the numbers travel with it.
export function evidenceLabel(ev?: CoverageEvidence | null): string | null {
  if (!ev) return null;
  const pct = (x: number) => `${Math.round(x * 100)}%`;
  const parts: string[] = [];
  if (ev.held_out_recall != null) {
    const n = ev.held_out_corpora;
    parts.push(
      `held-out recall ${pct(ev.held_out_recall)} (${ev.held_out_detected}/${ev.held_out_in_scope}, ` +
        `${n} ${n === 1 ? "corpus" : "corpora"})`,
    );
  } else if (ev.corpora > 0) {
    parts.push(`no held-out corpus (${ev.corpora} tuning)`);
  } else {
    parts.push("recall not measured");
  }
  if (ev.precision != null) parts.push(`precision ${pct(ev.precision)} (${ev.tp}/${ev.tp + ev.fp})`);
  if (ev.failed.length) parts.push(`fails ${ev.failed.map((f) => f.split(":")[0]).join(", ")}`);
  return parts.join(" · ");
}

// Percent of the repo's code (by LOC) in each coverage tier, for the detail view.
export function coverageBreakdown(
  coverage?: Scan["security_coverage"] | null,
): { label: string; pct: number }[] {
  if (!coverage) return [];
  const pct = (f: number) => Math.round(f * 100);
  return [
    { label: "strongly covered", pct: pct(coverage.strong_fraction) },
    { label: "thinly covered", pct: pct(coverage.limited_fraction) },
    { label: "no SAST rules", pct: pct(coverage.uncovered_fraction) },
  ].filter((r) => r.pct > 0);
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

export function filteredSecretsTotal(
  filtered?: { placeholder?: number; expired_jwt?: number } | null,
): number {
  if (!filtered) return 0;
  return (filtered.placeholder ?? 0) + (filtered.expired_jwt ?? 0);
}

// excluded_bundled -> a human sentence, or null when nothing was excluded. Bundled /
// minified third-party JS/TS is skipped by SAST (its findings are third-party noise
// and it can stall the scanner), but SCA + vendored fingerprinting still scan it — so
// this is stated, never silent. NOT a degradation: no OWNED-code coverage is lost.
export function excludedBundledLabel(
  excluded?: { files: number; bytes: number } | null,
): string | null {
  if (!excluded || excluded.files <= 0) return null;
  const mb = excluded.bytes / (1024 * 1024);
  const size = mb >= 0.1 ? `${mb.toFixed(1)} MB` : `${Math.round(excluded.bytes / 1024)} KB`;
  return `${excluded.files} bundled/minified file${
    excluded.files === 1 ? "" : "s"
  } excluded from SAST (${size}) — still scanned by SCA + vendored fingerprinting`;
}
