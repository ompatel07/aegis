import { cn, gradeColor, scoreColor } from "@/lib/utils";
import { gradeDisplay, scoreDisplay, overallState, partialQualifier } from "@/lib/display";
import { HelpCircle } from "lucide-react";
import type { Scan } from "@/lib/types";

// "Not measured" is an unresolved GAP, not a neutral absence — it must not be the
// quietest thing on the row (C2). It reads "we could not tell you", carrying the
// attention/amber semantic with a marker, at weight equal to a bold grade.
function NotMeasured() {
  return (
    <span className="inline-flex items-center gap-1 font-medium text-amber-700 dark:text-amber-400">
      <HelpCircle className="h-3.5 w-3.5" />
      Not measured
    </span>
  );
}

// A partial overall — a real number, but computed from a subset of pillars, so it is
// NOT comparable to a full grade. The qualifier is mandatory and it is styled amber
// (an unresolved gap), never green: it is not a good result, it is an incomplete one.
function Partial({ value, scan }: { value: string; scan: Pick<Scan, "security_score" | "quality_score"> }) {
  return (
    <span className="inline-flex items-baseline gap-1 font-semibold text-amber-700 dark:text-amber-400">
      <span className="tabular-nums">{value}</span>
      <span className="text-xs font-medium">· {partialQualifier(scan)}</span>
    </span>
  );
}

type OverallScan = Pick<Scan, "overall_grade" | "security_score" | "quality_score">;

// The overall GRADE (letter). Full → coloured letter; partial → "C · Quality only"
// amber; null → "Not measured". Never a bare grade on a partial scan.
export function GradeCell({ scan }: { scan: OverallScan }) {
  const st = overallState(scan);
  if (st === "not-measured") return <NotMeasured />;
  if (st === "partial") return <Partial value={scan.overall_grade as string} scan={scan} />;
  return <span className={cn("text-base font-bold", gradeColor(scan.overall_grade))}>{gradeDisplay(scan.overall_grade).text}</span>;
}

// The overall SCORE (0–100), same three states as the grade — a partial score also
// carries the qualifier and the amber weight, never a bare green number.
export function OverallScoreCell({ scan }: { scan: OverallScan & { overall_score?: number } }) {
  const st = overallState(scan);
  if (st === "not-measured") return <NotMeasured />;
  if (st === "partial") return <Partial value={String(scan.overall_score ?? scan.overall_grade)} scan={scan} />;
  return <span className={cn("font-semibold tabular-nums", scoreColor(scan.overall_score ?? undefined))}>{scoreDisplay(scan.overall_score).text}</span>;
}

// A single PILLAR score (security / quality). A pillar is measured or not — never
// "partial" — so this keeps the simple two-state treatment.
export function ScoreCell({ score }: { score?: number | null }) {
  const s = scoreDisplay(score);
  if (!s.measured) return <NotMeasured />;
  return <span className={cn("font-semibold tabular-nums", scoreColor(score ?? undefined))}>{s.text}</span>;
}
