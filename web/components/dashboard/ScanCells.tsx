import { cn, gradeColor, scoreColor } from "@/lib/utils";
import { gradeDisplay, scoreDisplay } from "@/lib/display";
import { HelpCircle } from "lucide-react";
import type { Scan } from "@/lib/types";

// "Not measured" is an unresolved GAP, not a neutral absence — it must not be the
// quietest thing on the row (C2). It reads "we could not tell you", carrying the
// attention/amber semantic with a marker, at weight equal to a bold grade — never a
// faint grey dash that looks calmer than a scan that actually passed.
function NotMeasured() {
  return (
    <span className="inline-flex items-center gap-1 font-medium text-amber-700 dark:text-amber-400">
      <HelpCircle className="h-3.5 w-3.5" />
      Not measured
    </span>
  );
}

export function GradeCell({ scan }: { scan: Pick<Scan, "overall_grade"> }) {
  const g = gradeDisplay(scan.overall_grade);
  if (!g.measured) return <NotMeasured />;
  return <span className={cn("text-base font-bold", gradeColor(scan.overall_grade))}>{g.text}</span>;
}

// A pillar score (0–100). null -> Not measured (weighted); a real 0 stays 0.
export function ScoreCell({ score }: { score?: number | null }) {
  const s = scoreDisplay(score);
  if (!s.measured) return <NotMeasured />;
  return <span className={cn("font-semibold tabular-nums", scoreColor(score ?? undefined))}>{s.text}</span>;
}
