import { cn, gradeColor, scoreColor } from "@/lib/utils";
import { gradeDisplay, scoreDisplay } from "@/lib/display";
import type { Scan } from "@/lib/types";

// A scan's overall grade in a summary table. A null grade renders an explicit
// "Not measured" (muted), never "—"/blank/A — a blank grade reads as "clean" to a
// customer, the exact defect D1 removed in the backend.
export function GradeCell({ scan }: { scan: Pick<Scan, "overall_grade"> }) {
  const g = gradeDisplay(scan.overall_grade);
  if (!g.measured) return <span className="text-xs text-muted-foreground italic">Not measured</span>;
  return <span className={cn("font-bold", gradeColor(scan.overall_grade))}>{g.text}</span>;
}

// A pillar score (0–100) in a summary table. null -> "Not measured"; a real 0 stays 0.
export function ScoreCell({ score }: { score?: number | null }) {
  const s = scoreDisplay(score);
  if (!s.measured) return <span className="text-xs text-muted-foreground italic">Not measured</span>;
  return <span className={scoreColor(score ?? undefined)}>{s.text}</span>;
}
