import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { ScanStatusBadge } from "@/components/dashboard/ScanStatusBadge";
import { scanSummaryState } from "@/lib/display";
import type { Scan } from "@/lib/types";
import { AlertTriangle, CheckCircle2, HelpCircle, XCircle } from "lucide-react";

// Leads a scan row with its OUTCOME, not its job status (C1). "Completed" only reads
// green when the scan is BOTH finished AND fully measured; a degraded or unmeasured
// scan leads with the outcome and the job-status pill drops to neutral & secondary,
// so the strongest thing on the row is what actually happened — not that the job
// ended.
export function ScanOutcomeBadge({ scan }: { scan: Pick<Scan, "status" | "overall_grade" | "engines_degraded"> }) {
  const state = scanSummaryState(scan);

  if (state === "queued" || state === "running") {
    return <ScanStatusBadge status={scan.status} />;
  }
  if (state === "failed") {
    return (
      <Badge className="gap-1 border-red-300 bg-red-100 font-semibold text-red-800 dark:border-red-500/40 dark:bg-red-500/15 dark:text-red-300">
        <XCircle className="h-3 w-3" /> Failed
      </Badge>
    );
  }
  if (state === "graded") {
    return (
      <Badge className="gap-1 border-green-200 bg-green-100 text-green-800 dark:border-green-500/40 dark:bg-green-500/15 dark:text-green-300">
        <CheckCircle2 className="h-3 w-3" /> Completed
      </Badge>
    );
  }
  // degraded | not-measured: lead with the outcome, demote "completed" to neutral.
  const outcome =
    state === "degraded"
      ? { label: "Degraded", Icon: AlertTriangle }
      : { label: "Not measured", Icon: HelpCircle };
  return (
    <span className="flex flex-wrap items-center gap-1.5">
      <Badge className="gap-1 border-amber-300 bg-amber-100 font-semibold text-amber-800 dark:border-amber-500/40 dark:bg-amber-500/15 dark:text-amber-300">
        <outcome.Icon className="h-3 w-3" /> {outcome.label}
      </Badge>
      <Badge className={cn("border-border bg-muted text-muted-foreground")}>completed</Badge>
    </span>
  );
}
