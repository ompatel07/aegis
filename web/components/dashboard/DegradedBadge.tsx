import { Badge } from "@/components/ui/badge";
import { AlertTriangle } from "lucide-react";
import { degradedCount, isDegraded } from "@/lib/display";
import type { Scan } from "@/lib/types";

// Consistent DEGRADED marker for every scan-summary surface (list, dashboard,
// trend, report). A degraded scan ran without full coverage or had an engine fail,
// so it must never be presentable as clean. Renders nothing for a non-degraded scan.
export function DegradedBadge({ scan }: { scan: Pick<Scan, "engines_degraded"> }) {
  if (!isDegraded(scan)) return null;
  const n = degradedCount(scan);
  return (
    <Badge
      className="border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-500"
      title={`Degraded — ${n} engine${n === 1 ? "" : "s"} ran without full coverage or failed; results are incomplete, not clean`}
    >
      <AlertTriangle className="mr-1 h-3 w-3" />
      degraded
    </Badge>
  );
}
