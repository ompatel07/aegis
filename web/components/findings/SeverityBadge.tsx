import { Badge } from "@/components/ui/badge";
import { cn, severityClasses } from "@/lib/utils";
import type { Severity } from "@/lib/types";

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <Badge className={cn(severityClasses(severity), "capitalize", className)}>{severity}</Badge>
  );
}
