import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { ScanStatus } from "@/lib/types";
import { CheckCircle2, Clock, Loader2, XCircle } from "lucide-react";

const config: Record<ScanStatus, { label: string; className: string; icon: React.ElementType; spin?: boolean }> = {
  queued: { label: "Queued", className: "bg-gray-100 text-gray-700 border-gray-200", icon: Clock },
  running: { label: "Running", className: "bg-blue-100 text-blue-800 border-blue-200", icon: Loader2, spin: true },
  completed: { label: "Completed", className: "bg-green-100 text-green-800 border-green-200", icon: CheckCircle2 },
  failed: { label: "Failed", className: "bg-red-100 text-red-800 border-red-200", icon: XCircle },
};

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  const c = config[status];
  const Icon = c.icon;
  return (
    <Badge className={cn(c.className, "gap-1")}>
      <Icon className={cn("h-3 w-3", c.spin && "animate-spin")} />
      {c.label}
    </Badge>
  );
}
