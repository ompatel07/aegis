"use client";

import { useScanProgress, STAGE_STEPS, stageIndex } from "@/lib/use-scan-progress";
import { CheckCircle2, Loader2, Circle } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * Live scan progress driven by Server-Sent Events. Highlights the current
 * pipeline stage in real time (no polling) — the onboarding "aha" moment.
 */
export function ScanProgress({ scanId, active }: { scanId: string; active: boolean }) {
  const stage = useScanProgress(scanId, active);
  const idx = stageIndex(stage);

  return (
    <ul className="space-y-2">
      {STAGE_STEPS.filter((s) => s.stage !== "completed").map((s, i) => {
        const done = idx > i || stage === "completed";
        const current = idx === i && stage !== "completed";
        return (
          <li key={s.stage} className="flex items-center gap-3 text-sm">
            {done ? (
              <CheckCircle2 className="h-5 w-5 text-emerald-500" />
            ) : current ? (
              <Loader2 className="h-5 w-5 animate-spin text-primary" />
            ) : (
              <Circle className="h-5 w-5 text-muted-foreground/40" />
            )}
            <span className={cn(current ? "font-medium" : done ? "text-muted-foreground" : "text-muted-foreground/60")}>
              {s.label}
            </span>
          </li>
        );
      })}
    </ul>
  );
}
