"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { useApi } from "@/lib/use-api";
import type { Pillar, Severity } from "@/lib/types";
import { FindingCard } from "./FindingCard";

const SEVERITIES: (Severity | "all")[] = ["all", "critical", "high", "medium", "low", "info"];

// Findings list scoped to a scan + pillar, with a severity filter.
export function FindingsList({ scanId, pillar }: { scanId: string; pillar: Pillar }) {
  const api = useApi();
  const [severity, setSeverity] = useState<Severity | "all">("all");

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["findings", scanId, pillar, severity],
    queryFn: () =>
      api.listFindings(scanId, {
        pillar,
        severity: severity === "all" ? undefined : severity,
        per_page: 100,
      }),
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        {SEVERITIES.map((s) => (
          <Button
            key={s}
            size="sm"
            variant={severity === s ? "default" : "outline"}
            className={cn("capitalize")}
            onClick={() => setSeverity(s)}
          >
            {s}
          </Button>
        ))}
      </div>

      {isLoading ? (
        <p className="py-8 text-center text-sm text-muted-foreground">Loading findings…</p>
      ) : isError ? (
        <p className="py-8 text-center text-sm text-destructive">{(error as Error).message}</p>
      ) : !data || data.data.length === 0 ? (
        <p className="py-8 text-center text-sm text-muted-foreground">
          No {pillar} findings{severity !== "all" ? ` at ${severity} severity` : ""}. 🎉
        </p>
      ) : (
        <>
          <p className="text-xs text-muted-foreground">
            Showing {data.data.length} of {data.meta.total}
          </p>
          <div className="space-y-2">
            {data.data.map((f) => (
              <FindingCard key={f.id} finding={f} onUpdated={refetch} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}
