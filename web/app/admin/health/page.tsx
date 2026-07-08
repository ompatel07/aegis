"use client";

import { useQuery } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

export default function AdminHealthPage() {
  const api = useApi();
  const health = useQuery({ queryKey: ["admin-health-page"], queryFn: () => api.admin.health(), refetchInterval: 5000 });
  const intel = useQuery({ queryKey: ["admin-intel-health"], queryFn: () => api.getIntelligenceStatus(), retry: false });

  const h = health.data as Record<string, number | string> | undefined;

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">System health</h1>
      <p className="text-sm text-muted-foreground">Live platform signals (auto-refreshing).</p>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-base">Core services</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm">
            <Row label="API" ok value="serving" />
            <Row label="Database" ok={h?.db === "ok"} value={String(h?.db ?? "…")} />
            <Row label="Scans queued" ok value={String(h?.scans_queued ?? "…")} />
            <Row label="Scans running" ok value={String(h?.scans_running ?? "…")} />
            <Row label="Failed scans (24h)" ok={Number(h?.scans_failed_24h ?? 0) === 0} value={String(h?.scans_failed_24h ?? "…")} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-base">Intelligence feeds</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm">
            {intel.isError ? (
              <p className="text-muted-foreground">Intelligence status unavailable.</p>
            ) : intel.data ? (
              (intel.data.sources ?? []).map((s) => (
                <Row key={s.source} label={s.source.toUpperCase()} ok={s.last_status === "success"} value={s.last_status ?? "—"} />
              ))
            ) : (
              <p className="text-muted-foreground">Loading…</p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function Row({ label, ok, value }: { label: string; ok: boolean; value: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-muted-foreground">{label}</span>
      <span className="flex items-center gap-2">
        <span className={cn("h-2 w-2 rounded-full", ok ? "bg-emerald-500" : "bg-destructive")} />
        <span className="font-mono text-xs">{value}</span>
      </span>
    </div>
  );
}
