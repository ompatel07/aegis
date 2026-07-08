"use client";

import { useQuery } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

const SEV_COLOR: Record<string, string> = {
  critical: "bg-red-500", high: "bg-orange-500", medium: "bg-amber-500", low: "bg-blue-500", info: "bg-slate-400",
};

export default function AdminOverviewPage() {
  const api = useApi();
  const overview = useQuery({ queryKey: ["admin-overview"], queryFn: () => api.admin.overview(), refetchInterval: 15000 });
  const health = useQuery({ queryKey: ["admin-health"], queryFn: () => api.admin.health(), refetchInterval: 10000 });

  const o = overview.data;
  const h = health.data as Record<string, number | string> | undefined;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Platform overview</h1>

      {overview.isLoading || !o ? (
        <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-4">
          {Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} className="h-24" />)}
        </div>
      ) : (
        <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-4">
          <Stat label="Organizations" value={o.organizations} />
          <Stat label="Users" value={o.users} sub={`+${o.signups_7d} in 7d`} />
          <Stat label="Projects" value={o.projects} />
          <Stat label="Active scans" value={o.active_scans} highlight={o.active_scans > 0} />
          <Stat label="Scans (all time)" value={o.scans_total} />
          <Stat label="Scans (7d)" value={o.scans_7d} />
          <Stat label="Scans (30d)" value={o.scans_30d} />
          <Stat label="Open tickets" value={o.open_tickets} highlight={o.open_tickets > 0} />
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-base">Findings by severity</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {o ? Object.entries(o.findings_by_severity).sort().map(([sev, n]) => {
              const total = Object.values(o.findings_by_severity).reduce((a, b) => a + b, 0) || 1;
              return (
                <div key={sev} className="flex items-center gap-3 text-sm">
                  <span className="w-16 capitalize text-muted-foreground">{sev}</span>
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-muted">
                    <div className={cn("h-full", SEV_COLOR[sev] ?? "bg-muted-foreground")} style={{ width: `${(n / total) * 100}%` }} />
                  </div>
                  <span className="w-14 text-right font-mono text-xs">{n.toLocaleString()}</span>
                </div>
              );
            }) : <Skeleton className="h-24" />}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-base">Platform health</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm">
            <HealthRow label="Database" ok={h?.db === "ok"} value={String(h?.db ?? "…")} />
            <HealthRow label="Scans queued" ok value={String(h?.scans_queued ?? "…")} />
            <HealthRow label="Scans running" ok value={String(h?.scans_running ?? "…")} />
            <HealthRow label="Failed (24h)" ok={Number(h?.scans_failed_24h ?? 0) === 0} value={String(h?.scans_failed_24h ?? "…")} />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function Stat({ label, value, sub, highlight }: { label: string; value: number; sub?: string; highlight?: boolean }) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className={cn("text-3xl font-bold", highlight && "text-primary")}>{value.toLocaleString()}</div>
        <div className="text-xs text-muted-foreground">{label}</div>
        {sub ? <div className="mt-0.5 text-xs text-emerald-600">{sub}</div> : null}
      </CardContent>
    </Card>
  );
}

function HealthRow({ label, ok, value }: { label: string; ok: boolean; value: string }) {
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
