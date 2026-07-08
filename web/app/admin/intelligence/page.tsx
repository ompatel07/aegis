"use client";

import { useQuery } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { SkeletonText } from "@/components/ui/skeleton";
import { formatDate } from "@/lib/utils";

export default function AdminIntelligencePage() {
  const api = useApi();
  const { data, isLoading, isError } = useQuery({ queryKey: ["admin-intel"], queryFn: () => api.getIntelligenceStatus(), refetchInterval: 30000 });

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Intelligence feed</h1>
      <p className="text-sm text-muted-foreground">CVE sync status across NVD, OSV, GHSA, and Semgrep.</p>

      {isLoading ? <Card><CardContent className="py-6"><SkeletonText lines={4} /></CardContent></Card>
        : isError || !data ? <Card><CardContent className="py-6 text-sm text-muted-foreground">Intelligence status unavailable.</CardContent></Card>
        : (
          <>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Card><CardContent className="p-4"><div className="text-3xl font-bold">{data.total_cves.toLocaleString()}</div><div className="text-xs text-muted-foreground">CVEs in database</div></CardContent></Card>
              {Object.entries(data.cve_counts ?? {}).map(([src, n]) => (
                <Card key={src}><CardContent className="p-4"><div className="text-3xl font-bold">{n.toLocaleString()}</div><div className="text-xs uppercase text-muted-foreground">{src}</div></CardContent></Card>
              ))}
            </div>

            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-base">Source sync status</CardTitle></CardHeader>
              <CardContent className="space-y-2">
                {data.sources.map((s) => (
                  <div key={s.source} className="flex items-center justify-between border-b py-2 text-sm last:border-0">
                    <div>
                      <span className="font-medium uppercase">{s.source}</span>
                      <span className="ml-2 text-xs text-muted-foreground">
                        {s.last_completed_at ? `last synced ${formatDate(s.last_completed_at)}` : "never synced"}
                        {s.records_added ? ` · +${s.records_added} added` : ""}
                      </span>
                    </div>
                    <Badge className={s.last_status === "success" ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600"
                      : s.last_status === "failed" ? "border-destructive/40 bg-destructive/10 text-destructive"
                      : "border-border bg-muted text-muted-foreground"}>
                      {s.last_status ?? "pending"}
                    </Badge>
                  </div>
                ))}
              </CardContent>
            </Card>
          </>
        )}
    </div>
  );
}
