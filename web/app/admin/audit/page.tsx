"use client";

import { useQuery } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { SkeletonTable } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { formatDate } from "@/lib/utils";
import { ScrollText } from "lucide-react";

export default function AdminAuditPage() {
  const api = useApi();
  const { data, isLoading } = useQuery({ queryKey: ["admin-audit"], queryFn: () => api.admin.audit(), refetchInterval: 20000 });

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold">Audit log</h1>
        <p className="text-sm text-muted-foreground">Append-only record of every admin action, including impersonation and role grants.</p>
      </div>
      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-4"><SkeletonTable rows={8} cols={4} /></div>
          ) : !data || data.length === 0 ? (
            <EmptyState icon={ScrollText} title="No admin actions yet" description="Admin actions will appear here as they happen." />
          ) : (
            <ul className="divide-y">
              {data.map((e) => (
                <li key={e.id} className="flex items-start justify-between gap-4 p-3 text-sm">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <Badge className="border-border bg-secondary font-mono text-xs text-secondary-foreground">{e.action}</Badge>
                      {e.target_type ? <span className="text-xs text-muted-foreground">{e.target_type} {e.target_id?.slice(0, 8)}</span> : null}
                    </div>
                    <div className="mt-1 text-xs text-muted-foreground">
                      by {e.admin_email ?? "system"}{e.ip ? ` · ${e.ip}` : ""}
                      {e.details ? ` · ${JSON.stringify(e.details)}` : ""}
                    </div>
                  </div>
                  <span className="whitespace-nowrap text-xs text-muted-foreground">{formatDate(e.created_at)}</span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
