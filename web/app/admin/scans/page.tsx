"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SkeletonTable } from "@/components/ui/skeleton";
import { cn, formatDate, formatDuration } from "@/lib/utils";

const STATUSES = ["", "queued", "running", "completed", "failed"];

export default function AdminScansPage() {
  const api = useApi();
  const [status, setStatus] = useState("");
  const { data, isLoading } = useQuery({ queryKey: ["admin-scans", status], queryFn: () => api.admin.scans(status), refetchInterval: status === "running" || status === "queued" ? 5000 : false });

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Scans</h1>
      <div className="flex flex-wrap gap-1.5">
        {STATUSES.map((s) => (
          <Button key={s || "all"} size="sm" variant={status === s ? "default" : "outline"} onClick={() => setStatus(s)} className="capitalize">
            {s || "all"}
          </Button>
        ))}
      </div>

      <Card>
        <CardContent className="overflow-x-auto p-0">
          {isLoading ? (
            <div className="p-4"><SkeletonTable rows={8} cols={5} /></div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Project</TableHead><TableHead>Status</TableHead><TableHead>Grade</TableHead>
                  <TableHead>Duration</TableHead><TableHead>When</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data?.map((s) => (
                  <TableRow key={s.id} className={cn(s.status === "failed" && "bg-destructive/5")}>
                    <TableCell>
                      <div className="font-medium">{s.project_name}</div>
                      {s.status === "failed" && s.error_message ? (
                        <div className="max-w-md truncate text-xs text-destructive" title={s.error_message}>{s.error_message}</div>
                      ) : null}
                      {s.duration_seconds != null && s.duration_seconds > 600 ? (
                        <Badge className="mt-1 border-amber-400/40 bg-amber-400/10 text-amber-600">long-running</Badge>
                      ) : null}
                    </TableCell>
                    <TableCell><StatusBadge status={s.status} /></TableCell>
                    <TableCell className="font-bold">{s.overall_grade ?? "—"}</TableCell>
                    <TableCell className="text-muted-foreground">{formatDuration(s.duration_seconds)}</TableCell>
                    <TableCell className="text-muted-foreground">{formatDate(s.created_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const cls: Record<string, string> = {
    completed: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600",
    failed: "border-destructive/40 bg-destructive/10 text-destructive",
    running: "border-primary/40 bg-primary/10 text-primary",
    queued: "border-border bg-muted text-muted-foreground",
  };
  return <Badge className={cls[status] ?? "border-border bg-muted"}>{status}</Badge>;
}
