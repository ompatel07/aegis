"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { formatDate } from "@/lib/utils";
import { BellRing, Radar } from "lucide-react";

const STATUS_CLASS: Record<string, string> = {
  success: "border-emerald-500/40 bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
  running: "border-blue-500/40 bg-blue-500/15 text-blue-600 dark:text-blue-400",
  failed: "border-red-500/40 bg-red-500/15 text-red-600 dark:text-red-400",
};

export default function IntelligencePage() {
  const api = useApi();
  const qc = useQueryClient();

  const statusQ = useQuery({
    queryKey: ["intel-status"],
    queryFn: () => api.getIntelligenceStatus(),
    refetchInterval: 30_000,
  });
  const notifQ = useQuery({ queryKey: ["notifications"], queryFn: () => api.listNotifications() });

  const markRead = useMutation({
    mutationFn: (id: string) => api.markNotificationRead(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["notifications"] }),
  });

  const status = statusQ.data;
  const notifs = notifQ.data?.notifications ?? [];

  return (
    <div className="space-y-8">
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-bold">
          <Radar className="h-6 w-6" /> Vulnerability intelligence
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Live CVE mirror synced from official feeds. New CVEs retroactively flag affected scans.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">CVEs mirrored</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{status?.total_cves ?? "—"}</div>
          </CardContent>
        </Card>
        {status
          ? Object.entries(status.cve_counts).map(([src, n]) => (
              <Card key={src}>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium uppercase text-muted-foreground">{src}</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-3xl font-bold">{n}</div>
                </CardContent>
              </Card>
            ))
          : null}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Feed sync status</CardTitle>
        </CardHeader>
        <CardContent>
          {statusQ.isLoading ? (
            <p className="py-4 text-sm text-muted-foreground">Loading…</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Source</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Added</TableHead>
                  <TableHead>Updated</TableHead>
                  <TableHead>Last sync</TableHead>
                  <TableHead>Next sync</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(status?.sources ?? []).map((s) => (
                  <TableRow key={s.source}>
                    <TableCell className="font-medium uppercase">{s.source}</TableCell>
                    <TableCell>
                      <Badge className={STATUS_CLASS[s.last_status ?? ""] ?? "border-border bg-muted text-muted-foreground"}>
                        {s.last_status ?? "—"}
                      </Badge>
                    </TableCell>
                    <TableCell>{s.records_added}</TableCell>
                    <TableCell>{s.records_updated}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {s.last_started_at ? formatDate(s.last_started_at) : "—"}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {s.next_sync ? formatDate(s.next_sync) : "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <BellRing className="h-4 w-4" /> Notifications
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {notifs.length === 0 ? (
            <p className="py-2 text-sm text-muted-foreground">No notifications.</p>
          ) : (
            notifs.map((n) => (
              <div
                key={n.id}
                className={`flex items-start justify-between gap-4 rounded-md border p-3 ${
                  n.is_read ? "opacity-60" : "border-amber-500/30 bg-amber-500/5"
                }`}
              >
                <div className="min-w-0">
                  <p className="font-medium">{n.title}</p>
                  {n.body ? <p className="text-sm text-muted-foreground">{n.body}</p> : null}
                  <p className="mt-1 text-xs text-muted-foreground">{formatDate(n.created_at)}</p>
                </div>
                {!n.is_read ? (
                  <Button variant="outline" size="sm" disabled={markRead.isPending} onClick={() => markRead.mutate(n.id)}>
                    Mark read
                  </Button>
                ) : null}
              </div>
            ))
          )}
        </CardContent>
      </Card>
    </div>
  );
}
