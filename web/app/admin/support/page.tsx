"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { SkeletonText } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { useToast } from "@/lib/use-toast";
import { formatDate } from "@/lib/utils";
import { LifeBuoy } from "lucide-react";

const STATUSES = ["", "new", "in_progress", "resolved"];

export default function AdminSupportPage() {
  const api = useApi();
  const qc = useQueryClient();
  const toast = useToast();
  const [status, setStatus] = useState("");
  const [reply, setReply] = useState<Record<string, string>>({});
  const { data, isLoading } = useQuery({ queryKey: ["admin-support", status], queryFn: () => api.admin.tickets(status) });

  const send = useMutation({
    mutationFn: ({ id, s }: { id: string; s: string }) => api.admin.replyTicket(id, { reply: reply[id] || "", status: s }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["admin-support"] }); toast.success("Reply sent to user by email"); },
    onError: (e: Error) => toast.error("Failed", e.message),
  });

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Support inbox</h1>
      <div className="flex gap-1.5">
        {STATUSES.map((s) => (
          <Button key={s || "all"} size="sm" variant={status === s ? "default" : "outline"} onClick={() => setStatus(s)} className="capitalize">{s.replace("_", " ") || "all"}</Button>
        ))}
      </div>

      {isLoading ? <Card><CardContent className="py-6"><SkeletonText lines={4} /></CardContent></Card>
        : !data || data.length === 0 ? <EmptyState icon={LifeBuoy} title="Inbox zero" description="No support tickets in this view." />
        : (
          <div className="space-y-3">
            {data.map((t) => (
              <Card key={t.id}>
                <CardContent className="space-y-2 py-4">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium">{t.subject}</span>
                    <Badge className={t.status === "resolved" ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600" : t.status === "new" ? "border-primary/40 bg-primary/10 text-primary" : "border-amber-400/40 bg-amber-400/10 text-amber-600"}>{t.status.replace("_", " ")}</Badge>
                  </div>
                  <p className="text-xs text-muted-foreground">{t.email ?? "unknown"} · {formatDate(t.created_at)}</p>
                  <p className="whitespace-pre-wrap text-sm text-muted-foreground">{t.message}</p>
                  {t.admin_reply ? <p className="rounded-md bg-muted p-2 text-sm"><span className="font-medium">Reply:</span> {t.admin_reply}</p> : null}
                  <textarea rows={2} placeholder="Reply (emailed to the user)…" value={reply[t.id] ?? ""} onChange={(e) => setReply((r) => ({ ...r, [t.id]: e.target.value }))}
                    className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm" />
                  <div className="flex gap-2">
                    <Button size="sm" disabled={send.isPending} onClick={() => send.mutate({ id: t.id, s: "in_progress" })}>Reply & mark in progress</Button>
                    <Button size="sm" variant="outline" disabled={send.isPending} onClick={() => send.mutate({ id: t.id, s: "resolved" })}>Reply & resolve</Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
    </div>
  );
}
