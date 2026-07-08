"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { SkeletonTable } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useToast } from "@/lib/use-toast";
import { formatDate } from "@/lib/utils";

const STATUS_CLS: Record<string, string> = {
  sent: "border-primary/40 bg-primary/10 text-primary",
  accepted: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600",
  expired: "border-border bg-muted text-muted-foreground",
  revoked: "border-destructive/40 bg-destructive/10 text-destructive",
};

export default function AdminBetaPage() {
  const api = useApi();
  const qc = useQueryClient();
  const toast = useToast();
  const [emails, setEmails] = useState("");
  const [welcome, setWelcome] = useState("");
  const { data, isLoading } = useQuery({ queryKey: ["admin-beta"], queryFn: () => api.admin.beta() });

  const invite = useMutation({
    mutationFn: () => api.admin.createBeta({ emails: emails.split(/[\s,]+/).filter(Boolean), welcome_message: welcome || undefined }),
    onSuccess: (r) => { qc.invalidateQueries({ queryKey: ["admin-beta"] }); setEmails(""); toast.success(`${r.created} invitation(s) sent`); },
    onError: (e: Error) => toast.error("Failed", e.message),
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api.admin.revokeBeta(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["admin-beta"] }); toast.success("Revoked"); },
  });

  const sent = data?.sent ?? 0;
  const accepted = data?.accepted ?? 0;

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Beta invitations</h1>
      <div className="grid gap-3 sm:grid-cols-3">
        <Card><CardContent className="p-4"><div className="text-3xl font-bold">{sent}</div><div className="text-xs text-muted-foreground">invited</div></CardContent></Card>
        <Card><CardContent className="p-4"><div className="text-3xl font-bold text-emerald-600">{accepted}</div><div className="text-xs text-muted-foreground">converted</div></CardContent></Card>
        <Card><CardContent className="p-4"><div className="text-3xl font-bold">{sent > 0 ? Math.round((accepted / sent) * 100) : 0}%</div><div className="text-xs text-muted-foreground">conversion</div></CardContent></Card>
      </div>

      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-base">Send invitations</CardTitle></CardHeader>
        <CardContent className="space-y-2">
          <textarea rows={2} placeholder="Emails (comma or space separated)" value={emails} onChange={(e) => setEmails(e.target.value)}
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm" />
          <input placeholder="Optional welcome message" value={welcome} onChange={(e) => setWelcome(e.target.value)}
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm" />
          <Button disabled={!emails.trim() || invite.isPending} onClick={() => invite.mutate()}>Send invitations</Button>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="overflow-x-auto p-0">
          {isLoading ? <div className="p-4"><SkeletonTable rows={5} cols={4} /></div> : (
            <Table>
              <TableHeader><TableRow><TableHead>Email</TableHead><TableHead>Status</TableHead><TableHead>Invited</TableHead><TableHead></TableHead></TableRow></TableHeader>
              <TableBody>
                {data?.invitations.map((b) => (
                  <TableRow key={b.id}>
                    <TableCell>{b.email}</TableCell>
                    <TableCell><Badge className={STATUS_CLS[b.status]}>{b.status}</Badge></TableCell>
                    <TableCell className="text-muted-foreground">{formatDate(b.created_at)}</TableCell>
                    <TableCell className="text-right">
                      {b.status === "sent" ? <Button size="sm" variant="ghost" onClick={() => revoke.mutate(b.id)}>Revoke</Button> : null}
                    </TableCell>
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
