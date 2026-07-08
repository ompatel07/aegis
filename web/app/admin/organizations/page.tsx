"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SkeletonTable } from "@/components/ui/skeleton";
import { useToast } from "@/lib/use-toast";
import { formatDate } from "@/lib/utils";

export default function AdminOrgsPage() {
  const api = useApi();
  const qc = useQueryClient();
  const toast = useToast();
  const [search, setSearch] = useState("");
  const { data, isLoading } = useQuery({ queryKey: ["admin-orgs", search], queryFn: () => api.admin.orgs(search) });

  const suspend = useMutation({
    mutationFn: ({ id, s }: { id: string; s: boolean }) => api.admin.suspendOrg(id, s),
    onSuccess: (_, v) => { qc.invalidateQueries({ queryKey: ["admin-orgs"] }); toast.success(v.s ? "Organization suspended" : "Organization restored"); },
    onError: (e: Error) => toast.error("Failed", e.message),
  });
  const setPlan = useMutation({
    mutationFn: ({ id, plan }: { id: string; plan: string }) => api.admin.setOrgPlan(id, plan),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["admin-orgs"] }); toast.success("Plan updated"); },
    onError: (e: Error) => toast.error("Failed", e.message),
  });

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Organizations</h1>
      <Input placeholder="Search by name or slug…" value={search} onChange={(e) => setSearch(e.target.value)} className="max-w-sm" />

      <Card>
        <CardContent className="overflow-x-auto p-0">
          {isLoading ? (
            <div className="p-4"><SkeletonTable rows={6} cols={6} /></div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead><TableHead>Plan</TableHead><TableHead>Members</TableHead>
                  <TableHead>Projects</TableHead><TableHead>Scans</TableHead><TableHead>Created</TableHead><TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data?.map((o) => (
                  <TableRow key={o.id}>
                    <TableCell>
                      <div className="font-medium">{o.name}{o.suspended_at ? <Badge className="ml-2 border-destructive/40 bg-destructive/10 text-destructive">suspended</Badge> : null}</div>
                      <div className="text-xs text-muted-foreground">{o.slug}{o.is_personal ? " · personal" : ""}</div>
                    </TableCell>
                    <TableCell>
                      <select value={o.plan} disabled={o.is_personal} onChange={(e) => setPlan.mutate({ id: o.id, plan: e.target.value })}
                        className="rounded-md border border-input bg-background px-2 py-1 text-xs capitalize">
                        <option value="free">free</option><option value="pro">pro</option><option value="enterprise">enterprise</option>
                      </select>
                    </TableCell>
                    <TableCell>{o.members}</TableCell>
                    <TableCell>{o.projects}</TableCell>
                    <TableCell>{o.scans}</TableCell>
                    <TableCell className="text-muted-foreground">{formatDate(o.created_at)}</TableCell>
                    <TableCell className="text-right">
                      {!o.is_personal ? (
                        <Button size="sm" variant="ghost" onClick={() => suspend.mutate({ id: o.id, s: !o.suspended_at })}>
                          {o.suspended_at ? "Restore" : "Suspend"}
                        </Button>
                      ) : null}
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
