"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SkeletonTable } from "@/components/ui/skeleton";
import { useToast } from "@/lib/use-toast";
import { useConfirm } from "@/lib/use-confirm";
import { startImpersonation } from "@/lib/impersonation";
import { formatDate } from "@/lib/utils";

export default function AdminUsersPage() {
  const api = useApi();
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const router = useRouter();
  const [search, setSearch] = useState("");
  const { data, isLoading } = useQuery({ queryKey: ["admin-users", search], queryFn: () => api.admin.users(search) });

  const invalidate = () => qc.invalidateQueries({ queryKey: ["admin-users"] });
  const superAdmin = useMutation({
    mutationFn: ({ id, grant }: { id: string; grant: boolean }) => api.admin.setSuperAdmin(id, grant),
    onSuccess: (_, v) => { invalidate(); toast.success(v.grant ? "Granted super-admin" : "Revoked super-admin"); },
    onError: (e: Error) => toast.error("Failed", e.message),
  });
  const suspend = useMutation({
    mutationFn: ({ id, s }: { id: string; s: boolean }) => api.admin.suspendUser(id, s),
    onSuccess: (_, v) => { invalidate(); toast.success(v.s ? "User suspended" : "User restored"); },
    onError: (e: Error) => toast.error("Failed", e.message),
  });

  async function impersonate(id: string, email: string) {
    const ok = await confirm({
      title: `Impersonate ${email}?`,
      description: "You'll browse as this user for support. The session is audit-logged and expires within 1 hour.",
      confirmLabel: "Impersonate",
    });
    if (!ok) return;
    try {
      const res = await api.admin.impersonate(id);
      startImpersonation(res.access_token, res.user.email, res.expires_in);
      toast.success(`Now impersonating ${res.user.email}`);
      router.push("/");
    } catch (e) {
      toast.error("Impersonation failed", (e as Error).message);
    }
  }

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Users</h1>
      <Input placeholder="Search by email or name…" value={search} onChange={(e) => setSearch(e.target.value)} className="max-w-sm" />

      <Card>
        <CardContent className="overflow-x-auto p-0">
          {isLoading ? (
            <div className="p-4"><SkeletonTable rows={6} cols={5} /></div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead><TableHead>Orgs</TableHead><TableHead>Role</TableHead>
                  <TableHead>Signed up</TableHead><TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data?.map((u) => (
                  <TableRow key={u.id}>
                    <TableCell>
                      <div className="font-medium">{u.name || u.email}
                        {u.suspended_at ? <Badge className="ml-2 border-destructive/40 bg-destructive/10 text-destructive">suspended</Badge> : null}
                      </div>
                      <div className="text-xs text-muted-foreground">{u.email}</div>
                    </TableCell>
                    <TableCell>{u.orgs}</TableCell>
                    <TableCell>
                      {u.is_super_admin ? <Badge className="border-red-500/40 bg-red-500/10 text-red-600">super-admin</Badge> : <span className="text-muted-foreground">user</span>}
                    </TableCell>
                    <TableCell className="text-muted-foreground">{formatDate(u.created_at)}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button size="sm" variant="ghost" onClick={() => impersonate(u.id, u.email)}>Impersonate</Button>
                        <Button size="sm" variant="ghost" onClick={() => superAdmin.mutate({ id: u.id, grant: !u.is_super_admin })}>
                          {u.is_super_admin ? "Revoke admin" : "Make admin"}
                        </Button>
                        <Button size="sm" variant="ghost" onClick={() => suspend.mutate({ id: u.id, s: !u.suspended_at })}>
                          {u.suspended_at ? "Restore" : "Suspend"}
                        </Button>
                      </div>
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
