"use client";

import { useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import type { OrgRole } from "@/lib/types";

const ROLES: OrgRole[] = ["owner", "admin", "member", "viewer"];

export default function OrgDetailPage() {
  const { orgId } = useParams<{ orgId: string }>();
  const api = useApi();
  const qc = useQueryClient();

  const orgQ = useQuery({ queryKey: ["org", orgId], queryFn: () => api.getOrg(orgId) });
  const membersQ = useQuery({ queryKey: ["members", orgId], queryFn: () => api.listMembers(orgId) });
  const invitesQ = useQuery({
    queryKey: ["invites", orgId],
    queryFn: () => api.listInvitations(orgId),
    retry: false,
  });

  const [name, setName] = useState("");
  const [billing, setBilling] = useState("");
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<OrgRole>("member");
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const org = orgQ.data;

  const saveSettings = useMutation({
    mutationFn: () => api.updateOrg(orgId, { name: name || org!.name, billing_email: billing || undefined }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["org", orgId] }); qc.invalidateQueries({ queryKey: ["orgs"] }); setMsg("Settings saved."); },
    onError: (e: Error) => setErr(e.message),
  });

  const invite = useMutation({
    mutationFn: () => api.inviteMember(orgId, { email: inviteEmail, role: inviteRole }),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["members", orgId] });
      qc.invalidateQueries({ queryKey: ["invites", orgId] });
      setInviteEmail("");
      setMsg("added" in (res ?? {}) ? "User added to the team." : "Invitation sent.");
      setErr(null);
    },
    onError: (e: Error) => setErr(e.message),
  });

  const setRole = useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: string }) => api.setMemberRole(orgId, userId, role),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["members", orgId] }),
    onError: (e: Error) => setErr(e.message),
  });

  const remove = useMutation({
    mutationFn: (userId: string) => api.removeMember(orgId, userId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["members", orgId] }),
    onError: (e: Error) => setErr(e.message),
  });

  const revoke = useMutation({
    mutationFn: (invId: string) => api.revokeInvitation(orgId, invId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["invites", orgId] }),
  });

  if (orgQ.isLoading) return <p className="text-sm text-muted-foreground">Loading…</p>;
  if (orgQ.isError) return <p className="text-sm text-destructive">{(orgQ.error as Error).message}</p>;

  return (
    <div className="space-y-6">
      <div>
        <Link href="/organizations" className="text-sm text-muted-foreground hover:underline">← Teams</Link>
        <h1 className="mt-1 text-2xl font-bold">{org!.name}</h1>
        <p className="text-sm text-muted-foreground">{org!.is_personal ? "Personal workspace" : "Team"} · plan {org!.plan}</p>
      </div>

      {msg ? <p className="text-sm text-emerald-600">{msg}</p> : null}
      {err ? <p className="text-sm text-destructive">{err}</p> : null}

      {/* Settings */}
      <Card>
        <CardHeader><CardTitle>Settings</CardTitle></CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-2">
          <div>
            <label className="mb-1 block text-sm font-medium">Name</label>
            <Input defaultValue={org!.name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium">Billing email</label>
            <Input defaultValue={org!.billing_email ?? ""} onChange={(e) => setBilling(e.target.value)} />
          </div>
          <div className="sm:col-span-2">
            <Button size="sm" disabled={saveSettings.isPending} onClick={() => saveSettings.mutate()}>Save settings</Button>
          </div>
        </CardContent>
      </Card>

      {/* Members */}
      <Card>
        <CardHeader><CardTitle>Members</CardTitle></CardHeader>
        <CardContent>
          <div className="mb-4 flex flex-wrap items-end gap-2">
            <div className="flex-1">
              <label className="mb-1 block text-sm font-medium">Invite by email</label>
              <Input placeholder="teammate@company.com" value={inviteEmail} onChange={(e) => setInviteEmail(e.target.value)} />
            </div>
            <select className="h-10 rounded-md border border-input bg-background px-2 text-sm"
              value={inviteRole} onChange={(e) => setInviteRole(e.target.value as OrgRole)}>
              {ROLES.filter((r) => r !== "owner").map((r) => <option key={r} value={r}>{r}</option>)}
            </select>
            <Button disabled={!inviteEmail || invite.isPending} onClick={() => invite.mutate()}>Invite</Button>
          </div>

          <Table>
            <TableHeader>
              <TableRow><TableHead>Member</TableHead><TableHead>Role</TableHead><TableHead></TableHead></TableRow>
            </TableHeader>
            <TableBody>
              {membersQ.data?.map((m) => (
                <TableRow key={m.user_id}>
                  <TableCell>
                    <div className="font-medium">{m.name || m.email}</div>
                    <div className="text-xs text-muted-foreground">{m.email}</div>
                  </TableCell>
                  <TableCell>
                    <select className="h-8 rounded-md border border-input bg-background px-2 text-sm capitalize"
                      value={m.role} onChange={(e) => setRole.mutate({ userId: m.user_id, role: e.target.value })}>
                      {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                    </select>
                  </TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="sm" onClick={() => remove.mutate(m.user_id)}>Remove</Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Pending invitations (admin+ only; query fails silently for others) */}
      {invitesQ.data && invitesQ.data.length > 0 ? (
        <Card>
          <CardHeader><CardTitle>Pending invitations</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {invitesQ.data.map((inv) => (
              <div key={inv.id} className="flex items-center justify-between text-sm">
                <span>{inv.email} <Badge className="ml-1 border-border bg-secondary capitalize text-secondary-foreground">{inv.role}</Badge></span>
                <span className="flex items-center gap-3">
                  <code className="text-xs text-muted-foreground">token: {inv.token.slice(0, 12)}…</code>
                  <Button variant="ghost" size="sm" onClick={() => revoke.mutate(inv.id)}>Revoke</Button>
                </span>
              </div>
            ))}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
