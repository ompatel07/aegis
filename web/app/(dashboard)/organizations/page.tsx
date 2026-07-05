"use client";

import { useState } from "react";
import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Building2, Plus } from "lucide-react";

export default function OrganizationsPage() {
  const api = useApi();
  const qc = useQueryClient();
  const { data: orgs, isLoading } = useQuery({ queryKey: ["orgs"], queryFn: () => api.listOrgs() });
  const [name, setName] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () => api.createOrg({ name }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["orgs"] });
      setName("");
      setErr(null);
    },
    onError: (e: Error) => setErr(e.message),
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-bold">
          <Building2 className="h-6 w-6" /> Teams
        </h1>
        <p className="text-muted-foreground">Organizations you belong to. Projects live inside a team.</p>
      </div>

      <Card>
        <CardContent className="flex flex-wrap items-end gap-3 py-4">
          <div className="flex-1">
            <label className="mb-1 block text-sm font-medium">Create a new team</label>
            <Input placeholder="Acme Inc" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <Button disabled={!name || create.isPending} onClick={() => create.mutate()}>
            <Plus className="mr-1 h-4 w-4" /> Create
          </Button>
        </CardContent>
      </Card>
      {err ? <p className="text-sm text-destructive">{err}</p> : null}

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2">
          {orgs?.map((o) => (
            <Link key={o.id} href={`/organizations/${o.id}`}>
              <Card className="transition-colors hover:border-primary">
                <CardContent className="flex items-center justify-between py-4">
                  <div>
                    <p className="font-medium">{o.name}</p>
                    <p className="text-xs text-muted-foreground">
                      {o.is_personal ? "Personal workspace" : "Team"} · {o.plan}
                    </p>
                  </div>
                  <Badge className="border-border bg-secondary capitalize text-secondary-foreground">{o.role}</Badge>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
