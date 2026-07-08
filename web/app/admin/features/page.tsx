"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/empty-state";
import { useToast } from "@/lib/use-toast";
import { useConfirm } from "@/lib/use-confirm";
import { FlaskConical } from "lucide-react";
import type { FeatureFlag } from "@/lib/types";

export default function AdminFeaturesPage() {
  const api = useApi();
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const [key, setKey] = useState("");
  const { data, isLoading } = useQuery({ queryKey: ["admin-flags"], queryFn: () => api.admin.flags() });
  const invalidate = () => qc.invalidateQueries({ queryKey: ["admin-flags"] });

  const create = useMutation({
    mutationFn: () => api.admin.createFlag({ key }),
    onSuccess: () => { invalidate(); setKey(""); toast.success("Flag created"); },
    onError: (e: Error) => toast.error("Failed", e.message),
  });
  const update = useMutation({
    mutationFn: (f: FeatureFlag) => api.admin.updateFlag(f.id, { enabled: f.enabled, rollout_pct: f.rollout_pct, enabled_orgs: f.enabled_orgs ?? [] }),
    onSuccess: () => { invalidate(); toast.success("Flag updated"); },
    onError: (e: Error) => toast.error("Failed", e.message),
  });
  const del = useMutation({
    mutationFn: (id: string) => api.admin.deleteFlag(id),
    onSuccess: () => { invalidate(); toast.success("Flag deleted"); },
  });

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Feature flags</h1>
      <Card>
        <CardContent className="flex items-end gap-2 py-4">
          <div className="flex-1">
            <label className="mb-1 block text-sm font-medium">New flag key</label>
            <Input placeholder="new-scanner-engine" value={key} onChange={(e) => setKey(e.target.value)} />
          </div>
          <Button disabled={!key || create.isPending} onClick={() => create.mutate()}>Create</Button>
        </CardContent>
      </Card>

      {isLoading ? null : !data || data.length === 0 ? (
        <EmptyState icon={FlaskConical} title="No feature flags" description="Create a flag to roll out features gradually." />
      ) : (
        <div className="space-y-3">
          {data.map((f) => (
            <Card key={f.id}>
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center justify-between text-base">
                  <span className="font-mono">{f.key}</span>
                  <Badge className={f.enabled ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600" : "border-border bg-muted text-muted-foreground"}>
                    {f.enabled ? "enabled" : "disabled"}
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="flex flex-wrap items-center gap-4 text-sm">
                <label className="flex items-center gap-2">
                  <input type="checkbox" checked={f.enabled} onChange={(e) => update.mutate({ ...f, enabled: e.target.checked })} />
                  Globally enabled
                </label>
                <label className="flex items-center gap-2">
                  Rollout %
                  <input type="number" min={0} max={100} defaultValue={f.rollout_pct}
                    onBlur={(e) => update.mutate({ ...f, rollout_pct: Math.max(0, Math.min(100, Number(e.target.value))) })}
                    className="w-20 rounded-md border border-input bg-background px-2 py-1" />
                </label>
                <span className="text-xs text-muted-foreground">{(f.enabled_orgs ?? []).length} org override(s)</span>
                <Button size="sm" variant="ghost" className="ml-auto text-destructive"
                  onClick={async () => { if (await confirm({ title: `Delete flag ${f.key}?`, destructive: true, confirmLabel: "Delete" })) del.mutate(f.id); }}>
                  Delete
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
