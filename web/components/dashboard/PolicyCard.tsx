"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ShieldCheck } from "lucide-react";

const TEMPLATES: { id: string; label: string; blurb: string }[] = [
  { id: "startup", label: "Startup", blurb: "Permissive — block only new critical vulns" },
  { id: "growing", label: "Growing team", blurb: "Moderate — block new high+ findings, security floor 60" },
  { id: "enterprise", label: "Enterprise", blurb: "Strict — no new findings, score + AI-safety floors" },
  { id: "compliance", label: "Compliance", blurb: "Maximum — nothing outside the approved baseline" },
];

/** Quality-gate policy configuration for a project (Phase 2C TASK 8). */
export function PolicyCard({ projectId }: { projectId: string }) {
  const api = useApi();
  const qc = useQueryClient();
  const policyQ = useQuery({ queryKey: ["policy", projectId], queryFn: () => api.getPolicy(projectId) });

  const setPolicy = useMutation({
    mutationFn: (template: string) => api.setPolicy(projectId, { template }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policy", projectId] }),
  });

  const active = policyQ.data?.template ?? null;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <ShieldCheck className="h-5 w-5 text-emerald-500" /> Quality gate policy
          {policyQ.data ? (
            <Badge className="border-emerald-400/40 bg-emerald-400/15 text-emerald-600">active: {policyQ.data.name}</Badge>
          ) : (
            <Badge className="border-border bg-muted text-muted-foreground">none</Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <p className="mb-3 text-sm text-muted-foreground">
          Gate pull requests on this project&apos;s scans. New (non-baseline) findings, score floors, and the
          AI-code safety score can each block a merge.
        </p>
        <div className="grid gap-2 sm:grid-cols-2">
          {TEMPLATES.map((t) => (
            <button
              key={t.id}
              onClick={() => setPolicy.mutate(t.id)}
              disabled={setPolicy.isPending}
              className={`rounded-md border p-3 text-left text-sm transition-colors hover:border-primary ${
                active === t.id ? "border-primary bg-primary/5" : "border-border"
              }`}
            >
              <div className="font-medium">{t.label}</div>
              <div className="text-xs text-muted-foreground">{t.blurb}</div>
            </button>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
