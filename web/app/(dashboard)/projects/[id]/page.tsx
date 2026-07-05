"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ScanStatusBadge } from "@/components/dashboard/ScanStatusBadge";
import { TrendChart } from "@/components/dashboard/TrendChart";
import { GitHubIntegrationCard } from "@/components/dashboard/GitHubIntegrationCard";
import { CustomRulesCard } from "@/components/dashboard/CustomRulesCard";
import { ProjectMemoryCard } from "@/components/dashboard/ProjectMemoryCard";
import { cn, formatDate, formatDuration, gradeColor, scoreColor } from "@/lib/utils";
import { Play, Sparkles } from "lucide-react";
import type { Project } from "@/lib/types";

export default function ProjectDetailPage() {
  const { id } = useParams<{ id: string }>();
  const api = useApi();
  const queryClient = useQueryClient();

  const projectQ = useQuery({ queryKey: ["project", id], queryFn: () => api.getProject(id) });

  const scansQ = useQuery({
    queryKey: ["scans", id],
    queryFn: () => api.listScans(id, 1, 50),
    // Poll while a scan is queued/running so the UI updates live.
    refetchInterval: (query) => {
      const active = query.state.data?.data.some((s) => s.status === "queued" || s.status === "running");
      return active ? 4000 : false;
    },
  });

  const trigger = useMutation({
    mutationFn: () => api.triggerScan(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scans", id] }),
  });

  if (projectQ.isLoading) return <p className="text-sm text-muted-foreground">Loading project…</p>;
  if (projectQ.isError) return <p className="text-sm text-destructive">{(projectQ.error as Error).message}</p>;

  const project = projectQ.data!;
  const scans = scansQ.data?.data ?? [];
  const canScan = Boolean(project.repo_url);

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <Link href="/projects" className="text-sm text-muted-foreground hover:underline">
            ← Projects
          </Link>
          <h1 className="mt-1 text-2xl font-bold">{project.name}</h1>
          {project.description ? <p className="text-muted-foreground">{project.description}</p> : null}
          <p className="mt-1 text-sm text-muted-foreground">
            {project.repo_url ?? "No repository configured"} · branch {project.default_branch}
          </p>
        </div>
        <Button onClick={() => trigger.mutate()} disabled={!canScan || trigger.isPending}>
          <Play className="h-4 w-4" />
          {trigger.isPending ? "Queuing…" : "Run scan"}
        </Button>
      </div>

      {!canScan ? (
        <Card>
          <CardContent className="py-6 text-sm text-muted-foreground">
            Add a repository URL to this project to enable scanning.
          </CardContent>
        </Card>
      ) : null}

      {trigger.isError ? (
        <p className="text-sm text-destructive">{(trigger.error as Error).message}</p>
      ) : null}

      {canScan ? <GitHubIntegrationCard projectId={id} /> : null}
      <CustomRulesCard projectId={id} />
      <AISettingsCard project={project} onChanged={() => projectQ.refetch()} />
      <ProjectMemoryCard project={project} onChanged={() => projectQ.refetch()} />

      <TrendChart scans={scans} />

      <Card>
        <CardHeader>
          <CardTitle>Scan history</CardTitle>
        </CardHeader>
        <CardContent>
          {scansQ.isLoading ? (
            <p className="py-6 text-sm text-muted-foreground">Loading scans…</p>
          ) : scans.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              No scans yet. Click “Run scan” to start.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Status</TableHead>
                  <TableHead>Grade</TableHead>
                  <TableHead>Overall</TableHead>
                  <TableHead>Security</TableHead>
                  <TableHead>Quality</TableHead>
                  <TableHead>Deployment</TableHead>
                  <TableHead>Trigger</TableHead>
                  <TableHead>Duration</TableHead>
                  <TableHead>When</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell>
                      <Link href={`/projects/${id}/scans/${s.id}`}>
                        <ScanStatusBadge status={s.status} />
                      </Link>
                    </TableCell>
                    <TableCell className={cn("font-bold", gradeColor(s.overall_grade))}>
                      {s.overall_grade ?? "—"}
                    </TableCell>
                    <TableCell className={scoreColor(s.overall_score)}>{s.overall_score ?? "—"}</TableCell>
                    <TableCell className={scoreColor(s.security_score)}>{s.security_score ?? "—"}</TableCell>
                    <TableCell className={scoreColor(s.quality_score)}>{s.quality_score ?? "—"}</TableCell>
                    <TableCell className={scoreColor(s.deployment_score)}>{s.deployment_score ?? "—"}</TableCell>
                    <TableCell className="capitalize text-muted-foreground">{s.trigger}</TableCell>
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

function AISettingsCard({ project, onChanged }: { project: Project; onChanged: () => void }) {
  const api = useApi();
  const statusQ = useQuery({ queryKey: ["ai-status"], queryFn: () => api.getAiStatus() });
  const toggle = useMutation({
    mutationFn: (enabled: boolean) =>
      api.updateProject(project.id, {
        name: project.name,
        description: project.description,
        repo_url: project.repo_url,
        repo_type: project.repo_type,
        default_branch: project.default_branch,
        language: project.language,
        ai_fix_enabled: enabled,
      }),
    onSuccess: onChanged,
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Sparkles className="h-4 w-4" /> AI fix suggestions
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <p className="text-muted-foreground">
          Opt-in, snippet-only, and fully audited — Aegis never auto-applies changes. Backend:{" "}
          {statusQ.data?.provider ?? "…"} ({statusQ.data?.enabled ? "configured" : "not configured"}).
        </p>
        <div className="flex items-center gap-3">
          <span>{project.ai_fix_enabled ? "Enabled for this project" : "Disabled for this project"}</span>
          <Button
            variant="outline"
            size="sm"
            className="ml-auto"
            disabled={toggle.isPending}
            onClick={() => toggle.mutate(!project.ai_fix_enabled)}
          >
            {project.ai_fix_enabled ? "Disable" : "Enable"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
