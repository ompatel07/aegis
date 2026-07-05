"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn, scoreColor } from "@/lib/utils";
import { Brain, TrendingDown, TrendingUp, Minus } from "lucide-react";
import type { Project } from "@/lib/types";

/**
 * Project memory (Phase 2C TASK 4): the baseline ("what's normal here"), team
 * pattern learning (rules this team dismisses), and the AI-generated-code
 * footprint over time. Makes Aegis get better at each project the more it sees.
 */
export function ProjectMemoryCard({ project, onChanged }: { project: Project; onChanged: () => void }) {
  const api = useApi();
  const projectId = project.id;
  const baseline = useQuery({ queryKey: ["baseline", projectId], queryFn: () => api.getBaseline(projectId) });
  const memory = useQuery({ queryKey: ["ai-memory", projectId], queryFn: () => api.getAICodeMemory(projectId) });
  const toggleGrandfather = useMutation({
    mutationFn: (enabled: boolean) =>
      api.updateProject(projectId, {
        name: project.name,
        description: project.description,
        repo_url: project.repo_url,
        repo_type: project.repo_type,
        default_branch: project.default_branch,
        language: project.language,
        grandfather_mode: enabled,
      }),
    onSuccess: () => {
      onChanged();
      baseline.refetch();
    },
  });

  const b = baseline.data;
  const m = memory.data;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Brain className="h-5 w-5 text-sky-500" /> Project memory
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        {/* Baseline */}
        <div>
          <p className="mb-1 text-sm font-medium">Baseline</p>
          {!b || !b.established ? (
            <p className="text-sm text-muted-foreground">
              No baseline yet — the first scan establishes what&apos;s normal for this codebase.
            </p>
          ) : (
            <div className="space-y-2 text-sm text-muted-foreground">
              <p>
                Established over <span className="font-medium text-foreground">{b.scan_count}</span> scan(s) ·{" "}
                {b.profile?.distinct_rules ?? b.rules.length} distinct rule(s) tracked · grandfathering{" "}
                <Badge className={cn("ml-1", b.grandfather_mode
                  ? "border-emerald-400/40 bg-emerald-400/15 text-emerald-600"
                  : "border-border bg-muted text-muted-foreground")}>
                  {b.grandfather_mode ? "on" : "off"}
                </Badge>
                <Button
                  variant="outline" size="sm" className="ml-2 h-6 px-2 text-xs"
                  disabled={toggleGrandfather.isPending}
                  onClick={() => toggleGrandfather.mutate(!project.grandfather_mode)}
                >
                  {project.grandfather_mode ? "Turn off" : "Turn on"}
                </Button>
              </p>
              <p className="text-xs">
                When on, only <span className="text-amber-600">new</span> findings (deviating from the
                baseline) gate PRs; pre-existing findings are informational.
              </p>
              {b.rules.length > 0 ? (
                <ul className="space-y-1">
                  {b.rules.slice(0, 5).map((r) => (
                    <li key={r.rule_id} className="flex items-center justify-between gap-2">
                      <span className="truncate">{r.rule_id}</span>
                      <span className="flex items-center gap-2 whitespace-nowrap">
                        {r.is_grandfathered ? (
                          <Badge className="border-border bg-muted text-xs text-muted-foreground">grandfathered</Badge>
                        ) : null}
                        <span className="text-xs">~{r.avg_count_per_scan}/scan</span>
                      </span>
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>
          )}
        </div>

        {/* Team pattern learning */}
        {b && b.team_learning.length > 0 ? (
          <div>
            <p className="mb-1 text-sm font-medium">Team pattern learning</p>
            <p className="mb-1 text-xs text-muted-foreground">
              How this team triages each rule — folded into a personalized false-positive prior.
            </p>
            <ul className="space-y-1 text-sm text-muted-foreground">
              {b.team_learning.slice(0, 5).map((s) => (
                <li key={s.rule_id} className="flex items-center justify-between gap-2">
                  <span className="truncate">{s.rule_id}</span>
                  <span className="whitespace-nowrap text-xs">
                    {Math.round(s.fp_rate * 100)}% dismissed ({s.total_feedback} signal{s.total_feedback === 1 ? "" : "s"})
                  </span>
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {/* AI-code memory */}
        <div>
          <p className="mb-1 text-sm font-medium">AI-generated code over time</p>
          {!m || m.scans_analyzed === 0 ? (
            <p className="text-sm text-muted-foreground">No AI-code analysis history yet.</p>
          ) : (
            <div className="space-y-2">
              <div className="flex items-center gap-4 text-sm">
                <TrendIcon trend={m.trend} />
                <span className="text-muted-foreground">
                  now <span className="font-medium text-foreground">{Math.round(m.current_pct)}%</span> AI ·
                  avg safety <span className={cn("font-medium", scoreColor(m.avg_safety))}>{m.avg_safety}</span> ·{" "}
                  {m.scans_analyzed} scan(s)
                </span>
              </div>
              <Sparkline points={m.series.map((p) => p.pct)} />
              <p className="text-sm text-muted-foreground">{m.note}</p>
              {m.persistent_files.length > 0 ? (
                <p className="text-xs text-muted-foreground">
                  Persistent AI files (2+ scans): {m.persistent_files.slice(0, 4).join(", ")}
                  {m.persistent_files.length > 4 ? ` +${m.persistent_files.length - 4} more` : ""}
                </p>
              ) : null}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function TrendIcon({ trend }: { trend: string }) {
  if (trend === "growing") return <span className="flex items-center gap-1 text-amber-600"><TrendingUp className="h-4 w-4" /> growing</span>;
  if (trend === "shrinking") return <span className="flex items-center gap-1 text-emerald-600"><TrendingDown className="h-4 w-4" /> shrinking</span>;
  return <span className="flex items-center gap-1 text-muted-foreground"><Minus className="h-4 w-4" /> stable</span>;
}

function Sparkline({ points }: { points: number[] }) {
  if (points.length === 0) return null;
  const max = Math.max(1, ...points);
  return (
    <div className="flex h-10 items-end gap-1">
      {points.map((p, i) => (
        <div
          key={i}
          className="w-2 rounded-sm bg-violet-400/50"
          style={{ height: `${Math.max(6, (p / max) * 100)}%` }}
          title={`${Math.round(p)}% AI`}
        />
      ))}
    </div>
  );
}
