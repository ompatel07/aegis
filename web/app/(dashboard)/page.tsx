"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { MetricCard } from "@/components/dashboard/MetricCard";
import { ScanOutcomeBadge } from "@/components/dashboard/ScanOutcomeBadge";
import { GradeCell, ScoreCell } from "@/components/dashboard/ScanCells";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { cn, formatDate, gradeColor, scoreColor } from "@/lib/utils";
import type { Project, Scan } from "@/lib/types";
import { FolderGit2, Activity, ShieldCheck, Gauge } from "lucide-react";

interface OverviewData {
  projects: Project[];
  total: number;
  scans: (Scan & { projectName: string })[];
}

function average(values: number[]): number | undefined {
  if (values.length === 0) return undefined;
  return Math.round(values.reduce((a, b) => a + b, 0) / values.length);
}

export default function OverviewPage() {
  const api = useApi();

  const { data, isLoading, isError, error } = useQuery<OverviewData>({
    queryKey: ["overview"],
    queryFn: async () => {
      const projectsPage = await api.listProjects(1, 100);
      const projects = projectsPage.data;
      // Fetch recent scans per project (bounded) and flatten.
      const perProject = await Promise.all(
        projects.map(async (p) => {
          const scans = await api.listScans(p.id, 1, 5);
          return scans.data.map((s) => ({ ...s, projectName: p.name }));
        }),
      );
      const scans = perProject.flat().sort((a, b) => b.created_at.localeCompare(a.created_at));
      return { projects, total: projectsPage.meta.total, scans };
    },
  });

  if (isLoading) return <p className="text-sm text-muted-foreground">Loading dashboard…</p>;
  if (isError) return <p className="text-sm text-destructive">{(error as Error).message}</p>;
  if (!data) return null;

  const completed = data.scans.filter((s) => s.status === "completed");
  // Latest completed scan per project for the score averages.
  const latestByProject = new Map<string, Scan>();
  for (const s of completed) {
    if (!latestByProject.has(s.project_id)) latestByProject.set(s.project_id, s);
  }
  const latest = [...latestByProject.values()];
  const avgSecurity = average(latest.map((s) => s.security_score!).filter((n) => n != null));
  const avgQuality = average(latest.map((s) => s.quality_score!).filter((n) => n != null));

  const today = new Date().toDateString();
  const scansToday = data.scans.filter((s) => new Date(s.created_at).toDateString() === today).length;

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold">Overview</h1>
        <p className="text-muted-foreground">A snapshot of your code intelligence across all projects.</p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Projects" value={data.total} icon={FolderGit2} />
        <MetricCard title="Scans today" value={scansToday} icon={Activity} subtitle="across recent activity" />
        <MetricCard
          title="Avg security"
          value={avgSecurity ?? "—"}
          icon={ShieldCheck}
          valueClassName={scoreColor(avgSecurity)}
        />
        <MetricCard
          title="Avg quality"
          value={avgQuality ?? "—"}
          icon={Gauge}
          valueClassName={scoreColor(avgQuality)}
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recent scans</CardTitle>
        </CardHeader>
        <CardContent>
          {data.scans.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">
              No scans yet. Create a project and trigger your first scan.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Project</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Grade</TableHead>
                  <TableHead>Security</TableHead>
                  <TableHead>Quality</TableHead>
                  <TableHead>When</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.scans.slice(0, 10).map((s) => (
                  <TableRow key={s.id}>
                    <TableCell>
                      <Link
                        href={`/projects/${s.project_id}/scans/${s.id}`}
                        className="font-medium hover:underline"
                      >
                        {s.projectName}
                      </Link>
                    </TableCell>
                    <TableCell>
                      <ScanOutcomeBadge scan={s} />
                    </TableCell>
                    <TableCell><GradeCell scan={s} /></TableCell>
                    <TableCell><ScoreCell score={s.security_score} /></TableCell>
                    <TableCell><ScoreCell score={s.quality_score} /></TableCell>
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
