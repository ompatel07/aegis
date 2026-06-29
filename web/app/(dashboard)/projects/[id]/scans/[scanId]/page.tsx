"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScanStatusBadge } from "@/components/dashboard/ScanStatusBadge";
import { FindingsList } from "@/components/findings/FindingsList";
import { cn, formatDate, formatDuration, gradeColor, scoreColor } from "@/lib/utils";

export default function ScanDetailPage() {
  const { id, scanId } = useParams<{ id: string; scanId: string }>();
  const api = useApi();

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => api.getScan(scanId),
    refetchInterval: (query) => {
      const status = query.state.data?.scan.status;
      return status === "queued" || status === "running" ? 4000 : false;
    },
  });

  if (isLoading) return <p className="text-sm text-muted-foreground">Loading scan…</p>;
  if (isError) return <p className="text-sm text-destructive">{(error as Error).message}</p>;

  const scan = data!.scan;
  const isDone = scan.status === "completed";

  return (
    <div className="space-y-8">
      <div>
        <Link href={`/projects/${id}`} className="text-sm text-muted-foreground hover:underline">
          ← Back to project
        </Link>
        <div className="mt-1 flex flex-wrap items-center gap-3">
          <h1 className="text-2xl font-bold">Scan results</h1>
          <ScanStatusBadge status={scan.status} />
          {scan.overall_grade ? (
            <span className={cn("text-3xl font-bold", gradeColor(scan.overall_grade))}>
              {scan.overall_grade}
            </span>
          ) : null}
        </div>
        <p className="mt-1 text-sm text-muted-foreground">
          {scan.branch ? `branch ${scan.branch} · ` : ""}
          {scan.trigger} · {formatDate(scan.created_at)} · {formatDuration(scan.duration_seconds)}
        </p>
      </div>

      {scan.status === "failed" ? (
        <Card>
          <CardContent className="py-6 text-sm text-destructive">
            Scan failed: {scan.error_message ?? "unknown error"}
          </CardContent>
        </Card>
      ) : null}

      {!isDone && scan.status !== "failed" ? (
        <Card>
          <CardContent className="py-6 text-sm text-muted-foreground">
            This scan is {scan.status}. Results will appear here automatically when it finishes.
          </CardContent>
        </Card>
      ) : null}

      {isDone ? (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <ScoreCard title="Overall" score={scan.overall_score} />
            <ScoreCard title="Security" score={scan.security_score} subtitle={`${scan.security_issues_total} issues · ${scan.secrets_found} secrets`} />
            <ScoreCard title="Quality" score={scan.quality_score} subtitle={`${scan.quality_issues_total} issues`} />
            <ScoreCard title="Deployment" score={scan.deployment_score} subtitle={`${scan.vulnerabilities_found} vulns`} />
          </div>

          <Tabs defaultValue="security">
            <TabsList>
              <TabsTrigger value="security">Security</TabsTrigger>
              <TabsTrigger value="quality">Quality</TabsTrigger>
              <TabsTrigger value="deployment">Deployment</TabsTrigger>
            </TabsList>
            <TabsContent value="security">
              <FindingsList scanId={scanId} pillar="security" />
            </TabsContent>
            <TabsContent value="quality">
              <FindingsList scanId={scanId} pillar="quality" />
            </TabsContent>
            <TabsContent value="deployment">
              <FindingsList scanId={scanId} pillar="deployment" />
            </TabsContent>
          </Tabs>
        </>
      ) : null}
    </div>
  );
}

function ScoreCard({ title, score, subtitle }: { title: string; score?: number; subtitle?: string }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className={cn("text-3xl font-bold", scoreColor(score))}>{score ?? "—"}</div>
        {subtitle ? <p className="mt-1 text-xs text-muted-foreground">{subtitle}</p> : null}
      </CardContent>
    </Card>
  );
}
