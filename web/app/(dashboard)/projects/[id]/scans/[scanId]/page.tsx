"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScanStatusBadge } from "@/components/dashboard/ScanStatusBadge";
import { AICodeCard } from "@/components/dashboard/AICodeCard";
import { PolicyResultCard } from "@/components/dashboard/PolicyResultCard";
import { ScanProgress } from "@/components/dashboard/ScanProgress";
import { FindingsList } from "@/components/findings/FindingsList";
import { Button } from "@/components/ui/button";
import { cn, formatDate, formatDuration, gradeColor, scoreColor } from "@/lib/utils";
import { Download, FileText } from "lucide-react";
import { useState } from "react";

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
          {isDone ? (
            <span className="ml-auto flex items-center gap-2">
              <Link
                href={`/projects/${id}/scans/${scanId}/report`}
                className="inline-flex h-8 items-center gap-1 rounded-md border px-3 text-sm hover:bg-muted"
              >
                <FileText className="h-4 w-4" /> Executive report
              </Link>
              <ExportSarifButton scanId={scanId} />
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
          <CardContent className="space-y-3 py-6 text-sm text-muted-foreground">
            <p>This scan is {scan.status}. Live progress:</p>
            <ScanProgress scanId={scanId} active={!isDone} />
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

          <PolicyResultCard scanId={scanId} />
          <AICodeCard scan={scan} />

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

function ExportSarifButton({ scanId }: { scanId: string }) {
  const api = useApi();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function download() {
    setBusy(true);
    setErr(null);
    try {
      await api.exportSarif(scanId);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <span className="ml-auto flex items-center gap-2">
      {err ? <span className="text-xs text-destructive">{err}</span> : null}
      <Button variant="outline" size="sm" onClick={download} disabled={busy} title="Download SARIF 2.1.0">
        <Download className="mr-1 h-4 w-4" />
        {busy ? "Exporting…" : "Export SARIF"}
      </Button>
    </span>
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
