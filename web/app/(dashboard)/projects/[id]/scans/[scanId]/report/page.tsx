"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import { cn, formatDate, gradeColor } from "@/lib/utils";
import { Download, FileText } from "lucide-react";

export default function ExecutiveReportPage() {
  const { id, scanId } = useParams<{ id: string; scanId: string }>();
  const api = useApi();

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["exec-report", scanId],
    queryFn: () => api.getExecutiveReport(scanId),
  });

  if (isLoading) return <p className="text-sm text-muted-foreground">Generating report…</p>;
  if (isError) return <p className="text-sm text-destructive">{(error as Error).message}</p>;

  const r = data!;
  const scan = r.scan;

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div className="flex items-center justify-between print:hidden">
        <Link href={`/projects/${id}/scans/${scanId}`} className="text-sm text-muted-foreground hover:underline">
          ← Back to scan
        </Link>
        <Button size="sm" onClick={() => window.print()}>
          <Download className="mr-1 h-4 w-4" /> Save as PDF
        </Button>
      </div>

      <div>
        <h1 className="flex items-center gap-2 text-2xl font-bold">
          <FileText className="h-6 w-6" /> Executive security report
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {r.project} · {formatDate(scan.created_at)} ·{" "}
          {r.generated_by.startsWith("ai:") ? `AI-generated (${r.generated_by})` : "generated from findings metadata"}
        </p>
      </div>

      <div className="flex items-center gap-6">
        <div className="text-center">
          <div className={cn("text-5xl font-bold", gradeColor(scan.overall_grade))}>{scan.overall_grade ?? "—"}</div>
          <div className="text-xs text-muted-foreground">overall grade</div>
        </div>
        <div className="grid flex-1 grid-cols-3 gap-3 text-center text-sm">
          <Metric label="Security" v={scan.security_score} />
          <Metric label="Quality" v={scan.quality_score} />
          <Metric label="Deployment" v={scan.deployment_score} />
        </div>
      </div>

      <Card>
        <CardHeader><CardTitle>Executive summary</CardTitle></CardHeader>
        <CardContent><p className="leading-relaxed text-muted-foreground">{r.summary}</p></CardContent>
      </Card>

      {r.trend ? (
        <Card>
          <CardHeader><CardTitle>Trend vs previous scan</CardTitle></CardHeader>
          <CardContent className="text-sm">
            <p className="text-muted-foreground">{r.trend.note}</p>
            <p className="mt-1 text-muted-foreground">
              Grade {r.trend.previous_grade || "—"} → {r.trend.current_grade || "—"} · overall{" "}
              {r.trend.overall_delta >= 0 ? "+" : ""}
              {r.trend.overall_delta} · security {r.trend.security_delta >= 0 ? "+" : ""}
              {r.trend.security_delta}
            </p>
          </CardContent>
        </Card>
      ) : null}


      <Card>
        <CardHeader><CardTitle>Top risks</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          {r.top_risks.length === 0 ? (
            <p className="text-sm text-muted-foreground">No critical/high/medium risks.</p>
          ) : (
            r.top_risks.map((risk, i) => (
              <div key={i} className="flex items-start gap-3">
                <SeverityBadge severity={risk.severity} />
                <div className="min-w-0">
                  <p className="font-medium">{risk.title}</p>
                  {risk.impact ? <p className="text-sm text-muted-foreground">{risk.impact}</p> : null}
                  <p className="text-xs text-muted-foreground">{risk.file}</p>
                </div>
              </div>
            ))
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Remediation priorities</CardTitle></CardHeader>
        <CardContent>
          <ol className="list-inside list-decimal space-y-1 text-sm text-muted-foreground">
            {r.priorities.map((p, i) => (
              <li key={i}>{p}</li>
            ))}
          </ol>
        </CardContent>
      </Card>
    </div>
  );
}

function Metric({ label, v }: { label: string; v?: number }) {
  return (
    <div>
      <div className="text-2xl font-bold">{v ?? "—"}</div>
      <div className="text-xs text-muted-foreground">{label}</div>
    </div>
  );
}
