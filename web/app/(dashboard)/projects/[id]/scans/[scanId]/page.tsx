"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScanStatusBadge } from "@/components/dashboard/ScanStatusBadge";
import { DegradedBadge } from "@/components/dashboard/DegradedBadge";
import { PolicyResultCard } from "@/components/dashboard/PolicyResultCard";
import { ScanProgress } from "@/components/dashboard/ScanProgress";
import { ScanFeedback } from "@/components/dashboard/ScanFeedback";
import { FindingsList } from "@/components/findings/FindingsList";
import { Button } from "@/components/ui/button";
import { cn, formatDate, formatDuration, gradeColor, scoreColor } from "@/lib/utils";
import { ratingDisplay, filteredSecretsLabel, filteredSecretsTotal, notMeasuredReason } from "@/lib/display";
import { Download, FileText, HelpCircle } from "lucide-react";
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
          <DegradedBadge scan={scan} />
          {scan.overall_grade ? (
            <span className={cn("text-3xl font-bold", gradeColor(scan.overall_grade))}>
              {scan.overall_grade}
            </span>
          ) : isDone ? (
            <span className="text-sm font-medium text-muted-foreground italic">Not measured</span>
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

      {scan.engines_degraded && scan.engines_degraded.length > 0 ? (
        <Card className="border-amber-500/50 bg-amber-500/5">
          <CardContent className="space-y-1 py-4 text-sm">
            <p className="font-medium text-amber-700 dark:text-amber-500">
              ⚠ Degraded scan — results are incomplete, not clean
            </p>
            <ul className="ml-4 list-disc text-muted-foreground">
              {scan.engines_degraded.map((d, i) => (
                <li key={i}>
                  <span className="font-medium">{d.engine}</span>: {d.reason}
                  {d.coverage_lost ? ` (lost: ${d.coverage_lost})` : ""}
                </li>
              ))}
            </ul>
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
          {/* Two-pillar product: Security + Code Quality. Deployment is offered
              only in CI mode (customer's own pipeline built the workspace), so its
              card/tab appear only when it was actually measured — never as a
              "not measured" slot on a web scan. */}
          <div className={cn("grid gap-4 sm:grid-cols-2", scan.deployment_score != null ? "lg:grid-cols-4" : "lg:grid-cols-3")}>
            <ScoreCard title="Overall" score={scan.overall_score} />
            <ScoreCard
              title="Security"
              score={scan.security_score}
              subtitle={`${scan.security_issues_total} issues · ${scan.secrets_found} secrets`}
              footnote={
                filteredSecretsTotal(scan.filtered_secrets) > 0
                  ? filteredSecretsLabel(scan.filtered_secrets) ?? undefined
                  : undefined
              }
            />
            <ScoreCard title="Quality" score={scan.quality_score} subtitle={`${scan.quality_issues_total} issues`} />
            {scan.deployment_score != null ? (
              <ScoreCard title="Deployment (CI)" score={scan.deployment_score} subtitle="pre-built workspace" />
            ) : null}
          </div>

          {/* SonarQube-style A–E ratings (P2c). The LETTER is worst-severity (one
              critical bug caps Reliability at E); Security also shows its density
              score. A null rating is an explicit, weighted "Not measured" with the
              REASON it could not be measured — never a blank, an A, or method jargon
              captioning a measurement that never ran. */}
          <div className="grid gap-4 sm:grid-cols-3">
            <RatingCard title="Reliability" rating={scan.reliability_rating} reason={notMeasuredReason(scan, "reliability")} />
            <RatingCard title="Security" rating={scan.security_rating} score={scan.security_score} reason={notMeasuredReason(scan, "security")} />
            <RatingCard title="Maintainability" rating={scan.maintainability_rating} reason={notMeasuredReason(scan, "maintainability")} />
          </div>

          <PolicyResultCard scanId={scanId} />

          <Tabs defaultValue="security">
            <TabsList>
              <TabsTrigger value="security">Security</TabsTrigger>
              <TabsTrigger value="quality">Quality</TabsTrigger>
              {scan.deployment_score != null ? <TabsTrigger value="deployment">Deployment (CI)</TabsTrigger> : null}
            </TabsList>
            <TabsContent value="security">
              <FindingsList scanId={scanId} pillar="security" />
            </TabsContent>
            <TabsContent value="quality">
              <FindingsList scanId={scanId} pillar="quality" />
            </TabsContent>
            {scan.deployment_score != null ? (
              <TabsContent value="deployment">
                <FindingsList scanId={scanId} pillar="deployment" />
              </TabsContent>
            ) : null}
          </Tabs>

          <Card>
            <CardContent className="py-4">
              <ScanFeedback scanId={scanId} />
            </CardContent>
          </Card>
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

  async function downloadSbom(format: "cyclonedx" | "spdx") {
    setBusy(true);
    setErr(null);
    try {
      await api.exportSbom(scanId, format);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <span className="ml-auto flex flex-wrap items-center gap-2">
      {err ? <span className="text-xs text-destructive">{err}</span> : null}
      <Button variant="outline" size="sm" onClick={download} disabled={busy} title="Download SARIF 2.1.0">
        <Download className="mr-1 h-4 w-4" />
        {busy ? "Exporting…" : "Export SARIF"}
      </Button>
      <Button variant="outline" size="sm" onClick={() => downloadSbom("cyclonedx")} disabled={busy} title="Download SBOM (CycloneDX)">
        <Download className="mr-1 h-4 w-4" /> SBOM · CycloneDX
      </Button>
      <Button variant="outline" size="sm" onClick={() => downloadSbom("spdx")} disabled={busy} title="Download SBOM (SPDX)">
        <Download className="mr-1 h-4 w-4" /> SBOM · SPDX
      </Button>
    </span>
  );
}

// A weighted "Not measured" — an unresolved gap, not a calm absence (C2).
function NotMeasuredBlock({ reason }: { reason?: string }) {
  return (
    <div>
      <div className="flex items-center gap-1.5 text-xl font-bold text-amber-700 dark:text-amber-400">
        <HelpCircle className="h-5 w-5" />
        Not measured
      </div>
      <p className="mt-1 text-xs text-amber-700/80 dark:text-amber-400/80">
        {reason ?? "no confident measurement for this scan"}
      </p>
    </div>
  );
}

function ScoreCard({ title, score, subtitle, footnote }: { title: string; score?: number; subtitle?: string; footnote?: string }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        {score == null ? (
          <NotMeasuredBlock />
        ) : (
          <div className={cn("text-3xl font-bold tabular-nums", scoreColor(score))}>{score}</div>
        )}
        {subtitle ? <p className="mt-1 text-xs text-muted-foreground">{subtitle}</p> : null}
        {footnote ? (
          <p className="mt-1 text-xs text-muted-foreground" title="Filtered secrets — definitively not credentials, excluded from the count">
            🛈 {footnote}
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}

const RATING_CLASS: Record<string, string> = {
  A: "text-emerald-600 dark:text-emerald-400",
  B: "text-lime-600 dark:text-lime-400",
  C: "text-amber-600 dark:text-amber-400",
  D: "text-orange-600 dark:text-orange-400",
  E: "text-red-600 dark:text-red-400",
};

// A–E rating card. Measured → the letter (+ Security's density score), no method
// jargon (C3). null → a weighted "Not measured" with the REASON it could not be
// measured (C2/C3), never a blank, an A, or a caption for a method that never ran.
function RatingCard({ title, rating, score, reason }: { title: string; rating?: string; score?: number; reason?: string | null }) {
  const r = ratingDisplay(rating);
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        {!r.measured ? (
          <NotMeasuredBlock reason={reason ?? undefined} />
        ) : (
          <div className="flex items-baseline gap-2">
            <span className={cn("text-3xl font-bold", RATING_CLASS[r.text] ?? "text-foreground")}>{r.text}</span>
            {score != null ? <span className={cn("text-lg font-semibold tabular-nums", scoreColor(score))}>{score}</span> : null}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
