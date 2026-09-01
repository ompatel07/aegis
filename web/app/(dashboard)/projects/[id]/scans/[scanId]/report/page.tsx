"use client";

import Link from "next/link";
import { useState } from "react";
import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import { cn, formatDate, gradeColor } from "@/lib/utils";
import { overallState, partialQualifier } from "@/lib/display";
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
          {(() => {
            const st = overallState(scan);
            if (st === "full") {
              return <div className={cn("text-5xl font-bold", gradeColor(scan.overall_grade))}>{scan.overall_grade}</div>;
            }
            if (st === "partial") {
              return (
                <div className="text-3xl font-bold text-amber-700 dark:text-amber-400">
                  {scan.overall_grade}
                  <span className="ml-1 text-base font-medium">· {partialQualifier(scan)}</span>
                </div>
              );
            }
            return <div className="text-2xl font-bold text-amber-700 dark:text-amber-400">Not measured</div>;
          })()}
          <div className="text-xs text-muted-foreground">overall grade</div>
        </div>
        <div className={cn("grid flex-1 gap-3 text-center text-sm", scan.deployment_score != null ? "grid-cols-3" : "grid-cols-2")}>
          <Metric label="Security" v={scan.security_score} />
          <Metric label="Quality" v={scan.quality_score} />
          {/* Two-pillar product; deployment shown only when measured (CI mode). */}
          {scan.deployment_score != null ? <Metric label="Deployment (CI)" v={scan.deployment_score} /> : null}
        </div>
      </div>

      {scan.engines_degraded && scan.engines_degraded.length > 0 ? (
        <Card className="border-amber-500/50 bg-amber-500/5">
          <CardContent className="space-y-1 py-4 text-sm">
            <p className="font-medium text-amber-700 dark:text-amber-500">
              ⚠ Degraded scan — coverage is incomplete. Scores below reflect only what ran.
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
                  {risk.reproduction ? (
                    <div className="mt-1.5 rounded-md border bg-muted/40 p-2 text-xs">
                      <p className="font-medium">Steps to reproduce{risk.reproduction.cwe ? ` (${risk.reproduction.cwe})` : ""}</p>
                      <p className="mt-0.5"><span className="text-blue-600 dark:text-blue-400">Source:</span> <code className="break-all">{risk.reproduction.source}</code></p>
                      <p><span className="text-red-600 dark:text-red-400">Sink:</span> <code className="break-all">{risk.reproduction.sink}</code></p>
                      <p className="mt-0.5 text-muted-foreground">{risk.reproduction.why}</p>
                      {risk.reproduction.example ? (
                        <p className="mt-0.5">Example trigger: <code className="break-all">{risk.reproduction.example}</code></p>
                      ) : null}
                    </div>
                  ) : null}
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

      <ComplianceReportCard scanId={scanId} />
    </div>
  );
}

const FRAMEWORKS: { id: string; label: string }[] = [
  { id: "soc2", label: "SOC 2" },
  { id: "pci_dss", label: "PCI-DSS" },
  { id: "hipaa", label: "HIPAA" },
  { id: "iso27001", label: "ISO 27001" },
  { id: "owasp_asvs", label: "OWASP ASVS" },
  { id: "nist_csf", label: "NIST CSF" },
];

// Compliance report generator (Phase 2G) — maps this scan's findings to a
// framework's controls and lets the user preview + download an audit-evidence HTML.
function ComplianceReportCard({ scanId }: { scanId: string }) {
  const api = useApi();
  const [framework, setFramework] = useState("soc2");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<{ score_pct: number; controls_needs_attention: number; controls_in_scope: number; html: string } | null>(null);

  async function generate() {
    setBusy(true);
    setErr(null);
    try {
      setResult(await api.getComplianceReport(scanId, framework));
    } catch (e) {
      setErr((e as Error).message);
      setResult(null);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="print:hidden">
      <CardHeader><CardTitle>Compliance report</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <p className="text-sm text-muted-foreground">
          Map this scan&apos;s findings to a compliance framework&apos;s controls (audit-ready technical
          evidence — not a certification).
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <select
            className="h-9 rounded-md border border-input bg-background px-3 text-sm"
            value={framework}
            onChange={(e) => { setFramework(e.target.value); setResult(null); }}
          >
            {FRAMEWORKS.map((f) => (
              <option key={f.id} value={f.id}>{f.label}</option>
            ))}
          </select>
          <Button size="sm" onClick={generate} disabled={busy}>
            {busy ? "Generating…" : "Generate report"}
          </Button>
          <Button size="sm" variant="outline" onClick={() => api.downloadComplianceReport(scanId, framework)} disabled={busy}>
            <Download className="mr-1 h-4 w-4" /> Download HTML
          </Button>
        </div>
        {err ? <p className="text-sm text-destructive">{err}</p> : null}
        {result ? (
          <div className="space-y-2">
            <p className="text-sm">
              <span className="font-medium">Compliance score: {result.score_pct}%</span>{" "}
              <span className="text-muted-foreground">
                ({result.controls_needs_attention} of {result.controls_in_scope} in-scope controls need attention)
              </span>
            </p>
            <iframe title="compliance-report" className="h-[420px] w-full rounded-md border bg-white" srcDoc={result.html} />
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

function Metric({ label, v }: { label: string; v?: number }) {
  return (
    <div>
      {v == null ? (
        <div className="text-sm font-semibold text-amber-700 dark:text-amber-400">Not measured</div>
      ) : (
        <div className="text-2xl font-bold tabular-nums">{v}</div>
      )}
      <div className="text-xs text-muted-foreground">{label}</div>
    </div>
  );
}
