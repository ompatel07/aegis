"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn, scoreColor } from "@/lib/utils";
import type { Scan } from "@/lib/types";
import { Bot, Sparkles } from "lucide-react";

/**
 * AI-generated-code report — the Aegis differentiator. Renders the per-scan
 * AI-code analysis: estimated % of the codebase that looks AI-generated, an
 * AI-code safety score, the finding split between AI vs human code, the top
 * issues found in AI code, and why files were flagged.
 */
export function AICodeCard({ scan }: { scan: Scan }) {
  const report = scan.ai_code_report;
  if (!report || scan.ai_generated_pct == null) return null;

  const pct = Math.round(report.ai_generated_pct);
  const safety = report.safety_score;

  return (
    <Card className="border-violet-400/30">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Bot className="h-5 w-5 text-violet-500" /> AI-generated code
          {!report.model_available ? (
            <Badge className="border-border bg-muted text-xs text-muted-foreground">heuristic</Badge>
          ) : null}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <Stat value={`${pct}%`} label="of codebase AI-generated" accent="text-violet-500" />
          <Stat value={`${safety}`} label="AI-code safety /100" accent={scoreColor(safety)} />
          <Stat value={`${report.findings_in_ai_code}`} label="findings in AI code" />
          <Stat value={`${report.ai_failure_mode_findings}`} label="AI failure-mode findings" />
        </div>

        {pct >= 20 ? (
          <p className="flex items-start gap-2 rounded-md bg-violet-400/10 p-3 text-sm text-muted-foreground">
            <Sparkles className="mt-0.5 h-4 w-4 shrink-0 text-violet-500" />
            AI-generated code carries roughly <span className="font-medium">2.7× the vulnerability
            density</span> of human-written code. {report.findings_in_ai_code} finding(s) sit in the{" "}
            {report.ai_file_count} file(s) flagged as AI-generated — prioritize their review.
          </p>
        ) : null}

        {report.top_ai_issues.length > 0 ? (
          <div>
            <p className="mb-1 text-sm font-medium">Top issues in AI-generated code</p>
            <ul className="space-y-1 text-sm text-muted-foreground">
              {report.top_ai_issues.map((it) => (
                <li key={it.rule_id} className="flex items-center justify-between gap-2">
                  <span className="truncate">{it.title}</span>
                  <Badge className="border-border bg-secondary text-secondary-foreground">{it.count}</Badge>
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {report.top_signals.length > 0 ? (
          <div>
            <p className="mb-1 text-sm font-medium">Why these files were flagged</p>
            <div className="flex flex-wrap gap-1.5">
              {report.top_signals.map((s) => (
                <Badge key={s} className="border-violet-400/30 bg-violet-400/10 text-xs text-violet-500">
                  {s}
                </Badge>
              ))}
            </div>
          </div>
        ) : null}

        <p className="text-xs text-muted-foreground">
          {report.files_scored} source file(s) analyzed locally · findings split{" "}
          {report.findings_in_ai_code} AI / {report.findings_in_human_code} human. No source code
          leaves your infrastructure.
        </p>
      </CardContent>
    </Card>
  );
}

function Stat({ value, label, accent }: { value: string; label: string; accent?: string }) {
  return (
    <div>
      <div className={cn("text-2xl font-bold", accent)}>{value}</div>
      <div className="text-xs text-muted-foreground">{label}</div>
    </div>
  );
}
