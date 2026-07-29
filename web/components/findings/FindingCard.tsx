"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { SeverityBadge } from "./SeverityBadge";
import { ReachabilityBadge, ReachabilityDetail } from "./ReachabilityBadge";
import { useApi } from "@/lib/use-api";
import { useToast } from "@/lib/use-toast";
import type { Finding, StepsToReproduce, SoRNode } from "@/lib/types";
import { ArrowDown, Check, Clock, Copy, FileCode2, ShieldAlert, Sparkles, Wrench, Route } from "lucide-react";

/** Small inline copy-to-clipboard button. */
function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      aria-label={`Copy ${label}`}
      title={`Copy ${label}`}
      onClick={(e) => {
        e.stopPropagation();
        navigator.clipboard?.writeText(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 1200);
      }}
      className="text-muted-foreground transition-colors hover:text-foreground"
    >
      {copied ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
    </button>
  );
}

const RISK_CLASS: Record<string, string> = {
  critical: "border-red-500/40 bg-red-500/15 text-red-600 dark:text-red-400",
  high: "border-orange-500/40 bg-orange-500/15 text-orange-600 dark:text-orange-400",
  medium: "border-amber-500/40 bg-amber-500/15 text-amber-600 dark:text-amber-400",
  low: "border-blue-500/40 bg-blue-500/15 text-blue-600 dark:text-blue-400",
  informational: "border-border bg-muted text-muted-foreground",
};

function RiskBadge({ risk }: { risk?: string }) {
  if (!risk) return null;
  return <Badge className={RISK_CLASS[risk] ?? RISK_CLASS.informational}>{risk}</Badge>;
}

function EffortBadge({ effort }: { effort?: string }) {
  if (!effort) return null;
  return (
    <Badge className="border-border bg-secondary text-secondary-foreground">
      <Clock className="mr-1 h-3 w-3" />
      {effort} fix
    </Badge>
  );
}

function LikelyFPBadge({ p }: { p?: number }) {
  if (p == null || p <= 0.5) return null;
  return (
    <Badge className="border-slate-400/40 bg-slate-400/15 text-slate-500" title="Local ML estimate">
      likely FP {Math.round(p * 100)}%
    </Badge>
  );
}

function NewBadge({ finding }: { finding: Finding }) {
  if (!finding.is_new) return null;
  return (
    <Badge
      className="border-amber-400/40 bg-amber-400/15 text-amber-600"
      title="New — deviates from this project's baseline"
    >
      new
    </Badge>
  );
}

export function FindingCard({ finding, onUpdated }: { finding: Finding; onUpdated?: () => void }) {
  const api = useApi();
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  const heading = finding.title_human || finding.title;
  const location = finding.line_start
    ? `${finding.file_path}:${finding.line_start}`
    : finding.file_path;

  async function triage(body: { is_false_positive?: boolean; is_suppressed?: boolean }, msg: string) {
    setBusy(true);
    try {
      await api.patchFinding(finding.id, body);
      onUpdated?.();
      toast.success(msg);
      setOpen(false);
    } catch (e) {
      toast.error("Action failed", (e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function feedback(action: "marked_fp" | "confirmed" | "ignored", msg: string) {
    setBusy(true);
    try {
      await api.sendFeedback(finding.id, action);
      onUpdated?.();
      toast.success(msg);
      setOpen(false);
    } catch (e) {
      toast.error("Action failed", (e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Card
        className="cursor-pointer transition-colors hover:bg-muted/40"
        onClick={() => setOpen(true)}
      >
        <CardContent className="flex items-start gap-3 p-4">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <RiskBadge risk={finding.risk_level} />
              <SeverityBadge severity={finding.severity} />
              <Badge className="border-border bg-secondary text-secondary-foreground">{finding.engine}</Badge>
              <NewBadge finding={finding} />
              <ReachabilityBadge metadata={finding.metadata} />
              <LikelyFPBadge p={finding.false_positive_probability} />
              {finding.is_suppressed ? (
                <Badge className="border-border bg-muted text-muted-foreground">suppressed</Badge>
              ) : null}
            </div>
            <p className="mt-2 truncate font-medium">{heading}</p>
            {finding.impact ? (
              <p className="mt-1 line-clamp-2 text-sm text-muted-foreground">{finding.impact}</p>
            ) : null}
            <p className="mt-1 flex items-center gap-1 truncate text-xs text-muted-foreground">
              <FileCode2 className="h-3 w-3" /> {location}
            </p>
          </div>
        </CardContent>
      </Card>

      <Dialog open={open} onClose={() => setOpen(false)} className="max-w-2xl">
        <DialogHeader>
          <div className="flex flex-wrap items-center gap-2">
            <RiskBadge risk={finding.risk_level} />
            <SeverityBadge severity={finding.severity} />
            <Badge className="border-border bg-secondary text-secondary-foreground">{finding.engine}</Badge>
            <EffortBadge effort={finding.estimated_effort} />
          </div>
          <DialogTitle>{heading}</DialogTitle>
        </DialogHeader>

        <div className="max-h-[60vh] space-y-4 overflow-auto text-sm">
          {finding.impact ? (
            <div>
              <p className="mb-1 font-medium">Impact</p>
              <p className="text-muted-foreground">{finding.impact}</p>
            </div>
          ) : null}

          <DetailRow label="Location" value={location} mono copyLabel="file path" />
          <DetailRow label="Rule" value={finding.rule_id} mono copyLabel="rule id" />
          {finding.cwe_id ? <DetailRow label="CWE" value={finding.cwe_id} /> : null}
          {finding.cve_id ? <DetailRow label="CVE" value={finding.cve_id} /> : null}
          {finding.owasp_category ? <DetailRow label="OWASP" value={finding.owasp_category} /> : null}

          <StepsToReproduceSection data={finding.context_metadata} />
          <ReachabilityDetail metadata={finding.metadata} />
          <ContextMetadata data={finding.context_metadata} />

          {finding.remediation_action ? (
            <div>
              <p className="mb-1 flex items-center gap-1 font-medium">
                <Wrench className="h-4 w-4" /> Remediation
              </p>
              <p className="text-muted-foreground">{finding.remediation_action}</p>
              {finding.remediation_details ? (
                <pre className="mt-2 overflow-auto whitespace-pre-wrap rounded-md bg-muted p-3 text-xs">
                  {finding.remediation_details}
                </pre>
              ) : null}
            </div>
          ) : null}

          {finding.description && finding.description !== finding.impact ? (
            <div>
              <p className="mb-1 font-medium">Details</p>
              <p className="whitespace-pre-wrap text-muted-foreground">{finding.description}</p>
            </div>
          ) : null}

          <AIFixSection findingId={finding.id} />
        </div>

        <div className="mt-4 space-y-2 border-t pt-3">
          <p className="text-xs text-muted-foreground">
            <strong className="text-foreground">Mark false positive</strong> = not a real issue (trains the
            local filter). <strong className="text-foreground">Ignore</strong> = a real issue you&apos;re
            accepting for now (hides it, doesn&apos;t train the filter).
          </p>
          <div className="flex flex-wrap justify-end gap-2">
            <Button variant="secondary" size="sm" disabled={busy} onClick={() => feedback("confirmed", "Marked as confirmed")}>
              Confirm
            </Button>
            <Button variant="outline" size="sm" disabled={busy} onClick={() => feedback("marked_fp", "Marked false positive")}>
              Mark false positive
            </Button>
            <Button variant="outline" size="sm" disabled={busy} onClick={() => feedback("ignored", "Finding ignored")}>
              Ignore
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={busy}
              onClick={() => triage({ is_suppressed: !finding.is_suppressed }, finding.is_suppressed ? "Unsuppressed" : "Suppressed")}
            >
              {finding.is_suppressed ? "Unsuppress" : "Suppress"}
            </Button>
          </div>
        </div>
      </Dialog>
    </>
  );
}

const CVSS_LABELS: Record<string, string> = {
  attack_vector: "Attack vector",
  attack_complexity: "Attack complexity",
  privileges_required: "Privileges required",
  user_interaction: "User interaction",
  scope: "Scope",
  confidentiality_impact: "Confidentiality",
  integrity_impact: "Integrity",
  availability_impact: "Availability",
};

/** Steps-of-Reproduction: source → flow → sink, extracted from the taint trace. */
function SoRStep({ node, tag, tagClass }: { node: SoRNode; tag: string; tagClass: string }) {
  return (
    <div className="rounded-md border bg-muted/40 p-2.5">
      <div className="flex items-center gap-2">
        <Badge className={tagClass}>{tag}</Badge>
        {node.line != null ? (
          <span className="flex items-center gap-1 text-xs text-muted-foreground">
            <FileCode2 className="h-3 w-3" /> {node.file.split("/").pop()}:{node.line}
          </span>
        ) : null}
      </div>
      <pre className="mt-1.5 overflow-x-auto whitespace-pre-wrap break-all rounded bg-background/70 px-2 py-1 font-mono text-xs">
        {node.code}
      </pre>
      {node.label ? <p className="mt-1 text-xs text-muted-foreground">{node.label}</p> : null}
    </div>
  );
}

function StepsToReproduceSection({ data }: { data?: Record<string, unknown> }) {
  const sor = data?.steps_to_reproduce as StepsToReproduce | undefined;
  if (!sor || !sor.source || !sor.sink) return null;
  return (
    <div>
      <p className="mb-2 flex items-center gap-1.5 font-medium">
        <Route className="h-4 w-4" /> Steps to reproduce
        <span className="text-xs font-normal text-muted-foreground">(how the tainted data flows)</span>
      </p>
      <div className="space-y-1.5">
        <SoRStep node={sor.source} tag="Source" tagClass="border-blue-500/40 bg-blue-500/15 text-blue-600 dark:text-blue-400" />
        {sor.flow.map((step, i) => (
          <div key={i} className="flex items-center gap-2 pl-2">
            <ArrowDown className="h-3.5 w-3.5 text-muted-foreground" />
            <span className="font-mono text-xs text-muted-foreground">
              {step.code}
              {step.line != null ? <span className="opacity-60"> · L{step.line}</span> : null}
            </span>
          </div>
        ))}
        <div className="flex justify-center">
          <ArrowDown className="h-3.5 w-3.5 text-muted-foreground" />
        </div>
        <SoRStep node={sor.sink} tag="Sink" tagClass="border-red-500/40 bg-red-500/15 text-red-600 dark:text-red-400" />
      </div>
      <div className="mt-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-2.5 text-xs">
        <p className="font-medium text-amber-700 dark:text-amber-400">Why this is exploitable</p>
        <p className="mt-0.5 text-muted-foreground">{sor.why_exploitable}</p>
        {sor.example_input ? (
          <p className="mt-1.5 flex flex-wrap items-center gap-1.5">
            <span className="font-medium">Example trigger:</span>
            <code className="break-all rounded bg-background/70 px-1.5 py-0.5 font-mono">{sor.example_input}</code>
          </p>
        ) : null}
      </div>
    </div>
  );
}

/** Renders engine-specific enrichment (CVSS breakdown, image-size, etc.). */
function ContextMetadata({ data }: { data?: Record<string, unknown> }) {
  if (!data || Object.keys(data).length === 0) return null;

  const cvss = Object.entries(CVSS_LABELS).filter(([k]) => data[k] != null);
  const isImage = data.reduction_pct != null && data.recommended_base != null;

  return (
    <div>
      <p className="mb-1 font-medium">Details</p>
      <div className="space-y-1 text-muted-foreground">
        {data.cvss_score != null ? (
          <DetailRow label="CVSS" value={String(data.cvss_score)} />
        ) : null}
        {cvss.map(([k, label]) => (
          <DetailRow key={k} label={label} value={String(data[k])} />
        ))}
        {isImage ? (
          <>
            <DetailRow label="Current size" value={`~${data.current_mb}MB (${data.base_image})`} />
            <DetailRow
              label="Recommended"
              value={`${data.recommended_base} — ~${data.reduction_pct}% smaller`}
            />
          </>
        ) : null}
      </div>
    </div>
  );
}

function AIFixSection({ findingId }: { findingId: string }) {
  const api = useApi();
  const [busy, setBusy] = useState(false);
  const [suggestion, setSuggestion] = useState<{ suggestion: string; model: string; provider: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function getFix() {
    setBusy(true);
    setErr(null);
    try {
      setSuggestion(await api.suggestFix(findingId));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="border-t pt-3">
      <div className="flex items-center gap-2">
        <Sparkles className="h-4 w-4" />
        <span className="font-medium">AI fix suggestion</span>
        <Button variant="secondary" size="sm" className="ml-auto" disabled={busy} onClick={getFix}>
          {busy ? "Generating…" : "Get AI fix suggestion"}
        </Button>
      </div>
      {err ? <p className="mt-2 text-xs text-destructive">{err}</p> : null}
      {suggestion ? (
        <div className="mt-2 space-y-2">
          <pre className="max-h-64 overflow-auto whitespace-pre-wrap rounded-md bg-muted p-3 text-xs">
            {suggestion.suggestion}
          </pre>
          <p className="text-xs text-muted-foreground">
            Advisory only via {suggestion.provider}/{suggestion.model}. Review and apply manually —
            Aegis never auto-applies changes.
          </p>
        </div>
      ) : null}
    </div>
  );
}

function DetailRow({ label, value, mono, copyLabel }: { label: string; value: string; mono?: boolean; copyLabel?: string }) {
  return (
    <div className="flex items-center gap-3">
      <span className="w-32 shrink-0 font-medium">{label}</span>
      <span className={mono ? "break-all font-mono text-xs" : "break-all text-muted-foreground"}>{value}</span>
      {copyLabel ? <CopyButton value={value} label={copyLabel} /> : null}
    </div>
  );
}
