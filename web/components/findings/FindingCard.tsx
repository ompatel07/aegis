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
import { ArrowDown, Check, Clock, Copy, FileCode2, Package, ShieldAlert, Sparkles, Wrench, Route } from "lucide-react";

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

function LikelyFPBadge({ p, severity, kev }: { p?: number; severity?: string; kev?: boolean }) {
  if (p == null || p <= 0.5) return null;
  // Floor: never badge a critical-severity or actively-exploited (CISA-KEV)
  // finding as a likely false positive, whatever the ML score. The score still
  // exists internally (sorting) — only the badge is suppressed here.
  if (severity === "critical" || kev) return null;
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

/** Marks findings that live in bundled/vendored third-party code (not the user's
 * own app code) so they read as secondary. Renders nothing for app-code findings. */
function OwnershipBadge({ metadata }: { metadata?: Record<string, unknown> }) {
  if ((metadata?.code_ownership as string | undefined) !== "third_party") return null;
  const reason = metadata?.ownership_reason as string | undefined;
  return (
    <Badge
      className="border-slate-400/40 bg-slate-400/15 text-slate-500"
      title={reason ? `Third-party / bundled code — ${reason}` : "Third-party / bundled code (not your app code)"}
    >
      <Package className="mr-1 h-3 w-3" />
      third-party
    </Badge>
  );
}

// CISA KEV — a real-world exploit campaign is using this vuln. The strongest triage
// signal; it already sorts first and suppresses the likely-FP badge, but had no
// visible marker until now (P4a).
function KEVBadge({ metadata }: { metadata?: Record<string, unknown> }) {
  if (metadata?.kev !== true) return null;
  return (
    <Badge
      className="border-red-600/50 bg-red-600/15 text-red-700 dark:text-red-400"
      title="CISA KEV — a real-world exploit campaign is actively using this vulnerability"
    >
      <ShieldAlert className="mr-1 h-3 w-3" /> actively exploited
    </Badge>
  );
}

const ISSUE_TYPE: Record<string, { label: string; cls: string }> = {
  bug: { label: "bug", cls: "border-red-500/40 bg-red-500/15 text-red-600 dark:text-red-400" },
  vulnerability: { label: "vulnerability", cls: "border-orange-500/40 bg-orange-500/15 text-orange-600 dark:text-orange-400" },
  code_smell: { label: "code smell", cls: "border-slate-400/40 bg-slate-400/15 text-slate-500" },
};
function IssueTypeBadge({ issueType }: { issueType?: string }) {
  const m = issueType ? ISSUE_TYPE[issueType] : undefined;
  if (!m) return null;
  return <Badge className={m.cls}>{m.label}</Badge>;
}

const SECRET_CTX: Record<string, string> = {
  "test-fixture": "test fixture",
  placeholder: "placeholder",
  expired: "expired JWT",
  documentation: "documentation",
  "live-format": "live-format key",
};
// Explains WHY a secret finding is down-ranked (or why it is NOT — live-format).
function SecretContextBadge({ metadata }: { metadata?: Record<string, unknown> }) {
  const ctx = metadata?.secret_context as string | undefined;
  if (!ctx) return null;
  const reason = metadata?.secret_context_reason as string | undefined;
  const live = ctx === "live-format";
  return (
    <Badge
      className={live ? "border-red-500/40 bg-red-500/15 text-red-600 dark:text-red-400" : "border-slate-400/40 bg-slate-400/15 text-slate-500"}
      title={reason ? `Why this severity: ${reason}` : SECRET_CTX[ctx] ?? ctx}
    >
      {SECRET_CTX[ctx] ?? ctx}
    </Badge>
  );
}

// Lifecycle vs the project's prior scans. "new" has its own badge; "existing" is the
// default and shows nothing — only the notable transitions (reopened/resolved) badge.
function LifecycleBadge({ status }: { status?: string }) {
  if (!status || status === "new" || status === "existing") return null;
  return (
    <Badge className="border-purple-400/40 bg-purple-400/15 text-purple-600 dark:text-purple-400" title="Lifecycle vs previous scans of this project">
      {status}
    </Badge>
  );
}

// Line-numbered snippet. The value is already redacted at the scanner egress
// chokepoint (secrets → masked), so this path renders it verbatim and never
// re-derives a plaintext secret.
function CodeSnippet({ code, startLine }: { code?: string; startLine?: number }) {
  if (!code) return null;
  const lines = code.replace(/\n$/, "").split("\n");
  return (
    <div>
      <p className="mb-1 flex items-center gap-1 font-medium">
        <FileCode2 className="h-4 w-4" /> Code
      </p>
      <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs leading-relaxed">
        <code>
          {lines.map((ln, i) => (
            <div key={i} className="flex">
              <span className="mr-3 w-8 shrink-0 select-none text-right text-muted-foreground/50">
                {startLine != null ? startLine + i : i + 1}
              </span>
              <span className="whitespace-pre">{ln || " "}</span>
            </div>
          ))}
        </code>
      </pre>
    </div>
  );
}

// SCA intelligence: EPSS exploit-probability + the transitive dependency path (how a
// bundled CVE reached the project).
function ScaIntel({ metadata }: { metadata?: Record<string, unknown> }) {
  const epss = metadata?.epss_score as number | undefined;
  const epssPct = metadata?.epss_percentile as number | undefined;
  const depPath = metadata?.dependency_path as string[] | undefined;
  const introduced = metadata?.introduced_through as string | undefined;
  const transitive = metadata?.is_transitive === true;
  if (epss == null && (!depPath || depPath.length === 0) && !introduced) return null;
  return (
    <div className="space-y-2">
      {epss != null ? (
        <DetailRow
          label="EPSS"
          value={`${(epss * 100).toFixed(1)}% exploit probability (30-day)${epssPct != null ? ` · ${Math.round(epssPct * 100)}th pct` : ""}`}
        />
      ) : null}
      {introduced ? (
        <DetailRow label={transitive ? "Transitive via" : "Introduced via"} value={introduced} />
      ) : null}
      {depPath && depPath.length > 0 ? (
        <div className="flex items-start gap-3">
          <span className="w-32 shrink-0 font-medium">Dependency path</span>
          <span className="flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
            {depPath.map((p, i) => (
              <span key={i} className="flex items-center gap-1">
                {i > 0 ? <span className="opacity-50">›</span> : null}
                <code className="rounded bg-muted px-1 py-0.5">{p}</code>
              </span>
            ))}
          </span>
        </div>
      ) : null}
    </div>
  );
}

// Explains, in the dialog, WHY a secret finding sits at its severity — the S1/P1
// down-rank reason, or that it is a confirmed live-format credential.
function SecretContextDetail({ metadata }: { metadata?: Record<string, unknown> }) {
  const ctx = metadata?.secret_context as string | undefined;
  if (!ctx) return null;
  const reason = metadata?.secret_context_reason as string | undefined;
  const live = ctx === "live-format";
  return (
    <div className={`rounded-md border p-2.5 text-xs ${live ? "border-red-500/30 bg-red-500/10" : "border-border bg-muted/40"}`}>
      <p className="font-medium">
        {live ? "Confirmed live-format credential — not down-ranked" : `Down-ranked: ${SECRET_CTX[ctx] ?? ctx}`}
      </p>
      {reason ? <p className="mt-0.5 text-muted-foreground">{reason}</p> : null}
    </div>
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
              <KEVBadge metadata={finding.metadata} />
              <RiskBadge risk={finding.risk_level} />
              <SeverityBadge severity={finding.severity} />
              <IssueTypeBadge issueType={finding.issue_type} />
              <Badge className="border-border bg-secondary text-secondary-foreground">{finding.engine}</Badge>
              <NewBadge finding={finding} />
              <LifecycleBadge status={finding.lifecycle_status} />
              <OwnershipBadge metadata={finding.metadata} />
              <ReachabilityBadge metadata={finding.metadata} />
              <SecretContextBadge metadata={finding.metadata} />
              <LikelyFPBadge
                p={finding.false_positive_probability}
                severity={finding.severity}
                kev={finding.metadata?.kev === true}
              />
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
            <KEVBadge metadata={finding.metadata} />
            <RiskBadge risk={finding.risk_level} />
            <SeverityBadge severity={finding.severity} />
            <IssueTypeBadge issueType={finding.issue_type} />
            <Badge className="border-border bg-secondary text-secondary-foreground">{finding.engine}</Badge>
            <LifecycleBadge status={finding.lifecycle_status} />
            <OwnershipBadge metadata={finding.metadata} />
            <SecretContextBadge metadata={finding.metadata} />
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

          <CodeSnippet code={finding.code_snippet} startLine={finding.snippet_start_line} />
          <SecretContextDetail metadata={finding.metadata} />
          <StepsToReproduceSection data={finding.context_metadata} />
          <ReachabilityDetail metadata={finding.metadata} />
          <ScaIntel metadata={finding.metadata} />
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
