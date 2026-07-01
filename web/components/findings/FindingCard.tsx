"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { SeverityBadge } from "./SeverityBadge";
import { ReachabilityBadge, ReachabilityDetail } from "./ReachabilityBadge";
import { useApi } from "@/lib/use-api";
import type { Finding } from "@/lib/types";
import { FileCode2, ShieldAlert } from "lucide-react";

export function FindingCard({ finding, onUpdated }: { finding: Finding; onUpdated?: () => void }) {
  const api = useApi();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  const location = finding.line_start
    ? `${finding.file_path}:${finding.line_start}`
    : finding.file_path;

  async function triage(body: { is_false_positive?: boolean; is_suppressed?: boolean }) {
    setBusy(true);
    try {
      await api.patchFinding(finding.id, body);
      onUpdated?.();
      setOpen(false);
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
              <SeverityBadge severity={finding.severity} />
              <Badge className="border-border bg-secondary text-secondary-foreground">{finding.engine}</Badge>
              <ReachabilityBadge metadata={finding.metadata} />
              {finding.is_suppressed ? (
                <Badge className="border-border bg-muted text-muted-foreground">suppressed</Badge>
              ) : null}
            </div>
            <p className="mt-2 truncate font-medium">{finding.title}</p>
            <p className="mt-1 flex items-center gap-1 truncate text-xs text-muted-foreground">
              <FileCode2 className="h-3 w-3" /> {location}
            </p>
          </div>
        </CardContent>
      </Card>

      <Dialog open={open} onClose={() => setOpen(false)} className="max-w-2xl">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <Badge className="border-border bg-secondary text-secondary-foreground">{finding.engine}</Badge>
          </div>
          <DialogTitle>{finding.title}</DialogTitle>
        </DialogHeader>

        <div className="max-h-[60vh] space-y-4 overflow-auto text-sm">
          <DetailRow label="Location" value={location} mono />
          <DetailRow label="Rule" value={finding.rule_id} mono />
          {finding.cwe_id ? <DetailRow label="CWE" value={finding.cwe_id} /> : null}
          {finding.cve_id ? <DetailRow label="CVE" value={finding.cve_id} /> : null}
          {finding.owasp_category ? <DetailRow label="OWASP" value={finding.owasp_category} /> : null}

          <ReachabilityDetail metadata={finding.metadata} />

          {finding.description ? (
            <div>
              <p className="mb-1 font-medium">Description</p>
              <p className="whitespace-pre-wrap text-muted-foreground">{finding.description}</p>
            </div>
          ) : null}

          {finding.fix_suggestion ? (
            <div>
              <p className="mb-1 font-medium">Suggested fix</p>
              <pre className="overflow-auto rounded-md bg-muted p-3 text-xs">{finding.fix_suggestion}</pre>
            </div>
          ) : null}
        </div>

        <div className="mt-4 flex justify-end gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={busy}
            onClick={() => triage({ is_false_positive: !finding.is_false_positive })}
          >
            {finding.is_false_positive ? "Unmark false positive" : "Mark false positive"}
          </Button>
          <Button
            variant="secondary"
            size="sm"
            disabled={busy}
            onClick={() => triage({ is_suppressed: !finding.is_suppressed })}
          >
            {finding.is_suppressed ? "Unsuppress" : "Suppress"}
          </Button>
        </div>
      </Dialog>
    </>
  );
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex gap-3">
      <span className="w-24 shrink-0 font-medium">{label}</span>
      <span className={mono ? "break-all font-mono text-xs" : "break-all text-muted-foreground"}>{value}</span>
    </div>
  );
}
