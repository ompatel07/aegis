"use client";

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorState } from "@/components/ui/error-state";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { useApi } from "@/lib/use-api";
import { useToast } from "@/lib/use-toast";
import type { Pillar, Severity } from "@/lib/types";
import { FindingCard } from "./FindingCard";
import { CheckCheck, ShieldCheck } from "lucide-react";

const SEVERITIES: (Severity | "all")[] = ["all", "critical", "high", "medium", "low", "info"];
const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

type SortKey = "severity" | "file" | "rule" | "fp";

function Pill({ active, onClick, children, className }: { active: boolean; onClick: () => void; children: React.ReactNode; className?: string }) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "rounded-full border px-3 py-1 text-xs font-medium capitalize transition-colors",
        active ? "border-primary bg-primary text-primary-foreground" : "border-border bg-background text-muted-foreground hover:text-foreground",
        className,
      )}
    >
      {children}
    </button>
  );
}

// Findings list scoped to a scan + pillar, with pill filters, sorting, and bulk actions.
export function FindingsList({ scanId, pillar }: { scanId: string; pillar: Pillar }) {
  const api = useApi();
  const toast = useToast();
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [engine, setEngine] = useState<string>("all");
  const [aiOnly, setAiOnly] = useState(false);
  const [newOnly, setNewOnly] = useState(false);
  const [hideSuppressed, setHideSuppressed] = useState(true);
  const [sort, setSort] = useState<SortKey>("severity");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkBusy, setBulkBusy] = useState(false);

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["findings", scanId, pillar],
    queryFn: () => api.listFindings(scanId, { pillar, per_page: 200 }),
  });

  const all = data?.data ?? [];
  const engines = useMemo(() => Array.from(new Set(all.map((f) => f.engine))).sort(), [all]);

  const shown = useMemo(() => {
    let list = all.filter((f) => {
      if (severity !== "all" && f.severity !== severity) return false;
      if (engine !== "all" && f.engine !== engine) return false;
      if (aiOnly && !f.in_ai_generated_code) return false;
      if (newOnly && !f.is_new) return false;
      if (hideSuppressed && f.is_suppressed) return false;
      return true;
    });
    list = [...list].sort((a, b) => {
      switch (sort) {
        case "file": return (a.file_path + a.line_start).localeCompare(b.file_path + b.line_start);
        case "rule": return a.rule_id.localeCompare(b.rule_id);
        case "fp": return (b.false_positive_probability ?? 0) - (a.false_positive_probability ?? 0);
        default: return SEV_RANK[a.severity] - SEV_RANK[b.severity];
      }
    });
    return list;
  }, [all, severity, engine, aiOnly, newOnly, hideSuppressed, sort]);

  function toggleSelect(id: string) {
    setSelected((s) => {
      const n = new Set(s);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });
  }
  const allSelected = shown.length > 0 && shown.every((f) => selected.has(f.id));

  async function bulk(kind: "fp" | "suppress") {
    const ids = shown.filter((f) => selected.has(f.id)).map((f) => f.id);
    if (ids.length === 0) return;
    setBulkBusy(true);
    try {
      await Promise.all(
        ids.map((id) =>
          kind === "fp" ? api.sendFeedback(id, "marked_fp") : api.patchFinding(id, { is_suppressed: true }),
        ),
      );
      toast.success(kind === "fp" ? `${ids.length} marked false positive` : `${ids.length} suppressed`);
      setSelected(new Set());
      refetch();
    } catch (e) {
      toast.error("Bulk action failed", (e as Error).message);
    } finally {
      setBulkBusy(false);
    }
  }

  if (isLoading) return <div className="space-y-2">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-20 w-full" />)}</div>;
  if (isError) return <ErrorState message={(error as Error).message} onRetry={() => refetch()} />;

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="space-y-2">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="mr-1 text-xs font-medium text-muted-foreground">Severity</span>
          {SEVERITIES.map((s) => <Pill key={s} active={severity === s} onClick={() => setSeverity(s)}>{s}</Pill>)}
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {engines.length > 1 ? (
            <>
              <span className="mr-1 text-xs font-medium text-muted-foreground">Engine</span>
              <Pill active={engine === "all"} onClick={() => setEngine("all")}>all</Pill>
              {engines.map((e) => <Pill key={e} active={engine === e} onClick={() => setEngine(e)}>{e}</Pill>)}
            </>
          ) : null}
          <span className="mx-1 h-4 w-px bg-border" />
          <Pill active={aiOnly} onClick={() => setAiOnly((v) => !v)} className="border-violet-400/40">AI code</Pill>
          <Pill active={newOnly} onClick={() => setNewOnly((v) => !v)} className="border-amber-400/40">new</Pill>
          <Pill active={!hideSuppressed} onClick={() => setHideSuppressed((v) => !v)}>show suppressed</Pill>
          <span className="mx-1 h-4 w-px bg-border" />
          <label className="flex items-center gap-1 text-xs text-muted-foreground">
            sort
            <select value={sort} onChange={(e) => setSort(e.target.value as SortKey)} className="rounded-md border border-input bg-background px-2 py-1 text-xs">
              <option value="severity">severity</option>
              <option value="file">file</option>
              <option value="rule">rule</option>
              <option value="fp">false-positive likelihood</option>
            </select>
          </label>
        </div>
      </div>

      {/* Bulk action bar */}
      {selected.size > 0 ? (
        <div className="flex flex-wrap items-center gap-2 rounded-md border bg-secondary/50 p-2 text-sm">
          <span className="font-medium">{selected.size} selected</span>
          <Button size="sm" variant="outline" disabled={bulkBusy} onClick={() => bulk("fp")}>Mark false positive</Button>
          <Button size="sm" variant="outline" disabled={bulkBusy} onClick={() => bulk("suppress")}>Suppress</Button>
          <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>Clear</Button>
        </div>
      ) : null}

      {shown.length === 0 ? (
        <EmptyState
          icon={ShieldCheck}
          title={`No ${pillar} findings match`}
          description={all.length === 0 ? "This scan surfaced nothing in this pillar — nice." : "No findings match the current filters."}
        />
      ) : (
        <>
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Showing {shown.length}{all.length > shown.length ? ` of ${all.length}` : ""}{data && data.meta.total > all.length ? ` (${data.meta.total} total)` : ""}</span>
            <button className="flex items-center gap-1 hover:text-foreground" onClick={() => setSelected(allSelected ? new Set() : new Set(shown.map((f) => f.id)))}>
              <CheckCheck className="h-3.5 w-3.5" /> {allSelected ? "Deselect all" : "Select all"}
            </button>
          </div>
          <div className="space-y-2">
            {shown.map((f) => (
              <div key={f.id} className="flex items-start gap-2">
                <input
                  type="checkbox"
                  aria-label={`Select finding ${f.rule_id}`}
                  checked={selected.has(f.id)}
                  onChange={() => toggleSelect(f.id)}
                  className="mt-4 h-4 w-4 shrink-0 rounded border-input"
                />
                <div className="min-w-0 flex-1">
                  <FindingCard finding={f} onUpdated={refetch} />
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
