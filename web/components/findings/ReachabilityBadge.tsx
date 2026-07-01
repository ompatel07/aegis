import { Badge } from "@/components/ui/badge";
import { Zap, PackageX } from "lucide-react";

type Meta = Record<string, unknown> | undefined;

function hasReachability(metadata: Meta): metadata is Record<string, unknown> {
  return !!metadata && ("reachable" in metadata || "reachability_ecosystem" in metadata);
}

/**
 * Compact reachability signal for a dependency (SCA) finding.
 * Reachable = the vulnerable package is imported/used in first-party code
 * (higher priority); Not reachable = present but unused (de-prioritized).
 * Renders nothing for non-dependency findings or when reachability is unknown.
 */
export function ReachabilityBadge({ metadata }: { metadata: Meta }) {
  if (!hasReachability(metadata)) return null;
  const reachable = metadata.reachable as boolean | null | undefined;
  const isDirect = metadata.is_direct as boolean | null | undefined;
  const fileCount = metadata.reachable_file_count as number | null | undefined;

  if (reachable === true) {
    return (
      <Badge className="border-amber-500/30 bg-amber-500/15 text-amber-600 dark:text-amber-400">
        <Zap className="mr-1 h-3 w-3" />
        {isDirect ? "Reachable · direct dep" : "Reachable"}
        {typeof fileCount === "number" && fileCount > 0 ? ` (${fileCount})` : ""}
      </Badge>
    );
  }
  if (reachable === false) {
    return (
      <Badge className="border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
        <PackageX className="mr-1 h-3 w-3" />
        Not reachable
      </Badge>
    );
  }
  return null; // undetermined
}

/** Expanded reachability details for the finding dialog. */
export function ReachabilityDetail({ metadata }: { metadata: Meta }) {
  if (!hasReachability(metadata)) return null;
  const reachable = metadata.reachable as boolean | null | undefined;
  const isDirect = metadata.is_direct as boolean | null | undefined;
  const files = (metadata.reachable_files as string[] | undefined) ?? [];
  const count = metadata.reachable_file_count as number | null | undefined;
  const fmt = (v: boolean | null | undefined) =>
    v === true ? "Yes" : v === false ? "No" : "Unknown";

  return (
    <div>
      <p className="mb-1 font-medium">Reachability</p>
      <div className="space-y-1 text-sm text-muted-foreground">
        <div className="flex gap-3">
          <span className="w-44 shrink-0">Imported / used in code</span>
          <span>{fmt(reachable)}</span>
        </div>
        <div className="flex gap-3">
          <span className="w-44 shrink-0">Direct dependency</span>
          <span>{fmt(isDirect)}</span>
        </div>
        {files.length > 0 ? (
          <div>
            <p className="mt-2">
              Reachable from
              {typeof count === "number" && count > files.length
                ? ` ${count} files, e.g.`
                : ""}
              :
            </p>
            <ul className="mt-1 list-inside list-disc font-mono text-xs">
              {files.slice(0, 10).map((f) => (
                <li key={f}>{f}</li>
              ))}
            </ul>
          </div>
        ) : null}
      </div>
    </div>
  );
}
