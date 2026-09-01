// The default finding triage order, extracted so it is testable and so the parity
// test can assert it matches the Go SQL ordering in the finding repository
// (kevFirstSQL, severityRankSQL, reachableFirstSQL, newFirstSQL, fp, fingerprint).
// If these two ever drift, page 2 could show a finding that belonged on page 1 — a
// silent bug. Keep this in lockstep with services/api/internal/repository/finding.go.

export interface OrderableFinding {
  metadata?: Record<string, unknown> | null;
  severity: string;
  is_new?: boolean;
  false_positive_probability?: number;
  fingerprint?: string;
}

export const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export const isKEV = (f: OrderableFinding) => f.metadata?.kev === true;
export const isReachable = (f: OrderableFinding) => f.metadata?.reachable === true;

// Returns <0 if a sorts before b. Order (each tier breaks ties into the next):
// KEV → severity band → reachable → new-since-last-scan → likely-FP down → stable
// fingerprint. Deterministic: identical scans order identically.
export function compareFindings(a: OrderableFinding, b: OrderableFinding): number {
  if (isKEV(a) !== isKEV(b)) return isKEV(a) ? -1 : 1;
  const sa = SEV_RANK[a.severity] ?? 99;
  const sb = SEV_RANK[b.severity] ?? 99;
  if (sa !== sb) return sa - sb;
  if (isReachable(a) !== isReachable(b)) return isReachable(a) ? -1 : 1;
  if (!!a.is_new !== !!b.is_new) return a.is_new ? -1 : 1;
  const fp = (a.false_positive_probability ?? 0) - (b.false_positive_probability ?? 0);
  if (fp !== 0) return fp;
  return (a.fingerprint ?? "").localeCompare(b.fingerprint ?? "");
}
