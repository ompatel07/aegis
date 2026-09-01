// B1 parity (P4b): the client comparator must reproduce the exact order the API SQL
// returns, or page 2 shows a finding that belonged on page 1 — a silent bug. This
// asserts the client side against the CANONICAL fixture + order; the Go side
// (services/api/internal/repository/finding_order_test.go) asserts the SQL keys
// against the same fixture. Both reference the same spec, so a drift on either side
// fails its test. Run: node --test --experimental-strip-types lib/*.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { compareFindings, type OrderableFinding } from "./findingOrder.ts";

// Canonical fixture — shared with the Go parity test. Scrambled input; each id
// encodes its ordering-relevant fields.
const FIXTURE: (OrderableFinding & { id: string })[] = [
  { id: "low", severity: "low", fingerprint: "f-low" },
  { id: "high-fp", severity: "high", false_positive_probability: 0.9, fingerprint: "f-hf" },
  { id: "kev-crit", severity: "critical", metadata: { kev: true }, fingerprint: "f-kev" },
  { id: "high", severity: "high", fingerprint: "f-h" },
  { id: "reach-crit", severity: "critical", metadata: { reachable: true }, fingerprint: "f-rc" },
  { id: "high-new", severity: "high", is_new: true, fingerprint: "f-hn" },
  { id: "crit", severity: "critical", fingerprint: "f-c" },
  { id: "reach-high", severity: "high", metadata: { reachable: true }, fingerprint: "f-rh" },
];

// KEV → severity → reachable → new → FP-down → fingerprint.
const CANONICAL_ORDER = [
  "kev-crit",   // KEV outranks everything
  "reach-crit", // critical, reachable
  "crit",       // critical
  "reach-high", // high, reachable
  "high-new",   // high, new
  "high",       // high
  "high-fp",    // high, likely-FP pushed down
  "low",        // low last
];

test("client comparator matches the canonical (server) order", () => {
  const sorted = [...FIXTURE].sort(compareFindings).map((f) => f.id);
  assert.deepEqual(sorted, CANONICAL_ORDER);
});

test("ordering is deterministic (stable across a re-sort)", () => {
  const once = [...FIXTURE].sort(compareFindings).map((f) => f.id);
  const twice = [...FIXTURE].sort(compareFindings).sort(compareFindings).map((f) => f.id);
  assert.deepEqual(once, twice);
});
