"use client";

import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { overallState } from "@/lib/display";
import type { Scan } from "@/lib/types";

// Plots the pillar scores across a project's scan history (oldest → newest). Aegis
// is a two-pillar product (Security + Code Quality); the Deployment line is drawn
// only if any scan in the history measured it (CI mode).
export function TrendChart({ scans }: { scans: Scan[] }) {
  // Only a FULLY-measured overall is comparable across scans. A degraded or partial
  // overall (computed from a subset of pillars — a missing engine inflates the score)
  // is NOT a comparable point, so it is excluded from the plotted line entirely, not
  // just captioned (A4 + follow-up). The DATA matches the note.
  const data = [...scans]
    .filter((s) => s.status === "completed" && overallState(s) === "full")
    .reverse()
    .map((s, i) => ({
      name: `#${i + 1}`,
      Overall: s.overall_score ?? null,
      Security: s.security_score ?? null,
      Quality: s.quality_score ?? null,
      Deployment: s.deployment_score ?? null,
    }));
  const showDeployment = data.some((d) => d.Deployment != null);
  const excludedCount = scans.filter((s) => s.status === "completed" && overallState(s) !== "full").length;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Score trend</CardTitle>
      </CardHeader>
      <CardContent>
        {data.length === 0 ? (
          <p className="py-12 text-center text-sm text-muted-foreground">
            No completed scans yet — run a scan to see trends.
          </p>
        ) : (
          <ResponsiveContainer width="100%" height={280}>
            <LineChart data={data} margin={{ top: 8, right: 16, left: -16, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
              <XAxis dataKey="name" fontSize={12} />
              <YAxis domain={[0, 100]} fontSize={12} />
              <Tooltip />
              <Line type="monotone" dataKey="Overall" stroke="#2563eb" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="Security" stroke="#dc2626" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="Quality" stroke="#16a34a" strokeWidth={2} dot={false} />
              {showDeployment ? (
                <Line type="monotone" dataKey="Deployment" stroke="#d97706" strokeWidth={2} dot={false} />
              ) : null}
            </LineChart>
          </ResponsiveContainer>
        )}
        {excludedCount > 0 ? (
          <p className="mt-2 text-xs text-amber-700 dark:text-amber-500">
            ⚠ {excludedCount} scan{excludedCount === 1 ? " is" : "s are"} excluded from this trend
            (degraded or partially-measured — not comparable to a full scan).
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}
