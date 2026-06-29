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
import type { Scan } from "@/lib/types";

// Plots the three pillar scores across a project's scan history (oldest → newest).
export function TrendChart({ scans }: { scans: Scan[] }) {
  const data = [...scans]
    .filter((s) => s.status === "completed")
    .reverse()
    .map((s, i) => ({
      name: `#${i + 1}`,
      Overall: s.overall_score ?? null,
      Security: s.security_score ?? null,
      Quality: s.quality_score ?? null,
      Deployment: s.deployment_score ?? null,
    }));

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
              <Line type="monotone" dataKey="Deployment" stroke="#d97706" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
