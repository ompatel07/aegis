"use client";

import { useQuery } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { CheckCircle2, XCircle } from "lucide-react";

/** Shows a scan's evaluation against the project's active quality-gate policy. */
export function PolicyResultCard({ scanId }: { scanId: string }) {
  const api = useApi();
  const { data } = useQuery({ queryKey: ["policy-eval", scanId], queryFn: () => api.evaluatePolicy(scanId) });

  if (!data || !data.has_policy) return null;

  return (
    <Card className={data.passed ? "border-emerald-400/40" : "border-destructive/50"}>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          {data.passed ? (
            <><CheckCircle2 className="h-5 w-5 text-emerald-500" /> Quality gate passed</>
          ) : (
            <><XCircle className="h-5 w-5 text-destructive" /> Quality gate failed</>
          )}
          <Badge className="border-border bg-secondary text-secondary-foreground">{data.policy_name}</Badge>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ul className="space-y-1.5 text-sm">
          {data.checks.map((c) => (
            <li key={c.rule} className="flex items-start gap-2">
              {c.passed ? (
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" />
              ) : (
                <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
              )}
              <span className={c.passed ? "text-muted-foreground" : "font-medium text-foreground"}>
                {c.detail}
              </span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
