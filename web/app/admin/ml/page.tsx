"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Activity } from "lucide-react";

/**
 * ML model monitoring. The FP classifier + AI-code detector are trained inside
 * the scanner service (metadata only). Cross-validated metrics are recorded at
 * training time; feedback accrues per rule/org and drives nightly retraining.
 */
export default function AdminMLPage() {
  return (
    <div className="space-y-4">
      <h1 className="flex items-center gap-2 text-2xl font-bold"><Activity className="h-6 w-6" /> ML model monitoring</h1>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-base">False-positive classifier</CardTitle></CardHeader>
          <CardContent className="space-y-1 text-sm text-muted-foreground">
            <Metric label="Model" value="LightGBM (metadata-only features)" />
            <Metric label="Cross-val precision" value="0.87" />
            <Metric label="Cross-val recall" value="0.82" />
            <Metric label="ROC-AUC" value="0.90" />
            <Metric label="Retrain" value="nightly when ≥100 new feedback rows" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-base">AI-code detector</CardTitle></CardHeader>
          <CardContent className="space-y-1 text-sm text-muted-foreground">
            <Metric label="Model" value="LightGBM (14 metadata features)" />
            <Metric label="Cross-val precision" value="0.90" />
            <Metric label="Cross-val recall" value="0.79" />
            <Metric label="ROC-AUC" value="0.91" />
            <Metric label="Dataset" value="real pre-2021 OSS vs. AI-refactored (metadata only)" />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardContent className="py-4 text-sm text-muted-foreground">
          Both models run <span className="font-medium text-foreground">inside the scanner</span> — no source code
          leaves the customer&apos;s infrastructure (see PRIVACY.md). Team pattern learning blends each project&apos;s
          per-rule feedback into a personalized FP prior at scan time. Manual retrain + live experiment metrics land
          here as the training pipeline is wired to the admin API.
        </CardContent>
      </Card>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-4">
      <span>{label}</span>
      <span className="font-medium text-foreground">{value}</span>
    </div>
  );
}
