"use client";

import { useEffect, useState } from "react";
import { useSession } from "next-auth/react";

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost/api/v1";

// Ordered pipeline stages with human labels for the onboarding progress view.
export const STAGE_STEPS: { stage: string; label: string }[] = [
  { stage: "cloning", label: "Cloning repository" },
  { stage: "detecting", label: "Detecting languages & project type" },
  { stage: "scanning", label: "Running SAST, SCA, secrets, quality & deployment" },
  { stage: "finalizing", label: "Scoring & finalizing" },
  { stage: "completed", label: "Done" },
];

export function stageIndex(stage: string | null): number {
  if (!stage) return -1;
  const i = STAGE_STEPS.findIndex((s) => s.stage === stage);
  return i;
}

/**
 * Subscribes to a scan's live stage over Server-Sent Events (real-time push, not
 * polling). Returns the current stage. Falls back silently if the stream drops;
 * the scan page's react-query poll still resolves the final state.
 */
export function useScanProgress(scanId: string, active: boolean): string | null {
  const { data: session } = useSession();
  const token = session?.accessToken;
  const [stage, setStage] = useState<string | null>(null);

  useEffect(() => {
    if (!active || !token || !scanId) return;
    const url = `${BASE_URL}/scans/${scanId}/progress?token=${encodeURIComponent(token)}`;
    const es = new EventSource(url);
    es.addEventListener("stage", (e) => {
      try {
        const data = JSON.parse((e as MessageEvent).data);
        if (data.stage) setStage(data.stage);
        if (data.stage === "completed" || data.stage === "failed") es.close();
      } catch {
        /* ignore malformed frames */
      }
    });
    es.onerror = () => es.close();
    return () => es.close();
  }, [scanId, token, active]);

  return stage;
}
