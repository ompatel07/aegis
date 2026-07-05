"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { useCurrentOrg } from "@/lib/use-current-org";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ScanProgress } from "@/components/dashboard/ScanProgress";
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import { Github, Gitlab, Rocket, CheckCircle2, ArrowRight } from "lucide-react";

type Step = "welcome" | "connect" | "scanning" | "results";

export default function OnboardingPage() {
  const api = useApi();
  const router = useRouter();
  const [currentOrg] = useCurrentOrg();
  const [step, setStep] = useState<Step>("welcome");
  const [repoUrl, setRepoUrl] = useState("");
  const [projectId, setProjectId] = useState<string | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const start = useMutation({
    mutationFn: async () => {
      const name = repoUrl.split("/").slice(-1)[0]?.replace(/\.git$/, "") || "first-project";
      const project = await api.createProject({
        name, repo_url: repoUrl, repo_type: "github", default_branch: "main",
        organization_id: currentOrg || undefined,
      });
      const scan = await api.triggerScan(project.id);
      return { project, scan };
    },
    onSuccess: ({ project, scan }) => {
      setProjectId(project.id);
      setScanId(scan.id);
      setStep("scanning");
      setErr(null);
    },
    onError: (e: Error) => setErr(e.message),
  });

  // While scanning, poll the scan until it completes, then reveal findings.
  const scanQ = useQuery({
    queryKey: ["onboard-scan", scanId],
    queryFn: () => api.getScan(scanId!),
    enabled: !!scanId && step === "scanning",
    refetchInterval: (q) => {
      const s = q.state.data?.scan.status;
      return s === "completed" || s === "failed" ? false : 3000;
    },
  });
  const done = scanQ.data?.scan.status === "completed";
  useEffect(() => {
    if (done && step === "scanning") setStep("results");
  }, [done, step]);

  const findingsQ = useQuery({
    queryKey: ["onboard-findings", scanId],
    queryFn: () => api.listFindings(scanId!, { per_page: 3 }),
    enabled: step === "results" && !!scanId,
  });

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      {step === "welcome" && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-2xl">
              <Rocket className="h-6 w-6 text-primary" /> Welcome to Aegis
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-muted-foreground">
              Let&apos;s scan your first repository. Aegis checks quality, security, and deployment —
              with special awareness of AI-generated code. This takes about 2 minutes.
            </p>
            <Button onClick={() => setStep("connect")}>
              Get started <ArrowRight className="ml-1 h-4 w-4" />
            </Button>
          </CardContent>
        </Card>
      )}

      {step === "connect" && (
        <Card>
          <CardHeader><CardTitle>Connect a repository</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-3 gap-2">
              <ProviderButton icon={<Github className="h-5 w-5" />} label="GitHub" active />
              <ProviderButton icon={<Gitlab className="h-5 w-5" />} label="GitLab" />
              <ProviderButton icon={<span className="text-lg">🪣</span>} label="Bitbucket" />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium">Repository URL</label>
              <Input placeholder="https://github.com/OWASP/NodeGoat.git" value={repoUrl} onChange={(e) => setRepoUrl(e.target.value)} />
              <p className="mt-1 text-xs text-muted-foreground">
                Try a repo with real code — Aegis gets better the more it sees.
              </p>
            </div>
            {err ? <p className="text-sm text-destructive">{err}</p> : null}
            <div className="flex justify-between">
              <Button variant="outline" onClick={() => setStep("welcome")}>Back</Button>
              <Button disabled={!repoUrl || start.isPending} onClick={() => start.mutate()}>
                {start.isPending ? "Starting…" : "Start first scan"}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {step === "scanning" && scanId && (
        <Card>
          <CardHeader><CardTitle>Scanning your repository…</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <ScanProgress scanId={scanId} active={!done} />
            <p className="text-xs text-muted-foreground">Live updates stream as each stage completes.</p>
          </CardContent>
        </Card>
      )}

      {step === "results" && (
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <CheckCircle2 className="h-5 w-5 text-emerald-500" /> First scan complete
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {findingsQ.data && findingsQ.data.data.length > 0 ? (
                <>
                  <p className="text-sm text-muted-foreground">Top findings by severity:</p>
                  {findingsQ.data.data.map((f) => (
                    <div key={f.id} className="flex items-start gap-3 rounded-md border p-3">
                      <SeverityBadge severity={f.severity} />
                      <div className="min-w-0">
                        <p className="font-medium">{f.title_human || f.title}</p>
                        {f.impact ? <p className="text-sm text-muted-foreground">{f.impact}</p> : null}
                        {f.in_ai_generated_code ? (
                          <Badge className="mt-1 border-violet-400/40 bg-violet-400/15 text-violet-500">in AI-generated code</Badge>
                        ) : null}
                      </div>
                    </div>
                  ))}
                </>
              ) : (
                <p className="text-sm text-muted-foreground">
                  This codebase looks clean. Try connecting more repos for a full picture.
                </p>
              )}
              <Button onClick={() => router.push(`/projects/${projectId}/scans/${scanId}`)}>
                View full report <ArrowRight className="ml-1 h-4 w-4" />
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle>Next steps</CardTitle></CardHeader>
            <CardContent>
              <ul className="space-y-2 text-sm">
                <ChecklistItem label="Invite your team" href="/organizations" />
                <ChecklistItem label="Connect more repos" href="/projects" />
                <ChecklistItem label="Configure quality gates" href={`/projects/${projectId}`} />
                <ChecklistItem label="Try the AI code security features" href={`/projects/${projectId}`} />
              </ul>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}

function ProviderButton({ icon, label, active }: { icon: React.ReactNode; label: string; active?: boolean }) {
  return (
    <div className={`flex flex-col items-center gap-1 rounded-md border p-3 text-sm ${active ? "border-primary bg-primary/5" : "border-border opacity-60"}`}>
      {icon}
      {label}
      {!active ? <span className="text-[10px] text-muted-foreground">soon</span> : null}
    </div>
  );
}

function ChecklistItem({ label, href }: { label: string; href: string }) {
  const router = useRouter();
  return (
    <li className="flex items-center justify-between">
      <span className="flex items-center gap-2"><span className="text-muted-foreground">☐</span> {label}</span>
      <Button variant="ghost" size="sm" onClick={() => router.push(href)}>Go</Button>
    </li>
  );
}
