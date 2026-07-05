"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Github } from "lucide-react";

export default function IntegrationsPage() {
  const api = useApi();
  const qc = useQueryClient();
  const installUrlQ = useQuery({ queryKey: ["gh-install-url"], queryFn: () => api.getGithubAppInstallUrl() });
  const instsQ = useQuery({ queryKey: ["gh-installations"], queryFn: () => api.listGithubAppInstallations() });

  const toggle = useMutation({
    mutationFn: ({ repoId, enabled }: { repoId: string; enabled: boolean }) => api.toggleGithubAppRepo(repoId, enabled),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["gh-installations"] }),
  });

  const enabled = installUrlQ.data?.enabled;
  const installUrl = installUrlQ.data?.install_url;
  const insts = instsQ.data ?? [];

  return (
    <div className="max-w-3xl space-y-6">
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-bold"><Github className="h-6 w-6" /> Integrations</h1>
        <p className="text-muted-foreground">
          Install the Aegis GitHub App to scan pushes and pull requests automatically, with PR checks and a single
          updateable comment.
        </p>
      </div>

      <Card>
        <CardHeader><CardTitle>GitHub App</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          {!enabled ? (
            <p className="text-sm text-muted-foreground">
              The GitHub App is not configured on this Aegis instance. Set <code className="rounded bg-muted px-1">GITHUB_APP_ID</code>,{" "}
              <code className="rounded bg-muted px-1">GITHUB_APP_PRIVATE_KEY</code>, and{" "}
              <code className="rounded bg-muted px-1">GITHUB_APP_WEBHOOK_SECRET</code> to enable it.
            </p>
          ) : (
            <a href={installUrl} target="_blank" rel="noreferrer">
              <Button><Github className="mr-1 h-4 w-4" /> Install Aegis on GitHub</Button>
            </a>
          )}

          {insts.length === 0 ? (
            <p className="text-sm text-muted-foreground">No installations yet.</p>
          ) : (
            insts.map((inst) => (
              <div key={inst.installation_id} className="rounded-md border p-3">
                <div className="mb-2 flex items-center gap-2">
                  <span className="font-medium">{inst.account_login}</span>
                  <Badge className="border-border bg-secondary text-secondary-foreground">{inst.account_type}</Badge>
                </div>
                <div className="space-y-1">
                  {inst.repos.map((repo) => (
                    <div key={repo.id} className="flex items-center justify-between text-sm">
                      <span>{repo.full_name}</span>
                      <Button variant="outline" size="sm"
                        onClick={() => toggle.mutate({ repoId: repo.id, enabled: !repo.enabled })}>
                        {repo.enabled ? "Enabled" : "Disabled"}
                      </Button>
                    </div>
                  ))}
                  {inst.repos.length === 0 ? <p className="text-xs text-muted-foreground">No repositories.</p> : null}
                </div>
              </div>
            ))
          )}
        </CardContent>
      </Card>
    </div>
  );
}
