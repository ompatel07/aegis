"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Github, Trash2 } from "lucide-react";
import type { ConnectGitHubResult } from "@/lib/types";

/** Connect / disconnect a project's GitHub webhook integration. */
export function GitHubIntegrationCard({ projectId }: { projectId: string }) {
  const api = useApi();
  const qc = useQueryClient();
  const [token, setToken] = useState("");
  const [justConnected, setJustConnected] = useState<ConnectGitHubResult | null>(null);

  const integrationsQ = useQuery({
    queryKey: ["integrations", projectId],
    queryFn: () => api.listIntegrations(projectId),
  });

  const connect = useMutation({
    mutationFn: () => api.connectGitHub(projectId, token ? { access_token: token } : undefined),
    onSuccess: (res) => {
      setJustConnected(res);
      setToken("");
      qc.invalidateQueries({ queryKey: ["integrations", projectId] });
    },
  });

  const disconnect = useMutation({
    mutationFn: (id: string) => api.deleteIntegration(id),
    onSuccess: () => {
      setJustConnected(null);
      qc.invalidateQueries({ queryKey: ["integrations", projectId] });
    },
  });

  const integration = integrationsQ.data?.[0];
  const origin = typeof window !== "undefined" ? window.location.origin : "";

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Github className="h-4 w-4" /> GitHub integration
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        {integrationsQ.isLoading ? (
          <p className="text-muted-foreground">Loading…</p>
        ) : integration ? (
          <>
            <p className="text-muted-foreground">
              Connected · pushes to this repo trigger a scan automatically.
            </p>
            <div className="space-y-1">
              <p className="font-medium">Webhook URL</p>
              <code className="block break-all rounded bg-muted px-2 py-1 text-xs">
                {origin}/api/v1/webhooks/github
              </code>
              <p className="text-xs text-muted-foreground">
                Add this as a <code>push</code> webhook (content-type application/json) in the repo
                settings, using the secret shown when you connected.
              </p>
            </div>
            {justConnected ? <SecretBox secret={justConnected.webhook_secret} /> : null}
            <Button
              variant="outline"
              size="sm"
              disabled={disconnect.isPending}
              onClick={() => disconnect.mutate(integration.id)}
            >
              <Trash2 className="mr-1 h-4 w-4" />
              {disconnect.isPending ? "Disconnecting…" : "Disconnect"}
            </Button>
            {disconnect.isError ? (
              <p className="text-xs text-destructive">{(disconnect.error as Error).message}</p>
            ) : null}
          </>
        ) : (
          <>
            <p className="text-muted-foreground">
              Connect this project to GitHub so pushes trigger scans. A personal access token is
              optional (used to clone private repos); the webhook secret is generated for you.
            </p>
            <Input
              type="password"
              placeholder="GitHub access token (optional)"
              value={token}
              onChange={(e) => setToken(e.target.value)}
            />
            <Button size="sm" disabled={connect.isPending} onClick={() => connect.mutate()}>
              <Github className="mr-1 h-4 w-4" />
              {connect.isPending ? "Connecting…" : "Connect GitHub"}
            </Button>
            {connect.isError ? (
              <p className="text-xs text-destructive">{(connect.error as Error).message}</p>
            ) : null}
          </>
        )}
      </CardContent>
    </Card>
  );
}

function SecretBox({ secret }: { secret: string }) {
  return (
    <div className="rounded border border-amber-500/30 bg-amber-500/10 p-3">
      <p className="font-medium text-amber-600 dark:text-amber-400">
        Webhook secret (shown once — copy it now)
      </p>
      <code className="mt-1 block break-all text-xs">{secret}</code>
    </div>
  );
}
