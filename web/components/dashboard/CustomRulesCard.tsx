"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { FileCode2, Trash2 } from "lucide-react";

const PLACEHOLDER = `rules:
  - id: no-hardcoded-token
    pattern: token = "..."
    message: Hard-coded token
    languages: [python]
    severity: WARNING`;

/** Upload / manage per-project custom Semgrep rules (validated before saving). */
export function CustomRulesCard({ projectId }: { projectId: string }) {
  const api = useApi();
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [yaml, setYaml] = useState("");

  const rulesQ = useQuery({ queryKey: ["rules", projectId], queryFn: () => api.listRules(projectId) });

  const create = useMutation({
    mutationFn: () => api.createRule(projectId, { name, rule_yaml: yaml }),
    onSuccess: () => {
      setName("");
      setYaml("");
      qc.invalidateQueries({ queryKey: ["rules", projectId] });
    },
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.deleteRule(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["rules", projectId] }),
  });

  const rules = rulesQ.data ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileCode2 className="h-4 w-4" /> Custom Semgrep rules
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        <p className="text-muted-foreground">
          Project-specific rules, validated with <code>semgrep --validate</code> and applied on top
          of the registry + Aegis packs on every scan.
        </p>

        {rules.length > 0 ? (
          <ul className="space-y-2">
            {rules.map((r) => (
              <li key={r.id} className="flex items-center justify-between gap-3 rounded border p-2">
                <span className="truncate font-medium">{r.name}</span>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={remove.isPending}
                  onClick={() => remove.mutate(r.id)}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-muted-foreground">No custom rules yet.</p>
        )}

        <div className="space-y-2 border-t pt-4">
          <Input placeholder="Rule name" value={name} onChange={(e) => setName(e.target.value)} />
          <textarea
            className="min-h-[140px] w-full rounded-md border bg-background p-2 font-mono text-xs"
            placeholder={PLACEHOLDER}
            value={yaml}
            onChange={(e) => setYaml(e.target.value)}
          />
          {create.isError ? (
            <p className="text-xs text-destructive">{(create.error as Error).message}</p>
          ) : null}
          <Button
            size="sm"
            disabled={create.isPending || !name.trim() || !yaml.trim()}
            onClick={() => create.mutate()}
          >
            {create.isPending ? "Validating…" : "Validate & add"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
