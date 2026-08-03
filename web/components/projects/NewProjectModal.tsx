"use client";

import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { useApi } from "@/lib/use-api";
import { useCurrentOrg } from "@/lib/use-current-org";

const schema = z.object({
  name: z.string().min(1, "Name is required").max(255),
  description: z.string().max(5000).optional(),
  repo_url: z.string().url("Must be a valid URL").max(1024).optional().or(z.literal("")),
  repo_type: z.enum(["github", "gitlab", "bitbucket", "upload"]).optional(),
});

type FormValues = z.infer<typeof schema>;

export function NewProjectModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const api = useApi();
  const queryClient = useQueryClient();
  const [currentOrg] = useCurrentOrg();
  const [serverError, setServerError] = useState<string | null>(null);

  // Branch handling (Phase 2G): never assume "main". Default to auto-detect; the
  // user can detect the real default/branches or type a branch explicitly.
  const [branchMode, setBranchMode] = useState<"auto" | "manual">("auto");
  const [manualBranch, setManualBranch] = useState("");
  const [detected, setDetected] = useState<{ default_branch: string; branches: string[] } | null>(null);
  const [detecting, setDetecting] = useState(false);
  const [detectError, setDetectError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    reset,
    watch,
    formState: { errors },
  } = useForm<FormValues>({ resolver: zodResolver(schema), defaultValues: { repo_type: "github" } });

  const repoUrl = watch("repo_url");

  async function detect() {
    if (!repoUrl) return;
    setDetecting(true);
    setDetectError(null);
    try {
      const d = await api.detectBranches(repoUrl);
      setDetected(d);
      if (!manualBranch) setManualBranch(d.default_branch);
    } catch (e) {
      setDetectError((e as Error).message);
      setDetected(null);
    } finally {
      setDetecting(false);
    }
  }

  const mutation = useMutation({
    mutationFn: (values: FormValues) =>
      api.createProject({
        name: values.name,
        description: values.description || undefined,
        repo_url: values.repo_url || undefined,
        repo_type: values.repo_type,
        // auto → send detected default if known, else empty (backend auto-detects
        // on connect / the orchestrator clones the remote default at scan time).
        default_branch:
          branchMode === "manual"
            ? manualBranch || undefined
            : detected?.default_branch || undefined,
        organization_id: currentOrg || undefined,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["projects"] });
      reset();
      setBranchMode("auto");
      setManualBranch("");
      setDetected(null);
      setDetectError(null);
      setServerError(null);
      onClose();
    },
    onError: (e: Error) => setServerError(e.message),
  });

  return (
    <Dialog open={open} onClose={onClose}>
      <DialogHeader>
        <DialogTitle>New project</DialogTitle>
        <DialogDescription>Connect a repository to start scanning it.</DialogDescription>
      </DialogHeader>

      <form onSubmit={handleSubmit((v) => mutation.mutate(v))} className="space-y-4">
        <Field label="Name" error={errors.name?.message}>
          <Input placeholder="my-service" {...register("name")} />
        </Field>
        <Field label="Description" error={errors.description?.message}>
          <Input placeholder="Optional summary" {...register("description")} />
        </Field>
        <Field label="Repository URL" error={errors.repo_url?.message}>
          <Input placeholder="https://github.com/org/repo" {...register("repo_url")} />
        </Field>
        <div className="grid grid-cols-2 gap-4">
          <Field label="Repo type">
            <select
              className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
              {...register("repo_type")}
            >
              <option value="github">GitHub</option>
              <option value="gitlab">GitLab</option>
              <option value="bitbucket">Bitbucket</option>
              <option value="upload">Upload</option>
            </select>
          </Field>
          <Field label="Branch">
            <select
              className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
              value={branchMode}
              onChange={(e) => setBranchMode(e.target.value as "auto" | "manual")}
            >
              <option value="auto">Use default branch (auto-detect)</option>
              <option value="manual">Choose a branch</option>
            </select>
          </Field>
        </div>

        {/* Branch detail — Phase 2G: never assume "main". */}
        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={!repoUrl || detecting}
              onClick={detect}
            >
              {detecting ? "Detecting…" : "Detect branches"}
            </Button>
            {detected ? (
              <span className="text-xs text-muted-foreground">
                default: <code>{detected.default_branch}</code> · {detected.branches.length} branch
                {detected.branches.length === 1 ? "" : "es"}
              </span>
            ) : null}
          </div>
          {detectError ? <p className="text-xs text-destructive">{detectError}</p> : null}

          {branchMode === "auto" ? (
            <p className="text-xs text-muted-foreground">
              Aegis will scan the repository&apos;s default branch
              {detected ? (
                <>
                  {" "}
                  (<code>{detected.default_branch}</code>)
                </>
              ) : (
                " (auto-detected when you connect — works for main, master, develop, …)"
              )}
              .
            </p>
          ) : detected && detected.branches.length > 0 ? (
            <select
              className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
              value={manualBranch}
              onChange={(e) => setManualBranch(e.target.value)}
            >
              {detected.branches.map((b) => (
                <option key={b} value={b}>
                  {b}
                </option>
              ))}
            </select>
          ) : (
            <Input
              placeholder="branch name (e.g. develop)"
              value={manualBranch}
              onChange={(e) => setManualBranch(e.target.value)}
            />
          )}
        </div>

        {serverError ? <p className="text-sm text-destructive">{serverError}</p> : null}

        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" disabled={mutation.isPending}>
            {mutation.isPending ? "Creating…" : "Create project"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function Field({
  label,
  error,
  children,
}: {
  label: string;
  error?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1.5">
      <Label>{label}</Label>
      {children}
      {error ? <p className="text-xs text-destructive">{error}</p> : null}
    </div>
  );
}
