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

const schema = z.object({
  name: z.string().min(1, "Name is required").max(255),
  description: z.string().max(5000).optional(),
  repo_url: z.string().url("Must be a valid URL").max(1024).optional().or(z.literal("")),
  repo_type: z.enum(["github", "gitlab", "bitbucket", "upload"]).optional(),
  default_branch: z.string().max(255).optional(),
});

type FormValues = z.infer<typeof schema>;

export function NewProjectModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const api = useApi();
  const queryClient = useQueryClient();
  const [serverError, setServerError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<FormValues>({ resolver: zodResolver(schema), defaultValues: { repo_type: "github" } });

  const mutation = useMutation({
    mutationFn: (values: FormValues) =>
      api.createProject({
        name: values.name,
        description: values.description || undefined,
        repo_url: values.repo_url || undefined,
        repo_type: values.repo_type,
        default_branch: values.default_branch || undefined,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["projects"] });
      reset();
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
          <Field label="Default branch" error={errors.default_branch?.message}>
            <Input placeholder="main" {...register("default_branch")} />
          </Field>
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
