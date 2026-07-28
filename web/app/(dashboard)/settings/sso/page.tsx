"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, KeyRound, Plus, ShieldCheck, Trash2, Copy, Check, Pencil, Building2 } from "lucide-react";
import { useApi } from "@/lib/use-api";
import { useToast } from "@/lib/use-toast";
import { useConfirm } from "@/lib/use-confirm";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Dialog, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import type { SSOConnection, SSOConnectionInput, SCIMToken, SSOProtocol } from "@/lib/types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost/api/v1";

export default function SSOAdminPage() {
  const api = useApi();
  const { data: orgs } = useQuery({ queryKey: ["orgs"], queryFn: () => api.listOrgs() });
  const owned = useMemo(() => (orgs ?? []).filter((o) => o.role === "owner"), [orgs]);
  const [orgId, setOrgId] = useState<string>("");
  const activeOrg = orgId || owned[0]?.id || "";

  return (
    <div className="max-w-3xl space-y-8">
      <div>
        <Link href="/settings" className="mb-2 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
          <ArrowLeft className="h-4 w-4" /> Settings
        </Link>
        <h1 className="flex items-center gap-2 text-2xl font-bold">
          <ShieldCheck className="h-6 w-6" /> Single Sign-On
        </h1>
        <p className="text-muted-foreground">
          Configure SAML / OIDC identity providers and SCIM provisioning for your organization.
        </p>
      </div>

      {orgs && owned.length === 0 && (
        <EmptyState
          icon={Building2}
          title="No organizations you own"
          description="SSO is configured per organization and can only be managed by an organization owner."
        />
      )}

      {owned.length > 0 && (
        <>
          {owned.length > 1 && (
            <div className="flex items-center gap-3">
              <Label htmlFor="org" className="shrink-0">Organization</Label>
              <select
                id="org"
                className="h-9 rounded-md border border-input bg-background px-2 text-sm"
                value={activeOrg}
                onChange={(e) => setOrgId(e.target.value)}
              >
                {owned.map((o) => (
                  <option key={o.id} value={o.id}>{o.name}</option>
                ))}
              </select>
            </div>
          )}

          {activeOrg && <ConnectionsCard orgId={activeOrg} />}
          {activeOrg && <ScimTokensCard orgId={activeOrg} />}
        </>
      )}
    </div>
  );
}

// ── Connections ────────────────────────────────────────────────────────────
function ConnectionsCard({ orgId }: { orgId: string }) {
  const api = useApi();
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const [editing, setEditing] = useState<SSOConnection | null>(null);
  const [creating, setCreating] = useState(false);

  const { data: conns, isLoading } = useQuery({
    queryKey: ["sso-connections", orgId],
    queryFn: () => api.sso.listConnections(orgId),
  });

  const invalidate = () => qc.invalidateQueries({ queryKey: ["sso-connections", orgId] });

  const toggle = useMutation({
    mutationFn: (c: SSOConnection) => api.sso.updateConnection(c.id, { ...connToInput(c), enabled: !c.enabled }),
    onSuccess: (_d, c) => { invalidate(); toast.success(c.enabled ? "Connection disabled" : "Connection enabled"); },
    onError: (e: Error) => toast.error("Update failed", e.message),
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.sso.deleteConnection(id),
    onSuccess: () => { invalidate(); toast.success("Connection deleted"); },
    onError: (e: Error) => toast.error("Delete failed", e.message),
  });

  const onDelete = async (c: SSOConnection) => {
    const ok = await confirm({
      title: "Delete SSO connection?",
      description: `“${c.display_name || c.protocol.toUpperCase()}” will be removed. Users routed through this IdP will no longer be able to sign in.`,
      confirmLabel: "Delete",
      destructive: true,
    });
    if (ok) remove.mutate(c.id);
  };

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-4">
        <div>
          <CardTitle>Identity providers</CardTitle>
          <CardDescription>SAML 2.0 and OIDC connections. Users are routed by email domain.</CardDescription>
        </div>
        <Button size="sm" onClick={() => setCreating(true)}>
          <Plus className="mr-1 h-4 w-4" /> Add
        </Button>
      </CardHeader>
      <CardContent className="space-y-3">
        {isLoading && <p className="text-sm text-muted-foreground">Loading…</p>}
        {conns && conns.length === 0 && (
          <p className="text-sm text-muted-foreground">No identity providers configured yet.</p>
        )}
        {conns?.map((c) => (
          <div key={c.id} className="rounded-lg border p-4">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-medium">{c.display_name || c.protocol.toUpperCase()}</span>
                  <Badge className="border-border bg-secondary uppercase text-secondary-foreground">{c.protocol}</Badge>
                  <Badge className={c.enabled ? "border-transparent bg-emerald-500/15 text-emerald-600 dark:text-emerald-400" : "border-border bg-muted text-muted-foreground"}>
                    {c.enabled ? "Enabled" : "Disabled"}
                  </Badge>
                </div>
                <p className="mt-1 truncate text-sm text-muted-foreground">
                  {c.email_domain ? <>Domain <code className="rounded bg-muted px-1">{c.email_domain}</code> · </> : null}
                  {c.jit_provisioning ? "JIT on" : "JIT off"} · default role {c.default_role}
                </p>
              </div>
              <div className="flex shrink-0 items-center gap-1">
                <Button variant="ghost" size="sm" onClick={() => toggle.mutate(c)} disabled={toggle.isPending}>
                  {c.enabled ? "Disable" : "Enable"}
                </Button>
                <Button variant="ghost" size="icon" aria-label="Edit" onClick={() => setEditing(c)}>
                  <Pencil className="h-4 w-4" />
                </Button>
                <Button variant="ghost" size="icon" aria-label="Delete" onClick={() => onDelete(c)}>
                  <Trash2 className="h-4 w-4 text-destructive" />
                </Button>
              </div>
            </div>
            {c.protocol === "saml" && <SamlEndpoints connId={c.id} />}
          </div>
        ))}
      </CardContent>

      {(creating || editing) && (
        <ConnectionDialog
          orgId={orgId}
          existing={editing}
          onClose={() => { setCreating(false); setEditing(null); }}
          onSaved={() => { setCreating(false); setEditing(null); invalidate(); }}
        />
      )}
    </Card>
  );
}

function SamlEndpoints({ connId }: { connId: string }) {
  return (
    <div className="mt-3 space-y-2 rounded-md bg-muted/50 p-3 text-xs">
      <p className="font-medium text-muted-foreground">Give these to your IdP</p>
      <CopyRow label="SP metadata" value={`${API_BASE}/auth/sso/${connId}/saml/metadata`} />
      <CopyRow label="ACS (Reply) URL" value={`${API_BASE}/auth/sso/saml/acs`} />
    </div>
  );
}

// ── Connection create/edit dialog ──────────────────────────────────────────
function ConnectionDialog({
  orgId, existing, onClose, onSaved,
}: {
  orgId: string; existing: SSOConnection | null; onClose: () => void; onSaved: () => void;
}) {
  const api = useApi();
  const toast = useToast();
  const [form, setForm] = useState<SSOConnectionInput>(
    existing ? connToInput(existing) : {
      organization_id: orgId, protocol: "oidc", display_name: "", enabled: true,
      email_domain: "", oidc_scopes: "openid email profile", default_role: "member",
      jit_provisioning: true, attr_email: "email", attr_name: "name",
    },
  );
  const set = (patch: Partial<SSOConnectionInput>) => setForm((f) => ({ ...f, ...patch }));

  const save = useMutation({
    mutationFn: () => {
      // Drop empty client secret so the stored one is preserved on edit.
      const body: SSOConnectionInput = { ...form, organization_id: orgId };
      if (!body.oidc_client_secret) delete body.oidc_client_secret;
      return existing ? api.sso.updateConnection(existing.id, body) : api.sso.createConnection(body);
    },
    onSuccess: () => { toast.success(existing ? "Connection updated" : "Connection created"); onSaved(); },
    onError: (e: Error) => toast.error("Save failed", e.message),
  });

  const isOIDC = form.protocol === "oidc";

  return (
    <Dialog open onClose={onClose} className="max-h-[90vh] overflow-y-auto">
      <DialogHeader>
        <DialogTitle>{existing ? "Edit connection" : "New identity provider"}</DialogTitle>
        <DialogDescription>Only organization owners can manage SSO. Secrets are encrypted at rest.</DialogDescription>
      </DialogHeader>

      <form
        className="space-y-4"
        onSubmit={(e) => { e.preventDefault(); save.mutate(); }}
      >
        <Field label="Protocol">
          <select
            className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm disabled:opacity-60"
            value={form.protocol}
            disabled={!!existing}
            onChange={(e) => set({ protocol: e.target.value as SSOProtocol })}
          >
            <option value="oidc">OIDC</option>
            <option value="saml">SAML 2.0</option>
          </select>
        </Field>

        <Field label="Display name">
          <Input value={form.display_name} onChange={(e) => set({ display_name: e.target.value })} placeholder="Acme Okta" required />
        </Field>

        <Field label="Email domain" hint="Users at this domain are auto-routed to this IdP.">
          <Input value={form.email_domain ?? ""} onChange={(e) => set({ email_domain: e.target.value })} placeholder="acme.com" />
        </Field>

        {isOIDC ? (
          <>
            <Field label="Issuer URL" hint="Discovery base; /.well-known/openid-configuration is fetched automatically.">
              <Input value={form.oidc_issuer ?? ""} onChange={(e) => set({ oidc_issuer: e.target.value })} placeholder="https://acme.okta.com" />
            </Field>
            <Field label="Client ID">
              <Input value={form.oidc_client_id ?? ""} onChange={(e) => set({ oidc_client_id: e.target.value })} />
            </Field>
            <Field label="Client secret" hint={existing ? "Leave blank to keep the current secret." : undefined}>
              <Input type="password" value={form.oidc_client_secret ?? ""} onChange={(e) => set({ oidc_client_secret: e.target.value })} placeholder={existing ? "••••••••" : ""} autoComplete="new-password" />
            </Field>
            <Field label="Scopes">
              <Input value={form.oidc_scopes ?? ""} onChange={(e) => set({ oidc_scopes: e.target.value })} placeholder="openid email profile" />
            </Field>
            <p className="rounded-md bg-muted/50 p-3 text-xs text-muted-foreground">
              Redirect URI for your IdP: <code className="rounded bg-muted px-1">{API_BASE}/auth/sso/oidc/callback</code>
            </p>
          </>
        ) : (
          <>
            <Field label="IdP Entity ID">
              <Input value={form.saml_idp_entity_id ?? ""} onChange={(e) => set({ saml_idp_entity_id: e.target.value })} />
            </Field>
            <Field label="IdP SSO URL">
              <Input value={form.saml_idp_sso_url ?? ""} onChange={(e) => set({ saml_idp_sso_url: e.target.value })} placeholder="https://idp.example.com/sso" />
            </Field>
            <Field label="IdP certificate (PEM)">
              <textarea
                className="min-h-[120px] w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs"
                value={form.saml_idp_certificate ?? ""}
                onChange={(e) => set({ saml_idp_certificate: e.target.value })}
                placeholder="-----BEGIN CERTIFICATE-----"
              />
            </Field>
          </>
        )}

        <div className="grid grid-cols-2 gap-3">
          <Field label="Email attribute">
            <Input value={form.attr_email ?? ""} onChange={(e) => set({ attr_email: e.target.value })} placeholder="email" />
          </Field>
          <Field label="Name attribute">
            <Input value={form.attr_name ?? ""} onChange={(e) => set({ attr_name: e.target.value })} placeholder="name" />
          </Field>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Field label="Default role">
            <select className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
              value={form.default_role ?? "member"} onChange={(e) => set({ default_role: e.target.value })}>
              <option value="member">Member</option>
              <option value="admin">Admin</option>
            </select>
          </Field>
          <div className="flex items-end gap-4 pb-2">
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" className="h-4 w-4" checked={!!form.jit_provisioning} onChange={(e) => set({ jit_provisioning: e.target.checked })} />
              JIT provisioning
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" className="h-4 w-4" checked={form.enabled} onChange={(e) => set({ enabled: e.target.checked })} />
              Enabled
            </label>
          </div>
        </div>

        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
          <Button type="submit" disabled={save.isPending}>{save.isPending ? "Saving…" : existing ? "Save changes" : "Create"}</Button>
        </div>
      </form>
    </Dialog>
  );
}

// ── SCIM tokens ────────────────────────────────────────────────────────────
function ScimTokensCard({ orgId }: { orgId: string }) {
  const api = useApi();
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const [newName, setNewName] = useState("");
  const [reveal, setReveal] = useState<string | null>(null);

  const { data: tokens } = useQuery({
    queryKey: ["scim-tokens", orgId],
    queryFn: () => api.sso.listScimTokens(orgId),
  });
  const invalidate = () => qc.invalidateQueries({ queryKey: ["scim-tokens", orgId] });

  const create = useMutation({
    mutationFn: () => api.sso.createScimToken({ organization_id: orgId, display_name: newName || "SCIM token" }),
    onSuccess: (d) => { setReveal(d.token); setNewName(""); invalidate(); },
    onError: (e: Error) => toast.error("Could not create token", e.message),
  });

  const revoke = useMutation({
    mutationFn: (id: string) => api.sso.revokeScimToken(id, orgId),
    onSuccess: () => { invalidate(); toast.success("Token revoked"); },
    onError: (e: Error) => toast.error("Revoke failed", e.message),
  });

  const onRevoke = async (t: SCIMToken) => {
    const ok = await confirm({
      title: "Revoke SCIM token?",
      description: `Provisioning using “${t.display_name}” (${t.token_prefix}…) will stop working immediately.`,
      confirmLabel: "Revoke",
      destructive: true,
    });
    if (ok) revoke.mutate(t.id);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><KeyRound className="h-5 w-5" /> SCIM provisioning</CardTitle>
        <CardDescription>
          Bearer tokens your IdP uses to provision users. Base URL:{" "}
          <code className="rounded bg-muted px-1">{API_BASE.replace(/\/api\/v1$/, "")}/scim/v2</code>
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-2">
          <Input placeholder="Token name (e.g. Okta SCIM)" value={newName} onChange={(e) => setNewName(e.target.value)} />
          <Button className="shrink-0" onClick={() => create.mutate()} disabled={create.isPending}>
            <Plus className="mr-1 h-4 w-4" /> Generate
          </Button>
        </div>

        {tokens && tokens.length === 0 && <p className="text-sm text-muted-foreground">No SCIM tokens yet.</p>}
        {tokens?.map((t) => (
          <div key={t.id} className="flex items-center justify-between rounded-lg border p-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-medium">{t.display_name}</span>
                <code className="rounded bg-muted px-1 text-xs">{t.token_prefix}…</code>
                {!t.enabled && <Badge className="border-border bg-muted text-muted-foreground">Revoked</Badge>}
              </div>
              <p className="mt-0.5 text-xs text-muted-foreground">
                {t.last_used_at ? `Last used ${new Date(t.last_used_at).toLocaleDateString()}` : "Never used"}
              </p>
            </div>
            {t.enabled && (
              <Button variant="ghost" size="sm" onClick={() => onRevoke(t)} disabled={revoke.isPending}>Revoke</Button>
            )}
          </div>
        ))}
      </CardContent>

      {reveal && (
        <Dialog open onClose={() => setReveal(null)}>
          <DialogHeader>
            <DialogTitle>Copy your SCIM token</DialogTitle>
            <DialogDescription>This token is shown once and cannot be retrieved again.</DialogDescription>
          </DialogHeader>
          <CopyRow label="Token" value={reveal} mono />
          <div className="mt-4 flex justify-end">
            <Button onClick={() => setReveal(null)}>Done</Button>
          </div>
        </Dialog>
      )}
    </Card>
  );
}

// ── Small helpers ──────────────────────────────────────────────────────────
function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <Label>{label}</Label>
      {children}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

function CopyRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  };
  return (
    <div className="flex items-center gap-2">
      <div className="min-w-0 flex-1">
        <span className="text-muted-foreground">{label}: </span>
        <span className={mono ? "break-all font-mono" : "break-all"}>{value}</span>
      </div>
      <Button type="button" variant="ghost" size="icon" aria-label="Copy" onClick={copy}>
        {copied ? <Check className="h-4 w-4 text-emerald-500" /> : <Copy className="h-4 w-4" />}
      </Button>
    </div>
  );
}

function connToInput(c: SSOConnection): SSOConnectionInput {
  return {
    organization_id: c.organization_id,
    protocol: c.protocol,
    display_name: c.display_name,
    enabled: c.enabled,
    email_domain: c.email_domain ?? "",
    oidc_issuer: c.oidc_issuer ?? "",
    oidc_client_id: c.oidc_client_id ?? "",
    oidc_scopes: c.oidc_scopes,
    saml_idp_entity_id: c.saml_idp_entity_id ?? "",
    saml_idp_sso_url: c.saml_idp_sso_url ?? "",
    saml_idp_certificate: c.saml_idp_certificate ?? "",
    attr_email: c.attr_email,
    attr_name: c.attr_name,
    default_role: c.default_role,
    jit_provisioning: c.jit_provisioning,
  };
}
