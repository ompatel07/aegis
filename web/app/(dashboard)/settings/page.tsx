"use client";

import { useSession } from "next-auth/react";
import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Bell, Github, Rocket, ShieldCheck } from "lucide-react";
import type { NotificationSettings } from "@/lib/types";

export default function SettingsPage() {
  const { data: session } = useSession();
  const webhookUrl =
    (process.env.NEXT_PUBLIC_API_URL || "http://localhost/api/v1") + "/webhooks/github";

  return (
    <div className="max-w-2xl space-y-8">
      <div>
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="text-muted-foreground">Manage your profile and integrations.</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Profile</CardTitle>
          <CardDescription>Your account details.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5">
            <Label>Name</Label>
            <Input value={session?.user?.name ?? ""} readOnly />
          </div>
          <div className="space-y-1.5">
            <Label>Email</Label>
            <Input value={session?.user?.email ?? ""} readOnly />
          </div>
          <div className="flex gap-2">
            <Badge className="border-border bg-secondary text-secondary-foreground capitalize">
              {session?.user?.plan ?? "free"} plan
            </Badge>
            <Badge className="border-border bg-secondary text-secondary-foreground capitalize">
              {session?.user?.role ?? "user"}
            </Badge>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Github className="h-5 w-5" /> GitHub integration
          </CardTitle>
          <CardDescription>Trigger scans automatically on every push.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 text-sm">
          <p className="text-muted-foreground">
            Add a webhook to your repository pointing at the URL below, using the{" "}
            <span className="font-medium">application/json</span> content type and a shared secret.
            Aegis verifies the <code className="rounded bg-muted px-1">X-Hub-Signature-256</code>{" "}
            header on every delivery before processing.
          </p>
          <div className="space-y-1.5">
            <Label>Webhook URL</Label>
            <Input value={webhookUrl} readOnly />
          </div>
          <p className="text-xs text-muted-foreground">
            Only <span className="font-medium">push</span> events are processed; all other events
            are acknowledged and ignored.
          </p>
        </CardContent>
      </Card>

      <NotificationsCard />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5" /> Single Sign-On
          </CardTitle>
          <CardDescription>Configure SAML / OIDC identity providers and SCIM provisioning for your organization.</CardDescription>
        </CardHeader>
        <CardContent>
          <Link href="/settings/sso">
            <Button variant="outline" size="sm">Manage SSO</Button>
          </Link>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Rocket className="h-5 w-5" /> Product tour
          </CardTitle>
          <CardDescription>Re-run the guided onboarding flow.</CardDescription>
        </CardHeader>
        <CardContent>
          <Link href="/onboarding">
            <Button variant="outline" size="sm">Restart tour</Button>
          </Link>
        </CardContent>
      </Card>
    </div>
  );
}

function NotificationsCard() {
  const api = useApi();
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ["notif-settings"], queryFn: () => api.getNotificationSettings() });
  const save = useMutation({
    mutationFn: (s: NotificationSettings) => api.updateNotificationSettings(s),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["notif-settings"] }),
  });
  if (!data) return null;
  const set = (patch: Partial<NotificationSettings>) => save.mutate({ ...data, ...patch });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><Bell className="h-5 w-5" /> Notifications</CardTitle>
        <CardDescription>Email alerts for scan events (delivered via the configured provider).</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <Toggle label="Email enabled" checked={data.email_enabled} onChange={(v) => set({ email_enabled: v })} />
        <Toggle label="Email me when a scan completes" checked={data.email_scan_complete} onChange={(v) => set({ email_scan_complete: v })} />
        <Toggle label="Email me on new critical findings" checked={data.email_new_critical} onChange={(v) => set({ email_new_critical: v })} />
        <div className="flex items-center justify-between">
          <span>Digest frequency</span>
          <select className="h-8 rounded-md border border-input bg-background px-2" value={data.digest_frequency}
            onChange={(e) => set({ digest_frequency: e.target.value as NotificationSettings["digest_frequency"] })}>
            <option value="daily">Daily</option><option value="weekly">Weekly</option><option value="never">Never</option>
          </select>
        </div>
        <div className="flex items-center justify-between">
          <span>Real-time alert threshold</span>
          <select className="h-8 rounded-md border border-input bg-background px-2" value={data.severity_threshold}
            onChange={(e) => set({ severity_threshold: e.target.value as NotificationSettings["severity_threshold"] })}>
            <option value="critical">Critical only</option><option value="high">High+</option>
            <option value="medium">Medium+</option><option value="all">All</option>
          </select>
        </div>
      </CardContent>
    </Card>
  );
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-center justify-between">
      <span>{label}</span>
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} className="h-4 w-4" />
    </label>
  );
}
