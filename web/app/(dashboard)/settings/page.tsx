"use client";

import { useSession } from "next-auth/react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Github } from "lucide-react";

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
    </div>
  );
}
