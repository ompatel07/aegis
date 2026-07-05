"use client";

import { Suspense, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Mail } from "lucide-react";

function AcceptInner() {
  const api = useApi();
  const router = useRouter();
  const params = useSearchParams();
  const [token, setToken] = useState("");
  const [joined, setJoined] = useState<string | null>(null);

  useEffect(() => {
    const t = params.get("token");
    if (t) setToken(t);
  }, [params]);

  const accept = useMutation({
    mutationFn: () => api.acceptInvitation(token),
    onSuccess: (org) => setJoined(org.name),
  });

  return (
    <div className="mx-auto max-w-md">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Mail className="h-5 w-5" /> Accept invitation</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {joined ? (
            <div className="space-y-3">
              <p className="text-sm text-emerald-600">You&apos;ve joined <span className="font-medium">{joined}</span>.</p>
              <Button onClick={() => router.push("/organizations")}>Go to teams</Button>
            </div>
          ) : (
            <>
              <p className="text-sm text-muted-foreground">
                Paste the invitation token you received. It must match your account&apos;s email.
              </p>
              <Input placeholder="invitation token" value={token} onChange={(e) => setToken(e.target.value)} />
              {accept.isError ? <p className="text-sm text-destructive">{(accept.error as Error).message}</p> : null}
              <Button disabled={!token || accept.isPending} onClick={() => accept.mutate()}>
                {accept.isPending ? "Joining…" : "Accept invitation"}
              </Button>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export default function AcceptInvitationPage() {
  return (
    <Suspense fallback={<p className="text-sm text-muted-foreground">Loading…</p>}>
      <AcceptInner />
    </Suspense>
  );
}
