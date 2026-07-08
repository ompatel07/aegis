"use client";

import { useEffect } from "react";
import { AlertOctagon, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function GlobalError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    // Surface for local debugging; production would forward to an error tracker.
    console.error(error);
  }, [error]);

  return (
    <div className="flex min-h-[70vh] flex-col items-center justify-center px-6 text-center">
      <div className="mb-5 flex h-14 w-14 items-center justify-center rounded-full bg-destructive/10 text-destructive">
        <AlertOctagon className="h-7 w-7" />
      </div>
      <h1 className="text-2xl font-bold">Something broke on our end</h1>
      <p className="mt-2 max-w-md text-muted-foreground">
        An unexpected error occurred. Try again, and if it keeps happening, contact{" "}
        <a href="mailto:support@aegis.dev" className="text-primary hover:underline">support@aegis.dev</a>
        {error.digest ? <> (ref <code className="text-xs">{error.digest}</code>).</> : "."}
      </p>
      <Button className="mt-6" onClick={reset}>
        <RefreshCw className="mr-1 h-4 w-4" /> Try again
      </Button>
    </div>
  );
}
