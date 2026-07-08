"use client";

import { useEffect, useState } from "react";
import { WifiOff } from "lucide-react";

/** A top banner shown when the browser reports it is offline. */
export function OfflineBanner() {
  const [offline, setOffline] = useState(false);

  useEffect(() => {
    const update = () => setOffline(!navigator.onLine);
    update();
    window.addEventListener("online", update);
    window.addEventListener("offline", update);
    return () => {
      window.removeEventListener("online", update);
      window.removeEventListener("offline", update);
    };
  }, []);

  if (!offline) return null;
  return (
    <div className="flex items-center justify-center gap-2 bg-destructive px-4 py-1.5 text-sm font-medium text-destructive-foreground">
      <WifiOff className="h-4 w-4" /> You&apos;re offline — changes may not be saved.
    </div>
  );
}
