"use client";

import { useEffect, useState } from "react";
import { UserCheck } from "lucide-react";
import { IMPERSONATION_EVENT, readImpersonation, stopImpersonation } from "@/lib/impersonation";

/** A persistent banner shown while an admin is impersonating another user. */
export function ImpersonationBanner() {
  const [email, setEmail] = useState<string | null>(null);

  useEffect(() => {
    const read = () => setEmail(readImpersonation()?.email ?? null);
    read();
    window.addEventListener(IMPERSONATION_EVENT, read);
    const t = setInterval(read, 30000); // auto-clear when the 1h token expires
    return () => {
      window.removeEventListener(IMPERSONATION_EVENT, read);
      clearInterval(t);
    };
  }, []);

  if (!email) return null;
  return (
    <div className="flex items-center justify-center gap-3 bg-amber-500 px-4 py-1.5 text-sm font-medium text-black">
      <UserCheck className="h-4 w-4" />
      Impersonating <span className="font-semibold">{email}</span> (support session, expires within 1h)
      <button onClick={() => { stopImpersonation(); location.reload(); }} className="underline hover:no-underline">
        Stop impersonating
      </button>
    </div>
  );
}
