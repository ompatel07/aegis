"use client";

import { useEffect, useMemo, useState } from "react";
import { useSession } from "next-auth/react";
import { createApi, type Api } from "./api";
import { IMPERSONATION_EVENT, readImpersonation } from "./impersonation";

/**
 * Returns a typed API client bound to the current session's access token — or,
 * when an admin is impersonating a user, that user's short-lived token instead.
 */
export function useApi(): Api {
  const { data: session } = useSession();
  const [impToken, setImpToken] = useState<string | undefined>();

  useEffect(() => {
    const read = () => setImpToken(readImpersonation()?.token);
    read();
    window.addEventListener(IMPERSONATION_EVENT, read);
    window.addEventListener("storage", read);
    return () => {
      window.removeEventListener(IMPERSONATION_EVENT, read);
      window.removeEventListener("storage", read);
    };
  }, []);

  const token = impToken ?? session?.accessToken;
  return useMemo(() => createApi(token), [token]);
}
