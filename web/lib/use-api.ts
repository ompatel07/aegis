"use client";

import { useMemo } from "react";
import { useSession } from "next-auth/react";
import { createApi, type Api } from "./api";

/** Returns a typed API client bound to the current session's access token. */
export function useApi(): Api {
  const { data: session } = useSession();
  const token = session?.accessToken;
  return useMemo(() => createApi(token), [token]);
}
