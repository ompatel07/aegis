"use client";

import { useCallback, useEffect, useState } from "react";

const KEY = "aegis.currentOrg";
const EVENT = "aegis:org-changed";

/**
 * Tracks the user's currently-selected organization in localStorage so the org
 * switcher and the new-project form agree on which org new work lands in.
 */
export function useCurrentOrg(): [string | null, (id: string) => void] {
  const [orgId, setOrgId] = useState<string | null>(null);

  useEffect(() => {
    setOrgId(localStorage.getItem(KEY));
    const onChange = () => setOrgId(localStorage.getItem(KEY));
    window.addEventListener(EVENT, onChange);
    window.addEventListener("storage", onChange);
    return () => {
      window.removeEventListener(EVENT, onChange);
      window.removeEventListener("storage", onChange);
    };
  }, []);

  const set = useCallback((id: string) => {
    localStorage.setItem(KEY, id);
    window.dispatchEvent(new Event(EVENT));
  }, []);

  return [orgId, set];
}
