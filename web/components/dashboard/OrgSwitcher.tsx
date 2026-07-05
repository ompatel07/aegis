"use client";

import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { useCurrentOrg } from "@/lib/use-current-org";
import { Building2 } from "lucide-react";

/** Header org switcher — picks the active organization for new work. */
export function OrgSwitcher() {
  const api = useApi();
  const [current, setCurrent] = useCurrentOrg();
  const { data: orgs } = useQuery({ queryKey: ["orgs"], queryFn: () => api.listOrgs() });

  // Default to the personal org once orgs load and nothing is selected.
  useEffect(() => {
    if (orgs && orgs.length > 0 && (!current || !orgs.some((o) => o.id === current))) {
      const personal = orgs.find((o) => o.is_personal) ?? orgs[0];
      setCurrent(personal.id);
    }
  }, [orgs, current, setCurrent]);

  if (!orgs || orgs.length === 0) return null;

  return (
    <div className="hidden items-center gap-2 sm:flex">
      <Building2 className="h-4 w-4 text-muted-foreground" />
      <select
        aria-label="Current organization"
        value={current ?? ""}
        onChange={(e) => setCurrent(e.target.value)}
        className="h-9 rounded-md border border-input bg-background px-2 text-sm"
      >
        {orgs.map((o) => (
          <option key={o.id} value={o.id}>
            {o.name}
            {o.is_personal ? " (personal)" : ""} · {o.role}
          </option>
        ))}
      </select>
    </div>
  );
}
