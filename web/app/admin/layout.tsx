"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { cn } from "@/lib/utils";
import {
  Activity, Building2, FlaskConical, Gauge, LifeBuoy, ListChecks, Radar, ScrollText,
  ServerCog, ShieldAlert, UserCog, Users,
} from "lucide-react";

const nav = [
  { href: "/admin", label: "Overview", icon: Gauge },
  { href: "/admin/organizations", label: "Organizations", icon: Building2 },
  { href: "/admin/users", label: "Users", icon: Users },
  { href: "/admin/scans", label: "Scans", icon: ListChecks },
  { href: "/admin/features", label: "Feature flags", icon: FlaskConical },
  { href: "/admin/beta", label: "Beta", icon: UserCog },
  { href: "/admin/support", label: "Support", icon: LifeBuoy },
  { href: "/admin/audit", label: "Audit log", icon: ScrollText },
  { href: "/admin/health", label: "System health", icon: ServerCog },
  { href: "/admin/intelligence", label: "Intelligence", icon: Radar },
  { href: "/admin/ml", label: "ML model", icon: Activity },
];

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const api = useApi();

  // Access probe: /admin/overview is behind RequireSuperAdmin — a 403 here means
  // this user is not a platform admin.
  const probe = useQuery({ queryKey: ["admin-probe"], queryFn: () => api.admin.overview(), retry: false });

  if (probe.isError) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center px-6 text-center">
        <ShieldAlert className="mb-4 h-10 w-10 text-destructive" />
        <h1 className="text-xl font-bold">Access denied</h1>
        <p className="mt-1 max-w-sm text-muted-foreground">
          The platform admin panel is restricted to super-admins.
        </p>
        <Link href="/" className="mt-4 text-sm text-primary hover:underline">← Back to dashboard</Link>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen">
      <aside className="hidden w-56 shrink-0 border-r bg-card md:block">
        <div className="flex h-16 items-center gap-2 border-b px-4 font-semibold">
          <ShieldAlert className="h-5 w-5 text-destructive" /> Aegis Admin
        </div>
        <nav className="flex flex-col p-2">
          {nav.map((item) => {
            const active = item.href === "/admin" ? pathname === "/admin" : pathname.startsWith(item.href);
            const Icon = item.icon;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                  active ? "bg-secondary text-foreground" : "text-muted-foreground hover:text-foreground",
                )}
              >
                <Icon className="h-4 w-4" /> {item.label}
              </Link>
            );
          })}
        </nav>
      </aside>
      <div className="flex-1">
        <header className="flex h-16 items-center justify-between border-b px-6">
          <span className="text-sm text-muted-foreground">Platform operations</span>
          <Link href="/" className="text-sm text-primary hover:underline">← Exit to dashboard</Link>
        </header>
        <main className="p-6">{children}</main>
      </div>
    </div>
  );
}
