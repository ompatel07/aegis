"use client";

import Link from "next/link";
import { useState } from "react";
import { usePathname } from "next/navigation";
import { signOut, useSession } from "next-auth/react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { OrgSwitcher } from "@/components/dashboard/OrgSwitcher";
import { ThemeToggle } from "@/components/ui/theme-toggle";
import { OfflineBanner } from "@/components/ui/offline-banner";
import { ImpersonationBanner } from "@/components/dashboard/ImpersonationBanner";
import { CommandPalette } from "@/components/dashboard/CommandPalette";
import { SupportWidget } from "@/components/dashboard/SupportWidget";
import { ShortcutHelp } from "@/components/dashboard/ShortcutHelp";
import { FolderGit2, LayoutDashboard, LogOut, Menu, Plug, Radar, Settings, ShieldCheck, Users, X } from "lucide-react";

const navItems = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/projects", label: "Projects", icon: FolderGit2 },
  { href: "/intelligence", label: "Intelligence", icon: Radar },
  { href: "/organizations", label: "Teams", icon: Users },
  { href: "/integrations", label: "Integrations", icon: Plug },
  { href: "/settings", label: "Settings", icon: Settings },
];

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { data: session } = useSession();
  const [mobileOpen, setMobileOpen] = useState(false);

  const isActive = (href: string) => (href === "/" ? pathname === "/" : pathname.startsWith(href));

  return (
    <div className="min-h-screen">
      <ImpersonationBanner />
      <OfflineBanner />
      <header className="sticky top-0 z-40 border-b bg-background/95 backdrop-blur">
        <div className="container flex h-16 items-center justify-between">
          <div className="flex items-center gap-8">
            <Button
              variant="ghost" size="icon" className="md:hidden"
              onClick={() => setMobileOpen((o) => !o)}
              aria-label="Toggle navigation" aria-expanded={mobileOpen}
            >
              {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </Button>
            <Link href="/" className="flex items-center gap-2 font-semibold">
              <span className="flex h-8 w-8 items-center justify-center rounded-md bg-primary text-primary-foreground">
                <ShieldCheck className="h-5 w-5" />
              </span>
              Aegis
            </Link>
            <nav className="hidden items-center gap-1 md:flex">
              {navItems.map((item) => {
                const Icon = item.icon;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={cn(
                      "flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                      isActive(item.href) ? "bg-secondary text-foreground" : "text-muted-foreground hover:text-foreground",
                    )}
                  >
                    <Icon className="h-4 w-4" />
                    {item.label}
                  </Link>
                );
              })}
            </nav>
          </div>
          <div className="flex items-center gap-2">
            <OrgSwitcher />
            <ThemeToggle />
            <span className="hidden text-sm text-muted-foreground lg:inline">{session?.user?.email}</span>
            <Button variant="ghost" size="icon" onClick={() => signOut({ callbackUrl: "/login" })} aria-label="Sign out">
              <LogOut className="h-4 w-4" />
            </Button>
          </div>
        </div>

        {/* Mobile nav drawer */}
        {mobileOpen ? (
          <nav className="border-t bg-background md:hidden">
            <div className="container flex flex-col py-2">
              {navItems.map((item) => {
                const Icon = item.icon;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    onClick={() => setMobileOpen(false)}
                    className={cn(
                      "flex items-center gap-2 rounded-md px-3 py-2.5 text-sm font-medium transition-colors",
                      isActive(item.href) ? "bg-secondary text-foreground" : "text-muted-foreground hover:text-foreground",
                    )}
                  >
                    <Icon className="h-4 w-4" />
                    {item.label}
                  </Link>
                );
              })}
            </div>
          </nav>
        ) : null}
      </header>

      <main className="container py-8">{children}</main>

      {/* Global helpers */}
      <CommandPalette />
      <SupportWidget />
      <ShortcutHelp />
    </div>
  );
}
