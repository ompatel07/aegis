import Link from "next/link";
import { ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";

export interface Crumb {
  label: string;
  href?: string;
}

/** Consistent breadcrumb trail for detail pages (org > project > scan > finding). */
export function Breadcrumbs({ items, className }: { items: Crumb[]; className?: string }) {
  return (
    <nav aria-label="Breadcrumb" className={cn("flex items-center gap-1 text-sm text-muted-foreground", className)}>
      {items.map((c, i) => {
        const last = i === items.length - 1;
        return (
          <span key={i} className="flex items-center gap-1">
            {c.href && !last ? (
              <Link href={c.href} className="truncate hover:text-foreground hover:underline">
                {c.label}
              </Link>
            ) : (
              <span className={cn("truncate", last && "font-medium text-foreground")} aria-current={last ? "page" : undefined}>
                {c.label}
              </span>
            )}
            {!last ? <ChevronRight className="h-3.5 w-3.5 shrink-0" /> : null}
          </span>
        );
      })}
    </nav>
  );
}
