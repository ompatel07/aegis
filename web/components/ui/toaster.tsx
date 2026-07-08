"use client";

import { CheckCircle2, Info, X, XCircle } from "lucide-react";
import { useToastStore, type ToastVariant } from "@/lib/use-toast";
import { cn } from "@/lib/utils";

const VARIANT: Record<ToastVariant, { icon: typeof Info; class: string }> = {
  default: { icon: Info, class: "border-border" },
  success: { icon: CheckCircle2, class: "border-emerald-500/40" },
  error: { icon: XCircle, class: "border-destructive/50" },
  info: { icon: Info, class: "border-primary/40" },
};

const ICON_COLOR: Record<ToastVariant, string> = {
  default: "text-muted-foreground",
  success: "text-emerald-500",
  error: "text-destructive",
  info: "text-primary",
};

/** Fixed toast stack. Mounted once in Providers. */
export function Toaster() {
  const toasts = useToastStore((s) => s.toasts);
  const dismiss = useToastStore((s) => s.dismiss);

  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-full max-w-sm flex-col gap-2">
      {toasts.map((t) => {
        const v = VARIANT[t.variant];
        const Icon = v.icon;
        return (
          <div
            key={t.id}
            role="status"
            className={cn(
              "pointer-events-auto flex items-start gap-3 rounded-lg border bg-card p-3 shadow-lg",
              "aegis-toast-in",
              v.class,
            )}
          >
            <Icon className={cn("mt-0.5 h-5 w-5 shrink-0", ICON_COLOR[t.variant])} />
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium">{t.title}</p>
              {t.description ? <p className="mt-0.5 text-sm text-muted-foreground">{t.description}</p> : null}
            </div>
            <button
              onClick={() => dismiss(t.id)}
              className="rounded p-0.5 text-muted-foreground transition-colors hover:text-foreground"
              aria-label="Dismiss notification"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
