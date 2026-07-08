"use client";

import { AlertTriangle } from "lucide-react";
import { Dialog, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { useConfirmStore } from "@/lib/use-confirm";

/** Global confirmation dialog host. Mounted once in Providers; driven by useConfirm(). */
export function ConfirmHost() {
  const { open, options, respond } = useConfirmStore();
  if (!open || !options) return null;

  return (
    <Dialog open={open} onClose={() => respond(false)} className="max-w-md">
      <DialogHeader>
        <div className="flex items-center gap-2">
          {options.destructive ? <AlertTriangle className="h-5 w-5 text-destructive" /> : null}
          <DialogTitle>{options.title}</DialogTitle>
        </div>
        {options.description ? <DialogDescription>{options.description}</DialogDescription> : null}
      </DialogHeader>
      <div className="mt-4 flex justify-end gap-2">
        <Button variant="outline" onClick={() => respond(false)}>
          {options.cancelLabel ?? "Cancel"}
        </Button>
        <Button variant={options.destructive ? "destructive" : "default"} onClick={() => respond(true)}>
          {options.confirmLabel ?? "Confirm"}
        </Button>
      </div>
    </Dialog>
  );
}
