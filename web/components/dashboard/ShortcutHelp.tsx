"use client";

import { useEffect, useState } from "react";
import { Dialog, DialogHeader, DialogTitle } from "@/components/ui/dialog";

const SHORTCUTS: [string, string][] = [
  ["⌘K / Ctrl+K", "Open command palette (quick navigation)"],
  ["?", "Show this shortcut help"],
  ["/", "Focus the findings search/filter"],
  ["Esc", "Close dialogs & palettes"],
  ["g then p", "Go to Projects"],
  ["g then i", "Go to Intelligence"],
];

function isTyping() {
  const el = document.activeElement as HTMLElement | null;
  return el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.isContentEditable);
}

/** Press "?" to view keyboard shortcuts. */
export function ShortcutHelp() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "?" && !isTyping()) {
        e.preventDefault();
        setOpen(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  if (!open) return null;
  return (
    <Dialog open={open} onClose={() => setOpen(false)} className="max-w-md">
      <DialogHeader>
        <DialogTitle>Keyboard shortcuts</DialogTitle>
      </DialogHeader>
      <div className="mt-3 space-y-2">
        {SHORTCUTS.map(([keys, desc]) => (
          <div key={keys} className="flex items-center justify-between gap-4 text-sm">
            <span className="text-muted-foreground">{desc}</span>
            <kbd className="whitespace-nowrap rounded border bg-muted px-2 py-0.5 text-xs">{keys}</kbd>
          </div>
        ))}
      </div>
    </Dialog>
  );
}
