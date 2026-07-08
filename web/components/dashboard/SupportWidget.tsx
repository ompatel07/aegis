"use client";

import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { useToast } from "@/lib/use-toast";
import { HelpCircle, MessageSquarePlus } from "lucide-react";

/** Floating help/support button (bottom-right) → submits a ticket to the admin inbox. */
export function SupportWidget() {
  const api = useApi();
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const [subject, setSubject] = useState("");
  const [message, setMessage] = useState("");

  const submit = useMutation({
    mutationFn: () => api.submitSupportTicket({ subject, message }),
    onSuccess: () => {
      toast.success("Message sent", "We'll get back to you by email.");
      setSubject("");
      setMessage("");
      setOpen(false);
    },
    onError: (e: Error) => toast.error("Couldn't send", e.message),
  });

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        aria-label="Help & support"
        className="fixed bottom-5 right-5 z-[80] flex h-11 w-11 items-center justify-center rounded-full bg-primary text-primary-foreground shadow-lg transition-transform hover:scale-105"
      >
        <HelpCircle className="h-5 w-5" />
      </button>

      <Dialog open={open} onClose={() => setOpen(false)} className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <MessageSquarePlus className="h-5 w-5" /> Contact support
          </DialogTitle>
          <DialogDescription>Tell us what&apos;s up — question, bug, or feedback. We reply by email.</DialogDescription>
        </DialogHeader>
        <div className="mt-3 space-y-3">
          <div>
            <label className="mb-1 block text-sm font-medium">Subject</label>
            <Input value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="Short summary" />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium">Message</label>
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              rows={5}
              placeholder="Describe the issue or idea…"
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring"
            />
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
            <Button disabled={!subject || !message || submit.isPending} onClick={() => submit.mutate()}>
              {submit.isPending ? "Sending…" : "Send message"}
            </Button>
          </div>
        </div>
      </Dialog>
    </>
  );
}
