"use client";

import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useApi } from "@/lib/use-api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/lib/use-toast";
import { ThumbsDown, ThumbsUp } from "lucide-react";

/** "How was this scan?" thumbs up/down + optional comment (product signal). */
export function ScanFeedback({ scanId }: { scanId: string }) {
  const api = useApi();
  const toast = useToast();
  const [rating, setRating] = useState<"up" | "down" | null>(null);
  const [comment, setComment] = useState("");
  const [done, setDone] = useState(false);

  const submit = useMutation({
    mutationFn: (r: "up" | "down") => api.submitScanFeedback(scanId, { rating: r, comment: comment || undefined }),
    onSuccess: () => { setDone(true); toast.success("Thanks for the feedback"); },
    onError: (e: Error) => toast.error("Couldn't submit", e.message),
  });

  if (done) {
    return <p className="text-sm text-muted-foreground">Thanks — your feedback helps us improve Aegis.</p>;
  }

  return (
    <div className="flex flex-wrap items-center gap-3">
      <span className="text-sm font-medium">How was this scan?</span>
      <div className="flex gap-1">
        <Button size="sm" variant={rating === "up" ? "default" : "outline"} onClick={() => setRating("up")} aria-label="Thumbs up">
          <ThumbsUp className="h-4 w-4" />
        </Button>
        <Button size="sm" variant={rating === "down" ? "default" : "outline"} onClick={() => setRating("down")} aria-label="Thumbs down">
          <ThumbsDown className="h-4 w-4" />
        </Button>
      </div>
      {rating ? (
        <>
          <Input placeholder="Optional comment…" value={comment} onChange={(e) => setComment(e.target.value)} className="h-9 max-w-xs" />
          <Button size="sm" disabled={submit.isPending} onClick={() => submit.mutate(rating)}>Submit</Button>
        </>
      ) : null}
    </div>
  );
}
