"use client";

import { create } from "zustand";

export type ToastVariant = "default" | "success" | "error" | "info";

export interface Toast {
  id: number;
  title: string;
  description?: string;
  variant: ToastVariant;
}

interface ToastState {
  toasts: Toast[];
  push: (t: Omit<Toast, "id" | "variant"> & { variant?: ToastVariant; durationMs?: number }) => void;
  dismiss: (id: number) => void;
}

let counter = 0;

export const useToastStore = create<ToastState>((set, get) => ({
  toasts: [],
  push: ({ title, description, variant = "default", durationMs = 4000 }) => {
    const id = ++counter;
    set((s) => ({ toasts: [...s.toasts, { id, title, description, variant }] }));
    if (durationMs > 0) {
      setTimeout(() => get().dismiss(id), durationMs);
    }
  },
  dismiss: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
}));

/** Convenience hook: `const toast = useToast(); toast.success("Saved")`. */
export function useToast() {
  const push = useToastStore((s) => s.push);
  return {
    show: (title: string, description?: string) => push({ title, description }),
    success: (title: string, description?: string) => push({ title, description, variant: "success" }),
    error: (title: string, description?: string) => push({ title, description, variant: "error" }),
    info: (title: string, description?: string) => push({ title, description, variant: "info" }),
  };
}
