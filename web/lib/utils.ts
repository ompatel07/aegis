import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import type { Grade, Severity } from "./types";

/** Merge Tailwind class names, resolving conflicts. */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

/** Tailwind classes for a severity badge. */
export function severityClasses(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "bg-red-100 text-red-800 border-red-200";
    case "high":
      return "bg-orange-100 text-orange-800 border-orange-200";
    case "medium":
      return "bg-yellow-100 text-yellow-800 border-yellow-200";
    case "low":
      return "bg-blue-100 text-blue-800 border-blue-200";
    default:
      return "bg-gray-100 text-gray-700 border-gray-200";
  }
}

/** Tailwind text color for a letter grade. */
export function gradeColor(grade?: Grade): string {
  switch (grade) {
    case "A":
      return "text-green-600";
    case "B":
      return "text-lime-600";
    case "C":
      return "text-yellow-600";
    case "D":
      return "text-orange-600";
    case "F":
      return "text-red-600";
    default:
      return "text-muted-foreground";
  }
}

/** Tailwind text color for a 0-100 score. */
export function scoreColor(score?: number): string {
  if (score === undefined || score === null) return "text-muted-foreground";
  if (score >= 90) return "text-green-600";
  if (score >= 75) return "text-lime-600";
  if (score >= 60) return "text-yellow-600";
  if (score >= 40) return "text-orange-600";
  return "text-red-600";
}

/** Human-friendly relative-ish timestamp. */
export function formatDate(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** Format a duration in seconds as a compact human string. */
export function formatDuration(seconds?: number): string {
  if (seconds === undefined || seconds === null) return "—";
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}m ${s}s`;
}
