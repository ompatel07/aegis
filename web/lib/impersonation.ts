"use client";

const KEY = "aegis.impersonation";
const EVENT = "aegis:impersonation";

export interface Impersonation {
  token: string;
  email: string;
  expiresAt: number; // epoch ms
}

/** Begin impersonating: store a short-lived token that useApi will prefer. */
export function startImpersonation(token: string, email: string, expiresInSec: number) {
  const rec: Impersonation = { token, email, expiresAt: Date.now() + expiresInSec * 1000 };
  localStorage.setItem(KEY, JSON.stringify(rec));
  window.dispatchEvent(new Event(EVENT));
}

export function stopImpersonation() {
  localStorage.removeItem(KEY);
  window.dispatchEvent(new Event(EVENT));
}

/** Returns the active impersonation, or null (auto-clears when expired). */
export function readImpersonation(): Impersonation | null {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return null;
    const rec = JSON.parse(raw) as Impersonation;
    if (!rec.token || Date.now() > rec.expiresAt) {
      localStorage.removeItem(KEY);
      return null;
    }
    return rec;
  } catch {
    return null;
  }
}

export const IMPERSONATION_EVENT = EVENT;
