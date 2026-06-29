// Client-side helper for the public register endpoint (no token required).
// Uses the browser-facing API base URL (through nginx).
import axios from "axios";
import type { AuthResponse } from "./types";

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost/api/v1";

export async function registerUser(input: {
  name: string;
  email: string;
  password: string;
}): Promise<AuthResponse> {
  try {
    const res = await axios.post<{ data: AuthResponse }>(`${BASE_URL}/auth/register`, input);
    return res.data.data;
  } catch (err) {
    const ax = err as { response?: { data?: { error?: { message?: string } } }; message?: string };
    throw new Error(ax.response?.data?.error?.message || ax.message || "Registration failed");
  }
}
