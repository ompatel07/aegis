// NextAuth configuration: credential login against the Go API, with JWT-based
// sessions that carry the API access/refresh tokens and auto-refresh on expiry.
import type { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import axios from "axios";
import type { AuthResponse, TokenPair } from "./types";

// Server-side calls use the internal service URL (container network).
const INTERNAL_API = process.env.API_INTERNAL_URL || "http://api:8080/api/v1";

async function refreshAccessToken(refreshToken: string): Promise<TokenPair> {
  const res = await axios.post<{ data: TokenPair }>(`${INTERNAL_API}/auth/refresh`, {
    refresh_token: refreshToken,
  });
  return res.data.data;
}

export const authOptions: NextAuthOptions = {
  session: { strategy: "jwt" },
  pages: { signIn: "/login" },
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) return null;
        try {
          const res = await axios.post<{ data: AuthResponse }>(`${INTERNAL_API}/auth/login`, {
            email: credentials.email,
            password: credentials.password,
          });
          const { user, tokens } = res.data.data;
          return {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role,
            plan: user.plan,
            accessToken: tokens.access_token,
            refreshToken: tokens.refresh_token,
            accessTokenExpires: Date.now() + tokens.expires_in * 1000,
          };
        } catch {
          // Returning null surfaces as an "invalid credentials" error to the UI.
          return null;
        }
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      // Initial sign-in: copy fields from the authorized user.
      if (user) {
        return { ...token, ...user };
      }
      // Still valid (60s safety margin) — reuse.
      if (token.accessTokenExpires && Date.now() < (token.accessTokenExpires as number) - 60_000) {
        return token;
      }
      // Expired — attempt a refresh.
      try {
        const refreshed = await refreshAccessToken(token.refreshToken as string);
        return {
          ...token,
          accessToken: refreshed.access_token,
          refreshToken: refreshed.refresh_token,
          accessTokenExpires: Date.now() + refreshed.expires_in * 1000,
        };
      } catch {
        return { ...token, error: "RefreshAccessTokenError" };
      }
    },
    async session({ session, token }) {
      session.accessToken = token.accessToken as string;
      session.error = token.error as string | undefined;
      if (session.user) {
        session.user.id = token.id as string;
        session.user.role = token.role as string;
        session.user.plan = token.plan as string;
      }
      return session;
    },
  },
};
