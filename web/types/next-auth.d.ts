import "next-auth";
import "next-auth/jwt";

// Augment NextAuth types so the API tokens + user fields are typed everywhere.
declare module "next-auth" {
  interface Session {
    accessToken?: string;
    error?: string;
    user: {
      id: string;
      name?: string | null;
      email?: string | null;
      role?: string;
      plan?: string;
    };
  }

  interface User {
    id: string;
    role?: string;
    plan?: string;
    accessToken?: string;
    refreshToken?: string;
    accessTokenExpires?: number;
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    id?: string;
    role?: string;
    plan?: string;
    accessToken?: string;
    refreshToken?: string;
    accessTokenExpires?: number;
    error?: string;
  }
}
