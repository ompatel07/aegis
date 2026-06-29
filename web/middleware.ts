// Protect dashboard routes: unauthenticated users are redirected to /login.
// next-auth's withAuth checks the session JWT cookie at the edge.
export { default } from "next-auth/middleware";

export const config = {
  // Match everything except the auth pages, NextAuth API, and static assets.
  matcher: ["/((?!login|register|api/auth|_next/static|_next/image|favicon.ico).*)"],
};
