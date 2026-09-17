import { NextResponse, type NextRequest } from "next/server";
import { AUTH_COOKIE, verifyAuthToken } from "@/lib/auth/session";

/**
 * Edge-level gate. This is a convenience redirect; the authoritative
 * authentication check happens server-side in the authenticated layout and in
 * every API route handler.
 */
const PROTECTED_PREFIXES = [
  "/dashboard",
  "/new-session",
  "/session",
  "/repeater",
  "/browser",
  "/automated",
  "/results",
  "/settings",
];

const AUTH_PAGES = ["/login", "/register"];

export async function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const isProtected = PROTECTED_PREFIXES.some(
    (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`),
  );
  const isAuthPage = AUTH_PAGES.includes(pathname);

  if (!isProtected && !isAuthPage) return NextResponse.next();

  const token = request.cookies.get(AUTH_COOKIE)?.value;
  const user = token ? await verifyAuthToken(token) : null;

  if (isProtected && !user) {
    const url = request.nextUrl.clone();
    url.pathname = "/login";
    url.search = "";
    return NextResponse.redirect(url);
  }

  if (isAuthPage && user) {
    const url = request.nextUrl.clone();
    url.pathname = "/dashboard";
    url.search = "";
    return NextResponse.redirect(url);
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    "/dashboard/:path*",
    "/new-session/:path*",
    "/session/:path*",
    "/repeater/:path*",
    "/browser/:path*",
    "/automated/:path*",
    "/results/:path*",
    "/settings/:path*",
    "/login",
    "/register",
  ],
};