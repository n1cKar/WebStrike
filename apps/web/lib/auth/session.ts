import { SignJWT, jwtVerify } from "jose";
import { getAuthSecret } from "./secret";

export const AUTH_COOKIE = "ws_auth";
export const AUTH_MAX_AGE_SECONDS = 60 * 60 * 24 * 7;

export interface AuthTokenPayload {
  sub: string;
  email: string;
}

export async function createAuthToken(payload: AuthTokenPayload): Promise<string> {
  return new SignJWT({ email: payload.email })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setSubject(payload.sub)
    .setIssuedAt()
    .setExpirationTime(`${AUTH_MAX_AGE_SECONDS}s`)
    .setIssuer("webstrike")
    .setAudience("webstrike-app")
    .sign(getAuthSecret());
}

export async function verifyAuthToken(token: string): Promise<AuthTokenPayload | null> {
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, getAuthSecret(), {
      issuer: "webstrike",
      audience: "webstrike-app",
    });
    if (typeof payload.sub !== "string" || typeof payload.email !== "string") return null;
    return { sub: payload.sub, email: payload.email };
  } catch {
    return null;
  }
}

export function authCookieOptions(maxAge = AUTH_MAX_AGE_SECONDS) {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    path: "/",
    maxAge,
  };
}