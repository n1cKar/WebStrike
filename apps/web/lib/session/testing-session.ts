import { SignJWT, jwtVerify } from "jose";
import type { TestingScope, TestingSession } from "@webstrike/types";
import { getAuthSecret } from "../auth/secret";

export const TESTING_SESSION_COOKIE = "ws_scope";

export type TestingSessionTokenPayload = TestingSession;

export function newSessionId(): string {
  return globalThis.crypto.randomUUID();
}

export function scopeOf(session: TestingSession): TestingScope {
  return {
    allowedDomains: session.allowedDomains,
    allowedPaths: session.allowedPaths,
    blockedDomains: session.blockedDomains,
  };
}

export function isExpired(session: TestingSession, now = Date.now()): boolean {
  return now >= session.expiresAt;
}

export function withDerivedStatus(
  session: TestingSession,
  now = Date.now(),
): TestingSession {
  if (session.status !== "ended" && isExpired(session, now)) {
    return { ...session, status: "expired" };
  }
  return session;
}

export async function createTestingSessionToken(
  session: TestingSession,
  now = Date.now(),
): Promise<string> {
  const ttlSeconds = Math.max(1, Math.floor((session.expiresAt - now) / 1000));
  return new SignJWT({
    sessionId: session.id,
    name: session.name,
    targetUrl: session.targetUrl,
    allowedDomains: session.allowedDomains,
    allowedPaths: session.allowedPaths,
    blockedDomains: session.blockedDomains,
    testingIdentity: session.testingIdentity,
    authorizationConfirmation: true,
    startTime: session.startTime,
    expiresAt: session.expiresAt,
    status: session.status,
    createdAt: session.createdAt,
    ownerId: session.ownerId,
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setSubject(session.id)
    .setIssuedAt()
    .setExpirationTime(`${ttlSeconds}s`)
    .setIssuer("webstrike")
    .setAudience("webstrike-testing-session")
    .sign(getAuthSecret());
}

export async function readTestingSessionToken(
  token: string,
): Promise<TestingSession | null> {
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, getAuthSecret(), {
      issuer: "webstrike",
      audience: "webstrike-testing-session",
    });

    const session: TestingSession = {
      id: String(payload.sessionId),
      name: String(payload.name),
      targetUrl: String(payload.targetUrl),
      allowedDomains: (payload.allowedDomains as string[]) ?? [],
      allowedPaths: (payload.allowedPaths as string[]) ?? [],
      blockedDomains: (payload.blockedDomains as string[]) ?? [],
      testingIdentity: String(payload.testingIdentity),
      authorizationConfirmation: true,
      startTime: Number(payload.startTime),
      expiresAt: Number(payload.expiresAt),
      status: (payload.status as TestingSession["status"]) ?? "active",
      createdAt: Number(payload.createdAt),
      ownerId: String(payload.ownerId),
    };

    if (!session.id || !session.targetUrl) return null;
    return withDerivedStatus(session);
  } catch {
    return null;
  }
}

export function testingSessionCookieOptions(expiresAt: number, now = Date.now()) {
  const maxAge = Math.max(0, Math.floor((expiresAt - now) / 1000));
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    path: "/",
    maxAge,
  };
}