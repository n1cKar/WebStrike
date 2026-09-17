import { cookies } from "next/headers";
import { createSessionSchema } from "@webstrike/validation";
import { checkCsrf } from "@/lib/api/csrf";
import { jsonError, jsonOk, readJson, zodErrorResponse } from "@/lib/api/responses";
import { getCurrentUser } from "@/lib/auth/current-user";
import { audit } from "@/lib/logging/audit";
import { buildScope, deriveDomainsFromTarget, selfCheckTarget } from "@/lib/scope";
import {
  TESTING_SESSION_COOKIE,
  createTestingSessionToken,
  newSessionId,
  readTestingSessionToken,
  testingSessionCookieOptions,
  withDerivedStatus,
} from "@/lib/session/testing-session";
import type { TestingSession } from "@webstrike/types";

export const runtime = "nodejs";

export async function GET() {
  const user = await getCurrentUser();
  if (!user) return jsonError(401, "UNAUTHENTICATED", "sign in required");

  const store = await cookies();
  const token = store.get(TESTING_SESSION_COOKIE)?.value;
  if (!token) return jsonOk({ session: null });

  const session = await readTestingSessionToken(token);
  if (!session || session.ownerId !== user.sub) {
    return jsonOk({ session: null });
  }
  return jsonOk({ session: withDerivedStatus(session) });
}

export async function POST(request: Request) {
  const csrf = checkCsrf(request);
  if (!csrf.ok) return jsonError(403, "CSRF", csrf.reason ?? "request refused");

  const user = await getCurrentUser();
  if (!user) return jsonError(401, "UNAUTHENTICATED", "sign in required");

  const body = await readJson(request);
  const parsed = createSessionSchema.safeParse(body);
  if (!parsed.success) return zodErrorResponse(parsed.error);

  const allowedDomains = parsed.data.allowedDomains.length
    ? parsed.data.allowedDomains
    : deriveDomainsFromTarget(parsed.data.targetUrl);

  if (allowedDomains.length === 0) {
    return jsonError(
      422,
      "SCOPE_EMPTY",
      "provide at least one allowed domain (or a target URL with a hostname)",
    );
  }

  const scope = buildScope({
    allowedDomains,
    allowedPaths: parsed.data.allowedPaths,
    blockedDomains: parsed.data.blockedDomains,
  });

  const self = selfCheckTarget(parsed.data.targetUrl, scope);
  if (!self.ok) {
    audit({ event: "session.create", actor: user.email, outcome: "deny", reason: self.message });
    return jsonError(422, "TARGET_OUT_OF_SCOPE", self.message);
  }

  const now = Date.now();
  const session: TestingSession = {
    id: newSessionId(),
    name: parsed.data.name,
    targetUrl: parsed.data.targetUrl,
    allowedDomains: scope.allowedDomains,
    allowedPaths: scope.allowedPaths,
    blockedDomains: scope.blockedDomains,
    testingIdentity: parsed.data.testingIdentity,
    authorizationConfirmation: true,
    startTime: now,
    expiresAt: now + parsed.data.durationHours * 60 * 60 * 1000,
    status: "active",
    createdAt: now,
    ownerId: user.sub,
  };

  const token = await createTestingSessionToken(session, now);
  const store = await cookies();
  store.set(
    TESTING_SESSION_COOKIE,
    token,
    testingSessionCookieOptions(session.expiresAt, now),
  );

  audit({
    event: "session.create",
    actor: user.email,
    target: session.targetUrl,
    outcome: "allow",
    meta: { allowedDomains: session.allowedDomains.length, allowedPaths: session.allowedPaths.length },
  });

  return jsonOk({ session }, 201);
}

export async function DELETE(request: Request) {
  const csrf = checkCsrf(request);
  if (!csrf.ok) return jsonError(403, "CSRF", csrf.reason ?? "request refused");

  const user = await getCurrentUser();
  if (!user) return jsonError(401, "UNAUTHENTICATED", "sign in required");

  const store = await cookies();
  store.delete(TESTING_SESSION_COOKIE);
  audit({ event: "session.end", actor: user.email, outcome: "allow" });
  return jsonOk({ ok: true });
}