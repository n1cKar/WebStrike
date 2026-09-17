import { cookies } from "next/headers";
import { createSessionSchema } from "@webstrike/validation";
import { checkCsrf } from "@/lib/api/csrf";
import { jsonError, jsonOk, readJson, zodErrorResponse } from "@/lib/api/responses";
import { getActor } from "@/lib/auth/actor";
import { audit } from "@/lib/logging/audit";
import { buildScope, deriveDomainsFromTarget, selfCheckTarget } from "@/lib/scope";
import { actorRateKey } from "@/lib/security/client-key";
import { checkRateLimit } from "@/lib/security/limits";
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

const SESSION_RATE_LIMIT = 20;
const SESSION_RATE_WINDOW_MS = 60_000;

export async function GET() {
  const actor = await getActor();
  if (!actor) return jsonError(401, "UNAUTHENTICATED", "sign in required");

  const store = await cookies();
  const token = store.get(TESTING_SESSION_COOKIE)?.value;
  if (!token) return jsonOk({ session: null });

  const session = await readTestingSessionToken(token);
  if (!session || session.ownerId !== actor.id) {
    return jsonOk({ session: null });
  }
  return jsonOk({ session: withDerivedStatus(session) });
}

export async function POST(request: Request) {
  const csrf = checkCsrf(request);
  if (!csrf.ok) return jsonError(403, "CSRF", csrf.reason ?? "request refused");

  const actor = await getActor();
  if (!actor) return jsonError(401, "UNAUTHENTICATED", "sign in required");

  const rate = checkRateLimit(
    `session:${actorRateKey(actor, request)}`,
    SESSION_RATE_LIMIT,
    SESSION_RATE_WINDOW_MS,
  );
  if (!rate.ok) {
    audit({ event: "security.refuse", actor: actor.email, outcome: "deny", reason: "rate limit" });
    return jsonError(429, "RATE_LIMITED", "too many sessions created — retry shortly");
  }

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
    audit({ event: "session.create", actor: actor.email, outcome: "deny", reason: self.message });
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
    ownerId: actor.id,
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
    actor: actor.email,
    target: session.targetUrl,
    outcome: "allow",
    meta: { allowedDomains: session.allowedDomains.length, allowedPaths: session.allowedPaths.length },
  });

  return jsonOk({ session }, 201);
}

export async function DELETE(request: Request) {
  const csrf = checkCsrf(request);
  if (!csrf.ok) return jsonError(403, "CSRF", csrf.reason ?? "request refused");

  const actor = await getActor();
  if (!actor) return jsonError(401, "UNAUTHENTICATED", "sign in required");

  const store = await cookies();
  store.delete(TESTING_SESSION_COOKIE);
  audit({ event: "session.end", actor: actor.email, outcome: "allow" });
  return jsonOk({ ok: true });
}