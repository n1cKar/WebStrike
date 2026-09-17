import { cookies } from "next/headers";
import { requestSpecSchema } from "@webstrike/validation";
import { checkCsrf } from "@/lib/api/csrf";
import { jsonError, jsonOk, readJson, zodErrorResponse } from "@/lib/api/responses";
import { getActor } from "@/lib/auth/actor";
import { audit } from "@/lib/logging/audit";
import { executeScopedRequest } from "@/lib/http";
import { analyzeResponse } from "@/lib/analysis";
import { TESTING_SESSION_COOKIE, readTestingSessionToken, scopeOf } from "@/lib/session/testing-session";
import { actorRateKey } from "@/lib/security/client-key";
import { acquireSlot, checkRateLimit, releaseSlot } from "@/lib/security/limits";

export const runtime = "nodejs";

const RATE_LIMIT = 60;
const RATE_WINDOW_MS = 60_000;
const MAX_IN_FLIGHT = 4;

export async function POST(request: Request) {
  const csrf = checkCsrf(request);
  if (!csrf.ok) return jsonError(403, "CSRF", csrf.reason ?? "request refused");

  const actor = await getActor();
  if (!actor) return jsonError(401, "UNAUTHENTICATED", "sign in required");

  const rateKey = actorRateKey(actor, request);

  const store = await cookies();
  const token = store.get(TESTING_SESSION_COOKIE)?.value;
  const session = token ? await readTestingSessionToken(token) : null;

  if (!session || session.ownerId !== actor.id) {
    return jsonError(409, "NO_ACTIVE_SESSION", "create an authorised testing session first");
  }
  if (session.status === "expired") {
    return jsonError(410, "SESSION_EXPIRED", "the testing session has expired");
  }
  if (session.status === "ended") {
    return jsonError(409, "SESSION_ENDED", "the testing session has ended");
  }

  const rate = checkRateLimit(`req:${rateKey}`, RATE_LIMIT, RATE_WINDOW_MS);
  if (!rate.ok) {
    audit({ event: "security.refuse", actor: actor.email, outcome: "deny", reason: "rate limit" });
    return jsonError(429, "RATE_LIMITED", "too many requests — slow down and retry shortly");
  }

  const body = await readJson(request);
  const parsed = requestSpecSchema.safeParse(body);
  if (!parsed.success) return zodErrorResponse(parsed.error);

  if (!acquireSlot(`run:${rateKey}`, MAX_IN_FLIGHT)) {
    return jsonError(429, "CONCURRENCY_LIMIT", "too many concurrent tests for this session");
  }

  try {
    const result = await executeScopedRequest(parsed.data, scopeOf(session));

    if (!result.ok && result.error) {
      const refuseKinds = ["OUT_OF_SCOPE", "SSRF_BLOCKED", "DNS_FAILURE"] as const;
      if ((refuseKinds as readonly string[]).includes(result.error.kind)) {
        audit({
          event: "security.refuse",
          actor: actor.email,
          target: result.finalUrl,
          outcome: "deny",
          reason: `${result.error.kind}: ${result.error.detail ?? result.error.message}`,
        });
        return jsonError(
          result.error.kind === "OUT_OF_SCOPE" ? 403 : 400,
          result.error.kind,
          result.error.message,
          result.error.detail,
        );
      }
    }

    audit({
      event: "request.execute",
      actor: actor.email,
      target: new URL(parsed.data.url).host,
      outcome: "allow",
      meta: {
        method: parsed.data.method,
        status: result.status,
        timingMs: result.timingMs,
        bytes: result.bodyBytes,
      },
    });

    return jsonOk({ result, analysis: analyzeResponse(result) });
  } finally {
    releaseSlot(`run:${rateKey}`);
  }
}