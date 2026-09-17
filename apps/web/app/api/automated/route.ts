import { cookies } from "next/headers";
import { automatedRunSchema, type RunProfile } from "@webstrike/validation";
import {
  runAutomatedTests,
  type RequestExecutor,
  type RunBudget,
} from "@webstrike/testing";
import { checkCsrf } from "@/lib/api/csrf";
import { jsonError, readJson, zodErrorResponse } from "@/lib/api/responses";
import { getActor } from "@/lib/auth/actor";
import { audit } from "@/lib/logging/audit";
import { executeScopedRequest } from "@/lib/http";
import {
  TESTING_SESSION_COOKIE,
  readTestingSessionToken,
  scopeOf,
} from "@/lib/session/testing-session";
import { actorRateKey } from "@/lib/security/client-key";
import { acquireSlot, checkRateLimit, releaseSlot } from "@/lib/security/limits";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 300;

const RATE_LIMIT = 6;
const RATE_WINDOW_MS = 5 * 60_000;
const MAX_IN_FLIGHT = 2;

const PROFILES: Record<RunProfile, Omit<RunBudget, "activeTests">> = {
  quick: { maxRequests: 40, maxWallClockMs: 45_000, perRequestTimeoutMs: 8_000 },
  standard: { maxRequests: 120, maxWallClockMs: 120_000, perRequestTimeoutMs: 10_000 },
  deep: { maxRequests: 240, maxWallClockMs: 240_000, perRequestTimeoutMs: 12_000 },
};

export async function POST(request: Request) {
  const csrf = checkCsrf(request);
  if (!csrf.ok) return jsonError(403, "CSRF", csrf.reason ?? "request refused");

  const actor = await getActor();
  if (!actor) return jsonError(401, "UNAUTHENTICATED", "sign in required");

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

  const rateKey = actorRateKey(actor, request);
  const rate = checkRateLimit(`automated:${rateKey}`, RATE_LIMIT, RATE_WINDOW_MS);
  if (!rate.ok) {
    audit({ event: "security.refuse", actor: actor.email, outcome: "deny", reason: "rate limit" });
    return jsonError(429, "RATE_LIMITED", "too many automated runs — retry in a few minutes");
  }

  const body = await readJson(request);
  const parsed = automatedRunSchema.safeParse(body);
  if (!parsed.success) return zodErrorResponse(parsed.error);

  if (!acquireSlot(`automated:${rateKey}`, MAX_IN_FLIGHT)) {
    return jsonError(429, "CONCURRENCY_LIMIT", "an automated run is already in progress");
  }

  const scope = scopeOf(session);
  const profile = parsed.data.profile;
  const budget: RunBudget = { ...PROFILES[profile], activeTests: parsed.data.activeTests };

  const executor: RequestExecutor = (request_) =>
    executeScopedRequest(
      {
        id: request_.id,
        method: request_.method,
        url: request_.url,
        query: {},
        headers: request_.headers,
        cookies: request_.cookies,
        body: request_.body ?? null,
        contentType: request_.contentType ?? null,
      },
      scope,
      { timeoutMs: budget.perRequestTimeoutMs },
    );

  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (payload: unknown) => {
        controller.enqueue(encoder.encode(`${JSON.stringify(payload)}\n`));
      };
      try {
        const outcome = await runAutomatedTests(
          {
            targetUrl: session.targetUrl,
            scope,
            categories: parsed.data.categories,
            identities: parsed.data.identities,
            budget,
            workflow: parsed.data.workflow,
            openapi: parsed.data.openapi,
            seedPaths: parsed.data.seedPaths,
            onProgress: (progress) => send({ type: "progress", progress }),
          },
          executor,
        );

        audit({
          event: "request.execute",
          actor: actor.email,
          target: new URL(session.targetUrl).host,
          outcome: "allow",
          meta: {
            mode: "automated",
            profile,
            activeTests: parsed.data.activeTests,
            requests: outcome.stats.requests,
            observations: outcome.observations.length,
            truncated: outcome.stats.truncated,
          },
        });

        send({ type: "result", outcome });
      } catch (error) {
        send({
          type: "error",
          message: error instanceof Error ? error.message : "automated run failed",
        });
      } finally {
        releaseSlot(`automated:${rateKey}`);
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "content-type": "application/x-ndjson; charset=utf-8",
      "cache-control": "no-store, no-transform",
      "x-accel-buffering": "no",
    },
  });
}
