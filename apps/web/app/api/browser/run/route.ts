import { cookies } from "next/headers";
import { browserRunSchema } from "@webstrike/validation";
import { CdpBrowserDriver, runBrowserChecks } from "@webstrike/testing";
import { checkCsrf } from "@/lib/api/csrf";
import { jsonError, jsonOk, readJson, zodErrorResponse } from "@/lib/api/responses";
import { getActor } from "@/lib/auth/actor";
import { browserConfigured, getBrowserConfig } from "@/lib/browser/config";
import { audit } from "@/lib/logging/audit";
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

const RATE_LIMIT = 10;
const RATE_WINDOW_MS = 5 * 60_000;
const MAX_IN_FLIGHT = 1;

export async function POST(request: Request) {
  const csrf = checkCsrf(request);
  if (!csrf.ok) return jsonError(403, "CSRF", csrf.reason ?? "request refused");

  const actor = await getActor();
  if (!actor) return jsonError(401, "UNAUTHENTICATED", "sign in required");

  const rateKey = actorRateKey(actor, request);

  if (!browserConfigured()) {
    return jsonError(
      503,
      "BROWSER_NOT_CONFIGURED",
      "no browser endpoint is configured — set BROWSER_WS_ENDPOINT to enable browser checks",
    );
  }

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

  const rate = checkRateLimit(`browser:${rateKey}`, RATE_LIMIT, RATE_WINDOW_MS);
  if (!rate.ok) {
    audit({ event: "security.refuse", actor: actor.email, outcome: "deny", reason: "rate limit" });
    return jsonError(429, "RATE_LIMITED", "too many browser runs — retry in a few minutes");
  }

  const body = await readJson(request);
  const parsed = browserRunSchema.safeParse(body ?? {});
  if (!parsed.success) return zodErrorResponse(parsed.error);

  if (!acquireSlot(`browser:${rateKey}`, MAX_IN_FLIGHT)) {
    return jsonError(429, "CONCURRENCY_LIMIT", "a browser run is already in progress");
  }

  const config = getBrowserConfig();
  if (!config) {
    releaseSlot(`browser:${rateKey}`);
    return jsonError(503, "BROWSER_NOT_CONFIGURED", "browser endpoint is not configured");
  }

  let driver: CdpBrowserDriver | null = null;
  try {
    driver = await CdpBrowserDriver.create(config);
    const outcome = await runBrowserChecks(session.targetUrl, driver, scopeOf(session), {
      maxPages: parsed.data.maxPages,
      timeoutMs: parsed.data.timeoutMs,
      screenshot: parsed.data.screenshot,
    });

    audit({
      event: "request.execute",
      actor: actor.email,
      target: new URL(session.targetUrl).host,
      outcome: "allow",
      meta: {
        mode: "browser",
        pages: outcome.stats.pages,
        observations: outcome.observations.length,
        errors: outcome.stats.errors,
      },
    });

    return jsonOk({ outcome });
  } catch (error) {
    audit({
      event: "security.refuse",
      actor: actor.email,
      target: new URL(session.targetUrl).host,
      outcome: "deny",
      reason: error instanceof Error ? error.message : "browser run failed",
    });
    return jsonError(
      502,
      "BROWSER_RUN_FAILED",
      error instanceof Error ? error.message : "browser run failed",
    );
  } finally {
    if (driver) {
      try {
        await driver.close();
      } catch {
        /* best effort */
      }
    }
    releaseSlot(`browser:${rateKey}`);
  }
}
