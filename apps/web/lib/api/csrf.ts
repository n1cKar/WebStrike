/**
 * CSRF protection for JSON route handlers.
 *
 * The primary defence is the custom `x-webstrike-csrf` header: it cannot be
 * set by a cross-site form and forces a CORS preflight for cross-origin
 * callers. Origin / Sec-Fetch-Site checks are defence-in-depth, and the auth
 * cookie itself is SameSite=Lax.
 */

export const CSRF_HEADER = "x-webstrike-csrf";

export interface CsrfVerdict {
  ok: boolean;
  reason?: string;
}

export function checkCsrf(request: Request): CsrfVerdict {
  const token = request.headers.get(CSRF_HEADER);
  if (token !== "1") {
    return { ok: false, reason: `missing ${CSRF_HEADER} header` };
  }

  const site = request.headers.get("sec-fetch-site");
  if (site && site !== "same-origin" && site !== "none") {
    return { ok: false, reason: `cross-site request refused (sec-fetch-site: ${site})` };
  }

  const origin = request.headers.get("origin");
  const host = request.headers.get("host");
  if (origin && host) {
    try {
      if (new URL(origin).host !== host) {
        return { ok: false, reason: "origin does not match host" };
      }
    } catch {
      return { ok: false, reason: "malformed origin header" };
    }
  }

  return { ok: true };
}