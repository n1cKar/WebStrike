import type { RequestMethod } from "@webstrike/types";
import type { DiscoveredEndpoint, EndpointClassification } from "./types";

/**
 * Deterministic endpoint classification. Classification decides which tests are
 * meaningful: a login page must never produce an "authentication bypass" just
 * because anonymous and authenticated responses match.
 */

const AUTH = /(^|\/)(login|signin|sign-in|auth|session)(\/|$)/i;
const REGISTRATION = /(^|\/)(register|signup|sign-up|create[-_]?account)(\/|$)/i;
const PASSWORD_RESET = /(forgot|reset|recover|new[-_]?password|password[-_]?reset)/i;
const ADMIN = /(^|\/)(admin|administrator|staff|manage|management|console|backoffice)(\/|$)/i;
const PRIVILEGED = /(^|\/)(settings|account|profile|billing|subscription|preferences)(\/|$)/i;
const API = /(^|\/)(api|graphql|rest|v[0-9]+)(\/|$)/i;
const WORKFLOW = /(checkout|cart|order|payment|pay|confirm|purchase|subscribe|process|approve)/i;
const PUBLIC_PAGE =
  /(^|\/)(about|help|support|privacy|terms|contact|legal|faq|pricing|blog|docs?|home|index)(\/|$)/i;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NUMERIC = /^\d{1,12}$/;
const ID_PARAM = /(^|[_-])(id|uid|uuid|guid|pk|key|ref|no|number)$/i;

/** Returns true when a value looks like an object reference (id/uid/uuid). */
export function looksLikeObjectId(value: string): boolean {
  return UUID.test(value) || NUMERIC.test(value);
}

/** Returns the name of a parameter that looks like an object reference. */
export function objectIdParam(
  params: { name: string; example?: string }[],
): { name: string; example?: string } | undefined {
  return params.find(
    (p) => ID_PARAM.test(p.name) && (p.example === undefined || looksLikeObjectId(p.example)),
  );
}

/** True when a URL path segment looks like an object reference. */
export function pathObjectId(pathname: string): string | undefined {
  const segments = pathname.split("/").filter(Boolean);
  for (let i = segments.length - 1; i >= 0; i -= 1) {
    if (looksLikeObjectId(segments[i]!)) return segments[i];
  }
  return undefined;
}

export function classifyUrl(
  url: string,
  method: RequestMethod = "GET",
  hasFileInput = false,
): EndpointClassification[] {
  let pathname = url;
  try {
    pathname = new URL(url).pathname;
  } catch {
    /* keep raw */
  }
  const out = new Set<EndpointClassification>();

  if (hasFileInput) out.add("FILE_UPLOAD");
  if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
    out.add("STATE_CHANGING");
  }
  if (API.test(pathname)) out.add("API");
  if (AUTH.test(pathname)) out.add("AUTHENTICATION");
  if (REGISTRATION.test(pathname)) out.add("REGISTRATION");
  if (PASSWORD_RESET.test(pathname)) out.add("PASSWORD_RESET");
  if (ADMIN.test(pathname)) out.add("ADMIN");
  if (PRIVILEGED.test(pathname)) out.add("PRIVILEGED");
  if (WORKFLOW.test(pathname)) out.add("WORKFLOW");

  const pathId = pathObjectId(pathname);
  let queryId: string | undefined;
  try {
    const params = [...new URL(url).searchParams.entries()].map(([name, example]) => ({
      name,
      example,
    }));
    queryId = objectIdParam(params)?.example;
  } catch {
    /* ignore */
  }
  if (pathId || queryId) out.add("RESOURCE_ACCESS");

  if (out.size === 0 || PUBLIC_PAGE.test(pathname)) out.add("PUBLIC");

  return [...out];
}

export function classifyEndpoint(endpoint: DiscoveredEndpoint): EndpointClassification[] {
  return classifyUrl(endpoint.url, endpoint.method, Boolean(endpoint.form?.hasFileInput));
}

export function hasClassification(
  classifications: EndpointClassification[] | undefined,
  value: EndpointClassification,
): boolean {
  return Boolean(classifications?.includes(value));
}

const AUTH_FLOW: EndpointClassification[] = [
  "AUTHENTICATION",
  "REGISTRATION",
  "PASSWORD_RESET",
];

/**
 * True for endpoints where "authentication boundary" checks are meaningless
 * (login/registration/reset flows and clearly public static pages).
 */
export function isAuthFlow(classifications: EndpointClassification[] | undefined): boolean {
  return Boolean(classifications?.some((c) => AUTH_FLOW.includes(c)));
}

export function isResourceAccess(classifications: EndpointClassification[] | undefined): boolean {
  return hasClassification(classifications, "RESOURCE_ACCESS");
}
