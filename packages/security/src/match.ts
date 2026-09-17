import {
  BLOCKED_HOSTNAME_NAMES,
  BLOCKED_HOSTNAME_SUFFIXES,
} from "./constants";

/**
 * Pure, dependency-free host matching. Safe to import in the browser
 * (no node:net, no DNS). The authoritative scope decision still happens
 * server-side in ./scope.ts.
 */

export type DomainPatternMatch = {
  type: "apex" | "subdomain";
  matched: string;
};

export function normalizeHost(host: string): string {
  return host.replace(/\.$/, "").toLowerCase();
}

export function normalizePattern(pattern: string): string {
  return pattern.trim().replace(/\.$/, "").toLowerCase();
}

const WILDCARD = "*.";

export function hostMatchesPattern(
  host: string,
  pattern: string,
): DomainPatternMatch | null {
  const h = normalizeHost(host);
  const p = normalizePattern(pattern);

  if (p.startsWith(WILDCARD)) {
    const base = p.slice(WILDCARD.length);
    if (base === h) return null;
    if (h.endsWith(`.${base}`)) return { type: "subdomain", matched: base };
    return null;
  }

  if (h === p) return { type: "apex", matched: p };
  if (h.endsWith(`.${p}`)) return { type: "subdomain", matched: p };
  return null;
}

export function isBlockedHost(
  host: string,
  blocked: readonly string[],
): { blocked: boolean; pattern?: string } {
  for (const pattern of blocked) {
    if (hostMatchesPattern(host, pattern)) {
      return { blocked: true, pattern };
    }
  }
  return { blocked: false };
}

export function isSystemBlockedHostname(host: string): string | null {
  const h = normalizeHost(host);
  const bare = h.replace(/^www\./, "");
  if (BLOCKED_HOSTNAME_NAMES.includes(bare) || BLOCKED_HOSTNAME_NAMES.includes(h)) {
    return `${h} is an internal/reserved hostname and is always refused`;
  }
  for (const suffix of BLOCKED_HOSTNAME_SUFFIXES) {
    if (h === suffix.slice(1) || h.endsWith(suffix)) {
      return `${h} is a reserved internal namespace${suffix} and is always refused`;
    }
  }
  return null;
}

export interface ClientScopeCheck {
  ok: boolean;
  message: string;
}

/**
 * Best-effort, client-side preview of the scope decision. The server performs
 * the real check (including DNS/SSRF); this only drives live UI feedback.
 */
export function previewScope(input: {
  targetUrl: string;
  allowedDomains: string[];
  allowedPaths: string[];
  blockedDomains: string[];
}): ClientScopeCheck {
  let url: URL;
  try {
    url = new URL(input.targetUrl);
  } catch {
    return { ok: false, message: "enter an absolute URL, e.g. https://app.example.com" };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, message: "only http and https targets are supported" };
  }

  const host = normalizeHost(url.hostname.replace(/^\[/, "").replace(/\]$/, ""));
  const system = isSystemBlockedHostname(host);
  if (system) return { ok: false, message: system };

  if (isBlockedHost(host, input.blockedDomains).blocked) {
    return { ok: false, message: `host ${host} is explicitly blocked` };
  }

  const allowed = input.allowedDomains.length
    ? input.allowedDomains
    : [host];
  if (!allowed.some((p) => hostMatchesPattern(host, p))) {
    return {
      ok: false,
      message: `host ${host} does not match any allowed domain pattern`,
    };
  }

  const path = url.pathname === "" ? "/" : url.pathname;
  const paths = input.allowedPaths.length ? input.allowedPaths : ["/"];
  if (
    !paths.some((prefix) => path === prefix || path.startsWith(prefix === "/" ? "/" : prefix))
  ) {
    return { ok: false, message: `path ${path} is outside the allowed path prefixes` };
  }

  return { ok: true, message: `target ${host}${path} is inside the configured scope` };
}