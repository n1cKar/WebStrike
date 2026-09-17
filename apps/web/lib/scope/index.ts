import type { TestingScope } from "@webstrike/types";
import {
  hostMatchesPattern,
  isSystemBlockedHostname,
  validateScopedUrl,
} from "@webstrike/security";

export { hostMatchesPattern, isSystemBlockedHostname, validateScopedUrl };

/**
 * Build an enforced scope from operator input. The system hostname denylist is
 * always applied inside the security core, so it is not duplicated here.
 */
export function buildScope(input: {
  allowedDomains: string[];
  allowedPaths: string[];
  blockedDomains: string[];
}): TestingScope {
  return {
    allowedDomains: input.allowedDomains.map((d) => d.trim()).filter(Boolean),
    allowedPaths: input.allowedPaths.length ? input.allowedPaths : ["/"],
    blockedDomains: input.blockedDomains.map((d) => d.trim()).filter(Boolean),
  };
}

/** Derive a sensible default allowed-domain list from the target URL. */
export function deriveDomainsFromTarget(targetUrl: string): string[] {
  try {
    const url = new URL(targetUrl);
    if (url.protocol !== "http:" && url.protocol !== "https:") return [];
    const host = url.hostname.replace(/^\[/, "").replace(/\]$/, "");
    return host ? [host] : [];
  } catch {
    return [];
  }
}

/** Explain, for the UI, whether the target itself passes scope validation. */
export function selfCheckTarget(targetUrl: string, scope: TestingScope) {
  const result = validateScopedUrl(targetUrl, scope);
  return result.ok
    ? { ok: true as const, message: `target ${targetUrl} is inside the configured scope` }
    : { ok: false as const, message: result.reason };
}