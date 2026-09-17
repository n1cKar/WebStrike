import { isIP } from "node:net";
import type { ScopeCheckResult, TestingScope } from "@webstrike/types";
import {
  hostMatchesPattern,
  isBlockedHost,
  isSystemBlockedHostname,
  normalizeHost,
  type DomainPatternMatch,
} from "./match";

export {
  hostMatchesPattern,
  isBlockedHost,
  isSystemBlockedHostname,
  normalizeHost,
  normalizePattern,
  type DomainPatternMatch,
} from "./match";

/** Host portion of a URL, bracketed IPv6 stripped. */
export function hostFromUrl(url: URL): string {
  return normalizeHost(url.hostname.replace(/^\[/, "").replace(/\]$/, ""));
}

const ipv4Guard = isIP("192.168.1.1") === 4;

function hostIsIpLiteral(host: string): boolean {
  return isIP(host) !== 0 || host.includes(":");
}

/**
 * Full scope validation for a URL *without* contacting the network.
 * Checks: scheme, structure, blocked hosts, allowed domains and allowed paths.
 */
export function validateScopedUrl(
  urlInput: string,
  scope: TestingScope,
): ScopeCheckResult & { url?: URL; host?: string } {
  let url: URL;
  try {
    url = new URL(urlInput);
  } catch {
    return { ok: false, reason: "malformed URL — could not parse" };
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, reason: `scheme ${url.protocol} is not allowed (http/https only)` };
  }

  if (!url.hostname) {
    return { ok: false, reason: "URL has no hostname" };
  }

  if (url.username || url.password) {
    return { ok: false, reason: "URLs containing embedded credentials are refused" };
  }

  if (url.port !== "" && (Number(url.port) < 1 || Number(url.port) > 65535)) {
    return { ok: false, reason: `port ${url.port} is invalid` };
  }

  const host = hostFromUrl(url);

  const system = isSystemBlockedHostname(host);
  if (system) return { ok: false, reason: system };

  const userBlocked = isBlockedHost(host, scope.blockedDomains);
  if (userBlocked.blocked) {
    return {
      ok: false,
      reason: `host ${host} is blocked explicitly (pattern ${userBlocked.pattern})`,
    };
  }

  let scopeKind: "exact" | "subdomain" | "ip-literal" = "exact";
  let matchedAllowed: DomainPatternMatch | null = null;

  if (hostIsIpLiteral(host)) {
    for (const pattern of scope.allowedDomains) {
      if (hostMatchesPattern(host, pattern)) {
        matchedAllowed = { type: "apex", matched: host };
        scopeKind = "ip-literal";
        break;
      }
    }
    if (!matchedAllowed) {
      return {
        ok: false,
        reason: `IP literal ${host} is not in the authorised target scope`,
      };
    }
  } else {
    for (const pattern of scope.allowedDomains) {
      const m = hostMatchesPattern(host, pattern);
      if (m) {
        matchedAllowed = m;
        scopeKind = m.type === "apex" ? "exact" : "subdomain";
        break;
      }
    }
    if (!matchedAllowed) {
      return {
        ok: false,
        reason: `host ${host} is not within the authorised target scope (allowed: ${scope.allowedDomains.join(", ")})`,
      };
    }
  }

  const pathname = url.pathname === "" ? "/" : url.pathname;
  const scopePaths = scope.allowedPaths.length ? scope.allowedPaths : ["/"];
  const pathOk = scopePaths.some((p) => {
    const prefix = p === "/" ? "/" : p;
    return pathname === prefix || pathname.startsWith(prefix);
  });

  if (!pathOk) {
    return {
      ok: false,
      reason: `path ${pathname} is outside the authorised scope (allowed paths: ${scopePaths.join(", ")})`,
    };
  }

  return {
    ok: true,
    reason: `in-scope (${scopeKind}${scope.allowedPaths.length ? " with path restriction" : ""})`,
    url,
    host,
  };
}

void ipv4Guard;