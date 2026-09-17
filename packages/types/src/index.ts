export type ScopeStatus = "active" | "expired" | "ended";

/**
 * DOMAIN PATTERN SEMANTICS
 * ------------------------
 * - `example.com`   matches `example.com` and every subdomain (`*.example.com`).
 * - `*.example.com` matches only subdomains (not the bare apex).
 * - An IPv4/IPv6 literal matches by equality after URL canonicalisation.
 * Matching is case-insensitive and ignores a single trailing dot.
 */
export type DomainPattern = string;

export interface TestingScope {
  /** Hosts that may be contacted. See DomainPattern semantics. */
  allowedDomains: DomainPattern[];
  /**
   * Allowed URL path prefixes (e.g. ["/api", "/"]). A request is allowed when
   * its pathname starts with at least one entry. Empty means "all paths".
   */
  allowedPaths: string[];
  /** Hosts excluded even if they would otherwise match an allowed domain. */
  blockedDomains: DomainPattern[];
}

export interface TestingSession {
  id: string;
  name: string;
  /** Full target URL used to seed the repeater (e.g. https://example.test). */
  targetUrl: string;
  allowedDomains: DomainPattern[];
  allowedPaths: string[];
  blockedDomains: DomainPattern[];
  /** Who is testing and under what authority (free text for the record). */
  testingIdentity: string;
  /** Operator confirms the target has authorised this testing. */
  authorizationConfirmation: true;
  startTime: number;
  expiresAt: number;
  status: ScopeStatus;
  createdAt: number;
  ownerId: string;
}

export type ScopeCheckResult =
  | { ok: true; reason: string }
  | { ok: false; reason: string };

export interface RequestedCookie {
  name: string;
  value: string;
  domain?: string;
  path?: string;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: "Strict" | "Lax" | "None";
  expires?: number;
  maxAge?: number;
}

export interface RawResponseCookie extends RequestedCookie {
  raw: string;
}

export type RequestMethod =
  | "GET"
  | "POST"
  | "PUT"
  | "PATCH"
  | "DELETE"
  | "HEAD"
  | "OPTIONS";

export interface HttpRequestSpec {
  id: string;
  method: RequestMethod;
  /** Absolute URL including scheme and host. */
  url: string;
  /** Extra query parameters appended to the URL by the client. */
  query?: Record<string, string>;
  headers: { name: string; value: string }[];
  cookies: RequestedCookie[];
  body?: string | null;
  contentType?: string | null;
}

export interface RedirectHop {
  from: string;
  to: string;
  status: number;
  reason: string;
}

export type RequestFailureKind =
  | "INVALID_URL"
  | "URL_PARSING"
  | "OUT_OF_SCOPE"
  | "SSRF_BLOCKED"
  | "DNS_FAILURE"
  | "TIMEOUT"
  | "NETWORK"
  | "RESPONSE_TOO_LARGE"
  | "INVALID_RESPONSE"
  | "ABORTED"
  | "INTERNAL";

export interface ScopedHttpResult {
  ok: boolean;
  finalUrl: string;
  status: number;
  statusText: string;
  redirected: boolean;
  redirectChain: RedirectHop[];
  headers: Record<string, string>;
  cookies: RawResponseCookie[];
  body: string;
  bodyBytes: number;
  bodyTruncated: boolean;
  timingMs: number;
  error?: {
    kind: RequestFailureKind;
    message: string;
    /** For OUT_OF_SCOPE / SSRF_BLOCKED / DNS_FAILURE — human readable detail. */
    detail?: string;
  };
}

export type HeaderAnalysis = "info" | "warning" | "good";

export interface HeaderObservation {
  header: string;
  present: boolean;
  value?: string;
  significance: HeaderAnalysis;
  message: string;
}

export interface CookieObservation {
  cookie: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
  domain?: string;
  path?: string;
  expires?: string;
  observations: string[];
}