/**
 * Secret redaction for evidence.
 *
 * Evidence is shown in the UI and kept in memory, so credential material must
 * never appear verbatim. We mask values while preserving the surrounding
 * structure (header/parameter names) so the evidence still explains itself.
 */

const SENSITIVE_HEADERS = new Set([
  "cookie",
  "set-cookie",
  "authorization",
  "proxy-authorization",
  "x-api-key",
  "api-key",
  "apikey",
  "x-auth-token",
  "x-access-token",
  "x-csrf-token",
  "x-xsrf-token",
]);

const SENSITIVE_PARAMS = new Set([
  "token",
  "access_token",
  "refresh_token",
  "id_token",
  "api_key",
  "apikey",
  "key",
  "secret",
  "client_secret",
  "password",
  "passwd",
  "pwd",
  "auth",
  "authorization",
  "session",
  "sessionid",
  "sid",
  "csrf",
  "csrf_token",
  "xsrf",
  "signature",
  "sig",
]);

/** Mask a single secret value, keeping a short non-identifying hint. */
export function maskValue(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "«empty»";
  if (trimmed.length <= 4) return "«redacted»";
  return "«redacted»";
}

/**
 * Redact a header value. Cookie/Set-Cookie keep their names so the shape of the
 * session is visible but every value is masked.
 */
export function redactHeaderValue(name: string, value: string): string {
  const lower = name.toLowerCase();
  if (SENSITIVE_HEADERS.has(lower)) {
    if (lower === "cookie" || lower === "set-cookie") {
      return value
        .split(";")
        .map((part) => {
          const eq = part.indexOf("=");
          if (eq === -1) return part.trim();
          return `${part.slice(0, eq).trim()}=«redacted»`;
        })
        .join("; ");
    }
    if (/^bearer\s/i.test(value)) return "Bearer «redacted»";
    return "«redacted»";
  }
  return value;
}

/** Redact sensitive query parameters in a URL, leaving the rest intact. */
export function redactUrl(rawUrl: string): string {
  try {
    const url = new URL(rawUrl);
    for (const key of [...url.searchParams.keys()]) {
      if (SENSITIVE_PARAMS.has(key.toLowerCase())) {
        url.searchParams.set(key, "«redacted»");
      }
    }
    return url.toString();
  } catch {
    return rawUrl;
  }
}

const BEARER = /\b(bearer)\s+[A-Za-z0-9._~+/=-]{12,}/gi;
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
const HEX_TOKEN = /\b[0-9a-f]{32,64}\b/gi;
const ASSIGNMENT =
  /((?:password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key)["']?\s*[:=]\s*["']?)([^"'\s,;&]{4,})/gi;
const PEM = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g;

/**
 * Redact credential material from free text (bodies, details). Deterministic
 * and conservative: it never tries to be clever, it just refuses to echo
 * something that looks like a secret.
 */
export function redactText(text: string): string {
  return text
    .replace(PEM, "«redacted private key»")
    .replace(BEARER, "$1 «redacted»")
    .replace(JWT, "«redacted jwt»")
    .replace(ASSIGNMENT, "$1«redacted»")
    .replace(HEX_TOKEN, "«redacted hex»");
}

/** Redact a list of request headers, preserving order. */
export function redactHeaders(
  headers: { name: string; value: string }[],
): { name: string; value: string }[] {
  return headers.map((h) => ({ name: h.name, value: redactHeaderValue(h.name, h.value) }));
}
