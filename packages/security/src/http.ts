import type {
  HttpRequestSpec,
  RawResponseCookie,
  RequestFailureKind,
  ScopedHttpResult,
  TestingScope,
} from "@webstrike/types";
import {
  MAX_HEADER_VALUE_BYTES,
  MAX_REDIRECTS,
  MAX_RESPONSE_HEADERS,
  MAX_RESPONSE_SIZE_BYTES,
  REQUEST_TIMEOUT_MS,
} from "./constants";
import { assertUrlRequestable } from "./ssrf";

export interface ScopedRequestOptions {
  timeoutMs?: number;
  maxRedirects?: number;
  maxResponseBytes?: number;
}

/** Headers the transport itself manages; operator-supplied values are dropped. */
const TRANSPORT_MANAGED_HEADERS = new Set([
  "host",
  "content-length",
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "expect",
]);

type HeaderRow = { name: string; value: string };

function buildHeaderList(
  headers: HeaderRow[],
  cookies: HttpRequestSpec["cookies"],
): HeaderRow[] {
  const list: HeaderRow[] = [];
  const seen = new Set<string>();
  let cookieParts: string[] = [];

  for (const { name, value } of headers) {
    const lower = name.toLowerCase();
    if (TRANSPORT_MANAGED_HEADERS.has(lower)) continue;
    if (lower === "cookie") {
      cookieParts.push(String(value));
      continue;
    }
    if (seen.has(lower)) continue;
    seen.add(lower);
    list.push({ name, value });
  }

  for (const c of cookies) {
    cookieParts.push(`${c.name}=${c.value}`);
  }

  if (cookieParts.length) {
    list.push({ name: "Cookie", value: cookieParts.join("; ") });
  }

  return list;
}

function parseSetCookie(raw: string): RawResponseCookie {
  const [head = "", ...attrs] = raw.split(";");
  const eq = head.indexOf("=");
  const name = eq === -1 ? head.trim() : head.slice(0, eq).trim();
  const value = eq === -1 ? "" : head.slice(eq + 1).trim();

  const cookie: RawResponseCookie = {
    name,
    value,
    raw,
    secure: false,
    httpOnly: false,
  };

  for (const attr of attrs) {
    const [k, ...rest] = attr.trim().split("=");
    const key = (k ?? "").trim().toLowerCase();
    const v = rest.join("=").trim();
    switch (key) {
      case "secure":
        cookie.secure = true;
        break;
      case "httponly":
        cookie.httpOnly = true;
        break;
      case "samesite":
        cookie.sameSite = v as RawResponseCookie["sameSite"];
        break;
      case "domain":
        cookie.domain = v;
        break;
      case "path":
        cookie.path = v;
        break;
      case "max-age": {
        const num = Number(v);
        if (Number.isFinite(num)) {
          cookie.maxAge = num;
          cookie.expires = Date.now() + num * 1000;
        }
        break;
      }
      case "expires":
        const t = Date.parse(v);
        if (Number.isFinite(t)) cookie.expires = t;
        break;
    }
  }
  return cookie;
}

function capHeaders(headers: Headers): { headers: Record<string, string>; cookies: RawResponseCookie[] } {
  const out: Record<string, string> = {};
  const cookies: RawResponseCookie[] = [];
  let count = 0;

  // undici lowercases header names.
  headers.forEach((value, name) => {
    if (count >= MAX_RESPONSE_HEADERS) return;
    if (name === "set-cookie") {
      // forEach on Headers yields combined value; split on the raw boundary.
      const rawCookies = value.split(/,(?=\s*[^=,\s]+=)/);
      for (const raw of rawCookies) {
        if (cookies.length >= 24) break;
        try {
          cookies.push(parseSetCookie(raw.trim()));
        } catch {
          /* ignore malformed single cookie */
        }
      }
      return;
    }
    count += 1;
    out[name] =
      value.length > MAX_HEADER_VALUE_BYTES
        ? value.slice(0, MAX_HEADER_VALUE_BYTES)
        : value;
  });

  return { headers: out, cookies };
}

async function readBodyLimited(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  limitBytes: number,
): Promise<{ text: string; bytes: number; truncated: boolean }> {
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  let truncated = false;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (bytes + value.length > limitBytes) {
      const remaining = limitBytes - bytes;
      chunks.push(value.slice(0, remaining));
      bytes = limitBytes;
      truncated = true;
      await reader.cancel();
      break;
    }
    chunks.push(value);
    bytes += value.length;
  }

  return { text: Buffer.concat(chunks).toString("utf8"), bytes, truncated };
}

interface RedirectDecision {
  action: "follow" | "stop" | "error";
  nextUrl?: string;
  message?: string;
  errorKind?: RequestFailureKind;
}

async function decideRedirect(
  status: number,
  location: string | null,
  currentUrl: string,
  scope: TestingScope,
): Promise<RedirectDecision> {
  if (!location) {
    return { action: "stop", message: "redirect without Location header" };
  }
  let next: URL;
  try {
    next = new URL(location, currentUrl);
  } catch {
    return {
      action: "error",
      message: "redirect Location header was not a valid URL",
      errorKind: "INVALID_RESPONSE",
    };
  }
  if (next.protocol !== "http:" && next.protocol !== "https:") {
    return {
      action: "error",
      message: `redirect to disallowed scheme ${next.protocol}`,
      errorKind: "INVALID_RESPONSE",
    };
  }

  const check = await assertUrlRequestable(next.toString(), scope);
  if (!check.ok) {
    return {
      action: "stop",
      message: `redirect destination refused (${check.kind}: ${check.message})`,
    };
  }
  return { action: "follow", nextUrl: next.toString() };
}

export async function runScopedRequest(
  spec: HttpRequestSpec,
  scope: TestingScope,
  options: ScopedRequestOptions = {},
): Promise<ScopedHttpResult> {
  const timeoutMs = options.timeoutMs ?? REQUEST_TIMEOUT_MS;
  const maxRedirects = options.maxRedirects ?? MAX_REDIRECTS;
  const maxResponseBytes = options.maxResponseBytes ?? MAX_RESPONSE_SIZE_BYTES;

  const fail = (
    kind: RequestFailureKind,
    message: string,
    detail?: string,
  ): ScopedHttpResult => ({
    ok: false,
    finalUrl: spec.url,
    status: 0,
    statusText: "",
    redirected: false,
    redirectChain: [],
    headers: {},
    cookies: [],
    body: "",
    bodyBytes: 0,
    bodyTruncated: false,
    timingMs: 0,
    error: { kind, message, detail },
  });

  let urlStr = spec.url;
  try {
    const u = new URL(spec.url);
    for (const [k, v] of Object.entries(spec.query ?? {})) {
      if (k) u.searchParams.set(k, v);
    }
    u.hash = "";
    urlStr = u.toString();
  } catch {
    return fail("URL_PARSING", "request URL is malformed");
  }

  const first = await assertUrlRequestable(urlStr, scope);
  if (!first.ok) {
    if (first.kind === "OUT_OF_SCOPE") {
      return fail("OUT_OF_SCOPE", "request is outside the authorised target scope", first.message);
    }
    if (first.kind === "DNS_FAILURE") {
      return fail("DNS_FAILURE", "target did not resolve", first.message);
    }
    return fail("SSRF_BLOCKED", "target refused by SSRF protection", first.message);
  }

  const headers = buildHeaderList(spec.headers, spec.cookies);
  const h = new Headers();
  for (const row of headers) h.append(row.name, row.value);
  if (spec.contentType) h.set("Content-Type", spec.contentType);

  const redirectChain: ScopedHttpResult["redirectChain"] = [];
  let currentUrl = urlStr;
  let response: Response | undefined;
  let finalStatus = 0;
  let finalStatusText = "";

  const started = Date.now();

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    let res: Response;
    try {
      res = await fetch(currentUrl, {
        method: spec.method,
        headers: h,
        body: spec.method === "GET" || spec.method === "HEAD" || spec.method === "OPTIONS" ? undefined : (spec.body ?? undefined),
        redirect: "manual",
        signal: controller.signal,
      });
    } catch (err) {
      clearTimeout(timer);
      if ((err as Error).name === "AbortError") {
        return fail("TIMEOUT", `request timed out after ${timeoutMs}ms`);
      }
      return fail("NETWORK", "request failed on the network", (err as Error).message);
    }
    clearTimeout(timer);

    response = res;
    finalStatus = res.status;
    finalStatusText = res.statusText || "";

    if (res.status >= 300 && res.status < 400) {
      const decision = await decideRedirect(
        res.status,
        res.headers.get("location"),
        currentUrl,
        scope,
      );
      if (decision.action === "error") {
        return {
          ...collapsedShape(response, currentUrl, started, redirectChain),
          error: { kind: decision.errorKind ?? "INVALID_RESPONSE", message: decision.message ?? "invalid redirect" },
        };
      }
      if (decision.action === "follow") {
        redirectChain.push({
          from: currentUrl,
          to: decision.nextUrl!,
          status: res.status,
          reason: `in-scope redirect followed (${decision.nextUrl!})`,
        });
        currentUrl = decision.nextUrl!;
        continue;
      }
      // stop: destination refused — return the 3xx we hold, with a note.
      redirectChain.push({
        from: currentUrl,
        to: res.headers.get("location") ?? "",
        status: res.status,
        reason: decision.message ?? "redirect not followed",
      });
      break;
    }

    break;
  }

  if (!response) {
    return fail("NETWORK", "no response received");
  }

  const capped = capHeaders(response.headers);
  const { text, bytes, truncated } = response.body
    ? await readBodyLimited(response.body.getReader(), maxResponseBytes)
    : { text: "", bytes: 0, truncated: false };

  return {
    ok: true,
    finalUrl: currentUrl,
    status: finalStatus,
    statusText: finalStatusText,
    redirected: redirectChain.length > 0,
    redirectChain,
    headers: capped.headers,
    cookies: capped.cookies,
    body: text,
    bodyBytes: bytes,
    bodyTruncated: truncated,
    timingMs: Date.now() - started,
  };
}

function collapsedShape(
  response: Response,
  currentUrl: string,
  started: number,
  redirectChain: ScopedHttpResult["redirectChain"],
): ScopedHttpResult {
  const capped = capHeaders(response.headers);
  return {
    ok: false,
    finalUrl: currentUrl,
    status: response.status,
    statusText: response.statusText || "",
    redirected: redirectChain.length > 0,
    redirectChain,
    headers: capped.headers,
    cookies: capped.cookies,
    body: "",
    bodyBytes: 0,
    bodyTruncated: false,
    timingMs: Date.now() - started,
  };
}

/** Redact sensitive values for display in the UI (values, not the tool). */
export function redactHeaders(
  headers: Record<string, string>,
): Record<string, string> {
  const sensitive = new Set([
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "cookie",
    "set-cookie",
    "x-auth-token",
    "x-access-token",
    "secret",
    "x-secret",
  ]);
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (sensitive.has(k.toLowerCase())) {
      out[k] = v.replace(
        /(?<=^(Bearer|Basic|Token|ApiKey)\s+).*/i,
        "[REDACTED]",
      );
      if (out[k] === v) out[k] = "[REDACTED]";
    } else {
      out[k] = v;
    }
  }
  return out;
}

export const headerDisplayValue = (v: string): string =>
  v.length > 512 ? `${v.slice(0, 512)}…` : v;