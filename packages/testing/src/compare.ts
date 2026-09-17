import type { ScopedHttpResult } from "@webstrike/types";
import { ERROR_SIGNATURES } from "./payloads";

const MAX_COMPARE_CHARS = 20000;
const MAX_PREVIEW_CHARS = 1200;

export function previewBody(body: string, max = MAX_PREVIEW_CHARS): string {
  if (body.length <= max) return body;
  return `${body.slice(0, max)}\n…[truncated ${body.length - max} chars]`;
}

/**
 * Replace values that legitimately change between two responses (tokens,
 * nonces, timestamps, ids) so structural comparison is not defeated by them.
 */
export function normalizeBody(body: string): string {
  return body
    .slice(0, MAX_COMPARE_CHARS)
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, "<uuid>")
    .replace(/\b[0-9a-f]{32,64}\b/gi, "<hex>")
    .replace(/\b\d{10,13}\b/g, "<epoch>")
    .replace(
      /(name|id|value|token|csrf|nonce|authenticity)["']?\s*[:=]\s*["'][^"']{8,}["']/gi,
      "$1=<token>",
    )
    .replace(/\s+/g, " ")
    .trim();
}

function tokenSet(text: string): Set<string> {
  return new Set(
    text
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter((t) => t.length > 1),
  );
}

/** Jaccard similarity of token sets, 0..1. */
export function bodySimilarity(a: string, b: string): number {
  if (a === b) return 1;
  const na = normalizeBody(a);
  const nb = normalizeBody(b);
  if (na === nb) return 1;
  const sa = tokenSet(na);
  const sb = tokenSet(nb);
  if (sa.size === 0 && sb.size === 0) return 1;
  let intersection = 0;
  for (const token of sa) if (sb.has(token)) intersection += 1;
  const union = sa.size + sb.size - intersection;
  return union === 0 ? 1 : intersection / union;
}

export function lengthDeltaRatio(a: string, b: string): number {
  const max = Math.max(a.length, b.length, 1);
  return Math.abs(a.length - b.length) / max;
}

/** True when the exact payload appears in the body without HTML encoding. */
export function reflectsUnescaped(body: string, payload: string): boolean {
  if (!payload) return false;
  const idx = body.indexOf(payload);
  if (idx === -1) return false;
  // For HTML-sensitive payloads, a raw `<`/`"` means it was not encoded.
  if (/[<>"']/.test(payload)) return true;
  return false;
}

/** True when the evaluated form of a template payload appears instead of it. */
export function appearsEvaluated(body: string, payload: string, evaluated: string): boolean {
  if (evaluated.length < 2) return false;
  return body.includes(evaluated) && !body.includes(payload);
}

export function hasErrorSignature(body: string): string | null {
  const lower = body.slice(0, MAX_COMPARE_CHARS).toLowerCase();
  for (const signature of ERROR_SIGNATURES) {
    if (lower.includes(signature)) return signature;
  }
  return null;
}

export function changedHeaders(
  a: Record<string, string>,
  b: Record<string, string>,
): string[] {
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  const changed: string[] = [];
  for (const key of keys) {
    if ((a[key] ?? "") !== (b[key] ?? "")) changed.push(key);
  }
  return changed;
}

export function isServerError(status: number): boolean {
  return status >= 500 && status <= 599;
}

export function isSuccess(status: number): boolean {
  return status >= 200 && status < 300;
}

export function isRedirect(status: number): boolean {
  return status >= 300 && status < 400;
}

export function isDenied(status: number): boolean {
  return status === 401 || status === 403;
}

export function describeResponse(result: ScopedHttpResult): string {
  return `${result.status} ${result.statusText} · ${result.bodyBytes} bytes · ${result.timingMs}ms`;
}
