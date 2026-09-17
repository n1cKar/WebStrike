import type { ScopedHttpResult } from "@webstrike/types";
import { bodySimilarity, lengthDeltaRatio } from "./compare";

/**
 * Names that commonly indicate security-sensitive or private properties. Used
 * to prioritise what a differential exposes, never to declare a finding.
 */
export const SENSITIVE_FIELD_PATTERNS: RegExp[] = [
  /pass(word|wd)?/i,
  /secret/i,
  /token/i,
  /api[_-]?key/i,
  /ssn|social[_-]?security|tax[_-]?id/i,
  /credit|card[_-]?number|cvv|cvc/i,
  /balance|salary|iban|account[_-]?number/i,
  /\brole\b|is[_-]?admin|admin\b|privilege|permission|scope/i,
  /owner([_-]?id)?/i,
  /user[_-]?id|account[_-]?id|customer[_-]?id/i,
  /email|phone|mobile|address|dob|birth/i,
  /internal|private/i,
];

export function isSensitiveField(name: string): boolean {
  return SENSITIVE_FIELD_PATTERNS.some((re) => re.test(name));
}

export interface JsonShape {
  isJson: boolean;
  kind: "object" | "array" | "primitive" | "invalid";
  keys: string[];
  /** Number of records: array length, or the largest nested array's length. */
  objectCount: number;
  sensitiveKeys: string[];
  /** Shallow scalar string values, used for marker/ownership detection. */
  scalars: string[];
}

const EMPTY_SHAPE: JsonShape = {
  isJson: false,
  kind: "invalid",
  keys: [],
  objectCount: 0,
  sensitiveKeys: [],
  scalars: [],
};

function collect(value: unknown, shape: JsonShape, depth: number): void {
  if (depth > 4 || value === null || typeof value !== "object") {
    if (typeof value === "string") shape.scalars.push(value);
    return;
  }
  if (Array.isArray(value)) {
    shape.objectCount = Math.max(shape.objectCount, value.length);
    for (const item of value.slice(0, 50)) collect(item, shape, depth + 1);
    return;
  }
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    shape.keys.push(key);
    if (isSensitiveField(key)) shape.sensitiveKeys.push(key);
    if (typeof child === "string") shape.scalars.push(child);
    else collect(child, shape, depth + 1);
  }
}

export function jsonShape(body: string): JsonShape {
  const trimmed = body.trim();
  if (!trimmed || (trimmed[0] !== "{" && trimmed[0] !== "[")) return EMPTY_SHAPE;
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return EMPTY_SHAPE;
  }
  const shape: JsonShape = {
    isJson: true,
    kind: Array.isArray(parsed) ? "array" : "object",
    keys: [],
    objectCount: Array.isArray(parsed) ? parsed.length : 0,
    sensitiveKeys: [],
    scalars: [],
  };
  collect(parsed, shape, 0);
  shape.keys = [...new Set(shape.keys)];
  shape.sensitiveKeys = [...new Set(shape.sensitiveKeys)];
  return shape;
}

export interface ResponseDiff {
  statusFrom: number;
  statusTo: number;
  statusChanged: boolean;
  contentTypeChanged: boolean;
  redirectChanged: boolean;
  lengthDeltaRatio: number;
  timingRatio: number;
  /** Token-set similarity (0..1); structural, not byte-for-byte. */
  similarity: number;
  structured: boolean;
  keysAdded: string[];
  keysRemoved: string[];
  sensitiveKeysAdded: string[];
  objectCountFrom: number;
  objectCountTo: number;
}

function contentType(res: ScopedHttpResult): string {
  return (res.headers["content-type"] ?? "").toLowerCase();
}

function sortKey(res: ScopedHttpResult): string {
  return [res.status, res.finalUrl, ...res.redirectChain].join(">");
}

/**
 * Compare two responses across the dimensions that carry security meaning.
 * Never reduces the verdict to a single byte-similarity number.
 */
export function diffResponses(
  from: ScopedHttpResult,
  to: ScopedHttpResult,
): ResponseDiff {
  const shapeFrom = jsonShape(from.body);
  const shapeTo = jsonShape(to.body);
  const keyFrom = new Set(shapeFrom.keys);
  const keyTo = new Set(shapeTo.keys);

  return {
    statusFrom: from.status,
    statusTo: to.status,
    statusChanged: from.status !== to.status,
    contentTypeChanged: contentType(from) !== contentType(to),
    redirectChanged: sortKey(from) !== sortKey(to),
    lengthDeltaRatio: lengthDeltaRatio(from.body, to.body),
    timingRatio:
      from.timingMs <= 0 ? 1 : Math.min(to.timingMs / from.timingMs, 100),
    similarity: bodySimilarity(from.body, to.body),
    structured: shapeFrom.isJson && shapeTo.isJson,
    keysAdded: shapeTo.keys.filter((k) => !keyFrom.has(k)),
    keysRemoved: shapeFrom.keys.filter((k) => !keyTo.has(k)),
    sensitiveKeysAdded: shapeTo.sensitiveKeys.filter((k) => !keyFrom.has(k)),
    objectCountFrom: shapeFrom.objectCount,
    objectCountTo: shapeTo.objectCount,
  };
}

/**
 * True when a response body appears to disclose private records rather than an
 * empty shell (e.g. `{"user": null}`).
 */
export function hasSubstantiveData(res: ScopedHttpResult): boolean {
  const shape = jsonShape(res.body);
  if (shape.isJson) {
    return shape.keys.length > 0 || shape.objectCount > 0;
  }
  const text = res.body.trim();
  if (text.length < 40) return false;
  if (/^(not found|forbidden|unauthori[sz]ed|access denied)\b/i.test(text)) return false;
  return true;
}
