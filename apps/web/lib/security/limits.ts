/**
 * Best-effort, per-instance request limits.
 *
 * Vercel runs many short-lived function instances, so these counters are not
 * globally shared. They still bound abuse on any single instance and are
 * intentionally in-memory — nothing is persisted.
 */

declare global {
  var __webstrikeRateBuckets: Map<string, number[]> | undefined;
  var __webstrikeInFlight: Map<string, number> | undefined;
}

function buckets(): Map<string, number[]> {
  globalThis.__webstrikeRateBuckets ??= new Map();
  return globalThis.__webstrikeRateBuckets;
}

export interface RateLimitResult {
  ok: boolean;
  retryAfterMs?: number;
}

export function checkRateLimit(
  key: string,
  limit: number,
  windowMs: number,
  now = Date.now(),
): RateLimitResult {
  const store = buckets();
  const windowStart = now - windowMs;
  const hits = (store.get(key) ?? []).filter((t) => t > windowStart);
  if (hits.length >= limit) {
    store.set(key, hits);
    return { ok: false, retryAfterMs: windowMs - (now - (hits[0] ?? now)) };
  }
  hits.push(now);
  store.set(key, hits);
  return { ok: true };
}

declare global {
  var __webstrikeConcurrency: Map<string, number> | undefined;
}

export function acquireSlot(key: string, limit: number): boolean {
  globalThis.__webstrikeConcurrency ??= new Map();
  const current = globalThis.__webstrikeConcurrency.get(key) ?? 0;
  if (current >= limit) return false;
  globalThis.__webstrikeConcurrency.set(key, current + 1);
  return true;
}

export function releaseSlot(key: string): void {
  globalThis.__webstrikeConcurrency ??= new Map();
  const current = globalThis.__webstrikeConcurrency.get(key) ?? 0;
  globalThis.__webstrikeConcurrency.set(key, Math.max(0, current - 1));
}