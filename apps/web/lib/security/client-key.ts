/**
 * Best-effort client key for rate limiting. Guests share one identity, so they
 * are keyed by source IP; signed-in users are keyed by account id instead.
 */
export function clientIp(request: Request): string {
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) {
    const first = forwarded.split(",")[0]?.trim();
    if (first) return first;
  }
  return request.headers.get("x-real-ip")?.trim() || "unknown";
}

export function actorRateKey(actor: { id: string; guest: boolean }, request: Request): string {
  return actor.guest ? `ip:${clientIp(request)}` : `user:${actor.id}`;
}
