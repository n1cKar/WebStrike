const DEV_FALLBACK_KEY = "__webstrike_dev_secret__";

declare global {
  var __webstrikeDevSecret: string | undefined;
}

/**
 * Resolve the signing secret used for auth and testing-session cookies.
 * Production fails closed when AUTH_SECRET is absent; development generates an
 * ephemeral secret so the app still runs, at the cost of resetting sessions on
 * restart.
 */
export function getAuthSecret(): Uint8Array {
  const secret = process.env.AUTH_SECRET;
  if (secret && secret.length >= 32) {
    return new TextEncoder().encode(secret);
  }

  if (process.env.NODE_ENV === "production") {
    throw new Error(
      "AUTH_SECRET is required in production (32+ characters). Refusing to start with an insecure default.",
    );
  }

  if (!globalThis.__webstrikeDevSecret) {
    const bytes = new Uint8Array(32);
    globalThis.crypto.getRandomValues(bytes);
    globalThis.__webstrikeDevSecret = Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    console.warn(
      `[webstrike] AUTH_SECRET not set — using an ephemeral development secret (${DEV_FALLBACK_KEY}). Sessions reset on restart.`,
    );
  }
  return new TextEncoder().encode(globalThis.__webstrikeDevSecret);
}