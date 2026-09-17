import type { BrowserConfig } from "@webstrike/testing";

/**
 * Browser testing is opt-in. It only works when an operator provisions a
 * remote CDP-compatible browser and sets BROWSER_WS_ENDPOINT (optionally
 * BROWSER_API_TOKEN). Nothing is launched locally on Vercel.
 */
export const BROWSER_TIMEOUT_MS = 12_000;

export function getBrowserConfig(): BrowserConfig | null {
  const endpoint = process.env.BROWSER_WS_ENDPOINT?.trim();
  if (!endpoint) return null;
  if (!/^wss?:\/\//i.test(endpoint)) return null;
  const apiToken = process.env.BROWSER_API_TOKEN?.trim();
  return {
    endpoint,
    apiToken: apiToken ? apiToken : undefined,
    timeoutMs: BROWSER_TIMEOUT_MS,
  };
}

export function browserConfigured(): boolean {
  return getBrowserConfig() !== null;
}
