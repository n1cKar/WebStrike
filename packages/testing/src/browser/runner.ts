import type { TestingScope } from "@webstrike/types";
import { validateScopedUrl } from "@webstrike/security";
import { extractLinks } from "../surface";
import type { TestObservation } from "../types";
import { analyzeSnapshot } from "./checks";
import type {
  BrowserDriver,
  BrowserPageSummary,
  BrowserRunOptions,
  BrowserRunOutcome,
} from "./types";

/**
 * Renders one or more in-scope pages and turns the observed browser state into
 * evidence-backed observations. Every URL is scope-validated before navigation
 * and links are followed breadth-first, bounded by `maxPages`.
 */
export async function runBrowserChecks(
  targetUrl: string,
  driver: BrowserDriver,
  scope: TestingScope,
  options: BrowserRunOptions = {},
): Promise<BrowserRunOutcome> {
  const maxPages = Math.max(1, options.maxPages ?? 1);
  const startedAt = Date.now();

  const start = validateScopedUrl(targetUrl, scope);
  if (!start.ok || !start.url) {
    throw new Error(`target is out of scope: ${start.reason}`);
  }

  const queue: string[] = [start.url.toString()];
  const visited = new Set<string>();
  const seenObservations = new Set<string>();
  const observations: TestObservation[] = [];
  const pages: BrowserPageSummary[] = [];

  let counter = 0;
  let errors = 0;
  let truncated = false;
  let screenshot: string | undefined;

  while (queue.length > 0 && pages.length < maxPages) {
    const url = queue.shift();
    if (!url || visited.has(url)) continue;
    visited.add(url);

    const wantScreenshot = Boolean(options.screenshot) && !screenshot;
    let snapshot;
    try {
      snapshot = await driver.open(url, {
        timeoutMs: options.timeoutMs,
        screenshot: wantScreenshot,
      });
    } catch {
      errors += 1;
      continue;
    }

    if (wantScreenshot && snapshot.screenshot) screenshot = snapshot.screenshot;

    const pageObservations = analyzeSnapshot(snapshot, scope, () => `browser-${++counter}`);
    for (const observation of pageObservations) {
      const key = `${observation.category}|${observation.title}`;
      if (seenObservations.has(key)) continue;
      seenObservations.add(key);
      observations.push(observation);
    }

    pages.push({
      url: snapshot.url,
      title: snapshot.title,
      requests: snapshot.requests.length,
      consoleErrors: snapshot.console.filter((message) => message.level === "error").length,
      cookies: snapshot.cookies.length,
    });

    const discovered = new Set<string>();
    for (const link of extractLinks(snapshot.html, snapshot.url)) {
      if (visited.has(link) || queue.includes(link) || discovered.has(link)) continue;
      const check = validateScopedUrl(link, scope);
      if (!check.ok) continue;
      discovered.add(link);
    }

    const remaining = maxPages - pages.length;
    if (discovered.size > remaining) truncated = true;
    queue.push(...[...discovered].slice(0, Math.max(0, remaining)));
  }

  if (queue.length > 0) truncated = true;

  return {
    observations,
    pages,
    screenshot,
    stats: {
      pages: pages.length,
      durationMs: Date.now() - startedAt,
      truncated,
      errors,
    },
  };
}
