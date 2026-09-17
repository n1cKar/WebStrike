"use client";

import type { BrowserRunOutcome } from "@webstrike/testing";
import { apiFetch } from "@/lib/api/client";

export interface BrowserStatus {
  configured: boolean;
}

export interface BrowserRunBody {
  maxPages: number;
  timeoutMs: number;
  screenshot: boolean;
}

export function fetchBrowserStatus(): Promise<BrowserStatus> {
  return apiFetch<BrowserStatus>("/api/browser/status");
}

export function runBrowser(body: BrowserRunBody): Promise<{ outcome: BrowserRunOutcome }> {
  return apiFetch<{ outcome: BrowserRunOutcome }>("/api/browser/run", {
    method: "POST",
    body: JSON.stringify(body),
  });
}
