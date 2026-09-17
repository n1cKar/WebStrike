import type { TestObservation } from "../types";

export interface BrowserConsoleMessage {
  level: "log" | "info" | "warning" | "error" | "debug";
  text: string;
  source?: string;
}

export interface BrowserNetworkEntry {
  url: string;
  method: string;
  status?: number;
  resourceType?: string;
  mimeType?: string;
  failed?: string;
  fromCache?: boolean;
  initiator?: string;
}

export interface BrowserCookie {
  name: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
  session?: boolean;
  expires?: number;
}

export interface BrowserSnapshot {
  /** Final URL after any client-side redirects. */
  url: string;
  title: string;
  html: string;
  documentHeaders: Record<string, string>;
  documentStatus: number;
  cookies: BrowserCookie[];
  console: BrowserConsoleMessage[];
  requests: BrowserNetworkEntry[];
  localStorage: Record<string, string>;
  sessionStorage: Record<string, string>;
  /** Base64-encoded PNG, when the driver can capture one. */
  screenshot?: string;
  timingMs: number;
}

export interface BrowserOpenOptions {
  timeoutMs?: number;
  screenshot?: boolean;
}

/**
 * A browser session driver. Implementations may talk to a remote CDP endpoint
 * or, in tests, replay a scripted page. Drivers never decide scope; the runner
 * validates every URL before calling `open`.
 */
export interface BrowserDriver {
  readonly kind: string;
  open(url: string, options?: BrowserOpenOptions): Promise<BrowserSnapshot>;
  evaluate<T = unknown>(expression: string): Promise<T>;
  screenshot(): Promise<string | null>;
  close(): Promise<void>;
}

export interface BrowserConfig {
  endpoint: string;
  apiToken?: string;
  timeoutMs: number;
}

export interface BrowserRunOptions {
  /** Maximum in-scope pages to visit (start URL + followed links). */
  maxPages?: number;
  /** Per-navigation timeout. */
  timeoutMs?: number;
  /** Capture a PNG screenshot of the first page. */
  screenshot?: boolean;
}

export interface BrowserPageSummary {
  url: string;
  title: string;
  requests: number;
  consoleErrors: number;
  cookies: number;
}

export interface BrowserRunOutcome {
  observations: TestObservation[];
  pages: BrowserPageSummary[];
  /** Base64 PNG of the first page, when requested and available. */
  screenshot?: string;
  stats: {
    pages: number;
    durationMs: number;
    truncated: boolean;
    errors: number;
  };
}
