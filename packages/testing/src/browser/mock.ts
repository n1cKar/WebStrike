import type {
  BrowserDriver,
  BrowserOpenOptions,
  BrowserSnapshot,
} from "./types";

export type MockPageSource =
  | Record<string, Partial<BrowserSnapshot>>
  | ((url: string) => Partial<BrowserSnapshot> | undefined);

function materialize(url: string, partial: Partial<BrowserSnapshot>): BrowserSnapshot {
  return {
    url: partial.url ?? url,
    title: partial.title ?? "",
    html: partial.html ?? "",
    documentHeaders: partial.documentHeaders ?? {},
    documentStatus: partial.documentStatus ?? 200,
    cookies: partial.cookies ?? [],
    console: partial.console ?? [],
    requests: partial.requests ?? [],
    localStorage: partial.localStorage ?? {},
    sessionStorage: partial.sessionStorage ?? {},
    screenshot: partial.screenshot,
    timingMs: partial.timingMs ?? 0,
  };
}

/**
 * A scripted browser driver for tests and local development. It replays a
 * snapshot per URL and records navigation order; no network or browser is used.
 */
export class MockBrowserDriver implements BrowserDriver {
  readonly kind = "mock";
  readonly navigations: string[] = [];
  private current: BrowserSnapshot | null = null;

  constructor(private readonly pages: MockPageSource) {}

  async open(url: string, _options?: BrowserOpenOptions): Promise<BrowserSnapshot> {
    this.navigations.push(url);
    const partial =
      typeof this.pages === "function" ? this.pages(url) : (this.pages[url] ?? this.pages["*"]);
    if (!partial) throw new Error(`mock browser has no page for ${url}`);
    this.current = materialize(url, partial);
    return this.current;
  }

  async evaluate<T = unknown>(_expression: string): Promise<T> {
    return undefined as T;
  }

  async screenshot(): Promise<string | null> {
    return this.current?.screenshot ?? null;
  }

  async close(): Promise<void> {
    this.current = null;
  }
}
