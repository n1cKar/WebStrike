import type {
  BrowserConfig,
  BrowserConsoleMessage,
  BrowserCookie,
  BrowserDriver,
  BrowserNetworkEntry,
  BrowserOpenOptions,
  BrowserSnapshot,
} from "./types";

const CONNECT_TIMEOUT_MS = 15_000;
const DEFAULT_CALL_TIMEOUT_MS = 30_000;
const MAX_HTML_LENGTH = 400_000;
const MAX_PREVIEW_LENGTH = 2_000;

interface CdpErrorShape {
  code: number;
  message: string;
  data?: string;
}

interface CdpMessage {
  id?: number;
  method?: string;
  params?: Record<string, unknown>;
  result?: unknown;
  error?: CdpErrorShape;
  sessionId?: string;
}

type SocketListener = (event: { data?: unknown }) => void;

interface WebSocketLike {
  send(data: string): void;
  close(): void;
  addEventListener(type: string, listener: SocketListener): void;
}

interface WebSocketConstructor {
  new (url: string): WebSocketLike;
}

function socketConstructor(): WebSocketConstructor {
  const ctor = (globalThis as unknown as { WebSocket?: WebSocketConstructor }).WebSocket;
  if (!ctor) {
    throw new Error("this runtime has no WebSocket implementation for the browser driver");
  }
  return ctor;
}

function withToken(endpoint: string, token?: string): string {
  if (!token) return endpoint;
  try {
    const url = new URL(endpoint);
    url.searchParams.set("token", token);
    return url.toString();
  } catch {
    return endpoint;
  }
}

function decodeMessageData(data: unknown): string {
  if (typeof data === "string") return data;
  if (data instanceof ArrayBuffer) return new TextDecoder().decode(data);
  if (ArrayBuffer.isView(data)) {
    return new TextDecoder().decode(data as ArrayBufferView as Uint8Array);
  }
  return data == null ? "" : String(data);
}

function mapCookie(raw: Record<string, unknown>): BrowserCookie {
  return {
    name: String(raw.name ?? ""),
    domain: String(raw.domain ?? ""),
    path: String(raw.path ?? "/"),
    secure: Boolean(raw.secure),
    httpOnly: Boolean(raw.httpOnly),
    sameSite: raw.sameSite ? String(raw.sameSite) : undefined,
    session: raw.session === undefined ? undefined : Boolean(raw.session),
    expires: typeof raw.expires === "number" ? raw.expires : undefined,
  };
}

class CdpConnection {
  private nextId = 1;
  private readonly pending = new Map<
    number,
    { resolve: (value: unknown) => void; reject: (error: Error) => void; timer: ReturnType<typeof setTimeout> }
  >();
  private readonly listeners = new Set<(message: CdpMessage) => void>();

  private constructor(private readonly ws: WebSocketLike) {
    ws.addEventListener("message", (event) => this.onMessage(decodeMessageData(event.data)));
    ws.addEventListener("close", () => this.failAll(new Error("browser connection closed")));
    ws.addEventListener("error", () => this.failAll(new Error("browser connection error")));
  }

  static connect(config: BrowserConfig): Promise<CdpConnection> {
    const url = withToken(config.endpoint, config.apiToken);
    let ws: WebSocketLike;
    try {
      ws = new (socketConstructor())(url);
    } catch (error) {
      return Promise.reject(error instanceof Error ? error : new Error("cannot open browser endpoint"));
    }

    return new Promise<CdpConnection>((resolve, reject) => {
      let settled = false;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        reject(new Error(`timed out connecting to the browser endpoint after ${CONNECT_TIMEOUT_MS}ms`));
      }, CONNECT_TIMEOUT_MS);

      ws.addEventListener("open", () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(new CdpConnection(ws));
      });
      ws.addEventListener("error", () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(new Error("failed to connect to the browser endpoint"));
      });
      ws.addEventListener("close", () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(new Error("browser endpoint closed the connection during handshake"));
      });
    });
  }

  send(
    method: string,
    params: Record<string, unknown> = {},
    sessionId?: string,
    timeoutMs = DEFAULT_CALL_TIMEOUT_MS,
  ): Promise<unknown> {
    const id = this.nextId++;
    const payload: Record<string, unknown> = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;

    return new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`browser command ${method} timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      try {
        this.ws.send(JSON.stringify(payload));
      } catch (error) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(error instanceof Error ? error : new Error("failed to send browser command"));
      }
    });
  }

  on(listener: (message: CdpMessage) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  close(): void {
    try {
      this.ws.close();
    } catch {
      /* already closing */
    }
    this.failAll(new Error("browser connection closed by client"));
  }

  private onMessage(text: string): void {
    if (!text) return;
    let message: CdpMessage;
    try {
      message = JSON.parse(text) as CdpMessage;
    } catch {
      return;
    }

    if (typeof message.id === "number") {
      const entry = this.pending.get(message.id);
      if (!entry) return;
      this.pending.delete(message.id);
      clearTimeout(entry.timer);
      if (message.error) {
        entry.reject(new Error(`browser error ${message.error.code}: ${message.error.message}`));
      } else {
        entry.resolve(message.result);
      }
      return;
    }

    if (message.method) {
      for (const listener of this.listeners) listener(message);
    }
  }

  private failAll(error: Error): void {
    for (const entry of this.pending.values()) {
      clearTimeout(entry.timer);
      entry.reject(error);
    }
    this.pending.clear();
  }
}

export class CdpBrowserDriver implements BrowserDriver {
  readonly kind = "cdp";

  private consoleMessages: BrowserConsoleMessage[] = [];
  private networkEntries: BrowserNetworkEntry[] = [];
  private readonly requestIndex = new Map<string, BrowserNetworkEntry>();
  private documentHeaders: Record<string, string> = {};
  private documentStatus = 0;
  private detachListeners: (() => void)[] = [];

  private constructor(
    private readonly connection: CdpConnection,
    private readonly config: BrowserConfig,
    private readonly sessionId: string | undefined,
    private readonly targetId: string | undefined,
  ) {}

  static async create(config: BrowserConfig): Promise<CdpBrowserDriver> {
    const connection = await CdpConnection.connect(config);
    const browserLevel = await isBrowserLevel(connection);

    let targetId: string | undefined;
    let sessionId: string | undefined;

    if (browserLevel) {
      const created = (await connection.send("Target.createTarget", { url: "about:blank" })) as {
        targetId: string;
      };
      targetId = created.targetId;
      const attached = (await connection.send("Target.attachToTarget", {
        targetId,
        flatten: true,
      })) as { sessionId: string };
      sessionId = attached.sessionId;
    }

    const driver = new CdpBrowserDriver(connection, config, sessionId, targetId);
    driver.attachEvents();
    await driver.enableDomains();
    return driver;
  }

  private send(method: string, params: Record<string, unknown> = {}, timeoutMs?: number) {
    return this.connection.send(method, params, this.sessionId, timeoutMs);
  }

  private attachEvents() {
    this.detachListeners.push(
      this.connection.on((message) => {
        if (this.sessionId && message.sessionId && message.sessionId !== this.sessionId) return;
        this.handleEvent(message);
      }),
    );
  }

  private async enableDomains() {
    await this.send("Page.enable");
    await this.send("Runtime.enable");
    await this.send("Network.enable");
    try {
      await this.send("Log.enable");
    } catch {
      /* Log domain is optional */
    }
  }

  private handleEvent(message: CdpMessage): void {
    const params = message.params ?? {};
    switch (message.method) {
      case "Network.requestWillBeSent": {
        const request = (params.request ?? {}) as Record<string, unknown>;
        const entry: BrowserNetworkEntry = {
          url: String(request.url ?? ""),
          method: String(request.method ?? "GET"),
          resourceType: params.type ? String(params.type) : undefined,
          initiator: params.initiator ? String((params.initiator as { type?: string }).type ?? "") : undefined,
        };
        const requestId = String(params.requestId ?? "");
        if (requestId) this.requestIndex.set(requestId, entry);
        this.networkEntries.push(entry);
        break;
      }
      case "Network.responseReceived": {
        const requestId = String(params.requestId ?? "");
        const response = (params.response ?? {}) as Record<string, unknown>;
        const entry = this.requestIndex.get(requestId);
        const headers = normalizeHeaders((response.headers ?? {}) as Record<string, unknown>);
        if (entry) {
          entry.status = typeof response.status === "number" ? response.status : undefined;
          entry.mimeType = response.mimeType ? String(response.mimeType) : undefined;
          entry.fromCache = typeof response.fromDiskCache === "boolean" ? response.fromDiskCache : undefined;
        }
        if (String(params.type ?? "") === "Document") {
          this.documentHeaders = headers;
          this.documentStatus = typeof response.status === "number" ? response.status : 0;
        }
        break;
      }
      case "Network.loadingFailed": {
        const requestId = String(params.requestId ?? "");
        const entry = this.requestIndex.get(requestId);
        if (entry) entry.failed = String(params.errorText ?? "failed");
        break;
      }
      case "Runtime.consoleAPICalled": {
        const args = Array.isArray(params.args) ? (params.args as Record<string, unknown>[]) : [];
        this.consoleMessages.push({
          level: normalizeConsoleLevel(String(params.type ?? "log")),
          text: args
            .map((arg) => String(arg.value ?? arg.description ?? ""))
            .join(" ")
            .slice(0, MAX_PREVIEW_LENGTH),
        });
        break;
      }
      case "Log.entryAdded": {
        const entry = (params.entry ?? {}) as Record<string, unknown>;
        this.consoleMessages.push({
          level: normalizeConsoleLevel(String(entry.level ?? "log")),
          text: String(entry.text ?? "").slice(0, MAX_PREVIEW_LENGTH),
          source: entry.url ? String(entry.url) : undefined,
        });
        break;
      }
      case "Runtime.exceptionThrown": {
        const details = (params.exceptionDetails ?? {}) as Record<string, unknown>;
        this.consoleMessages.push({
          level: "error",
          text: String(
            (details.exception as { description?: string } | undefined)?.description ??
              details.text ??
              "uncaught exception",
          ).slice(0, MAX_PREVIEW_LENGTH),
        });
        break;
      }
      default:
        break;
    }
  }

  async open(url: string, options: BrowserOpenOptions = {}): Promise<BrowserSnapshot> {
    this.resetBuffers();
    const timeoutMs = options.timeoutMs ?? this.config.timeoutMs;

    await this.send("Page.navigate", { url }, timeoutMs);
    await this.waitForLoad(timeoutMs);
    await delay(200);

    return this.capture(Boolean(options.screenshot));
  }

  private resetBuffers() {
    this.consoleMessages = [];
    this.networkEntries = [];
    this.requestIndex.clear();
    this.documentHeaders = {};
    this.documentStatus = 0;
  }

  private waitForLoad(timeoutMs: number): Promise<void> {
    return new Promise((resolve) => {
      let settled = false;
      const finish = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        detach();
        resolve();
      };
      const detach = this.connection.on((message) => {
        if (message.method === "Page.loadEventFired" || message.method === "Page.frameStoppedLoading") {
          finish();
        }
      });
      const timer = setTimeout(finish, timeoutMs);
    });
  }

  private async capture(withScreenshot: boolean): Promise<BrowserSnapshot> {
    const started = Date.now();
    const url = await this.evaluate<string>("location.href").catch(() => "");
    const title = await this.evaluate<string>("document.title").catch(() => "");
    const html = await this.evaluate<string>("document.documentElement.outerHTML").catch(() => "");
    const storage = await this.evaluate<{
      localStorage?: Record<string, string>;
      sessionStorage?: Record<string, string>;
    }>(
      "(() => { try { return { localStorage: {...localStorage}, sessionStorage: {...sessionStorage} }; } catch { return { localStorage: {}, sessionStorage: {} }; } })()",
    ).catch(() => ({ localStorage: {}, sessionStorage: {} }));

    const cookies = await this.collectCookies();

    let screenshot: string | undefined;
    if (withScreenshot) {
      screenshot = (await this.screenshot().catch(() => null)) ?? undefined;
    }

    return {
      url: url || "about:blank",
      title,
      html: html.slice(0, MAX_HTML_LENGTH),
      documentHeaders: this.documentHeaders,
      documentStatus: this.documentStatus,
      cookies,
      console: [...this.consoleMessages],
      requests: [...this.networkEntries],
      localStorage: storage.localStorage ?? {},
      sessionStorage: storage.sessionStorage ?? {},
      screenshot,
      timingMs: Date.now() - started,
    };
  }

  private async collectCookies(): Promise<BrowserCookie[]> {
    try {
      const result = (await this.connection.send("Network.getAllCookies", {}, undefined)) as {
        cookies?: Record<string, unknown>[];
      };
      return (result.cookies ?? []).map(mapCookie);
    } catch {
      try {
        const result = (await this.send("Network.getCookies")) as {
          cookies?: Record<string, unknown>[];
        };
        return (result.cookies ?? []).map(mapCookie);
      } catch {
        return [];
      }
    }
  }

  async evaluate<T = unknown>(expression: string): Promise<T> {
    const result = (await this.send("Runtime.evaluate", {
      expression,
      returnByValue: true,
      awaitPromise: true,
    })) as {
      result?: { value?: unknown };
      exceptionDetails?: { text?: string };
    };
    if (result.exceptionDetails) {
      throw new Error(`browser evaluation failed: ${result.exceptionDetails.text ?? "unknown error"}`);
    }
    return result.result?.value as T;
  }

  async screenshot(): Promise<string | null> {
    const result = (await this.send("Page.captureScreenshot", { format: "png" })) as {
      data?: string;
    };
    return result.data ?? null;
  }

  async close(): Promise<void> {
    for (const detach of this.detachListeners) detach();
    this.detachListeners = [];
    if (this.targetId) {
      try {
        await this.connection.send("Target.closeTarget", { targetId: this.targetId });
      } catch {
        /* best effort */
      }
    }
    this.connection.close();
  }
}

async function isBrowserLevel(connection: CdpConnection): Promise<boolean> {
  try {
    await connection.send("Target.getTargets", {}, undefined, 5_000);
    return true;
  } catch {
    return false;
  }
}

function normalizeHeaders(headers: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    out[key.toLowerCase()] = String(value);
  }
  return out;
}

function normalizeConsoleLevel(level: string): BrowserConsoleMessage["level"] {
  const lower = level.toLowerCase();
  if (lower === "warning" || lower === "warn") return "warning";
  if (lower === "error") return "error";
  if (lower === "info") return "info";
  if (lower === "debug" || lower === "verbose") return "debug";
  return "log";
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
