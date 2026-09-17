import { afterEach, describe, expect, it } from "vitest";
import {
  CdpBrowserDriver,
  MockBrowserDriver,
  analyzeSnapshot,
  runBrowserChecks,
  type BrowserSnapshot,
} from "../src/index";

const scope = { allowedDomains: ["target.test"], allowedPaths: ["/"], blockedDomains: [] };

function snapshot(partial: Partial<BrowserSnapshot>): BrowserSnapshot {
  return {
    url: "https://target.test/",
    title: "Home",
    html: "",
    documentHeaders: {},
    documentStatus: 200,
    cookies: [],
    console: [],
    requests: [],
    localStorage: {},
    sessionStorage: {},
    timingMs: 1,
    ...partial,
  };
}

describe("browser checks", () => {
  it("reports console errors, mixed content, cookies, storage and framing", () => {
    const observations = analyzeSnapshot(
      snapshot({
        console: [
          { level: "error", text: "Uncaught TypeError: x is undefined" },
          { level: "log", text: "app started" },
        ],
        requests: [
          { url: "http://cdn.target.test/app.js", method: "GET", status: 200 },
          { url: "https://target.test/app.js.map", method: "GET", status: 200 },
        ],
        cookies: [
          {
            name: "session_id",
            domain: ".target.test",
            path: "/",
            secure: false,
            httpOnly: false,
            sameSite: "None",
          },
        ],
        localStorage: { authToken: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature" },
        html: '<form method="post" action="https://other.test/login"><input name="user"></form>',
      }),
      scope,
      (() => {
        let i = 0;
        return () => `o-${++i}`;
      })(),
    );

    const titles = observations.map((o) => o.title);
    expect(titles).toContain("Client-side errors observed");
    expect(titles).toContain("Mixed content requested over http");
    expect(titles).toContain("Session-like cookie readable from JavaScript");
    expect(titles).toContain("SameSite=None cookie without Secure");
    expect(titles).toContain("Credential-like data in localStorage");
    expect(titles).toContain("Cross-origin form without an anti-CSRF token");
    expect(titles).toContain("No frame-embedding protection observed");
    expect(titles).toContain("Source maps served to the browser");
    expect(observations.every((o) => o.id.startsWith("o-"))).toBe(true);
  });

  it("escalates console output that references credentials", () => {
    const observations = analyzeSnapshot(
      snapshot({ console: [{ level: "error", text: "failed to use token=abc123" }] }),
      scope,
      () => "x",
    );
    const sensitive = observations.find((o) => o.title === "Client-side errors reference credentials");
    expect(sensitive?.state).toBe("Needs Verification");
  });

  it("ignores cookies that do not apply to the page host", () => {
    const observations = analyzeSnapshot(
      snapshot({
        cookies: [
          {
            name: "session",
            domain: ".elsewhere.test",
            path: "/",
            secure: false,
            httpOnly: false,
          },
        ],
      }),
      scope,
      () => "x",
    );
    expect(observations.some((o) => o.title.includes("readable from JavaScript"))).toBe(false);
  });
});

describe("browser runner", () => {
  const pages = {
    "https://target.test/": {
      title: "Home",
      html: [
        '<a href="/admin">admin</a>',
        '<a href="https://evil.test/x">out of scope</a>',
        '<a href="/admin">dupe</a>',
      ].join(""),
      console: [{ level: "error" as const, text: "boom" }],
    },
    "https://target.test/admin": {
      title: "Admin",
      html: "<p>admin</p>",
      console: [{ level: "error" as const, text: "boom" }],
    },
  };

  it("follows only in-scope links and dedupes observations", async () => {
    const driver = new MockBrowserDriver(pages);
    const outcome = await runBrowserChecks("https://target.test/", driver, scope, {
      maxPages: 2,
    });

    expect(driver.navigations).toEqual(["https://target.test/", "https://target.test/admin"]);
    expect(outcome.pages.map((p) => p.title)).toEqual(["Home", "Admin"]);
    const consoleObservations = outcome.observations.filter(
      (o) => o.title === "Client-side errors observed",
    );
    expect(consoleObservations).toHaveLength(1);
    expect(outcome.stats.truncated).toBe(false);
  });

  it("stops at maxPages and marks the run truncated", async () => {
    const driver = new MockBrowserDriver(pages);
    const outcome = await runBrowserChecks("https://target.test/", driver, scope, {
      maxPages: 1,
    });
    expect(driver.navigations).toEqual(["https://target.test/"]);
    expect(outcome.stats.truncated).toBe(true);
  });

  it("refuses an out-of-scope target", async () => {
    const driver = new MockBrowserDriver(pages);
    await expect(
      runBrowserChecks("https://evil.test/", driver, scope),
    ).rejects.toThrow(/out of scope/);
    expect(driver.navigations).toEqual([]);
  });
});

interface SocketEvent {
  data?: unknown;
}

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  private readonly listeners = new Map<string, Set<(event: SocketEvent) => void>>();

  constructor(readonly url: string) {
    FakeWebSocket.instances.push(this);
    setTimeout(() => this.emit("open", {}), 0);
  }

  addEventListener(type: string, listener: (event: SocketEvent) => void) {
    const set = this.listeners.get(type) ?? new Set();
    set.add(listener);
    this.listeners.set(type, set);
  }

  private emit(type: string, event: SocketEvent) {
    for (const listener of this.listeners.get(type) ?? []) listener(event);
  }

  close() {
    this.emit("close", {});
  }

  send(raw: string) {
    const message = JSON.parse(raw) as {
      id: number;
      method: string;
      params: Record<string, unknown>;
      sessionId?: string;
    };
    const respond = (result: unknown, sessionId = message.sessionId) =>
      setTimeout(
        () =>
          this.emit("message", {
            data: JSON.stringify({ id: message.id, sessionId, result }),
          }),
        0,
      );
    const event = (method: string, params: Record<string, unknown>) =>
      setTimeout(
        () =>
          this.emit("message", {
            data: JSON.stringify({ method, sessionId: "s1", params }),
          }),
        1,
      );

    switch (message.method) {
      case "Target.getTargets":
        return respond({ targetInfos: [] });
      case "Target.createTarget":
        return respond({ targetId: "t1" });
      case "Target.attachToTarget":
        return respond({ sessionId: "s1" });
      case "Page.navigate":
        respond({ frameId: "f1" });
        event("Network.responseReceived", {
          requestId: "doc",
          type: "Document",
          response: { status: 201, headers: { "X-Test": "yes" } },
        });
        event("Page.loadEventFired", {});
        return;
      case "Runtime.evaluate": {
        const expression = String(message.params.expression ?? "");
        let value: unknown = null;
        if (expression.includes("location.href")) value = "https://target.test/";
        else if (expression.includes("document.title")) value = "Test page";
        else if (expression.includes("outerHTML")) value = "<html><body>hi</body></html>";
        else if (expression.includes("localStorage")) value = { localStorage: {}, sessionStorage: {} };
        return respond({ result: { type: "string", value } });
      }
      case "Network.getAllCookies":
        return respond({
          cookies: [
            { name: "sid", domain: ".target.test", path: "/", secure: true, httpOnly: true, sameSite: "Lax" },
          ],
        });
      case "Page.captureScreenshot":
        return respond({ data: "UE5H" });
      default:
        return respond({});
    }
  }
}

describe("CDP browser driver", () => {
  const original = (globalThis as unknown as { WebSocket?: unknown }).WebSocket;

  afterEach(() => {
    (globalThis as unknown as { WebSocket?: unknown }).WebSocket = original;
    FakeWebSocket.instances = [];
  });

  it("routes commands through a flattened session and captures a snapshot", async () => {
    (globalThis as unknown as { WebSocket?: unknown }).WebSocket = FakeWebSocket;

    const driver = await CdpBrowserDriver.create({
      endpoint: "ws://localhost:9222/devtools/browser/abc",
      apiToken: "tok",
      timeoutMs: 2000,
    });

    const result = await driver.open("https://target.test/", { screenshot: true });
    expect(result.url).toBe("https://target.test/");
    expect(result.title).toBe("Test page");
    expect(result.documentStatus).toBe(201);
    expect(result.documentHeaders["x-test"]).toBe("yes");
    expect(result.cookies[0]?.name).toBe("sid");
    expect(result.screenshot).toBe("UE5H");

    await driver.close();
    expect(FakeWebSocket.instances[0]?.url).toContain("token=tok");
  });
});
