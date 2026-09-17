import { beforeEach, describe, expect, it, vi } from "vitest";
import type { HttpRequestSpec, TestingScope } from "@webstrike/types";
import { runScopedRequest } from "../src/http";

const scope: TestingScope = {
  allowedDomains: ["example.test"],
  allowedPaths: ["/"],
  blockedDomains: [],
};

const spec: HttpRequestSpec = {
  id: "t1",
  method: "GET",
  url: "https://example.test/",
  headers: [{ name: "X-Test", value: "1" }],
  cookies: [],
  body: null,
  contentType: null,
};

function resp(status: number, init: { headers?: Record<string, string>; body?: string }) {
  return new Response(init.body, { status, statusText: "OK", headers: init.headers });
}

// The URL/SSRF layer is deterministic: only allow example.test -> public IP.
vi.mock("../src/ssrf", () => ({
  assertUrlRequestable: vi.fn(
    async (url: string): Promise<
      | { ok: true; url: URL; host: string; addresses: string[] }
      | { ok: false; kind: "OUT_OF_SCOPE" | "SSRF_BLOCKED" | "DNS_FAILURE"; message: string }
    > => {
      if (new URL(url).hostname.endsWith("example.test")) {
        return { ok: true, url: new URL(url), host: new URL(url).hostname, addresses: ["1.1.1.1"] };
      }
      return { ok: false, kind: "OUT_OF_SCOPE", message: "host is outside the authorised scope" };
    },
  ),
}));

describe("runScopedRequest", () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
  });

  it("executes a basic request and parses cookies/headers", async () => {
    const fetchMock = vi.fn(async () =>
      resp(200, {
        headers: {
          "content-type": "application/json",
          "x-powered-by": "Express",
          "set-cookie": "session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax",
        },
        body: '{"ok":true}',
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const result = await runScopedRequest(spec, scope);

    expect(result.ok).toBe(true);
    expect(result.status).toBe(200);
    expect(result.body).toBe('{"ok":true}');
    expect(result.cookies).toHaveLength(1);
    expect(result.cookies[0]).toMatchObject({
      name: "session",
      httpOnly: true,
      secure: true,
      sameSite: "Lax",
    });
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("drops transport-managed headers and merges cookies", async () => {
    const fetchMock = vi.fn(
      async (_url?: string, _init?: RequestInit) => resp(200, { body: "" }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await runScopedRequest(
      {
        ...spec,
        headers: [
          { name: "Host", value: "evil.com" },
          { name: "Content-Length", value: "999" },
          { name: "Transfer-Encoding", value: "chunked" },
          { name: "X-Keep", value: "yes" },
        ],
        cookies: [{ name: "a", value: "1" }, { name: "b", value: "2" }],
      },
      scope,
    );

    const init = fetchMock.mock.calls[0]![1]!;
    const headers = init.headers as Headers;
    expect(headers.get("host")).toBeNull();
    expect(headers.get("content-length")).toBeNull();
    expect(headers.get("transfer-encoding")).toBeNull();
    expect(headers.get("x-keep")).toBe("yes");
    expect(headers.get("cookie")).toBe("a=1; b=2");
  });

  it("caps oversized response bodies", async () => {
    const fetchMock = vi.fn(async () =>
      resp(200, { headers: { "content-type": "text/plain" }, body: "a".repeat(200_000) }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const result = await runScopedRequest(spec, scope, { maxResponseBytes: 100_000 });
    expect(result.bodyBytes).toBe(100_000);
    expect(result.bodyTruncated).toBe(true);
  });

  it("refuses redirects that leave scope without following them", async () => {
    const fetchMock = vi.fn(async (url: string) => {
      if (new URL(url).hostname.endsWith("example.test")) {
        return resp(302, { headers: { location: "https://evil.com/away", "set-cookie": "k=v; HttpOnly" } });
      }
      return resp(200, { body: "must never be reached" });
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await runScopedRequest(spec, scope);
    expect(result.status).toBe(302);
    expect(result.redirected).toBe(true);
    expect(result.redirectChain).toHaveLength(1);
    expect(result.redirectChain[0]!.reason).toMatch(/refused/);
    expect(fetchMock).toHaveBeenCalledOnce(); // never followed off-scope
  });

  it("follows in-scope redirect chains within the limit", async () => {
    const fetchMock = vi.fn(async (url: string) => {
      if (!url.includes("/final")) {
        return resp(301, { headers: { location: "https://example.test/final" } });
      }
      return resp(204, {});
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await runScopedRequest(spec, scope);
    expect(result.status).toBe(204);
    expect(result.redirected).toBe(true);
    expect(result.redirectChain).toHaveLength(1);
    expect(result.finalUrl).toContain("/final");
  });

  it("aborts on timeout with a TIMEOUT error", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, init: RequestInit) => {
        const signal = init.signal as AbortSignal;
        return new Promise((_, reject) => {
          const done = () =>
            reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
          if (signal.aborted) return done();
          signal.addEventListener("abort", done, { once: true });
        });
      }),
    );

    const result = await runScopedRequest(spec, scope, { timeoutMs: 50 });
    expect(result.ok).toBe(false);
    expect(result.error?.kind).toBe("TIMEOUT");
  });
});