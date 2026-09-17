import { describe, expect, it } from "vitest";
import type { ScopedHttpResult } from "@webstrike/types";
import {
  bodySimilarity,
  buildMultipart,
  buildSurface,
  createBudget,
  generateOpenApiCases,
  normalizeBody,
  reflectsUnescaped,
  runAutomatedTests,
  type AutomatedRequest,
  type Identity,
  type RequestExecutor,
} from "../src/index";

function result(
  url: string,
  status: number,
  body: string,
  options: {
    headers?: Record<string, string>;
    cookies?: ScopedHttpResult["cookies"];
  } = {},
): ScopedHttpResult {
  return {
    ok: true,
    finalUrl: url,
    status,
    statusText: status === 200 ? "OK" : status === 500 ? "Internal Server Error" : "",
    redirected: false,
    redirectChain: [],
    headers: { "content-type": "text/html; charset=utf-8", ...options.headers },
    cookies: options.cookies ?? [],
    body,
    bodyBytes: body.length,
    bodyTruncated: false,
    timingMs: 5,
  };
}

const BASE_HTML = `<!doctype html><html><body>
  <a href="/admin">admin</a>
  <a href="/api/items?id=1">items</a>
  <a href="/api/account">account</a>
  <a href="/api/orders/1">order</a>
  <form method="post" action="/login">
    <input type="hidden" name="csrf_token" value="tok-123">
    <input type="text" name="username" value="alice">
    <input type="password" name="password">
  </form>
  <form method="post" action="/upload" enctype="multipart/form-data">
    <input type="text" name="title" value="mytest">
    <input type="file" name="file">
  </form>
</body></html>`;

const fakeSite: RequestExecutor = async (request: AutomatedRequest) => {
  const url = new URL(request.url);
  const path = url.pathname;
  const origin = request.headers.find((h) => h.name.toLowerCase() === "origin")?.value;

  const withCors = (res: ScopedHttpResult): ScopedHttpResult => {
    if (!origin) return res;
    return {
      ...res,
      headers: {
        ...res.headers,
        "access-control-allow-origin": origin,
        "access-control-allow-credentials": "true",
      },
    };
  };

  if (path === "/") {
    return withCors(
      result(request.url, 200, BASE_HTML, {
        headers: { server: "nginx/1.2.3" },
        cookies: [
          {
            name: "session",
            value: "abc",
            raw: "session=abc; Path=/; HttpOnly",
            secure: false,
            httpOnly: true,
          },
        ],
      }),
    );
  }

  if (path === "/admin") {
    return result(request.url, 200, "<h1>admin panel secret</h1>");
  }

  if (path === "/api/account") {
    const authed =
      request.cookies.some((c) => c.name === "session") ||
      request.headers.some(
        (h) => h.name.toLowerCase() === "cookie" && h.value.includes("session="),
      );
    if (!authed) {
      return result(request.url, 401, JSON.stringify({ error: "unauthorized" }), {
        headers: { "content-type": "application/json" },
      });
    }
    return result(request.url, 200, JSON.stringify({ owner: "alice", balance: 100 }), {
      headers: { "content-type": "application/json" },
    });
  }

  if (path === "/api/orders/1") {
    const authed =
      request.cookies.some((c) => c.name === "session") ||
      request.headers.some(
        (h) => h.name.toLowerCase() === "cookie" && h.value.includes("session="),
      );
    if (!authed) {
      return result(request.url, 401, JSON.stringify({ error: "unauthorized" }), {
        headers: { "content-type": "application/json" },
      });
    }
    return result(
      request.url,
      200,
      JSON.stringify({ orderId: 1, owner: "Alice", total: 42, email: "alice@target.test" }),
      { headers: { "content-type": "application/json" } },
    );
  }

  if (path === "/api/items") {
    const id = url.searchParams.get("id") ?? "";
    if (id.includes("{{7*7}}") || id.includes("${7*7}")) {
      return result(request.url, 200, "49");
    }
    if (id.includes("'") || id.includes(";")) {
      return result(request.url, 500, "SQLSTATE[42000]: syntax error near \"'\"");
    }
    if (id.includes("<wsprobe")) {
      return result(request.url, 200, `<div>you searched for ${id}</div>`);
    }
    return result(request.url, 200, `<div>item ${id}</div>`);
  }

  if (path === "/login") {
    return result(request.url, 200, "<p>ok</p>");
  }

  if (path === "/upload") {
    return result(request.url, 200, "uploaded");
  }

  return result(request.url, 404, "not found");
};

const identities: Identity[] = [
  { id: "A", label: "Alice", headers: [{ name: "Cookie", value: "session=alice" }], cookies: [] },
  { id: "B", label: "Bob", headers: [{ name: "Cookie", value: "session=bob" }], cookies: [] },
];

const scope = { allowedDomains: ["target.test"], allowedPaths: ["/"], blockedDomains: [] };

describe("compare", () => {
  it("treats token-only differences as similar", () => {
    const a = `<input name="csrf" value="aaaa1111bbbb2222">hello`;
    const b = `<input name="csrf" value="cccc3333dddd4444">hello`;
    expect(normalizeBody(a)).toBe(normalizeBody(b));
    expect(bodySimilarity(a, b)).toBe(1);
  });

  it("detects unescaped reflection only for metacharacter payloads", () => {
    expect(reflectsUnescaped("<div>hi <wsprobe></div>", "<wsprobe>")).toBe(true);
    expect(reflectsUnescaped("<div>hi wsprobe</div>", "wsprobe")).toBe(false);
    expect(reflectsUnescaped("<div>&lt;wsprobe&gt;</div>", "<wsprobe>")).toBe(false);
  });
});

describe("surface discovery", () => {
  it("extracts links, forms, csrf tokens and file inputs", () => {
    const surface = buildSurface({
      targetUrl: "https://target.test/",
      scope,
      pages: [{ url: "https://target.test/", html: BASE_HTML }],
    });
    const urls = surface.endpoints.map((e) => e.url);
    expect(urls).toContain("https://target.test/admin");
    expect(urls).toContain("https://target.test/api/items?id=1");
    expect(surface.forms).toHaveLength(2);
    const login = surface.forms.find((f) => f.action.endsWith("/login"))!;
    expect(login.hasCsrfToken).toBe(true);
    expect(login.csrfFieldName).toBe("csrf_token");
    const upload = surface.forms.find((f) => f.action.endsWith("/upload"))!;
    expect(upload.hasFileInput).toBe(true);
  });
});

describe("multipart", () => {
  it("builds a well-formed body with fields and a file", () => {
    const { body, contentType } = buildMultipart(
      [{ name: "title", value: "hi" }],
      [{ fieldName: "file", filename: "a.txt", contentType: "text/plain", content: "data" }],
    );
    expect(contentType).toContain("multipart/form-data; boundary=");
    expect(body).toContain('name="title"');
    expect(body).toContain('filename="a.txt"');
    expect(body).toContain("data");
    expect(body.trim().endsWith("--")).toBe(true);
  });
});

describe("openapi", () => {
  it("generates parameter probes from a JSON document", () => {
    const doc = {
      openapi: "3.0.0",
      servers: [{ url: "https://target.test" }],
      paths: {
        "/api/items": {
          get: {
            operationId: "listItems",
            parameters: [{ name: "id", in: "query", schema: { type: "string" } }],
          },
          post: {
            operationId: "createItem",
            parameters: [{ name: "id", in: "query", schema: { type: "string" } }],
          },
        },
      },
    };
    const generated = generateOpenApiCases(doc, {
      baseUrl: "https://target.test",
      activeTests: false,
      maxOperations: 8,
      idPrefix: "oa",
    });
    expect(generated.cases).toHaveLength(1);
    expect(generated.cases[0]!.requests.length).toBeGreaterThan(1);
    expect(generated.cases[0]!.requests[0]!.url).toContain("id=");
  });

  it("reports a skip when nothing can be parsed", () => {
    const generated = generateOpenApiCases("not: [valid", {
      baseUrl: "https://target.test",
      activeTests: false,
      maxOperations: 8,
      idPrefix: "oa",
    });
    expect(generated.cases).toHaveLength(0);
    expect(generated.skipped[0]?.category).toBe("openapi");
  });
});

describe("budget", () => {
  it("stops at the request ceiling", async () => {
    const budget = createBudget(fakeSite, {
      maxRequests: 2,
      maxWallClockMs: 10_000,
      perRequestTimeoutMs: 1000,
      activeTests: false,
    });
    const req = (id: string): AutomatedRequest => ({
      id,
      label: id,
      method: "GET",
      url: "https://target.test/",
      headers: [],
      cookies: [],
    });
    await budget.run(req("a"));
    await budget.run(req("b"));
    await expect(budget.run(req("c"))).rejects.toThrow(/budget/);
  });
});

describe("runAutomatedTests", () => {
  it("produces evidence-backed observations across categories", async () => {
    const outcome = await runAutomatedTests(
      {
        targetUrl: "https://target.test/",
        scope,
        categories: [
          "security-headers",
          "cors",
          "csrf",
          "authentication",
          "authorization",
          "input-validation",
          "file-upload",
        ],
        identities,
        budget: {
          maxRequests: 300,
          maxWallClockMs: 20_000,
          perRequestTimeoutMs: 1000,
          activeTests: false,
        },
      },
      fakeSite,
    );

    const titles = outcome.observations.map((o) => o.title).join(" | ");
    expect(titles).toMatch(/Security headers not observed/);
    expect(titles).toMatch(/Technology banner/);
    expect(titles).toMatch(/CORS|origin reflected|Arbitrary origin/i);
    expect(titles).toMatch(/authentication|anonymous responses match/i);
    expect(titles).toMatch(/matching content|Two identities/i);
    expect(titles).toMatch(/server error|evaluated|reflected/i);
    expect(
      outcome.observations.some(
        (o) => o.state === "Potential Issue" || o.state === "Verified Security Issue",
      ),
    ).toBe(true);
    expect(outcome.stats.requests).toBeGreaterThan(5);
    expect(outcome.stats.truncated).toBe(false);
  });

  it("marks the run truncated when the budget is tiny", async () => {
    const outcome = await runAutomatedTests(
      {
        targetUrl: "https://target.test/",
        scope,
        categories: ["security-headers", "cors", "input-validation"],
        identities,
        budget: {
          maxRequests: 3,
          maxWallClockMs: 20_000,
          perRequestTimeoutMs: 1000,
          activeTests: false,
        },
      },
      fakeSite,
    );
    expect(outcome.stats.truncated).toBe(true);
    expect(outcome.stats.budgetExhausted).toBe(true);
  });

  it("runs an operator-defined workflow and reports unmet expectations", async () => {
    const outcome = await runAutomatedTests(
      {
        targetUrl: "https://target.test/",
        scope,
        categories: ["business-logic"],
        identities,
        workflow: [
          {
            id: "s1",
            label: "list items",
            method: "GET",
            url: "https://target.test/api/items?id=1",
            extract: { pattern: "item (\\w+)", as: "item" },
          },
          {
            id: "s2",
            label: "fetch extracted item",
            method: "GET",
            url: "https://target.test/api/items?id={{item}}",
            expect: { status: 200, bodyContains: "item" },
          },
        ],
        budget: {
          maxRequests: 20,
          maxWallClockMs: 10_000,
          perRequestTimeoutMs: 1000,
          activeTests: false,
        },
      },
      fakeSite,
    );
    expect(outcome.observations.some((o) => o.title === "Workflow executed")).toBe(true);
  });
});
