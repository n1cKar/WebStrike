import { describe, expect, it } from "vitest";
import type { ScopedHttpResult, TestingScope } from "@webstrike/types";
import {
  getAnalyzer,
  type AnalyzeContext,
  type AutomatedRequest,
  type Identity,
  type TestCase,
} from "../src/index";

const scope: TestingScope = {
  allowedDomains: ["target.test"],
  allowedPaths: ["/"],
  blockedDomains: [],
};

function res(
  url: string,
  status: number,
  body: string,
  headers: Record<string, string> = {},
  cookies: ScopedHttpResult["cookies"] = [],
): ScopedHttpResult {
  return {
    ok: true,
    finalUrl: url,
    status,
    statusText: status === 200 ? "OK" : "",
    redirected: false,
    redirectChain: [],
    headers: { "content-type": "text/html; charset=utf-8", ...headers },
    cookies,
    body,
    bodyBytes: body.length,
    bodyTruncated: false,
    timingMs: 3,
  };
}

function request(
  id: string,
  url: string,
  extra: Partial<AutomatedRequest> = {},
): AutomatedRequest {
  return {
    id,
    label: id,
    method: "GET",
    url,
    headers: [],
    cookies: [],
    ...extra,
  };
}

function analyze(
  testCase: TestCase,
  results: Record<string, ScopedHttpResult>,
  identities: Identity[] = [],
  activeTests = false,
) {
  const analyzer = getAnalyzer(testCase.analyzer);
  if (!analyzer) throw new Error(`no analyzer ${testCase.analyzer}`);
  const context: AnalyzeContext = {
    testCase,
    surface: {
      baseUrl: "https://target.test/",
      origin: "https://target.test",
      endpoints: [],
      forms: [],
      notes: [],
    },
    results,
    identities,
    activeTests,
  };
  return analyzer(context);
}

const authenticatedIdentity: Identity = {
  id: "A",
  label: "Alice",
  headers: [{ name: "Cookie", value: "session=alice" }],
  cookies: [{ name: "session", value: "alice" }],
};

describe("CORS accuracy", () => {
  const testCase: TestCase = {
    id: "cors",
    category: "cors",
    title: "CORS policy",
    analyzer: "cors",
    metadata: { probeOrigin: "https://webstrike-probe.invalid" },
    requests: [
      request("base", "https://target.test/"),
      request(
        "probe",
        "https://target.test/",
        { headers: [{ name: "Origin", value: "https://webstrike-probe.invalid" }] },
      ),
    ],
  };

  it("does not escalate a reflected origin to a potential issue when the probe is unauthenticated", () => {
    const reflected = { "access-control-allow-origin": "https://webstrike-probe.invalid" };
    const observations = analyze(testCase, {
      base: res("https://target.test/", 200, "ok"),
      probe: res("https://target.test/", 200, "ok", {
        ...reflected,
        "access-control-allow-credentials": "true",
      }),
    });
    expect(observations).toHaveLength(1);
    expect(observations[0]!.state).toBe("Needs Verification");
    expect(observations[0]!.confidence).toBe("low");
    expect(observations[0]!.title).toMatch(/unauthenticated/i);
  });

  it("escalates arbitrary-origin reflection with credentials only when the probe carried credentials", () => {
    const withCredentials: TestCase = {
      ...testCase,
      requests: [
        request("base", "https://target.test/"),
        request(
          "probe",
          "https://target.test/",
          {
            headers: [{ name: "Origin", value: "https://webstrike-probe.invalid" }],
            cookies: [{ name: "session", value: "alice" }],
          },
        ),
      ],
    };
    const observations = analyze(withCredentials, {
      base: res("https://target.test/", 200, "ok"),
      probe: res("https://target.test/", 200, "ok", {
        "access-control-allow-origin": "https://webstrike-probe.invalid",
        "access-control-allow-credentials": "true",
      }),
    });
    expect(observations).toHaveLength(1);
    expect(observations[0]!.state).toBe("Potential Issue");
    expect(observations[0]!.confidence).toBe("high");
  });

  it("stays silent when no CORS headers are present", () => {
    const observations = analyze(testCase, {
      base: res("https://target.test/", 200, "ok"),
      probe: res("https://target.test/", 200, "ok"),
    });
    expect(observations).toEqual([]);
  });
});

describe("security header accuracy", () => {
  const testCase: TestCase = {
    id: "headers",
    category: "security-headers",
    title: "Security headers",
    analyzer: "security-headers",
    requests: [request("base", "https://target.test/")],
  };

  it("does not report missing headers for a fully configured HTTPS site", () => {
    const observations = analyze(testCase, {
      base: res("https://target.test/", 200, "<html></html>", {
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "x-frame-options": "DENY",
        "strict-transport-security": "max-age=63072000",
        "set-cookie": "session=abc; Secure; HttpOnly; SameSite=Strict",
      }),
    });
    expect(observations).toEqual([]);
  });

  it("reports missing headers as a low-confidence observation, never a potential issue", () => {
    const observations = analyze(testCase, {
      base: res("https://target.test/", 200, "<html></html>"),
    });
    const headerObservation = observations.find((o) => o.title.includes("Security headers"));
    expect(headerObservation).toBeDefined();
    expect(headerObservation!.state).toBe("Observation");
    expect(headerObservation!.confidence).toBe("low");
    expect(observations.some((o) => o.state === "Potential Issue")).toBe(false);
  });
});

describe("authentication accuracy", () => {
  const testCase: TestCase = {
    id: "auth",
    category: "authentication",
    title: "Authentication boundary",
    analyzer: "auth-anon",
    requests: [
      request("authed", "https://target.test/about", {
        headers: [{ name: "Cookie", value: "session=alice" }],
      }),
      request("anon", "https://target.test/about"),
    ],
  };

  it("treats identical public content as a low-confidence observation", () => {
    const html = "<html><body>About us</body></html>";
    const observations = analyze(
      testCase,
      {
        authed: res("https://target.test/about", 200, html),
        anon: res("https://target.test/about", 200, html),
      },
      [authenticatedIdentity],
    );
    expect(observations).toHaveLength(1);
    expect(observations[0]!.state).toBe("Observation");
    expect(observations[0]!.confidence).toBe("low");
    expect(observations.some((o) => o.state === "Potential Issue")).toBe(false);
  });
});

describe("authorization accuracy", () => {
  const testCase: TestCase = {
    id: "authz",
    category: "authorization",
    title: "Object ownership",
    analyzer: "authz-compare",
    requests: [
      request("a", "https://target.test/api/items/1", {
        headers: [{ name: "Cookie", value: "session=alice" }],
      }),
      request("b", "https://target.test/api/items/1", {
        headers: [{ name: "Cookie", value: "session=bob" }],
      }),
    ],
  };

  const identities: Identity[] = [
    authenticatedIdentity,
    {
      id: "B",
      label: "Bob",
      headers: [{ name: "Cookie", value: "session=bob" }],
      cookies: [{ name: "session", value: "bob" }],
    },
  ];

  it("does not flag identical HTML pages shared by two identities", () => {
    const html = "<html><body>Public catalogue</body></html>";
    const observations = analyze(
      testCase,
      {
        a: res("https://target.test/api/items/1", 200, html),
        b: res("https://target.test/api/items/1", 200, html),
      },
      identities,
    );
    expect(observations).toEqual([]);
  });

  it("raises a needs-verification item for identical structured records", () => {
    const body = JSON.stringify({ id: 1, owner: "alice", balance: 10 });
    const observations = analyze(
      testCase,
      {
        a: res("https://target.test/api/items/1", 200, body, {
          "content-type": "application/json",
        }),
        b: res("https://target.test/api/items/1", 200, body, {
          "content-type": "application/json",
        }),
      },
      identities,
    );
    expect(observations).toHaveLength(1);
    expect(observations[0]!.state).toBe("Needs Verification");
    expect(observations.some((o) => o.state === "Potential Issue")).toBe(false);
  });
});

describe("input validation accuracy", () => {
  const testCase: TestCase = {
    id: "input",
    category: "input-validation",
    title: "Search input",
    analyzer: "input-validation",
    metadata: {
      probes: [
        {
          requestId: "safe",
          probeId: "safe",
          value: "hello",
          intent: "ordinary value",
        },
        {
          requestId: "encoded",
          probeId: "encoded",
          value: "<wsprobe>",
          intent: "reflected value",
        },
      ],
    },
    requests: [
      request("base", "https://target.test/search?q=hello"),
      request("safe", "https://target.test/search?q=hello"),
      request("encoded", "https://target.test/search?q=%3Cwsprobe%3E"),
    ],
  };

  it("produces no potential issues for ordinary and safely encoded input", () => {
    const observations = analyze(testCase, {
      base: res("https://target.test/search?q=hello", 200, "<div>results</div>"),
      safe: res("https://target.test/search?q=hello", 200, "<div>results</div>"),
      encoded: res(
        "https://target.test/search?q=%3Cwsprobe%3E",
        200,
        "<div>you searched for &lt;wsprobe&gt;</div>",
      ),
    });
    expect(observations).toEqual([]);
  });

  it("downgrades raw reflection to a low-confidence needs-verification item", () => {
    const observations = analyze(testCase, {
      base: res("https://target.test/search?q=hello", 200, "<div>results</div>"),
      safe: res("https://target.test/search?q=hello", 200, "<div>results</div>"),
      encoded: res(
        "https://target.test/search?q=%3Cwsprobe%3E",
        200,
        "<div>you searched for <wsprobe></div>",
      ),
    });
    const reflection = observations.find((o) => o.title === "Input reflected without encoding");
    expect(reflection).toBeDefined();
    expect(reflection!.state).toBe("Needs Verification");
    expect(reflection!.confidence).toBe("low");
  });

  it("still escalates server errors triggered by a probe", () => {
    const errorCase: TestCase = {
      ...testCase,
      metadata: {
        probes: [
          { requestId: "boom", probeId: "boom", value: "'", intent: "quote character" },
        ],
      },
      requests: [
        request("base", "https://target.test/search?q=hello"),
        request("boom", "https://target.test/search?q=%27"),
      ],
    };
    const observations = analyze(errorCase, {
      base: res("https://target.test/search?q=hello", 200, "<div>results</div>"),
      boom: res("https://target.test/search?q=%27", 500, "Internal Server Error"),
    });
    expect(observations).toHaveLength(1);
    expect(observations[0]!.state).toBe("Potential Issue");
  });
});
