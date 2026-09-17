import { describe, expect, it } from "vitest";
import type { ScopedHttpResult } from "@webstrike/types";
import {
  aiAssessmentSchema,
  analyzeWithGroq,
  classifyUrl,
  dedupeObservations,
  diffResponses,
  enrichObservationsWithAi,
  formatAiNote,
  isAuthFlow,
  isResourceAccess,
  isSensitiveField,
  prioritizeObservations,
  redactHeaderValue,
  redactText,
  redactUrl,
  summarizeStates,
  type TestObservation,
} from "../src/index";

function res(
  status: number,
  body: string,
  headers: Record<string, string> = { "content-type": "application/json" },
): ScopedHttpResult {
  return {
    ok: true,
    finalUrl: "https://target.test/x",
    status,
    statusText: status === 200 ? "OK" : "",
    redirected: false,
    redirectChain: [],
    headers,
    cookies: [],
    body,
    bodyBytes: body.length,
    bodyTruncated: false,
    timingMs: 5,
  };
}

function obs(partial: Partial<TestObservation> & Pick<TestObservation, "id" | "state">): TestObservation {
  return {
    category: "authorization",
    title: "Potential broken object-level authorization",
    confidence: "high",
    summary: "summary",
    evidence: {
      detail: "detail",
      request: { label: "B", method: "GET", url: "https://target.test/api/orders/1", headers: [] },
      response: { status: 200, statusText: "OK", bodyBytes: 10, bodyPreview: "{}", headers: {} },
    },
    ...partial,
  };
}

describe("redaction", () => {
  it("masks bearer tokens, assignments and hex tokens in free text", () => {
    const text = "Authorization: Bearer abcdefghijklmnop1234 password=hunter2 token=deadbeefdeadbeefdeadbeefdeadbeef";
    const redacted = redactText(text);
    expect(redacted).not.toContain("hunter2");
    expect(redacted).not.toContain("abcdefghijklmnop1234");
    expect(redacted).not.toContain("deadbeefdeadbeefdeadbeefdeadbeef");
    expect(redacted).toContain("«redacted»");
  });

  it("masks session values while keeping cookie names", () => {
    expect(redactHeaderValue("Cookie", "session=alice; theme=dark")).toBe(
      "session=«redacted»; theme=«redacted»",
    );
    expect(redactHeaderValue("Authorization", "Bearer abc.def")).toBe("Bearer «redacted»");
  });

  it("masks sensitive query parameters in URLs", () => {
    const url = redactUrl("https://target.test/cb?token=secretvalue&page=2");
    expect(url).not.toContain("secretvalue");
    expect(url).toContain("page=2");
  });
});

describe("response diff", () => {
  it("identifies sensitive keys and structured bodies", () => {
    const a = res(200, JSON.stringify({ owner: "alice" }));
    const b = res(200, JSON.stringify({ owner: "alice", balance: 100, email: "a@b.c" }));
    const diff = diffResponses(a, b);
    expect(isSensitiveField("balance")).toBe(true);
    expect(isSensitiveField("theme")).toBe(false);
    expect(diff.structured).toBe(true);
    expect(diff.keysAdded).toEqual(["balance", "email"]);
    expect(diff.sensitiveKeysAdded).toEqual(["balance", "email"]);
  });
});

describe("classification", () => {
  it("separates auth flows, admin areas and resource access", () => {
    expect(isAuthFlow(classifyUrl("https://target.test/login"))).toBe(true);
    expect(classifyUrl("https://target.test/admin")).toContain("ADMIN");
    expect(isResourceAccess(classifyUrl("https://target.test/api/orders/1"))).toBe(true);
    expect(classifyUrl("https://target.test/about")).toContain("PUBLIC");
  });
});

describe("prioritisation", () => {
  it("collapses duplicates onto the strongest state", () => {
    const observations = [
      obs({ id: "1", state: "Observation", title: "Same thing" }),
      obs({ id: "2", state: "Potential Issue", title: "Same thing" }),
      obs({ id: "3", state: "Potential Issue", title: "Same thing" }),
    ];
    const deduped = dedupeObservations(observations);
    expect(deduped).toHaveLength(1);
    expect(deduped[0]!.state).toBe("Potential Issue");
  });

  it("orders tier-1 verified issues ahead of tier-3 hardening and fills defaults", () => {
    const observations = [
      obs({ id: "h", state: "Observation", category: "security-headers", title: "headers" }),
      obs({
        id: "v",
        state: "Verified Security Issue",
        category: "authorization",
        title: "bola",
      }),
    ];
    const ordered = prioritizeObservations(observations);
    expect(ordered[0]!.id).toBe("v");
    expect(ordered[0]!.tier).toBe(1);
    expect(ordered[0]!.severity).toBe("high");
    expect(ordered[1]!.tier).toBe(3);
    expect(summarizeStates(ordered)["Verified Security Issue"]).toBe(1);
  });
});

describe("ai advisory layer", () => {
  it("validates the assessment shape", () => {
    expect(
      aiAssessmentSchema.safeParse({
        supportsSecurityIssue: true,
        confidence: "medium",
        explanation: "x",
        falsePositiveExplanations: [],
        additionalVerification: [],
      }).success,
    ).toBe(true);
    expect(
      aiAssessmentSchema.safeParse({
        supportsSecurityIssue: true,
        confidence: "certain",
        explanation: "x",
      }).success,
    ).toBe(false);
  });

  it("parses a model response and fails open on transport errors", async () => {
    const okFetch = (async () =>
      ({
        ok: true,
        json: async () => ({
          choices: [
            {
              message: {
                content: JSON.stringify({
                  supportsSecurityIssue: true,
                  confidence: "low",
                  explanation: "marker leak",
                  falsePositiveExplanations: ["seed data"],
                  additionalVerification: ["confirm ownership"],
                }),
              },
            },
          ],
        }),
      }) as Response) as typeof fetch;

    const assessment = await analyzeWithGroq(
      {
        target: "https://target.test/",
        endpoint: "https://target.test/api/orders/1",
        method: "GET",
        category: "authorization",
        claim: "Potential broken object-level authorization",
      },
      { apiKey: "test", fetchImpl: okFetch },
    );
    expect(assessment?.supportsSecurityIssue).toBe(true);
    expect(formatAiNote(assessment!)).toContain("AI (advisory");

    const brokenFetch = (async () => ({ ok: false, json: async () => ({}) }) as Response) as typeof fetch;
    expect(
      await analyzeWithGroq(
        {
          target: "https://target.test/",
          endpoint: "https://target.test/api/orders/1",
          method: "GET",
          category: "authorization",
          claim: "x",
        },
        { apiKey: "test", fetchImpl: brokenFetch },
      ),
    ).toBeNull();
  });

  it("annotates only serious results and never changes their state", async () => {
    const fetchImpl = (async () =>
      ({
        ok: true,
        json: async () => ({
          choices: [
            {
              message: {
                content: JSON.stringify({
                  supportsSecurityIssue: false,
                  confidence: "low",
                  explanation: "likely benign",
                }),
              },
            },
          ],
        }),
      }) as Response) as typeof fetch;

    const input = [
      obs({ id: "p", state: "Potential Issue" }),
      obs({ id: "o", state: "Observation" }),
    ];
    const enriched = await enrichObservationsWithAi(input, { apiKey: "test", fetchImpl });
    expect(enriched[0]!.aiNote).toContain("likely benign");
    expect(enriched[0]!.state).toBe("Potential Issue");
    expect(enriched[1]!.aiNote).toBeUndefined();
  });
});
