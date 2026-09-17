import { describe, expect, it } from "vitest";
import {
  hostMatchesPattern,
  isBlockedHost,
  isSystemBlockedHostname,
  validateScopedUrl,
} from "../src/scope";
import type { TestingScope } from "@webstrike/types";

const scope = (partial: Partial<TestingScope> = {}): TestingScope =>
  ({
    allowedDomains: ["example.test"],
    allowedPaths: ["/"],
    blockedDomains: [],
    ...partial,
  }) as TestingScope;

describe("hostMatchesPattern", () => {
  it("matches the apex and subdomains of a bare pattern", () => {
    expect(hostMatchesPattern("example.test", "example.test")).toBeTruthy();
    expect(hostMatchesPattern("api.example.test", "example.test")).toMatchObject({ type: "subdomain" });
    expect(hostMatchesPattern("a.b.example.test", "example.test")).toBeTruthy();
  });

  it("wildcard matches only subdomains", () => {
    expect(hostMatchesPattern("example.test", "*.example.test")).toBeNull();
    expect(hostMatchesPattern("api.example.test", "*.example.test")).toBeTruthy();
    expect(hostMatchesPattern("x.y.example.test", "*.example.test")).toBeTruthy();
  });

  it("is case insensitive and resolves a trailing dot", () => {
    expect(hostMatchesPattern("EXAMPLE.TEST.", "example.test")).toBeTruthy();
  });

  it("rejects unrelated hosts and partial-suffix lookalikes", () => {
    expect(hostMatchesPattern("notexample.test", "example.test")).toBeNull();
    expect(hostMatchesPattern("exampl.test", "example.test")).toBeNull();
    expect(hostMatchesPattern("example.test.evil.com", "example.test")).toBeNull();
  });
});

describe("isBlockedHost", () => {
  it("blocked beats allowed", () => {
    expect(isBlockedHost("sub.example.test", ["*.example.test"])).toMatchObject({ blocked: true });
    expect(isBlockedHost("example.test", ["*.example.test"])).toMatchObject({ blocked: false });
  });
});

describe("isSystemBlockedHostname", () => {
  it.each(["localhost", "metadata.google.internal", "myhost.internal", "printer.local", "x.home.arpa"])(
    "blocks %s",
    (host) => {
      expect(isSystemBlockedHostname(host)).toBeTruthy();
    },
  );
  it.each(["example.test", "api.example.com", "internal.example.com"])(
    "allows %s",
    (host) => {
      expect(isSystemBlockedHostname(host)).toBeNull();
    },
  );
});

describe("validateScopedUrl", () => {
  it("accepts an in-scope URL", () => {
    const r = validateScopedUrl("https://example.test/api/users/1?x=1", scope({}));
    expect(r.ok).toBe(true);
  });

  it("rejects a non-allowed host", () => {
    const r = validateScopedUrl("https://evil.com/", scope({}));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/not within the authorised target scope/i);
  });

  it("allows a configured subdomain-only wildcard", () => {
    const r = validateScopedUrl(
      "https://api.example.test/v1",
      scope({ allowedDomains: ["*.example.test"] }),
    );
    expect(r.ok).toBe(true);
  });

  it("rejects the apex when only a wildcard is allowed", () => {
    const r = validateScopedUrl(
      "https://example.test/v1",
      scope({ allowedDomains: ["*.example.test"] }),
    );
    expect(r.ok).toBe(false);
  });

  it("enforces path prefixes", () => {
    const ok = validateScopedUrl(
      "https://example.test/api/profile",
      scope({ allowedPaths: ["/api"] }),
    );
    expect(ok.ok).toBe(true);
    const bad = validateScopedUrl(
      "https://example.test/admin/panel",
      scope({ allowedPaths: ["/api"] }),
    );
    expect(bad.ok).toBe(false);
    expect(bad.reason).toMatch(/outside the authorised scope/);
  });

  it("background: '/' prefix allows every path", () => {
    expect(validateScopedUrl("https://example.test/deep/path", scope({ allowedPaths: ["/"] })).ok).toBe(true);
  });

  it("refuses non-http schemes, credentials and malformed URLs", () => {
    expect(validateScopedUrl("file:///etc/passwd", scope({})).ok).toBe(false);
    expect(validateScopedUrl("gopher://example.test", scope({})).ok).toBe(false);
    expect(validateScopedUrl("https://user:pass@example.test/", scope({})).ok).toBe(false);
    expect(validateScopedUrl("not a url", scope({})).ok).toBe(false);
    expect(validateScopedUrl("", scope({})).ok).toBe(false);
  });

  it("blocks explicitly listed blocked domains even if allowed", () => {
    const r = validateScopedUrl(
      "https://sub.example.test/x",
      scope({ allowedDomains: ["example.test"], blockedDomains: ["*.example.test"] }),
    );
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/blocked explicitly/);
  });

  it("accepts a public IP literal only when listed", () => {
    const allowedScope = scope({});
    allowedScope.allowedDomains = ["93.184.216.34"];
    expect(validateScopedUrl("http://93.184.216.34/", allowedScope).ok).toBe(true);
    const notAllowed = scope({});
    expect(validateScopedUrl("http://93.184.216.34/", notAllowed).ok).toBe(false);
  });

  it("canonicalises numeric IP forms before scope matching", () => {
    // WHATWG URL normalises 0x7f000001 to 127.0.0.1 — a claimed literal
    // "0x7f000001" can therefore never be an allowed domain that matches.
    const allowedScope = scope({});
    allowedScope.allowedDomains = ["0x7f000001"];
    const r = validateScopedUrl("https://0x7f000001/", allowedScope);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/127\.0\.0\.1 is not in the authorised target scope/);
  });
});