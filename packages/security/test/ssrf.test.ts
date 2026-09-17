import { afterEach, describe, expect, it, vi } from "vitest";
import type { TestingScope } from "@webstrike/types";
import { checkResolvedAddress, assertUrlRequestable } from "../src/ssrf";

afterEach(() => vi.restoreAllMocks());

const scope: TestingScope = {
  allowedDomains: ["example.test"],
  allowedPaths: ["/"],
  blockedDomains: [],
};

const mockLookup = (records: { address: string }[] | Error) => {
  const lookup = vi.fn(async () => {
    if (records instanceof Error) throw records;
    return records;
  });
  vi.doMock("node:dns/promises", () => ({ lookup }));
  return lookup;
};

describe("checkResolvedAddress", () => {
  it("refuses a private IP returned by DNS", async () => {
    vi.resetModules();
    mockLookup([{ address: "127.0.0.1" }]);
    const { checkResolvedAddress } = await import("../src/ssrf");
    const r = await checkResolvedAddress("attacker.example.com");
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected refusal");
    expect(r.reason).toMatch(/loopback/);
  });

  it("refuses the metadata IP returned by DNS", async () => {
    vi.resetModules();
    mockLookup([{ address: "169.254.169.254" }]);
    const { checkResolvedAddress } = await import("../src/ssrf");
    const r = await checkResolvedAddress("metadata.evil.test");
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected refusal");
    expect(r.reason).toMatch(/metadata/i);
  });

  it("refuses when any single record is private (mixed results)", async () => {
    vi.resetModules();
    mockLookup([{ address: "8.8.8.8" }, { address: "10.0.0.4" }]);
    const { checkResolvedAddress } = await import("../src/ssrf");
    const r = await checkResolvedAddress("mixed.example.com");
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected refusal");
    expect(r.reason).toMatch(/10\.0\.0\.4 refused/);
  });

  it("allows a fully public resolution", async () => {
    vi.resetModules();
    mockLookup([{ address: "93.184.216.34" }, { address: "2606:4700:4700::1111" }]);
    const { checkResolvedAddress } = await import("../src/ssrf");
    const r = await checkResolvedAddress("example.com");
    expect(r.ok).toBe(true);
    if (!r.ok) throw new Error("expected success");
    expect(r.addresses).toHaveLength(2);
  });

  it("handles unresolvable hosts as DNS_FAILURE", async () => {
    vi.resetModules();
    const err = new Error("nope") as NodeJS.ErrnoException;
    err.code = "ENOTFOUND";
    mockLookup(err);
    const { checkResolvedAddress } = await import("../src/ssrf");
    const r = await checkResolvedAddress("no-such-host.invalid");
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected refusal");
    expect(r.reason).toMatch(/did not resolve/);
  });
});

describe("assertUrlRequestable", () => {
  it("refuses an out-of-scope host before DNS", async () => {
    vi.resetModules();
    const lookup = vi.fn();
    vi.doMock("node:dns/promises", () => ({ lookup }));
    const { assertUrlRequestable } = await import("../src/ssrf");
    const r = await assertUrlRequestable("https://evil.com/x", scope);
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected refusal");
    expect(r.kind).toBe("OUT_OF_SCOPE");
    expect(lookup).not.toHaveBeenCalled();
  });

  it("blocks a host whose DNS points into RFC1918", async () => {
    vi.resetModules();
    mockLookup([{ address: "192.168.0.10" }]);
    const { assertUrlRequestable } = await import("../src/ssrf");
    const r = await assertUrlRequestable("https://example.test/x", scope);
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected refusal");
    expect(r.kind).toBe("SSRF_BLOCKED");
    expect(r.message).toMatch(/192\.168\.0\.10/);
  });

  it("passes an in-scope host with public addresses", async () => {
    vi.resetModules();
    mockLookup([{ address: "1.1.1.1" }]);
    const { assertUrlRequestable } = await import("../src/ssrf");
    const r = await assertUrlRequestable("https://example.test/api", scope);
    expect(r.ok).toBe(true);
    if (!r.ok) throw new Error("expected success");
    expect(r.addresses).toEqual(["1.1.1.1"]);
  });
});