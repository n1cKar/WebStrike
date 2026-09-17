import { describe, expect, it } from "vitest";
import { classifyIp, isBlockedIp } from "../src/ip";

describe("classifyIp", () => {
  it.each(
    [
      "10.1.2.3",
      "172.16.0.1",
      "172.31.255.255",
      "192.168.1.1",
      "127.0.0.1",
      "0.0.0.0",
      "169.254.169.254",
      "169.254.1.1",
      "100.64.0.1",
      "192.0.2.55",
      "198.51.100.1",
      "203.0.113.1",
      "198.18.0.1",
      "224.0.0.1",
      "240.0.0.1",
      "255.255.255.255",
    ],
  )("blocks %s", (ip) => {
    expect(isBlockedIp(ip)).toBe(true);
  });

  it.each(["1.1.1.1", "8.8.8.8", "93.184.216.34", "104.16.132.229"])(
    "allows public %s",
    (ip) => {
      expect(isBlockedIp(ip)).toBe(false);
    },
  );

  it("blocks loopback and reserved IPv6", () => {
    expect(isBlockedIp("::1")).toBe(true);
    expect(isBlockedIp("::")).toBe(true);
    expect(isBlockedIp("fe80::1")).toBe(true);
    expect(isBlockedIp("fd00::1")).toBe(true);
    expect(isBlockedIp("ff02::1")).toBe(true);
    expect(isBlockedIp("2001:db8::1")).toBe(true);
  });

  it("allows global unicast IPv6", () => {
    expect(isBlockedIp("2606:4700:4700::1111")).toBe(false);
    expect(isBlockedIp("2001:4860:4860::8888")).toBe(false);
  });

  it("resolves IPv4-mapped IPv6 to the embedded IPv4", () => {
    expect(isBlockedIp("::ffff:192.168.1.1")).toBe(true);
    expect(isBlockedIp("::ffff:1.1.1.1")).toBe(false);
  });

  it("classifyIp returns a reason for the operator", () => {
    const r = classifyIp("169.254.169.254");
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected blocked");
    expect(r.reason).toMatch(/metadata/i);
  });

  it("rejects malformed addresses", () => {
    expect(() => classifyIp("not-an-ip")).toThrow();
  });
});

// 172.20.0.2 is private; it's included here to catch accidental over-permissiveness.
describe("private range coverage sanity", () => {
  it("172.20.0.2 is correctly classified private", () => {
    expect(isBlockedIp("172.20.0.2")).toBe(true);
  });
  it("172.15.0.1 is public (outside RFC1918)", () => {
    expect(isBlockedIp("172.15.0.1")).toBe(false);
  });
});