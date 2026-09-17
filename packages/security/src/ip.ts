import ipaddr from "ipaddr.js";

export type IpCheck =
  | { ok: true; address: string }
  | { ok: false; address: string; reason: string };

/**
 * IPv4 CIDR blocks that WebStrike will never connect to. Covers private,
 * loopback, link-local (incl. cloud metadata 169.254.169.254), CGNAT,
 * documentation/test-net, benchmarking, multicast and reserved ranges.
 */
const BLOCKED_V4 = [
  "0.0.0.0/8",
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.0.0.0/24",
  "192.0.2.0/24",
  "192.168.0.0/16",
  "198.18.0.0/15",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "224.0.0.0/4",
  "240.0.0.0/4",
  "255.255.255.255/32",
];

/**
 * IPv6 CIDR blocks: unspecified, loopback, IPv4-mapped (checked as IPv4),
 * documentation, ULA, link-local, discard and multicast.
 */
const BLOCKED_V6 = [
  "::/128",
  "::1/128",
  "::ffff:0:0/96",
  "64:ff9b::/96",
  "100::/64",
  "2001:db8::/32",
  "4000::/3",
  "fc00::/7",
  "fe80::/10",
  "ff00::/8",
];

const V4_CACHE = BLOCKED_V4.map((cidr) => {
  const [addr, bits] = ipaddr.parseCIDR(cidr);
  return { addr, bits };
});

const V6_CACHE = BLOCKED_V6.map((cidr) => {
  const [addr, bits] = ipaddr.parseCIDR(cidr);
  return { addr, bits };
});

function reasonForBlockedV4(address: string): string {
  if (ipaddr.process(address).match(V4_CACHE[1]!.addr, V4_CACHE[1]!.bits))
    return "RFC 1918 private range (10.0.0.0/8)";
  if (ipaddr.process(address).match(V4_CACHE[5]!.addr, V4_CACHE[5]!.bits))
    return "RFC 1918 private range (172.16.0.0/12)";
  if (ipaddr.process(address).match(V4_CACHE[7]!.addr, V4_CACHE[7]!.bits))
    return "RFC 1918 private range (192.168.0.0/16)";
  if (ipaddr.process(address).match(V4_CACHE[2]!.addr, V4_CACHE[2]!.bits))
    return "CGNAT range (100.64.0.0/10)";
  if (ipaddr.process(address).match(V4_CACHE[3]!.addr, V4_CACHE[3]!.bits))
    return "loopback range (127.0.0.0/8)";
  if (ipaddr.process(address).match(V4_CACHE[4]!.addr, V4_CACHE[4]!.bits))
    return "link-local range (169.254.0.0/16, includes cloud metadata)";
  if (ipaddr.process(address).match(V4_CACHE[0]!.addr, V4_CACHE[0]!.bits))
    return "unspecified/this-network range (0.0.0.0/8)";
  return "private, reserved or non-routable IPv4 range";
}

function reasonForBlockedV6(address: string): string {
  const a = ipaddr.parse(address);
  if (a.match(V6_CACHE[1]!.addr, V6_CACHE[1]!.bits))
    return "IPv6 loopback (::1)";
  if (a.kind() === "ipv6" && (a as ipaddr.IPv6).isIPv4MappedAddress())
    return "IPv4-mapped IPv6 address";
  if (a.match(V6_CACHE[6]!.addr, V6_CACHE[6]!.bits))
    return "IPv6 unique-local range (fc00::/7)";
  if (a.match(V6_CACHE[7]!.addr, V6_CACHE[7]!.bits))
    return "IPv6 link-local range (fe80::/10)";
  if (a.match(V6_CACHE[8]!.addr, V6_CACHE[8]!.bits))
    return "IPv6 multicast range (ff00::/8)";
  return "private, reserved or non-routable IPv6 range";
}

/** Classify a single IP address string. Throws on non-IP input. */
export function classifyIp(input: string): IpCheck {
  const parsed = ipaddr.process(input);
  const canonical = parsed.toString();
  let v4: ipaddr.IPv4 | null = null;

  if (parsed.kind() === "ipv4") {
    v4 = parsed as ipaddr.IPv4;
  } else if (parsed.kind() === "ipv6" && (parsed as ipaddr.IPv6).isIPv4MappedAddress()) {
    v4 = (parsed as ipaddr.IPv6).toIPv4Address();
  }

  if (v4) {
    for (const entry of V4_CACHE) {
      if (v4.match(entry.addr as ipaddr.IPv4, entry.bits)) {
        return { ok: false, address: canonical, reason: reasonForBlockedV4(canonical) };
      }
    }
    return { ok: true, address: canonical };
  }

  const v6 = parsed as ipaddr.IPv6;
  for (const entry of V6_CACHE) {
    if (
      entry.addr.kind() === "ipv6" &&
      v6.match(entry.addr as ipaddr.IPv6, entry.bits)
    ) {
      return { ok: false, address: canonical, reason: reasonForBlockedV6(canonical) };
    }
  }
  return { ok: true, address: canonical };
}

/** Convenience boolean assertion used by callers that just need allow/deny. */
export function isBlockedIp(input: string): boolean {
  return !classifyIp(input).ok;
}