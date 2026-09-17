import { isIP } from "node:net";
import { lookup } from "node:dns/promises";
import type { TestingScope } from "@webstrike/types";
import { classifyIp } from "./ip";
import { hostFromUrl, validateScopedUrl } from "./scope";

export type DnsCheckResult =
  | { ok: true; addresses: string[]; host: string }
  | { ok: false; reason: string };

/**
 * Resolve `host` and require that EVERY resolved address is a public
 * routable address. A single private/loopback/link-local/mapped result
 * refuses the whole request.
 */
export async function checkResolvedAddress(host: string): Promise<DnsCheckResult> {
  const literal = isIP(host);
  if (literal !== 0) {
    const verdict = classifyIp(host);
    if (!verdict.ok) {
      return { ok: false, reason: `address ${host} refused (${verdict.reason})` };
    }
    return { ok: true, addresses: [verdict.address], host };
  }

  let records: { address: string; family: number }[];
  try {
    records = await lookup(host, { all: true, verbatim: true });
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOTFOUND" || code === "EAI_AGAIN" || code === "ENODATA") {
      return { ok: false, reason: `host ${host} did not resolve (${code})` };
    }
    return { ok: false, reason: `DNS resolution for ${host} failed` };
  }

  if (records.length === 0) {
    return { ok: false, reason: `host ${host} resolved to no addresses` };
  }

  for (const record of records) {
    const verdict = classifyIp(record.address);
    if (!verdict.ok) {
      return {
        ok: false,
        reason: `resolved address ${verdict.address} refused (${verdict.reason})`,
      };
    }
  }

  return { ok: true, addresses: records.map((r) => r.address), host };
}

export type UrlRequestability =
  | { ok: true; url: URL; host: string; addresses: string[] }
  | { ok: false; kind: "OUT_OF_SCOPE" | "SSRF_BLOCKED" | "DNS_FAILURE"; message: string };

/**
 * Validate a URL against the authorised scope, then resolve the host and
 * enforce the IP allowlist. The request may proceed only when both pass.
 *
 * DNS-rebinding note: on the Vercel Node runtime the connection is made with
 * a fresh resolution shortly after this check, which tightens (but does not
 * fully eliminate) the rebinding window. Private-address refusal is enforced
 * at resolution time on every hop.
 */
export async function assertUrlRequestable(
  urlInput: string,
  scope: TestingScope,
): Promise<UrlRequestability> {
  const scoped = validateScopedUrl(urlInput, scope);
  if (!scoped.ok) {
    return { ok: false, kind: "OUT_OF_SCOPE", message: scoped.reason };
  }

  const host = hostFromUrl(scoped.url!);
  const dns = await checkResolvedAddress(host);
  if (!dns.ok) {
    return {
      ok: false,
      kind: dns.reason.startsWith("host") || dns.reason.startsWith("DNS")
        ? "DNS_FAILURE"
        : "SSRF_BLOCKED",
      message: dns.reason,
    };
  }

  return { ok: true, url: scoped.url!, host, addresses: dns.addresses };
}