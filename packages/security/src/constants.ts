export const MAX_RESPONSE_SIZE_BYTES = 2 * 1024 * 1024;
export const MAX_REQUEST_BODY_BYTES = 512 * 1024;
export const MAX_REDIRECTS = 5;
export const REQUEST_TIMEOUT_MS = 15_000;
export const MAX_CRAWL_DEPTH = 3;
export const MAX_CONCURRENT_TESTS = 4;
export const MAX_HEADER_VALUE_BYTES = 4096;
export const MAX_RESPONSE_HEADERS = 64;

/**
 * Hostname patterns that are blocked by name even before DNS resolution.
 * Defense-in-depth: the authoritative check is the resolved IP, but these
 * names are never legitimate targets for WebStrike.
 */
export const BLOCKED_HOSTNAME_NAMES: readonly string[] = [
  "localhost",
  "localhost.localdomain",
  "ip6-localhost",
  "ip6-loopback",
  "metadata.google.internal",
  "metadata",
  "instance-data",
  "instance-data.ec2.internal",
  "kubernetes.default.svc",
];

/**
 * Hostname suffix patterns blocked by name (matches the name or any
 * subdomain). Applied as defense-in-depth before DNS resolution.
 */
export const BLOCKED_HOSTNAME_SUFFIXES: readonly string[] = [
  ".localhost",
  ".local",
  ".internal",
  ".lan",
  ".home",
  ".home.arpa",
  ".localdomain",
  ".intranet",
  ".corp",
];

/**
 * Free-form remarks appended to negative results so the operator always knows
 * why a request was refused.
 */
export const SYSTEM_BLOCKLIST_DESCRIPTION =
  "internal/reserved hostnames, metadata endpoints, and private networks are always refused";