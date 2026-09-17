/**
 * Controlled input probes.
 *
 * These payloads are deliberately non-destructive: they probe *parsing and
 * reflection*, never execution, filesystem access, or denial of service. There
 * are no sleep payloads, no OS commands, no path chains that read files. The
 * benign marker round-trips so reflection can be detected unambiguously.
 */
export interface InputProbe {
  id: string;
  value: string;
  /** What this probe is trying to learn. */
  intent: string;
  /** Detect evaluation rather than reflection (e.g. template engines). */
  evaluated?: string;
}

export const BENIGN_MARKER = "wsprobe7f3a91";

export const INPUT_PROBES: InputProbe[] = [
  { id: "marker", value: BENIGN_MARKER, intent: "echo/reflection of an inert marker" },
  { id: "quote", value: `'";\``, intent: "quote handling in downstream queries or rendering" },
  { id: "angle", value: `<${BENIGN_MARKER}>`, intent: "HTML metacharacter handling (reflection encoding)" },
  { id: "type", value: "not-a-number", intent: "type coercion for a value that looks numeric" },
  { id: "boundary", value: "-1", intent: "boundary handling for numeric identifiers" },
  { id: "overflow", value: "999999999999999999999999999999", intent: "large integer handling" },
  { id: "template", value: "{{7*7}}", intent: "server-side template evaluation", evaluated: "49" },
  { id: "expression", value: "${7*7}", intent: "expression evaluation", evaluated: "49" },
  { id: "null-byte", value: "%00", intent: "null-byte handling" },
  { id: "encoding", value: "%3C%3E", intent: "double-decoding of encoded metacharacters" },
];

/** A single large value used to probe length handling. */
export function oversizedProbe(size = 2048): InputProbe {
  return {
    id: "oversized",
    value: "A".repeat(size),
    intent: "oversized value handling",
  };
}

/** Server-error signatures used to spot new error paths. */
export const ERROR_SIGNATURES = [
  "stack trace",
  "traceback (most recent call last)",
  "syntaxerror",
  "sequelize",
  "sqlexception",
  "sqlexception",
  "odbc",
  "postgresql",
  "psql:",
  "mysqli",
  "sqlstate",
  "ora-0",
  "microsoft ole db",
  "at java.",
  "at org.springframework",
  "django.core.exceptions",
  "werkzeug debugger",
  "laravel",
  "symfony",
  "runtimeerror",
  "nullpointerexception",
  "internal server error",
  "unhandled exception",
];
