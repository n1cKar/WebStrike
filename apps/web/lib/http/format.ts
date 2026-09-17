export interface JsonFormatResult {
  ok: boolean;
  text: string;
}

export function tryFormatJson(input: string): JsonFormatResult {
  const trimmed = input.trim();
  if (!trimmed) return { ok: false, text: input };
  if (!/^[[{]/.test(trimmed)) return { ok: false, text: input };
  try {
    return { ok: true, text: JSON.stringify(JSON.parse(trimmed), null, 2) };
  } catch {
    return { ok: false, text: input };
  }
}

export function looksLikeJson(contentType?: string, body?: string): boolean {
  if (contentType?.toLowerCase().includes("json")) return true;
  const trimmed = body?.trim() ?? "";
  return /^[[{]/.test(trimmed) && trimmed.length > 1;
}

const SENSITIVE_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "api-key",
  "x-auth-token",
  "x-access-token",
  "x-secret",
]);

export function redactHeaderValue(name: string, value: string): string {
  if (!SENSITIVE_HEADERS.has(name.toLowerCase())) return value;
  return "[REDACTED]";
}

export interface DiffLine {
  type: "same" | "add" | "del";
  text: string;
  leftNo?: number;
  rightNo?: number;
}

const MAX_DIFF_LINES = 1500;

/**
 * Small LCS-based line diff for response comparison. Capped to keep the UI
 * responsive; this is the only analysis WebStrike performs on stored-in-memory
 * response bodies and it never leaves the browser.
 */
export function lineDiff(left: string, right: string): DiffLine[] {
  const a = left.split("\n").slice(0, MAX_DIFF_LINES);
  const b = right.split("\n").slice(0, MAX_DIFF_LINES);
  const n = a.length;
  const m = b.length;

  const lcs: number[][] = Array.from({ length: n + 1 }, () =>
    new Array<number>(m + 1).fill(0),
  );
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      lcs[i]![j] =
        a[i] === b[j] ? lcs[i + 1]![j + 1]! + 1 : Math.max(lcs[i + 1]![j]!, lcs[i]![j + 1]!);
    }
  }

  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ type: "same", text: a[i]!, leftNo: i + 1, rightNo: j + 1 });
      i += 1;
      j += 1;
    } else if (lcs[i + 1]![j]! >= lcs[i]![j + 1]!) {
      out.push({ type: "del", text: a[i]!, leftNo: i + 1 });
      i += 1;
    } else {
      out.push({ type: "add", text: b[j]!, rightNo: j + 1 });
      j += 1;
    }
  }
  while (i < n) {
    out.push({ type: "del", text: a[i]!, leftNo: i + 1 });
    i += 1;
  }
  while (j < m) {
    out.push({ type: "add", text: b[j]!, rightNo: j + 1 });
    j += 1;
  }
  return out;
}

export function countDiff(lines: DiffLine[]): { added: number; removed: number } {
  let added = 0;
  let removed = 0;
  for (const line of lines) {
    if (line.type === "add") added += 1;
    if (line.type === "del") removed += 1;
  }
  return { added, removed };
}
