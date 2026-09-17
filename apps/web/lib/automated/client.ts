"use client";

import type { Progress, RunOutcome } from "@webstrike/testing";
import { ApiClientError } from "@/lib/api/client";
import { CSRF_HEADER } from "@/lib/api/csrf";

export interface AutomatedRunRequestBody {
  categories: string[];
  profile: "quick" | "standard" | "deep";
  activeTests: boolean;
  identities: {
    id: string;
    label: string;
    headers: { name: string; value: string }[];
    cookies: { name: string; value: string }[];
  }[];
  workflow?: unknown[];
  openapi?: unknown;
  seedPaths: string[];
}

type StreamMessage =
  | { type: "progress"; progress: Progress }
  | { type: "result"; outcome: RunOutcome }
  | { type: "error"; message: string };

/**
 * Streams an automated run. The server sends NDJSON progress lines and a final
 * result line; nothing is persisted on either side.
 */
export async function streamAutomatedRun(
  body: AutomatedRunRequestBody,
  onProgress: (progress: Progress) => void,
  signal?: AbortSignal,
): Promise<RunOutcome> {
  const response = await fetch("/api/automated", {
    method: "POST",
    headers: { [CSRF_HEADER]: "1", "content-type": "application/json" },
    body: JSON.stringify(body),
    credentials: "same-origin",
    signal,
  });

  if (!response.ok) {
    let message = `run failed (${response.status})`;
    let code = "API_ERROR";
    let detail: unknown;
    try {
      const payload = (await response.json()) as {
        error?: { message?: string; code?: string; detail?: unknown };
      };
      message = payload.error?.message ?? message;
      code = payload.error?.code ?? code;
      detail = payload.error?.detail;
    } catch {
      /* keep defaults */
    }
    throw new ApiClientError(response.status, message, code, detail);
  }

  if (!response.body) throw new Error("run stream was not available");

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let outcome: RunOutcome | null = null;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      let message: StreamMessage;
      try {
        message = JSON.parse(trimmed) as StreamMessage;
      } catch {
        continue;
      }
      if (message.type === "progress") onProgress(message.progress);
      else if (message.type === "result") outcome = message.outcome;
      else if (message.type === "error") throw new Error(message.message);
    }
  }

  if (!outcome) throw new Error("run ended without a result");
  return outcome;
}
