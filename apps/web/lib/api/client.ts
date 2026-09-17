"use client";

import { CSRF_HEADER } from "./csrf";

export class ApiClientError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly code = "API_ERROR",
    readonly detail?: unknown,
  ) {
    super(message);
  }
}

interface ApiErrorBody {
  error?: { code?: string; message?: string; detail?: unknown };
}

export async function apiFetch<T>(
  input: string,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set(CSRF_HEADER, "1");
  if (init.body && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }

  const response = await fetch(input, {
    ...init,
    headers,
    credentials: "same-origin",
  });

  let payload: unknown = null;
  const text = await response.text();
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = text;
    }
  }

  if (!response.ok) {
    const body = payload as ApiErrorBody;
    throw new ApiClientError(
      response.status,
      body?.error?.message ?? `request failed (${response.status})`,
      body?.error?.code ?? "API_ERROR",
      body?.error?.detail,
    );
  }

  return payload as T;
}