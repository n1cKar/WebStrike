import { NextResponse } from "next/server";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly code: string,
  ) {
    super(message);
  }
}

export function jsonError(status: number, code: string, message: string, detail?: unknown) {
  return NextResponse.json(
    { error: { code, message, detail } },
    { status },
  );
}

export function jsonOk<T>(data: T, status = 200) {
  return NextResponse.json(data as Record<string, unknown>, { status });
}

export async function readJson(request: Request): Promise<unknown> {
  const contentLength = Number(request.headers.get("content-length") ?? "0");
  if (contentLength > 1_000_000) {
    throw new ApiError(413, "request body too large", "PAYLOAD_TOO_LARGE");
  }
  try {
    return await request.json();
  } catch {
    throw new ApiError(400, "request body must be valid JSON", "BAD_JSON");
  }
}

export function zodErrorResponse(error: {
  issues: { path: PropertyKey[]; message: string }[];
}) {
  const detail = error.issues.map((issue) => ({
    path: issue.path.join("."),
    message: issue.message,
  }));
  return jsonError(422, "VALIDATION_ERROR", "request failed validation", detail);
}