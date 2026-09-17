import type { ScopedHttpResult } from "@webstrike/types";
import { previewBody } from "./compare";
import { redactHeaders, redactHeaderValue, redactText, redactUrl } from "./redact";
import type { AutomatedRequest, Evidence, EvidenceRequest, EvidenceResponse } from "./types";

export function evidenceRequest(request: AutomatedRequest): EvidenceRequest {
  return {
    label: request.label,
    identityId: request.identityId,
    method: request.method,
    url: redactUrl(request.url),
    headers: redactHeaders(request.headers),
    bodyPreview: request.body ? redactText(previewBody(request.body, 600)) : undefined,
  };
}

export function evidenceResponse(result: ScopedHttpResult): EvidenceResponse {
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(result.headers)) {
    headers[name] = redactHeaderValue(name, value);
  }
  return {
    status: result.status,
    statusText: result.statusText,
    bodyBytes: result.bodyBytes,
    bodyPreview: redactText(previewBody(result.body)),
    headers,
  };
}

export function makeEvidence(
  request: AutomatedRequest,
  result: ScopedHttpResult,
  detail: string,
  baseline?: ScopedHttpResult,
): Evidence {
  return {
    detail: redactText(detail),
    request: evidenceRequest(request),
    response: evidenceResponse(result),
    baseline: baseline
      ? {
          status: baseline.status,
          bodyBytes: baseline.bodyBytes,
          bodyPreview: redactText(previewBody(baseline.body)),
        }
      : undefined,
  };
}
