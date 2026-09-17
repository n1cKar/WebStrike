import type { ScopedHttpResult } from "@webstrike/types";
import { previewBody } from "./compare";
import type { AutomatedRequest, Evidence, EvidenceRequest, EvidenceResponse } from "./types";

export function evidenceRequest(request: AutomatedRequest): EvidenceRequest {
  return {
    label: request.label,
    identityId: request.identityId,
    method: request.method,
    url: request.url,
    headers: request.headers,
    bodyPreview: request.body ? previewBody(request.body, 600) : undefined,
  };
}

export function evidenceResponse(result: ScopedHttpResult): EvidenceResponse {
  return {
    status: result.status,
    statusText: result.statusText,
    bodyBytes: result.bodyBytes,
    bodyPreview: previewBody(result.body),
    headers: result.headers,
  };
}

export function makeEvidence(
  request: AutomatedRequest,
  result: ScopedHttpResult,
  detail: string,
  baseline?: ScopedHttpResult,
): Evidence {
  return {
    detail,
    request: evidenceRequest(request),
    response: evidenceResponse(result),
    baseline: baseline
      ? {
          status: baseline.status,
          bodyBytes: baseline.bodyBytes,
          bodyPreview: previewBody(baseline.body),
        }
      : undefined,
  };
}
