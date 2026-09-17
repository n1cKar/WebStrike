import type {
  CookieObservation,
  HeaderObservation,
  ScopedHttpResult,
} from "@webstrike/types";
import {
  analyzeCookies,
  analyzeHeaders,
  summarize,
} from "@webstrike/security";

export interface ResponseAnalysis {
  headers: HeaderObservation[];
  cookies: CookieObservation[];
  notes: string[];
}

/**
 * Produce observations — never verdicts. Missing headers and attribute gaps are
 * reported with their evidence and confidence so an operator can verify them.
 */
export function analyzeResponse(result: ScopedHttpResult): ResponseAnalysis {
  return {
    headers: analyzeHeaders(result),
    cookies: analyzeCookies(result),
    notes: summarize(result),
  };
}