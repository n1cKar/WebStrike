import type {
  HttpRequestSpec,
  ScopedHttpResult,
  TestingScope,
} from "@webstrike/types";
import { runScopedRequest } from "@webstrike/security";
import type { RequestSpecInput } from "@webstrike/validation";

export type { ScopedHttpResult };

/**
 * The single sanctioned path for outbound requests. Converts a validated
 * request spec into the scoped HTTP executor; scope + SSRF enforcement lives
 * entirely inside @webstrike/security.
 */
export async function executeScopedRequest(
  spec: RequestSpecInput,
  scope: TestingScope,
  options: { timeoutMs?: number } = {},
): Promise<ScopedHttpResult> {
  const httpSpec: HttpRequestSpec = {
    id: spec.id,
    method: spec.method,
    url: spec.url,
    query: spec.query,
    headers: spec.headers,
    cookies: spec.cookies,
    body: spec.body,
    contentType: spec.contentType,
  };
  return runScopedRequest(httpSpec, scope, options);
}