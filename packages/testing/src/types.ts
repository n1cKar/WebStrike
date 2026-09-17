import type {
  RequestMethod,
  ScopedHttpResult,
  TestingScope,
} from "@webstrike/types";

/** Verification vocabulary. Automated output is never called a "vulnerability". */
export type ResultState =
  | "Observation"
  | "Potential Issue"
  | "Needs Verification"
  | "Verified"
  | "Not Reproducible";

export type Confidence = "low" | "medium" | "high";

export type TestCategory =
  | "security-headers"
  | "cors"
  | "csrf"
  | "authentication"
  | "authorization"
  | "input-validation"
  | "business-logic"
  | "file-upload"
  | "openapi"
  | "browser";

/** A credential context. Two identities enable authorization comparison. */
export interface Identity {
  id: string;
  label: string;
  headers: { name: string; value: string }[];
  cookies: { name: string; value: string }[];
}

/** One outbound request the engine wants executed. */
export interface AutomatedRequest {
  id: string;
  label: string;
  method: RequestMethod;
  url: string;
  headers: { name: string; value: string }[];
  cookies: { name: string; value: string }[];
  body?: string | null;
  contentType?: string | null;
  identityId?: string;
  /** True when the request may change server state (POST/PUT/PATCH/DELETE). */
  mutating?: boolean;
}

/** A generated, self-contained test whose evidence is recorded and analysed. */
export interface TestCase {
  id: string;
  category: TestCategory;
  title: string;
  requests: AutomatedRequest[];
  analyzer: string;
  metadata?: Record<string, unknown>;
}

export interface EvidenceRequest {
  label: string;
  identityId?: string;
  method: RequestMethod;
  url: string;
  headers: { name: string; value: string }[];
  bodyPreview?: string;
}

export interface EvidenceResponse {
  status: number;
  statusText: string;
  bodyBytes: number;
  bodyPreview: string;
  headers: Record<string, string>;
}

export interface Evidence {
  detail: string;
  request: EvidenceRequest;
  response: EvidenceResponse;
  baseline?: {
    status: number;
    bodyBytes: number;
    bodyPreview: string;
  };
}

export interface TestObservation {
  id: string;
  category: TestCategory;
  title: string;
  state: ResultState;
  confidence: Confidence;
  summary: string;
  evidence: Evidence;
  guidance?: string;
}

export interface Progress {
  phase: "discover" | "generate" | "execute" | "analyze" | "done";
  message: string;
  completed: number;
  total: number;
  observations: number;
}

export interface RunBudget {
  maxRequests: number;
  maxWallClockMs: number;
  perRequestTimeoutMs: number;
  /** When false, only safe/idempotent requests (GET/HEAD/OPTIONS) are sent. */
  activeTests: boolean;
}

export interface WorkflowStep {
  id: string;
  label: string;
  method: RequestMethod;
  url: string;
  headers?: { name: string; value: string }[];
  cookies?: { name: string; value: string }[];
  body?: string | null;
  contentType?: string | null;
  identityId?: string;
  /** Regex applied to the response body; first capture group becomes `{{as}}`. */
  extract?: { pattern: string; as: string };
  expect?: {
    status?: number;
    statusIn?: number[];
    bodyContains?: string;
    bodyAbsent?: string;
  };
}

export interface RunInput {
  targetUrl: string;
  scope: TestingScope;
  categories: TestCategory[];
  identities: Identity[];
  budget: RunBudget;
  workflow?: WorkflowStep[];
  openapi?: unknown;
  /** Extra same-scope paths to treat as known surface. */
  seedPaths?: string[];
  onProgress?: (progress: Progress) => void;
}

export interface RunStats {
  requests: number;
  durationMs: number;
  truncated: boolean;
  errors: number;
  budgetExhausted: boolean;
}

export interface SkippedCategory {
  category: TestCategory;
  reason: string;
}

export interface RunOutcome {
  observations: TestObservation[];
  surface: Surface;
  stats: RunStats;
  skipped: SkippedCategory[];
}

export type RequestExecutor = (
  request: AutomatedRequest,
) => Promise<ScopedHttpResult>;

export interface DiscoveredParam {
  name: string;
  location: "query" | "form";
  example?: string;
}

export interface DiscoveredForm {
  action: string;
  method: RequestMethod;
  fields: {
    name: string;
    type: string;
    required: boolean;
    value?: string;
  }[];
  hasFileInput: boolean;
  hasCsrfToken: boolean;
  csrfFieldName?: string;
}

export interface DiscoveredEndpoint {
  url: string;
  method: RequestMethod;
  params: DiscoveredParam[];
  source: "start-url" | "link" | "form" | "seed";
  form?: DiscoveredForm;
}

export interface Surface {
  baseUrl: string;
  origin: string;
  endpoints: DiscoveredEndpoint[];
  forms: DiscoveredForm[];
  notes: string[];
}

export interface AnalyzeContext {
  testCase: TestCase;
  surface: Surface;
  results: Record<string, ScopedHttpResult>;
  identities: Identity[];
  activeTests: boolean;
}

export type Analyzer = (context: AnalyzeContext) => TestObservation[];
