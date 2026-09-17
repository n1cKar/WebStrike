import type {
  RequestMethod,
  ScopedHttpResult,
  TestingScope,
} from "@webstrike/types";

/** Verification vocabulary. Automated output is never called a "vulnerability". */
export type ResultState =
  | "Observation"
  | "Informational"
  | "Potential Issue"
  | "Needs Verification"
  | "Verified Security Issue"
  | "Not Reproducible";

export type Confidence = "low" | "medium" | "high";

/** Impact ranking, assigned only after a security consequence is established. */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** How far a result has moved through the verification pipeline. */
export type VerificationStatus =
  | "not-required"
  | "needs-verification"
  | "reproduced"
  | "unreproduced";

/** Result prioritisation tiers. Tier 1 is real security impact. */
export type ResultTier = 1 | 2 | 3;

/**
 * Endpoint classification drives which tests are meaningful. A login page must
 * not generate an "authentication bypass" merely because anonymous and
 * authenticated responses match.
 */
export type EndpointClassification =
  | "PUBLIC"
  | "AUTHENTICATED"
  | "PRIVILEGED"
  | "ADMIN"
  | "STATE_CHANGING"
  | "FILE_UPLOAD"
  | "API"
  | "AUTHENTICATION"
  | "REGISTRATION"
  | "PASSWORD_RESET"
  | "RESOURCE_ACCESS"
  | "WORKFLOW";

/** A credential context. Two identities enable authorization comparison. */
export interface Identity {
  id: string;
  label: string;
  /** Free-form role label (e.g. "user", "admin") for privilege comparison. */
  role?: string;
  /** True for an administrative/privileged identity. */
  privileged?: boolean;
  headers: { name: string; value: string }[];
  cookies: { name: string; value: string }[];
}

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
  /** The test case that produced this observation (used for verification). */
  caseId?: string;
  /** Short directive for the next manual/automated step. */
  guidance?: string;

  /* ---- professional result fields (optional, filled where meaningful) ---- */
  /** Impact ranking, only set once a security consequence is established. */
  severity?: Severity;
  /** Prioritisation tier (1 = real security impact, 3 = hardening). */
  tier?: ResultTier;
  /** Endpoint this result concerns, when known. */
  endpoint?: string;
  /** Identity whose request produced the decisive evidence. */
  identityId?: string;
  /** What correct behaviour would have been. */
  expected?: string;
  /** What was actually observed. */
  observed?: string;
  /** Why the difference is security-relevant. */
  impact?: string;
  /** How the conclusion was reached. */
  reasoning?: string;
  /** Suggested, safe follow-up test. */
  nextTest?: string;
  /** Remediation guidance. */
  remediation?: string;
  /** How far the result has progressed through verification. */
  verification?: VerificationStatus;
  /** Detail about the verification attempt(s). */
  verificationDetail?: string;
  /** Advisory note produced by the optional AI analysis layer. */
  aiNote?: string;
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
  /** Optional advisory AI analysis layer. Never changes state or severity. */
  ai?: {
    apiKey?: string;
    model?: string;
    max?: number;
  };
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
  /** Classification assigned during planning; drives test selection. */
  classifications?: EndpointClassification[];
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
