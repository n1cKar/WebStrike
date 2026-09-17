/**
 * Client-safe mirror of the engine's category catalog.
 *
 * The engine's own catalog lives in @webstrike/testing, which pulls in
 * node-only modules, so the browser uses this static copy for rendering.
 */

export type CategoryId =
  | "security-headers"
  | "cors"
  | "csrf"
  | "authentication"
  | "authorization"
  | "input-validation"
  | "business-logic"
  | "file-upload"
  | "openapi";

export interface CategoryInfo {
  id: CategoryId;
  label: string;
  description: string;
  requiresIdentities?: number;
  active?: boolean;
}

export const AUTOMATED_CATEGORIES: CategoryInfo[] = [
  {
    id: "security-headers",
    label: "Security headers & cookies",
    description: "Transport/security headers, CSP, HSTS and cookie attributes.",
  },
  {
    id: "cors",
    label: "CORS",
    description: "Probes allowed origins and observes ACAO/ACAC behaviour.",
  },
  {
    id: "csrf",
    label: "CSRF",
    description: "Anti-CSRF token presence and token-vs-origin comparison.",
    active: true,
  },
  {
    id: "authentication",
    label: "Authentication behaviour",
    description: "Anonymous vs authenticated access and session cookie handling.",
  },
  {
    id: "authorization",
    label: "Authorization boundaries",
    description: "Compares two identities against the same resource.",
    requiresIdentities: 2,
  },
  {
    id: "input-validation",
    label: "Input validation",
    description: "Controlled parsing probes; error signatures and reflection.",
  },
  {
    id: "business-logic",
    label: "Business-logic workflows",
    description: "Operator-defined multi-step workflow vs expectations.",
  },
  {
    id: "file-upload",
    label: "File upload",
    description: "Submits harmless test files to upload forms.",
    active: true,
  },
  {
    id: "openapi",
    label: "OpenAPI import",
    description: "Generates temporary cases from an OpenAPI 3.x document.",
  },
];

export const DEFAULT_CATEGORIES: CategoryId[] = [
  "security-headers",
  "cors",
  "csrf",
  "authentication",
  "input-validation",
];
