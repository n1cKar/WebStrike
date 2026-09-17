import type { TestCategory } from "./types";

export interface CategoryInfo {
  id: TestCategory;
  label: string;
  description: string;
  /** Needs at least two identities to be meaningful. */
  requiresIdentities?: number;
  /** Sends state-changing requests; only runs when activeTests is true. */
  active?: boolean;
}

export const CATEGORIES: CategoryInfo[] = [
  {
    id: "security-headers",
    label: "Security headers & cookies",
    description:
      "Reviews transport/security headers, CSP, HSTS and cookie attributes. Observations only.",
  },
  {
    id: "cors",
    label: "CORS",
    description:
      "Probes configured allowed origins and observes ACAO/ACAC behaviour. Safe GET requests.",
  },
  {
    id: "csrf",
    label: "CSRF",
    description:
      "Checks forms for anti-CSRF tokens and compares token-present vs token-absent responses.",
    active: true,
  },
  {
    id: "authentication",
    label: "Authentication behaviour",
    description:
      "Compares anonymous and authenticated access, and reviews session cookie handling.",
  },
  {
    id: "authorization",
    label: "Authorization boundaries",
    description:
      "Compares responses across two identities against the same resource. Needs two identities.",
    requiresIdentities: 2,
  },
  {
    id: "input-validation",
    label: "Input validation",
    description:
      "Sends controlled parsing probes and inspects error signatures and reflection.",
  },
  {
    id: "business-logic",
    label: "Business-logic workflows",
    description:
      "Runs an operator-defined multi-step workflow and compares observed behaviour to expectations.",
  },
  {
    id: "file-upload",
    label: "File upload",
    description:
      "Submits harmless test files to upload forms and inspects how they are stored and served.",
    active: true,
  },
  {
    id: "openapi",
    label: "OpenAPI import",
    description:
      "Generates temporary test cases from an OpenAPI 3.x document, discarded after the session.",
  },
  {
    id: "browser",
    label: "Browser checks",
    description:
      "Renders pages in a remote browser and reviews console output, mixed content, storage and cookie exposure. Gated behind a configured browser endpoint.",
  },
];

export const ALL_CATEGORIES: TestCategory[] = CATEGORIES.map((c) => c.id);

export function categoryInfo(id: TestCategory): CategoryInfo {
  const found = CATEGORIES.find((c) => c.id === id);
  if (!found) throw new Error(`unknown category ${id}`);
  return found;
}
