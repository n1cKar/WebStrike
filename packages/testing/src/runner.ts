import type { ScopedHttpResult } from "@webstrike/types";
import { BudgetExhausted, createBudget } from "./budget";
import { getAnalyzer } from "./analyzers";
import { buildCases } from "./planner";
import { buildSurface, type DiscoveryPage } from "./surface";
import { runWorkflow } from "./workflow";
import { dedupeObservations, prioritizeObservations } from "./prioritize";
import { enrichObservationsWithAi } from "./ai";
import type {
  AutomatedRequest,
  Progress,
  RequestExecutor,
  RunInput,
  RunOutcome,
  SkippedCategory,
  Surface,
  TestCase,
  TestObservation,
} from "./types";

const MAX_DISCOVERY_PAGES = 3;
/** Maximum number of potential issues to independently re-verify. */
const MAX_VERIFICATIONS = 12;

function failedResult(url: string, message: string): ScopedHttpResult {
  return {
    ok: false,
    finalUrl: url,
    status: 0,
    statusText: "",
    redirected: false,
    redirectChain: [],
    headers: {},
    cookies: [],
    body: "",
    bodyBytes: 0,
    bodyTruncated: false,
    timingMs: 0,
    error: { kind: "INTERNAL", message },
  };
}

function isHtml(result: ScopedHttpResult): boolean {
  return (result.headers["content-type"] ?? "").toLowerCase().includes("html");
}

export async function runAutomatedTests(
  input: RunInput,
  executor: RequestExecutor,
): Promise<RunOutcome> {
  const budget = createBudget(executor, input.budget);
  const report = (progress: Progress) => input.onProgress?.(progress);

  const observations: TestObservation[] = [];
  const skipped: SkippedCategory[] = [];
  let truncated = false;
  let budgetExhausted = false;

  /* ---------------- discovery ---------------- */
  report({ phase: "discover", message: `Fetching ${input.targetUrl}`, completed: 0, total: 0, observations: 0 });

  const pages: DiscoveryPage[] = [];
  const seenPaths = new Set<string>();
  const discoveryQueue: string[] = [input.targetUrl, ...(input.seedPaths ?? [])];

  for (const url of discoveryQueue) {
    if (pages.length >= MAX_DISCOVERY_PAGES) break;
    let path = url;
    try {
      path = new URL(url).pathname;
    } catch {
      /* keep raw */
    }
    if (seenPaths.has(path)) continue;
    seenPaths.add(path);
    try {
      const result = await budget.run({
        id: `discover-${pages.length}`,
        label: `discover ${url}`,
        method: "GET",
        url,
        headers: [{ name: "Accept", value: "text/html,application/xhtml+xml,*/*" }],
        cookies: [],
      });
      if (result.ok && isHtml(result)) {
        pages.push({ url: result.finalUrl || url, html: result.body });
      }
    } catch (error) {
      if (error instanceof BudgetExhausted) {
        budgetExhausted = true;
        truncated = true;
        break;
      }
      /* discovery failure is non-fatal */
    }
  }

  const surface = buildSurface({
    targetUrl: input.targetUrl,
    scope: input.scope,
    pages,
    seedPaths: input.seedPaths,
  });

  /* ---------------- generate ---------------- */
  report({
    phase: "generate",
    message: "Building test cases",
    completed: 0,
    total: 0,
    observations: 0,
  });

  const plan = buildCases(surface, {
    categories: input.categories,
    identities: input.identities,
    activeTests: input.budget.activeTests,
    workflow: input.workflow,
    openapi: input.openapi,
  });
  skipped.push(...plan.skipped);

  /* ---------------- execute + analyze ---------------- */
  const total = plan.cases.length;
  let completedCases = 0;

  for (const testCase of plan.cases) {
    if (budget.exhausted()) {
      budgetExhausted = true;
      truncated = true;
      break;
    }
    const results = await executeCase(testCase, budget, () => {
      budgetExhausted = true;
      truncated = true;
    });
    const analyzer = getAnalyzer(testCase.analyzer);
    if (analyzer) {
      try {
        observations.push(
          ...analyzer({
            testCase,
            surface,
            results,
            identities: input.identities,
            activeTests: input.budget.activeTests,
          }),
        );
      } catch {
        /* an analyzer must never break the run */
      }
    }
    completedCases += 1;
    report({
      phase: "execute",
      message: testCase.title,
      completed: completedCases,
      total,
      observations: observations.length,
    });
  }

  /* ---------------- workflow ---------------- */
  if (input.categories.includes("business-logic") && input.workflow?.length) {
    report({
      phase: "execute",
      message: "Running workflow",
      completed: completedCases,
      total,
      observations: observations.length,
    });
    try {
      const workflow = await runWorkflow(input.workflow, {
        executor: (request) => budget.run(request),
        activeTests: input.budget.activeTests,
        identityA: input.identities[0],
        identities: input.identities,
      });
      observations.push(...workflow.observations);
    } catch (error) {
      if (error instanceof BudgetExhausted) {
        budgetExhausted = true;
        truncated = true;
      }
    }
  }

  report({
    phase: "analyze",
    message: "Verifying and prioritising results",
    completed: completedCases,
    total,
    observations: observations.length,
  });

  let results = dedupeObservations(observations);
  results = await verifyObservations(results, plan.cases, surface, input, budget, () => {
    budgetExhausted = true;
    truncated = true;
  });
  if (input.ai?.apiKey) {
    results = await enrichObservationsWithAi(results, {
      apiKey: input.ai.apiKey,
      model: input.ai.model,
      max: input.ai.max,
    });
  }
  results = prioritizeObservations(results);

  report({
    phase: "done",
    message: `Completed ${completedCases}/${total} test groups`,
    completed: completedCases,
    total,
    observations: results.length,
  });

  const counters = budget.counters();
  return {
    observations: results,
    surface,
    stats: {
      requests: counters.requests,
      durationMs: Date.now() - counters.startedAt,
      truncated,
      errors: counters.errors,
      budgetExhausted,
    },
    skipped,
  };
}

/**
 * Independently re-run the requests behind each serious result. A result only
 * becomes `Verified Security Issue` when the same condition reproduces from a
 * fresh execution. Mutating test cases are never re-run.
 */
async function verifyObservations(
  observations: TestObservation[],
  cases: TestCase[],
  surface: Surface,
  input: RunInput,
  budget: ReturnType<typeof createBudget>,
  onExhausted: () => void,
): Promise<TestObservation[]> {
  const byId = new Map(cases.map((testCase) => [testCase.id, testCase]));
  const out: TestObservation[] = [];
  let attempts = 0;

  for (const observation of observations) {
    if (observation.state !== "Potential Issue") {
      out.push(observation);
      continue;
    }
    const testCase = observation.caseId ? byId.get(observation.caseId) : undefined;
    if (
      !testCase ||
      testCase.requests.some((request) => request.mutating) ||
      attempts >= MAX_VERIFICATIONS ||
      budget.exhausted()
    ) {
      out.push({
        ...observation,
        verification: observation.verification ?? "needs-verification",
        verificationDetail:
          observation.verificationDetail ??
          (testCase?.requests.some((r) => r.mutating)
            ? "Not re-run automatically: the check uses a state-changing request."
            : "Not re-run: verification budget reached."),
      });
      continue;
    }

    attempts += 1;
    try {
      const results = await executeCase(testCase, budget, onExhausted);
      const analyzer = getAnalyzer(testCase.analyzer);
      const produced = analyzer
        ? analyzer({
            testCase,
            surface,
            results,
            identities: input.identities,
            activeTests: input.budget.activeTests,
          })
        : [];
      const reproduced = produced.some(
        (candidate) =>
          candidate.id === observation.id &&
          (candidate.state === "Potential Issue" || candidate.state === "Verified Security Issue"),
      );
      out.push(
        reproduced
          ? {
              ...observation,
              state: "Verified Security Issue",
              confidence: "high",
              severity: observation.severity ?? "high",
              verification: "reproduced",
              verificationDetail:
                "Independently re-executed the same requests and reproduced the condition.",
            }
          : {
              ...observation,
              state: "Needs Verification",
              verification: "unreproduced",
              verificationDetail:
                "Re-execution did not reproduce the condition; treat as unconfirmed.",
            },
      );
    } catch (error) {
      if (error instanceof BudgetExhausted) {
        onExhausted();
        out.push(observation);
        break;
      }
      out.push({
        ...observation,
        verification: "unreproduced",
        verificationDetail: "Verification attempt failed to complete.",
      });
    }
  }

  return out;
}

async function executeCase(
  testCase: TestCase,
  budget: ReturnType<typeof createBudget>,
  onExhausted: () => void,
): Promise<Record<string, ScopedHttpResult>> {
  const results: Record<string, ScopedHttpResult> = {};
  for (const request of testCase.requests) {
    try {
      results[request.id] = await budget.run(request);
    } catch (error) {
      if (error instanceof BudgetExhausted) {
        onExhausted();
        break;
      }
      results[request.id] = failedResult(
        request.url,
        error instanceof Error ? error.message : "request failed",
      );
    }
  }
  return results;
}

export type { AutomatedRequest };
