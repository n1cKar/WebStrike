import type { ScopedHttpResult } from "@webstrike/types";
import { BudgetExhausted, createBudget } from "./budget";
import { getAnalyzer } from "./analyzers";
import { buildCases } from "./planner";
import { buildSurface, type DiscoveryPage } from "./surface";
import { runWorkflow } from "./workflow";
import type {
  AutomatedRequest,
  Progress,
  RequestExecutor,
  RunInput,
  RunOutcome,
  SkippedCategory,
  TestCase,
  TestObservation,
} from "./types";

const MAX_DISCOVERY_PAGES = 3;

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
    phase: "done",
    message: `Completed ${completedCases}/${total} test groups`,
    completed: completedCases,
    total,
    observations: observations.length,
  });

  const counters = budget.counters();
  return {
    observations: sortObservations(observations),
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

const STATE_WEIGHT: Record<string, number> = {
  "Potential Issue": 4,
  "Needs Verification": 3,
  Observation: 2,
  Verified: 1,
  "Not Reproducible": 0,
};

function sortObservations(observations: TestObservation[]): TestObservation[] {
  return [...observations].sort(
    (a, b) => (STATE_WEIGHT[b.state] ?? 0) - (STATE_WEIGHT[a.state] ?? 0),
  );
}

export type { AutomatedRequest };
