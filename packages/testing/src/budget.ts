import type { ScopedHttpResult } from "@webstrike/types";
import type { AutomatedRequest, RequestExecutor, RunBudget } from "./types";

export class BudgetExhausted extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BudgetExhausted";
  }
}

export interface BudgetCounters {
  requests: number;
  errors: number;
  startedAt: number;
}

export interface BudgetController {
  run(request: AutomatedRequest): Promise<ScopedHttpResult>;
  counters(): BudgetCounters;
  exhausted(): boolean;
  remaining(): number;
}

/**
 * Wraps the executor so every category shares one hard request budget and a
 * wall-clock ceiling. This is what keeps an automated run bounded on a
 * serverless function and prevents a runaway scan.
 */
export function createBudget(
  executor: RequestExecutor,
  budget: RunBudget,
): BudgetController {
  const counters: BudgetCounters = { requests: 0, errors: 0, startedAt: Date.now() };

  const expired = () => Date.now() - counters.startedAt > budget.maxWallClockMs;

  return {
    counters(): BudgetCounters {
      return { ...counters };
    },
    exhausted(): boolean {
      return counters.requests >= budget.maxRequests || expired();
    },
    remaining(): number {
      return Math.max(0, budget.maxRequests - counters.requests);
    },
    async run(request: AutomatedRequest): Promise<ScopedHttpResult> {
      if (counters.requests >= budget.maxRequests) {
        throw new BudgetExhausted(`request budget of ${budget.maxRequests} exhausted`);
      }
      if (expired()) {
        throw new BudgetExhausted(`wall-clock budget of ${budget.maxWallClockMs}ms exhausted`);
      }
      counters.requests += 1;
      try {
        const result = (await executor(request)) as ScopedHttpResult;
        if (!result.ok && result.error) counters.errors += 1;
        return result;
      } catch (error) {
        counters.errors += 1;
        throw error;
      }
    },
  };
}
