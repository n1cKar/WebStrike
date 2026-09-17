import type { ScopedHttpResult } from "@webstrike/types";
import { describeResponse, isRedirect, isSuccess } from "./compare";
import { makeEvidence } from "./evidence";
import type {
  AutomatedRequest,
  Identity,
  RequestExecutor,
  TestObservation,
  WorkflowStep,
} from "./types";

export interface WorkflowContext {
  executor: RequestExecutor;
  activeTests: boolean;
  identityA?: Identity;
  identities?: Identity[];
}

export interface WorkflowOutcome {
  observations: TestObservation[];
  executed: number;
  failedSteps: number;
}

function applyTemplate(text: string, vars: Record<string, string>): string {
  return text.replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (match, name: string) =>
    name in vars ? vars[name]! : match,
  );
}

function mutating(method: AutomatedRequest["method"]): boolean {
  return method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
}

export async function runWorkflow(
  steps: WorkflowStep[],
  context: WorkflowContext,
): Promise<WorkflowOutcome> {
  const observations: TestObservation[] = [];
  const vars: Record<string, string> = {};
  let executed = 0;
  let failedSteps = 0;
  let lastRequest: AutomatedRequest | null = null;
  let lastResult: ScopedHttpResult | null = null;

  for (const step of steps.slice(0, 25)) {
    const method = step.method;
    if (mutating(method) && !context.activeTests) {
      observations.push({
        id: `wf-${step.id}-skipped`,
        category: "business-logic",
        title: `Workflow step skipped: ${step.label}`,
        state: "Observation",
        confidence: "low",
        summary:
          "This step changes server state and was skipped because active tests are disabled.",
        evidence: makeEvidence(
          {
            id: `wf-${step.id}`,
            label: step.label,
            method,
            url: step.url,
            headers: [],
            cookies: [],
          },
          {
            ok: false,
            finalUrl: step.url,
            status: 0,
            statusText: "skipped",
            redirected: false,
            redirectChain: [],
            headers: {},
            cookies: [],
            body: "",
            bodyBytes: 0,
            bodyTruncated: false,
            timingMs: 0,
          },
          "skipped: mutating step requires active tests",
        ),
      });
      continue;
    }

    const identity =
      context.identities?.find((i) => i.id === step.identityId) ?? context.identityA;

    const request: AutomatedRequest = {
      id: `wf-${step.id}`,
      label: step.label,
      method,
      url: applyTemplate(step.url, vars),
      headers: [
        ...(step.headers ?? []).map((h) => ({
          name: h.name,
          value: applyTemplate(h.value, vars),
        })),
        ...(identity?.headers ?? []),
      ],
      cookies: [...(step.cookies ?? []), ...(identity?.cookies ?? [])],
      body: step.body ? applyTemplate(step.body, vars) : null,
      contentType: step.contentType ?? null,
      identityId: identity?.id,
      mutating: mutating(method),
    };

    const result = await context.executor(request);
    executed += 1;
    lastRequest = request;
    lastResult = result;

    if (step.extract && result.ok) {
      try {
        const match = new RegExp(step.extract.pattern, "s").exec(result.body);
        if (match && match[1] !== undefined) vars[step.extract.as] = match[1];
      } catch {
        observations.push({
          id: `wf-${step.id}-extract-error`,
          category: "business-logic",
          title: `Workflow extraction failed: ${step.label}`,
          state: "Observation",
          confidence: "low",
          summary: `The extract pattern could not be applied: ${step.extract.pattern}`,
          evidence: makeEvidence(request, result, "invalid extraction regex"),
        });
      }
    }

    if (step.expect) {
      const failures: string[] = [];
      const expected = step.expect;
      if (expected.status !== undefined && result.status !== expected.status) {
        failures.push(`expected status ${expected.status}, observed ${result.status}`);
      }
      if (expected.statusIn && !expected.statusIn.includes(result.status)) {
        failures.push(`expected status in [${expected.statusIn.join(", ")}], observed ${result.status}`);
      }
      if (expected.bodyContains && !result.body.includes(expected.bodyContains)) {
        failures.push(`expected body to contain "${expected.bodyContains}"`);
      }
      if (expected.bodyAbsent && result.body.includes(expected.bodyAbsent)) {
        failures.push(`expected body to omit "${expected.bodyAbsent}"`);
      }

      if (failures.length) {
        failedSteps += 1;
        observations.push({
          id: `wf-${step.id}-expect`,
          category: "business-logic",
          title: `Workflow expectation not met: ${step.label}`,
          state: "Needs Verification",
          confidence: "medium",
          summary: failures.join("; "),
          evidence: makeEvidence(request, result, failures.join("\n")),
          guidance:
            "Decide whether the application behaviour is wrong or the expectation is wrong before acting on this.",
        });
      }
    }
  }

  if (lastRequest && lastResult) {
    observations.push({
      id: `wf-summary-${lastRequest.id}`,
      category: "business-logic",
      title: "Workflow executed",
      state: "Observation",
      confidence: "low",
      summary: `${executed} step(s) executed, ${failedSteps} expectation(s) unmet, ${observations.length - failedSteps} note(s).`,
      evidence: makeEvidence(
        lastRequest,
        lastResult,
        `final step: ${lastRequest.method} ${lastRequest.url} → ${resultSummary(lastResult)}`,
      ),
    });
  }

  return { observations, executed, failedSteps };
}

function resultSummary(result: ScopedHttpResult): string {
  if (!result.ok) return result.error?.message ?? "no response";
  return `${describeResponse(result)}${isSuccess(result.status) || isRedirect(result.status) ? "" : " (unexpected)"}`;
}
