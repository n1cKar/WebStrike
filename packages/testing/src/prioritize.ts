import type { ResultState, ResultTier, Severity, TestObservation } from "./types";

/**
 * Deduplication and prioritisation.
 *
 * The engine prefers a few high-quality results over hundreds of noisy ones.
 * Duplicates are collapsed to the strongest observation, every result receives
 * a severity/tier, and the list is ordered by real security impact.
 */

const STATE_WEIGHT: Record<ResultState, number> = {
  "Verified Security Issue": 6,
  "Potential Issue": 5,
  "Needs Verification": 4,
  Observation: 3,
  Informational: 2,
  "Not Reproducible": 1,
};

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const TIER_BY_CATEGORY: Record<string, ResultTier> = {
  authorization: 1,
  authentication: 1,
  "business-logic": 2,
  csrf: 2,
  "file-upload": 2,
  "input-validation": 2,
  cors: 2,
  openapi: 2,
  "security-headers": 3,
  browser: 3,
};

/** A stable subject key so the same underlying issue collapses to one result. */
function dedupeKey(observation: TestObservation): string {
  if (/cookie/i.test(observation.title)) {
    const match = observation.title.match(/:\s*([A-Za-z0-9_.-]+)\s*$/);
    if (match) return `cookie:${match[1]!.toLowerCase()}`;
  }
  const title = observation.title
    .toLowerCase()
    .replace(/\[[^\]]*\]/g, "")
    .replace(/\d+/g, "#")
    .replace(/\s+/g, " ")
    .trim();
  return `${observation.category}:${title}:${observation.endpoint ?? ""}`;
}

/** Collapse duplicates, keeping the most serious variant and noting the rest. */
export function dedupeObservations(observations: TestObservation[]): TestObservation[] {
  const byKey = new Map<string, TestObservation>();
  for (const observation of observations) {
    const key = dedupeKey(observation);
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, { ...observation });
      continue;
    }
    if ((STATE_WEIGHT[observation.state] ?? 0) > (STATE_WEIGHT[existing.state] ?? 0)) {
      byKey.set(key, {
        ...observation,
        reasoning: mergeReasoning(observation.reasoning, existing),
      });
    } else {
      existing.reasoning = mergeReasoning(existing.reasoning, observation);
    }
  }
  return [...byKey.values()];
}

function mergeReasoning(current: string | undefined, other: TestObservation): string {
  const note = `Also observed ${other.state} for "${other.title}".`;
  if (!current) return note;
  if (current.includes(note)) return current;
  return `${current} ${note}`;
}

function defaultSeverity(observation: TestObservation): Severity {
  if (observation.severity) return observation.severity;
  switch (observation.state) {
    case "Verified Security Issue":
      return "high";
    case "Potential Issue":
      return observation.category === "authorization" || observation.category === "authentication"
        ? "high"
        : "medium";
    case "Needs Verification":
      return "medium";
    case "Observation":
      return "low";
    default:
      return "info";
  }
}

function defaultTier(observation: TestObservation): ResultTier {
  if (observation.tier) return observation.tier;
  if (observation.state === "Verified Security Issue" || observation.state === "Potential Issue") {
    return TIER_BY_CATEGORY[observation.category] ?? 2;
  }
  if (observation.state === "Needs Verification") return TIER_BY_CATEGORY[observation.category] ?? 3;
  return 3;
}

/** Assign severity/tier where missing, then order by impact. */
export function prioritizeObservations(observations: TestObservation[]): TestObservation[] {
  const enriched = observations.map((observation) => ({
    ...observation,
    severity: defaultSeverity(observation),
    tier: defaultTier(observation),
  }));

  return enriched.sort((a, b) => {
    const tier = (a.tier ?? 3) - (b.tier ?? 3);
    if (tier !== 0) return tier;
    const state = (STATE_WEIGHT[b.state] ?? 0) - (STATE_WEIGHT[a.state] ?? 0);
    if (state !== 0) return state;
    return (SEVERITY_WEIGHT[b.severity ?? "info"] ?? 0) - (SEVERITY_WEIGHT[a.severity ?? "info"] ?? 0);
  });
}

/** Count results by state, for concise summaries. */
export function summarizeStates(
  observations: TestObservation[],
): Record<ResultState, number> {
  const counts = {
    Observation: 0,
    Informational: 0,
    "Potential Issue": 0,
    "Needs Verification": 0,
    "Verified Security Issue": 0,
    "Not Reproducible": 0,
  } satisfies Record<ResultState, number>;
  for (const observation of observations) counts[observation.state] += 1;
  return counts;
}
