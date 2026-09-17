import { z } from "zod";
import { redactText, redactUrl } from "./redact";
import type { TestObservation } from "./types";

/**
 * Optional Groq analysis layer.
 *
 * The deterministic engine is authoritative. Groq is used only to explain,
 * group, and suggest additional safe verification. Its output can never turn a
 * result into `Verified Security Issue`; that requires deterministic
 * reproduction. Every call is fail-open: any error yields no annotation.
 */

export const aiAssessmentSchema = z.object({
  supportsSecurityIssue: z.boolean(),
  confidence: z.enum(["low", "medium", "high"]),
  explanation: z.string().max(2000),
  falsePositiveExplanations: z.array(z.string().max(500)).max(8).default([]),
  additionalVerification: z.array(z.string().max(500)).max(8).default([]),
});

export type AiAssessment = z.infer<typeof aiAssessmentSchema>;

export const DEFAULT_GROQ_MODEL = "openai/gpt-oss-120b";
const GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions";

export interface AiEvidencePackage {
  target: string;
  endpoint: string;
  method: string;
  identity?: string;
  category: string;
  claim: string;
  expected?: string;
  observed?: string;
  status?: number;
  baselineStatus?: number;
  responseContains?: string[];
  sensitiveFields?: string[];
  anonymousRefused?: boolean;
}

export interface AiClientOptions {
  apiKey: string;
  model?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

const SYSTEM_PROMPT = [
  "You assist a deterministic web-security testing engine.",
  "You are NOT the decision maker and you must not assume a vulnerability.",
  "Given one evidence package, judge whether it supports the stated claim.",
  "Distinguish configuration gaps from demonstrable security impact.",
  "Respond with JSON only, exactly matching this shape:",
  '{"supportsSecurityIssue":boolean,"confidence":"low"|"medium"|"high",',
  '"explanation":string,"falsePositiveExplanations":string[],"additionalVerification":string[]}',
  "explanation: what was observed, what correct behaviour would be, and whether the evidence supports the claim.",
  "falsePositiveExplanations: plausible benign explanations.",
  "additionalVerification: safe, non-destructive follow-up steps.",
].join("\n");

function toPackageText(pack: AiEvidencePackage): string {
  const sanitised: AiEvidencePackage = {
    ...pack,
    target: redactUrl(pack.target),
    endpoint: redactUrl(pack.endpoint),
    expected: pack.expected ? redactText(pack.expected) : undefined,
    observed: pack.observed ? redactText(pack.observed) : undefined,
    responseContains: pack.responseContains?.map(redactText),
  };
  return JSON.stringify(sanitised);
}

/** Ask Groq to assess a single evidence package. Returns null on any failure. */
export async function analyzeWithGroq(
  pack: AiEvidencePackage,
  options: AiClientOptions,
): Promise<AiAssessment | null> {
  const { apiKey, model = DEFAULT_GROQ_MODEL, timeoutMs = 12_000 } = options;
  if (!apiKey) return null;

  const doFetch = options.fetchImpl ?? globalThis.fetch;
  if (!doFetch) return null;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await doFetch(GROQ_ENDPOINT, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${apiKey}`,
      },
      signal: controller.signal,
      body: JSON.stringify({
        model,
        temperature: 0.1,
        max_tokens: 700,
        response_format: { type: "json_object" },
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user", content: toPackageText(pack) },
        ],
      }),
    });

    if (!response.ok) return null;
    const payload = (await response.json()) as {
      choices?: { message?: { content?: string } }[];
    };
    const content = payload.choices?.[0]?.message?.content;
    if (!content) return null;

    const parsed = aiAssessmentSchema.safeParse(JSON.parse(content));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** Render a concise, clearly-advisory annotation for an observation. */
export function formatAiNote(assessment: AiAssessment): string {
  const verdict = assessment.supportsSecurityIssue
    ? "model leans toward the claim"
    : "model does not support the claim";
  const parts = [`AI (advisory, ${assessment.confidence}): ${verdict}. ${assessment.explanation}`];
  if (assessment.falsePositiveExplanations.length) {
    parts.push(`Possible benign explanations: ${assessment.falsePositiveExplanations.join("; ")}.`);
  }
  if (assessment.additionalVerification.length) {
    parts.push(`Suggested verification: ${assessment.additionalVerification.join("; ")}.`);
  }
  return parts.join(" ");
}

export interface AiEnrichOptions extends Partial<AiClientOptions> {
  /** Maximum number of observations to send to the model. */
  max?: number;
  /** Restrict enrichment to these observation ids. */
  onlyIds?: string[];
}

function packageFromObservation(observation: TestObservation): AiEvidencePackage {
  return {
    target: observation.evidence.request.url,
    endpoint: observation.endpoint ?? observation.evidence.request.url,
    method: observation.evidence.request.method,
    identity: observation.identityId,
    category: observation.category,
    claim: observation.title,
    expected: observation.expected,
    observed: observation.observed,
    status: observation.evidence.response.status,
    baselineStatus: observation.evidence.baseline?.status,
    responseContains: observation.evidence.response.bodyPreview
      ? [observation.evidence.response.bodyPreview.slice(0, 800)]
      : [],
  };
}

/**
 * Annotate serious observations with advisory AI notes. Never changes state or
 * severity and never throws.
 */
export async function enrichObservationsWithAi(
  observations: TestObservation[],
  options: AiEnrichOptions,
): Promise<TestObservation[]> {
  if (!options.apiKey) return observations;
  const max = options.max ?? 6;
  const only = options.onlyIds ? new Set(options.onlyIds) : null;

  const out = [...observations];
  let used = 0;

  for (let i = 0; i < out.length && used < max; i += 1) {
    const observation = out[i]!;
    if (only && !only.has(observation.id)) continue;
    if (observation.state !== "Potential Issue" && observation.state !== "Needs Verification") {
      continue;
    }
    used += 1;
    const assessment = await analyzeWithGroq(packageFromObservation(observation), {
      apiKey: options.apiKey,
      model: options.model,
      timeoutMs: options.timeoutMs,
      fetchImpl: options.fetchImpl,
    });
    if (assessment) {
      out[i] = { ...observation, aiNote: formatAiNote(assessment) };
    }
  }

  return out;
}
