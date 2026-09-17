import { parse as parseYaml } from "yaml";
import type { RequestMethod } from "@webstrike/types";
import type { Identity, SkippedCategory, TestCase } from "./types";
import { INPUT_PROBES } from "./payloads";

export interface OpenApiOptions {
  baseUrl: string;
  identity?: Identity;
  activeTests: boolean;
  maxOperations: number;
  idPrefix: string;
}

export interface OpenApiResult {
  cases: TestCase[];
  skipped: SkippedCategory[];
  operationCount: number;
}

const PROBE_IDS = ["marker", "angle", "quote", "template"];
const METHODS = ["get", "post", "put", "patch", "delete", "head", "options"] as const;
const SAFE_METHODS = new Set(["get", "head", "options"]);

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

export function parseOpenApiDocument(input: unknown): Record<string, unknown> | null {
  if (typeof input === "string") {
    const trimmed = input.trim();
    if (!trimmed) return null;
    try {
      return asRecord(JSON.parse(trimmed));
    } catch {
      try {
        return asRecord(parseYaml(trimmed));
      } catch {
        return null;
      }
    }
  }
  return asRecord(input);
}

function exampleFor(schema: unknown, fallback: string): string {
  const s = asRecord(schema);
  const direct = s?.example ?? s?.default;
  if (typeof direct === "string") return direct;
  if (typeof direct === "number" || typeof direct === "boolean") return String(direct);
  const type = typeof s?.type === "string" ? s.type : undefined;
  if (type === "integer" || type === "number") return "1";
  if (type === "boolean") return "true";
  return fallback;
}

function baseFromSpec(spec: Record<string, unknown>, fallback: string): string {
  const servers = Array.isArray(spec.servers) ? spec.servers : [];
  const first = asRecord(servers[0]);
  const url = typeof first?.url === "string" ? first.url : undefined;
  if (!url) return fallback;
  try {
    return new URL(url, fallback).origin + new URL(url, fallback).pathname.replace(/\/$/, "");
  } catch {
    return fallback;
  }
}

interface Parameter {
  name: string;
  location: "path" | "query";
  example: string;
}

function parametersOf(value: unknown): Parameter[] {
  if (!Array.isArray(value)) return [];
  const out: Parameter[] = [];
  for (const raw of value) {
    const param = asRecord(raw);
    const name = typeof param?.name === "string" ? param.name : undefined;
    const location = param?.in;
    if (!name || (location !== "path" && location !== "query")) continue;
    out.push({
      name,
      location,
      example: exampleFor(param?.schema ?? param, "webstrike"),
    });
  }
  return out;
}

function applyIdentityHeader(
  request: TestCase["requests"][number],
  identity?: Identity,
): TestCase["requests"][number] {
  if (!identity) return request;
  request.identityId = identity.id;
  request.headers = [
    ...request.headers,
    ...identity.headers.filter(
      (h) => !request.headers.some((existing) => existing.name.toLowerCase() === h.name.toLowerCase()),
    ),
  ];
  request.cookies = [...request.cookies, ...identity.cookies];
  return request;
}

export function generateOpenApiCases(
  input: unknown,
  options: OpenApiOptions,
): OpenApiResult {
  const skipped: SkippedCategory[] = [];
  const spec = parseOpenApiDocument(input);
  if (!spec) {
    skipped.push({ category: "openapi", reason: "document could not be parsed as JSON or YAML" });
    return { cases: [], skipped, operationCount: 0 };
  }

  const paths = asRecord(spec.paths);
  if (!paths) {
    skipped.push({ category: "openapi", reason: "document has no paths object" });
    return { cases: [], skipped, operationCount: 0 };
  }

  const base = baseFromSpec(spec, options.baseUrl);
  const cases: TestCase[] = [];
  let operationCount = 0;

  for (const [rawPath, pathItemRaw] of Object.entries(paths)) {
    const pathItem = asRecord(pathItemRaw);
    if (!pathItem) continue;
    const pathParams = parametersOf(pathItem.parameters);

    for (const method of METHODS) {
      const operation = asRecord(pathItem[method]);
      if (!operation) continue;
      operationCount += 1;
      if (cases.length >= options.maxOperations) continue;

      const mutating = !SAFE_METHODS.has(method);
      if (mutating && !options.activeTests) {
        continue;
      }

      const params = [...pathParams, ...parametersOf(operation.parameters)];
      if (params.length === 0) continue;

      const methodUpper = method.toUpperCase() as RequestMethod;

      const substitute = (target: Parameter, value: string): string => {
        let url = `${base}${rawPath}`;
        const query = new URLSearchParams();
        for (const p of params) {
          const chosen = p === target ? value : p.example;
          if (p.location === "path") {
            url = url.replace(`{${p.name}}`, encodeURIComponent(chosen));
          } else if (p !== target) {
            query.set(p.name, chosen);
          }
        }
        if (target.location === "query") query.set(target.name, value);
        const qs = query.toString();
        return qs ? `${url}?${qs}` : url;
      };

      const target = params[0]!;
      const operationId =
        typeof operation.operationId === "string" ? operation.operationId : `${methodUpper} ${rawPath}`;

      const caseId = `${options.idPrefix}-${cases.length + 1}`;
      const requests: TestCase["requests"] = [];
      const probes: {
        requestId: string;
        probeId: string;
        value: string;
        intent: string;
        evaluated?: string;
      }[] = [];

      requests.push(
        applyIdentityHeader(
          {
            id: `${caseId}:r0`,
            label: "baseline",
            method: methodUpper,
            url: substitute(target, target.example),
            headers: [{ name: "Accept", value: "application/json" }],
            cookies: [],
            body: null,
            contentType: null,
            mutating,
          },
          options.identity,
        ),
      );

      const selected = INPUT_PROBES.filter((p) => PROBE_IDS.includes(p.id));
      selected.forEach((probe, index) => {
        const requestId = `${caseId}:r${index + 1}`;
        const request = applyIdentityHeader(
          {
            id: requestId,
            label: `probe: ${probe.intent}`,
            method: methodUpper,
            url: substitute(target, probe.value),
            headers: [{ name: "Accept", value: "application/json" }],
            cookies: [],
            body: null,
            contentType: null,
            mutating,
          },
          options.identity,
        );
        requests.push(request);
        probes.push({
          requestId,
          probeId: probe.id,
          value: probe.value,
          intent: probe.intent,
          evaluated: probe.evaluated,
        });
      });

      cases.push({
        id: caseId,
        category: "openapi",
        title: `OpenAPI ${operationId} — parameter "${target.name}"`,
        analyzer: "input-validation",
        metadata: { param: target.name, location: target.location, probes, source: "openapi" },
        requests,
      });
    }
  }

  if (operationCount === 0) {
    skipped.push({ category: "openapi", reason: "no operations found in the document" });
  } else if (cases.length === 0) {
    skipped.push({
      category: "openapi",
      reason: "operations found, but none had path/query parameters to probe (or active tests are off)",
    });
  }

  return { cases, skipped, operationCount };
}
