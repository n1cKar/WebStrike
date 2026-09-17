import type { RequestMethod } from "@webstrike/types";
import type {
  DiscoveredEndpoint,
  DiscoveredForm,
  Identity,
  SkippedCategory,
  Surface,
  TestCase,
  TestCategory,
  WorkflowStep,
} from "./types";
import { INPUT_PROBES, BENIGN_MARKER, type InputProbe } from "./payloads";
import { buildMultipart, formUrlEncoded } from "./multipart";
import { generateOpenApiCases } from "./openapi";

export const PROBE_ORIGIN = "https://webstrike-probe.invalid";

const PROBE_PRIORITY = [
  "marker",
  "angle",
  "template",
  "expression",
  "type",
  "quote",
  "overflow",
  "boundary",
  "encoding",
  "null-byte",
];

function orderedProbes(count: number): InputProbe[] {
  const ordered = PROBE_PRIORITY.map((id) => INPUT_PROBES.find((p) => p.id === id)).filter(
    (p): p is InputProbe => Boolean(p),
  );
  return ordered.slice(0, count);
}

export interface PlanCaps {
  corsEndpoints: number;
  authEndpoints: number;
  authzEndpoints: number;
  inputEndpoints: number;
  inputParamsPerEndpoint: number;
  inputProbes: number;
  csrfForms: number;
  uploadForms: number;
}

export const DEFAULT_CAPS: PlanCaps = {
  corsEndpoints: 5,
  authEndpoints: 6,
  authzEndpoints: 6,
  inputEndpoints: 5,
  inputParamsPerEndpoint: 2,
  inputProbes: 5,
  csrfForms: 5,
  uploadForms: 3,
};

export interface PlanOptions {
  categories: TestCategory[];
  identities: Identity[];
  activeTests: boolean;
  caps?: Partial<PlanCaps>;
  workflow?: WorkflowStep[];
  openapi?: unknown;
}

export interface PlanResult {
  cases: TestCase[];
  skipped: SkippedCategory[];
}

function mergeHeaders(
  base: { name: string; value: string }[],
  extra: { name: string; value: string }[],
): { name: string; value: string }[] {
  const out = [...base];
  const seen = new Set(base.map((h) => h.name.toLowerCase()));
  for (const header of extra) {
    if (seen.has(header.name.toLowerCase())) continue;
    seen.add(header.name.toLowerCase());
    out.push(header);
  }
  return out;
}

export function buildCases(surface: Surface, options: PlanOptions): PlanResult {
  const caps = { ...DEFAULT_CAPS, ...options.caps };
  const cases: TestCase[] = [];
  const skipped: SkippedCategory[] = [];
  const wants = new Set(options.categories);
  let counter = 0;
  const nextId = (category: string) => `${category}-${(counter += 1)}`;

  const identityA = options.identities[0];
  const identityB = options.identities[1];

  const makeRequest = (
    caseId: string,
    index: number,
    label: string,
    method: RequestMethod,
    url: string,
    extra: Partial<TestCase["requests"][number]> = {},
  ): TestCase["requests"][number] => ({
    id: `${caseId}:r${index}`,
    label,
    method,
    url,
    headers: extra.headers ?? [],
    cookies: extra.cookies ?? [],
    body: extra.body ?? null,
    contentType: extra.contentType ?? null,
    identityId: extra.identityId,
    mutating: method !== "GET" && method !== "HEAD" && method !== "OPTIONS",
  });

  const withIdentity = (
    request: TestCase["requests"][number],
    identity: Identity | undefined,
  ) => {
    if (!identity) return request;
    request.identityId = identity.id;
    request.headers = mergeHeaders(request.headers, identity.headers);
    request.cookies = [...request.cookies, ...identity.cookies];
    return request;
  };

  const endpointsWithParams = surface.endpoints.filter((e) => e.params.length > 0);
  const nonFormEndpoints = surface.endpoints.filter((e) => e.source !== "form");

  /* security headers */
  if (wants.has("security-headers")) {
    const caseId = nextId("headers");
    cases.push({
      id: caseId,
      category: "security-headers",
      title: "Security headers, cookies and banners",
      analyzer: "security-headers",
      requests: [makeRequest(caseId, 0, "baseline", "GET", surface.baseUrl)],
    });
  }

  /* CORS */
  if (wants.has("cors")) {
    for (const endpoint of nonFormEndpoints.slice(0, caps.corsEndpoints)) {
      const caseId = nextId("cors");
      cases.push({
        id: caseId,
        category: "cors",
        title: `CORS: ${endpoint.url}`,
        analyzer: "cors",
        metadata: { probeOrigin: PROBE_ORIGIN },
        requests: [
          makeRequest(caseId, 0, "baseline (no Origin)", "GET", endpoint.url),
          makeRequest(caseId, 1, `probe Origin: ${PROBE_ORIGIN}`, "GET", endpoint.url, {
            headers: [{ name: "Origin", value: PROBE_ORIGIN }],
          }),
        ],
      });
    }
  }

  /* CSRF static */
  if (wants.has("csrf")) {
    for (const form of surface.forms.slice(0, caps.csrfForms)) {
      const caseId = nextId("csrf");
      cases.push({
        id: caseId,
        category: "csrf",
        title: `CSRF review: ${form.method} ${form.action}`,
        analyzer: "csrf-static",
        metadata: {
          form: {
            action: form.action,
            method: form.method,
            hasCsrfToken: form.hasCsrfToken,
            csrfFieldName: form.csrfFieldName,
            fieldNames: form.fields.map((f) => f.name),
          },
        },
        requests: [makeRequest(caseId, 0, "baseline", "GET", form.action)],
      });
    }

    if (options.activeTests) {
      for (const form of surface.forms
        .filter((f) => f.method !== "GET")
        .slice(0, caps.csrfForms)) {
        const caseId = nextId("csrf-active");
        const textFields = form.fields.filter((f) => f.type !== "file");
        const tokenName = form.csrfFieldName;
        const fields = textFields.map((f) => ({
          name: f.name,
          value: f.value && f.value.length ? f.value : "webstrike",
        }));
        const encoded = formUrlEncoded(fields);
        const withoutToken = formUrlEncoded(fields.filter((f) => f.name !== tokenName));

        cases.push({
          id: caseId,
          category: "csrf",
          title: `CSRF active: ${form.method} ${form.action}`,
          analyzer: "csrf-active",
          metadata: {
            mode: tokenName ? "token-removal" : "origin",
            tokenName,
          },
          requests: [
            withIdentity(
              makeRequest(caseId, 0, "baseline (token/origin as expected)", form.method, form.action, {
                body: encoded,
                contentType: "application/x-www-form-urlencoded",
                headers: [{ name: "Origin", value: surface.origin }],
              }),
              identityA,
            ),
            withIdentity(
              makeRequest(caseId, 1, "test (token removed / foreign origin)", form.method, form.action, {
                body: withoutToken,
                contentType: "application/x-www-form-urlencoded",
                headers: [{ name: "Origin", value: PROBE_ORIGIN }],
              }),
              identityA,
            ),
          ],
        });
      }
    }
  }

  /* Authentication */
  if (wants.has("authentication")) {
    if (!identityA) {
      skipped.push({ category: "authentication", reason: "provide at least one identity" });
    } else {
      for (const endpoint of nonFormEndpoints.slice(0, caps.authEndpoints)) {
        const caseId = nextId("auth");
        cases.push({
          id: caseId,
          category: "authentication",
          title: `Authenticated vs anonymous: ${endpoint.url}`,
          analyzer: "auth-anon",
          requests: [
            withIdentity(
              makeRequest(caseId, 0, `authenticated (${identityA.label})`, "GET", endpoint.url),
              identityA,
            ),
            makeRequest(caseId, 1, "anonymous", "GET", endpoint.url),
          ],
        });
      }
    }
  }

  /* Authorization */
  if (wants.has("authorization")) {
    if (!identityA || !identityB) {
      skipped.push({ category: "authorization", reason: "provide two identities to compare" });
    } else {
      for (const endpoint of nonFormEndpoints.slice(0, caps.authzEndpoints)) {
        const caseId = nextId("authz");
        cases.push({
          id: caseId,
          category: "authorization",
          title: `Identity comparison: ${endpoint.url}`,
          analyzer: "authz-compare",
          metadata: { identityA: identityA.label, identityB: identityB.label },
          requests: [
            withIdentity(
              makeRequest(caseId, 0, `identity A (${identityA.label})`, "GET", endpoint.url),
              identityA,
            ),
            withIdentity(
              makeRequest(caseId, 1, `identity B (${identityB.label})`, "GET", endpoint.url),
              identityB,
            ),
          ],
        });
      }
    }
  }

  /* Input validation */
  if (wants.has("input-validation")) {
    const probes = orderedProbes(caps.inputProbes);
    const candidates = endpointsWithParams
      .filter((e) => e.source !== "form" || options.activeTests)
      .slice(0, caps.inputEndpoints);

    for (const endpoint of candidates) {
      const params = endpoint.params
        .filter((p) => (p.location === "form" ? options.activeTests : true))
        .slice(0, caps.inputParamsPerEndpoint);

      for (const param of params) {
        const caseId = nextId("input");
        const requests: TestCase["requests"] = [];
        const probeMeta: {
          requestId: string;
          probeId: string;
          value: string;
          intent: string;
          evaluated?: string;
        }[] = [];

        const buildUrl = (value: string): string => {
          const url = new URL(endpoint.url);
          if (param.location === "query") url.searchParams.set(param.name, value);
          return url.toString();
        };

        const buildFormBody = (value: string): string =>
          formUrlEncoded(
            endpoint.params.map((p) => ({
              name: p.name,
              value: p.name === param.name ? value : (p.example ?? "webstrike"),
            })),
          );

        if (param.location === "query") {
          requests.push(makeRequest(caseId, 0, "baseline", "GET", buildUrl(param.example ?? "webstrike")));
        } else {
          requests.push(
            withIdentity(
              makeRequest(caseId, 0, "baseline", endpoint.method === "GET" ? "GET" : "POST", endpoint.url, {
                body: endpoint.method === "GET" ? null : buildFormBody(param.example ?? "webstrike"),
                contentType: endpoint.method === "GET" ? null : "application/x-www-form-urlencoded",
              }),
              identityA,
            ),
          );
        }

        probes.forEach((probe, index) => {
          const requestIndex = index + 1;
          const request =
            param.location === "query"
              ? makeRequest(caseId, requestIndex, `probe: ${probe.intent}`, "GET", buildUrl(probe.value))
              : withIdentity(
                  makeRequest(caseId, requestIndex, `probe: ${probe.intent}`, endpoint.method === "GET" ? "GET" : "POST", endpoint.url, {
                    body: endpoint.method === "GET" ? null : buildFormBody(probe.value),
                    contentType: endpoint.method === "GET" ? null : "application/x-www-form-urlencoded",
                  }),
                  identityA,
                );
          requests.push(request);
          probeMeta.push({
            requestId: request.id,
            probeId: probe.id,
            value: probe.value,
            intent: probe.intent,
            evaluated: probe.evaluated,
          });
        });

        if (requests.length > 1) {
          cases.push({
            id: caseId,
            category: "input-validation",
            title: `Parameter "${param.name}" on ${endpoint.url}`,
            analyzer: "input-validation",
            metadata: {
              param: param.name,
              location: param.location,
              probes: probeMeta,
              marker: BENIGN_MARKER,
            },
            requests,
          });
        }
      }
    }
  }

  /* File upload */
  if (wants.has("file-upload")) {
    const uploadForms = surface.forms.filter((f) => f.hasFileInput).slice(0, caps.uploadForms);
    if (uploadForms.length === 0) {
      skipped.push({ category: "file-upload", reason: "no upload forms discovered" });
    }
    for (const form of uploadForms) {
      const caseId = nextId("upload");
      if (!options.activeTests) {
        cases.push({
          id: caseId,
          category: "file-upload",
          title: `Upload form: ${form.action}`,
          analyzer: "upload-static",
          metadata: { form: { action: form.action } },
          requests: [makeRequest(caseId, 0, "baseline", "GET", form.action)],
        });
        continue;
      }

      const fileField = form.fields.find((f) => f.type === "file");
      if (!fileField) continue;
      const textFields = form.fields.filter((f) => f.type !== "file" && f.name !== form.csrfFieldName);

      const files = [
        {
          name: "webstrike-test.txt",
          type: "text/plain",
          content: `wsprobe-upload-marker ${BENIGN_MARKER}\n`,
        },
        {
          name: "webstrike-test.html",
          type: "text/html",
          content: `<!doctype html><title>wsprobe-upload-marker</title>wsprobe-upload-marker ${BENIGN_MARKER}`,
        },
        {
          name: "webstrike-test.svg",
          type: "image/svg+xml",
          content: `<svg xmlns="http://www.w3.org/2000/svg"><text>wsprobe-upload-marker ${BENIGN_MARKER}</text></svg>`,
        },
      ];

      const requests = files.map((file, index) => {
        const multipart = buildMultipart(
          textFields.map((f) => ({
            name: f.name,
            value: f.value && f.value.length ? f.value : "webstrike",
          })),
          [
            {
              fieldName: fileField.name,
              filename: file.name,
              contentType: file.type,
              content: file.content,
            },
          ],
        );
        const request = makeRequest(caseId, index, `upload ${file.name}`, "POST", form.action, {
          body: multipart.body,
          contentType: multipart.contentType,
        });
        if (request.body) request.headers = mergeHeaders(request.headers, []);
        return withIdentity(request, identityA);
      });

      cases.push({
        id: caseId,
        category: "file-upload",
        title: `Upload probes: ${form.action}`,
        analyzer: "upload-active",
        metadata: {
          files: files.map((f) => ({ name: f.name, type: f.type })),
        },
        requests,
      });
    }
  }

  /* Business logic */
  if (wants.has("business-logic")) {
    if (!options.workflow || options.workflow.length === 0) {
      skipped.push({ category: "business-logic", reason: "define a workflow to run" });
    }
  }

  /* OpenAPI */
  if (wants.has("openapi")) {
    if (!options.openapi) {
      skipped.push({ category: "openapi", reason: "import an OpenAPI 3.x document" });
    } else {
      const generated = generateOpenApiCases(options.openapi, {
        baseUrl: surface.baseUrl,
        identity: identityA,
        activeTests: options.activeTests,
        maxOperations: 8,
        idPrefix: `openapi-${counter}`,
      });
      counter += generated.cases.length;
      cases.push(...generated.cases);
      skipped.push(...generated.skipped);
    }
  }

  return { cases, skipped };
}
