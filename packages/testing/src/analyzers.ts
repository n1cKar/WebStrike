import type { ScopedHttpResult } from "@webstrike/types";
import { analyzeCookies } from "@webstrike/security";
import {
  appearsEvaluated,
  bodySimilarity,
  changedHeaders,
  describeResponse,
  hasErrorSignature,
  isDenied,
  isRedirect,
  isServerError,
  isSuccess,
  previewBody,
  reflectsUnescaped,
} from "./compare";
import { makeEvidence } from "./evidence";
import type {
  AnalyzeContext,
  Analyzer,
  AutomatedRequest,
  Confidence,
  ResultState,
  TestObservation,
} from "./types";

function pair(ctx: AnalyzeContext, index = 0): { req: AutomatedRequest; res: ScopedHttpResult } | null {
  const req = ctx.testCase.requests[index];
  if (!req) return null;
  const res = ctx.results[req.id];
  if (!res) return null;
  return { req, res };
}

function observation(
  ctx: AnalyzeContext,
  suffix: string,
  fields: {
    title: string;
    state: ResultState;
    confidence: Confidence;
    summary: string;
    detail: string;
    req: AutomatedRequest;
    res: ScopedHttpResult;
    baseline?: ScopedHttpResult;
    guidance?: string;
  },
): TestObservation {
  return {
    id: `${ctx.testCase.id}-${suffix}`,
    category: ctx.testCase.category,
    title: fields.title,
    state: fields.state,
    confidence: fields.confidence,
    summary: fields.summary,
    guidance: fields.guidance,
    evidence: makeEvidence(fields.req, fields.res, fields.detail, fields.baseline),
  };
}

function contentType(res: ScopedHttpResult): string {
  return (res.headers["content-type"] ?? "").toLowerCase();
}

function isHtml(res: ScopedHttpResult): boolean {
  return contentType(res).includes("text/html");
}

/* ------------------------------------------------------------------ */
/* Security headers & cookies                                          */
/* ------------------------------------------------------------------ */

const REQUIRED_HEADERS: { name: string; httpsOnly?: boolean; why: string }[] = [
  { name: "content-security-policy", why: "constrains script/style sources" },
  { name: "x-content-type-options", why: "stops MIME sniffing" },
  { name: "referrer-policy", why: "limits referrer leakage" },
  { name: "x-frame-options", why: "frames/clickjacking control" },
  { name: "strict-transport-security", httpsOnly: true, why: "forces HTTPS" },
];

const securityHeaders: Analyzer = (ctx) => {
  const base = pair(ctx, 0);
  if (!base || !base.res.ok) return [];
  const out: TestObservation[] = [];
  const https = base.res.finalUrl.startsWith("https:");

  const missing = REQUIRED_HEADERS.filter(
    (h) => (!h.httpsOnly || https) && base.res.headers[h.name] === undefined,
  );
  if (missing.length) {
    out.push(
      observation(ctx, "missing", {
        title: `Security headers not observed (${missing.length})`,
        state: "Observation",
        confidence: "low",
        summary: `Not observed: ${missing.map((m) => m.name).join(", ")}. Absence is contextual evidence, not a vulnerability; each gap is reported for manual review.`,
        detail: missing.map((m) => `${m.name}: not present — ${m.why}`).join("\n"),
        req: base.req,
        res: base.res,
      }),
    );
  }

  const server = base.res.headers["server"];
  const poweredBy = base.res.headers["x-powered-by"];
  if ((server && /\d/.test(server)) || (poweredBy && /\d/.test(poweredBy))) {
    out.push(
      observation(ctx, "banner", {
        title: "Version banner exposed",
        state: "Observation",
        confidence: "medium",
        summary: `Server/technology banner reveals a version: ${[server, poweredBy].filter(Boolean).join(", ")}.`,
        detail: "Version disclosure helps an attacker target known issues in that release.",
        req: base.req,
        res: base.res,
      }),
    );
  }

  for (const cookie of analyzeCookies(base.res)) {
    if (cookie.observations.length === 0) continue;
    const weak = !cookie.secure || !cookie.httpOnly;
    out.push(
      observation(ctx, `cookie-${cookie.cookie}`, {
        title: `Cookie attribute review: ${cookie.cookie}`,
        state: weak ? "Needs Verification" : "Observation",
        confidence: "low",
        summary: cookie.observations.join("; "),
        detail: `cookie ${cookie.cookie}: secure=${cookie.secure}, httpOnly=${cookie.httpOnly}, sameSite=${cookie.sameSite ?? "unset"}`,
        req: base.req,
        res: base.res,
      }),
    );
  }

  return out;
};

/* ------------------------------------------------------------------ */
/* CORS                                                                */
/* ------------------------------------------------------------------ */

const cors: Analyzer = (ctx) => {
  const baseline = pair(ctx, 0);
  const probe = pair(ctx, 1);
  if (!baseline || !probe || !probe.res.ok) return [];
  const probeOrigin = (ctx.testCase.metadata?.probeOrigin as string) ?? "";
  const acao = probe.res.headers["access-control-allow-origin"];
  const acac = (probe.res.headers["access-control-allow-credentials"] ?? "").toLowerCase();
  if (acao === undefined) {
    return [];
  }

  const reflectsProbe = acao === probeOrigin;
  const wildcard = acao === "*";
  const credentials = acac === "true";
  const carriesCredentials =
    probe.req.cookies.length > 0 ||
    probe.req.headers.some((h) => /^(cookie|authorization)$/i.test(h.name));

  if (reflectsProbe && credentials && carriesCredentials) {
    return [
      observation(ctx, "reflect-credentials", {
        title: "Arbitrary origin reflected with credentials",
        state: "Potential Issue",
        confidence: "high",
        summary: `The response reflected the request Origin "${probeOrigin}" in Access-Control-Allow-Origin while allowing credentials, and the probe carried a session credential. A malicious site could read authenticated responses if the session is cookie-based.`,
        detail: `Access-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac}\nBaseline ACAO: ${baseline.res.headers["access-control-allow-origin"] ?? "(none)"}`,
        req: probe.req,
        res: probe.res,
        baseline: baseline.res,
        guidance:
          "Validate the Origin against a strict allowlist server-side; never reflect arbitrary origins when credentials are allowed.",
      }),
    ];
  }

  if (reflectsProbe && credentials) {
    return [
      observation(ctx, "reflect-credentials-unauthenticated", {
        title: "Origin reflected with credentials flag (unauthenticated probe)",
        state: "Needs Verification",
        confidence: "low",
        summary: `Access-Control-Allow-Origin echoed "${probeOrigin}" with Allow-Credentials: true. The probe was unauthenticated, so browser impact depends on whether credentialed requests are accepted.`,
        detail: `Access-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac}`,
        req: probe.req,
        res: probe.res,
        baseline: baseline.res,
        guidance:
          "Repeat with a real identity; only reflected origins plus accepted credentials constitute a cross-origin read risk.",
      }),
    ];
  }

  if (reflectsProbe) {
    const changed = changedHeaders(baseline.res.headers, probe.res.headers);
    return [
      observation(ctx, "reflect", {
        title: "Request origin reflected in CORS policy",
        state: "Needs Verification",
        confidence: "low",
        summary: `Access-Control-Allow-Origin echoed the probe Origin "${probeOrigin}". Reflection without Allow-Credentials has limited browser impact; confirm whether the allowed origin list is enforced.`,
        detail: `Access-Control-Allow-Origin: ${acao}; changed headers vs baseline: ${changed.join(", ") || "(none)"}`,
        req: probe.req,
        res: probe.res,
        baseline: baseline.res,
        guidance:
          "Compare with an Origin the application should reject. Reflection without credentials is usually benign.",
      }),
    ];
  }

  if (wildcard && credentials) {
    return [
      observation(ctx, "wildcard-credentials", {
        title: "Wildcard origin with credentials",
        state: "Observation",
        confidence: "low",
        summary:
          "Access-Control-Allow-Origin is * together with Allow-Credentials. Browsers reject this combination, so impact is limited; review why it is configured.",
        detail: `Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true`,
        req: probe.req,
        res: probe.res,
        baseline: baseline.res,
      }),
    ];
  }

  return [];
};

/* ------------------------------------------------------------------ */
/* CSRF (static)                                                       */
/* ------------------------------------------------------------------ */

const csrfStatic: Analyzer = (ctx) => {
  const base = pair(ctx, 0);
  if (!base) return [];
  const out: TestObservation[] = [];
  const form = ctx.testCase.metadata?.form as
    | { action: string; method: string; hasCsrfToken: boolean; csrfFieldName?: string; fieldNames: string[] }
    | undefined;

  if (form && form.method !== "GET" && !form.hasCsrfToken) {
    out.push(
      observation(ctx, "no-token", {
        title: "State-changing form without an anti-CSRF token",
        state: "Needs Verification",
        confidence: "low",
        summary: `The ${form.method} form at ${form.action} exposes no visible anti-CSRF token field. If the action is cookie-authenticated and SameSite is not Strict, CSRF may be possible.`,
        detail: `fields: ${form.fieldNames.join(", ") || "(none)"}; method: ${form.method}`,
        req: base.req,
        res: base.res,
        guidance:
          "Confirm with an active token-removal test, and verify the session cookie's SameSite attribute.",
      }),
    );
  }

  for (const cookie of analyzeCookies(base.res)) {
    const samesite = (cookie.sameSite ?? "").toLowerCase();
    if (samesite === "strict") continue;
    if (!cookie.observations.length && samesite !== "none") continue;
    out.push(
      observation(ctx, `samesite-${cookie.cookie}`, {
        title: `CSRF-relevant cookie: ${cookie.cookie}`,
        state: samesite === "none" ? "Needs Verification" : "Observation",
        confidence: "low",
        summary: `sameSite=${cookie.sameSite ?? "unset"}; secure=${cookie.secure}; httpOnly=${cookie.httpOnly}.`,
        detail: `Cookie ${cookie.cookie} SameSite=${cookie.sameSite ?? "unset (browser default Lax)"}`,
        req: base.req,
        res: base.res,
      }),
    );
  }

  return out;
};

/* ------------------------------------------------------------------ */
/* CSRF (active token removal)                                         */
/* ------------------------------------------------------------------ */

const csrfActive: Analyzer = (ctx) => {
  const expected = pair(ctx, 0);
  const test = pair(ctx, 1);
  if (!expected || !test) return [];
  const baseline = ctx.results[expected.req.id];
  if (!baseline) return [];

  const mode = (ctx.testCase.metadata?.mode as string | undefined) ?? "token-removal";
  const tokenName = ctx.testCase.metadata?.tokenName as string | undefined;

  const accepted = (res: ScopedHttpResult) => isSuccess(res.status) || isRedirect(res.status);
  const sameOutcome =
    accepted(test.res) &&
    accepted(expected.res) &&
    Math.abs(test.res.status - expected.res.status) < 100;

  if (!accepted(expected.res)) {
    return [
      observation(ctx, "inconclusive", {
        title: "CSRF active test inconclusive",
        state: "Not Reproducible",
        confidence: "low",
        summary:
          "The baseline request was not accepted, so no conclusion can be drawn. Supply a valid session/identity (and a fresh token) and retry.",
        detail: `baseline status: ${expected.res.status}`,
        req: test.req,
        res: test.res,
        baseline: expected.res,
      }),
    ];
  }

  if (sameOutcome) {
    const what =
      mode === "token-removal"
        ? `the "${tokenName}" token was omitted and a foreign Origin was supplied`
        : "a foreign Origin was supplied (no token field is present)";
    return [
      observation(ctx, "accepted", {
        title:
          mode === "token-removal"
            ? "State-changing request accepted without anti-CSRF token"
            : "Cross-origin request accepted without an anti-CSRF token",
        state: "Potential Issue",
        confidence: "high",
        summary: `A ${test.req.method} request to ${test.req.url} was accepted even though ${what}, while carrying the session cookie. This is the observable shape of a CSRF weakness.`,
        detail: `expected: ${describeResponse(expected.res)}\ntest: ${describeResponse(test.res)}`,
        req: test.req,
        res: test.res,
        baseline: expected.res,
        guidance:
          "Confirm the action actually changed server state, then require a per-request token and/or SameSite=Strict with Origin validation.",
      }),
    ];
  }

  return [
    observation(ctx, "rejected", {
      title: "CSRF protection appeared to reject the altered request",
      state: "Not Reproducible",
      confidence: "medium",
      summary:
        "Removing the token / changing the origin changed the outcome, which is consistent with CSRF protection.",
      detail: `expected: ${describeResponse(expected.res)}\ntest: ${describeResponse(test.res)}`,
      req: test.req,
      res: test.res,
      baseline: expected.res,
    }),
  ];
};

/* ------------------------------------------------------------------ */
/* Authentication: anonymous vs authenticated                          */
/* ------------------------------------------------------------------ */

const authAnon: Analyzer = (ctx) => {
  const authed = pair(ctx, 0);
  const anon = pair(ctx, 1);
  if (!authed || !anon) return [];
  if (!authed.res.ok || !anon.res.ok) return [];

  if (isDenied(authed.res.status)) return [];

  const similarity = bodySimilarity(authed.res.body, anon.res.body);

  if (isDenied(anon.res.status)) {
    return [
      observation(ctx, "boundary", {
        title: "Authentication boundary enforced",
        state: "Not Reproducible",
        confidence: "medium",
        summary: `Anonymous access was refused (${anon.res.status}) while the authenticated request succeeded (${authed.res.status}).`,
        detail: `anonymous: ${describeResponse(anon.res)}\nauthenticated: ${describeResponse(authed.res)}`,
        req: anon.req,
        res: anon.res,
        baseline: authed.res,
      }),
    ];
  }

  if (isSuccess(authed.res.status) && isSuccess(anon.res.status) && similarity > 0.9) {
    return [
      observation(ctx, "public-equiv", {
        title: "Authenticated and anonymous responses match",
        state: "Observation",
        confidence: "low",
        summary: `Anonymous and authenticated responses to ${anon.req.url} are ${(similarity * 100).toFixed(0)}% similar. This is expected for public pages; it only warrants review if this endpoint is meant to be private.`,
        detail: `similarity: ${(similarity * 100).toFixed(0)}%\nanonymous: ${describeResponse(anon.res)}\nauthenticated: ${describeResponse(authed.res)}`,
        req: anon.req,
        res: anon.res,
        baseline: authed.res,
        guidance:
          "Confirm whether the endpoint is intended to be public. Matching content is not itself evidence of a missing authentication check.",
      }),
    ];
  }

  return [];
};

/* ------------------------------------------------------------------ */
/* Authorization: identity A vs identity B                             */
/* ------------------------------------------------------------------ */

const authzCompare: Analyzer = (ctx) => {
  const a = pair(ctx, 0);
  const b = pair(ctx, 1);
  if (!a || !b) return [];
  if (!a.res.ok || !b.res.ok) return [];

  const sim = bodySimilarity(a.res.body, b.res.body);
  const structured = contentType(a.res).includes("json") || contentType(b.res).includes("json");

  if (isSuccess(a.res.status) && isSuccess(b.res.status) && structured && sim > 0.98) {
    return [
      observation(ctx, "same-content", {
        title: "Two identities receive identical structured content",
        state: "Needs Verification",
        confidence: "medium",
        summary: `Identity A and identity B both received ${a.res.status} for ${a.req.url} with ${(sim * 100).toFixed(0)}% identical structured bodies. If this record is owned by A, B may be able to reach it — confirm ownership in the application.`,
        detail: `identity A: ${describeResponse(a.res)}\nidentity B: ${describeResponse(b.res)}\nsimilarity: ${(sim * 100).toFixed(0)}%`,
        req: b.req,
        res: b.res,
        baseline: a.res,
        guidance:
          "Confirm which account owns the object. Identical public records are expected; only identical private records imply a boundary gap.",
      }),
    ];
  }

  if (isDenied(a.res.status) && isSuccess(b.res.status)) {
    return [
      observation(ctx, "b-broader", {
        title: "Identity B reaches a resource denied to A",
        state: "Needs Verification",
        confidence: "medium",
        summary: `Identity A was denied (${a.res.status}) while identity B succeeded (${b.res.status}) for ${b.req.url}. Confirm whether B legitimately has broader access (role, ownership, or share).`,
        detail: `identity A: ${describeResponse(a.res)}\nidentity B: ${describeResponse(b.res)}`,
        req: b.req,
        res: b.res,
        baseline: a.res,
      }),
    ];
  }

  return [];
};

/* ------------------------------------------------------------------ */
/* Input validation                                                    */
/* ------------------------------------------------------------------ */

interface ProbeMeta {
  requestId: string;
  probeId: string;
  value: string;
  intent: string;
  evaluated?: string;
}

const inputValidation: Analyzer = (ctx) => {
  const base = pair(ctx, 0);
  if (!base) return [];
  const probes = (ctx.testCase.metadata?.probes as ProbeMeta[] | undefined) ?? [];
  const out: TestObservation[] = [];
  const baselineError = hasErrorSignature(base.res.body);

  for (const meta of probes) {
    const req = ctx.testCase.requests.find((r) => r.id === meta.requestId);
    const res = ctx.results[meta.requestId];
    if (!req || !res || !res.ok) continue;

    if (meta.evaluated && appearsEvaluated(res.body, meta.value, meta.evaluated)) {
      out.push(
        observation(ctx, `eval-${meta.probeId}`, {
          title: "Input appears to be evaluated",
          state: "Potential Issue",
          confidence: "high",
          summary: `Sending ${meta.value} to "${ctx.testCase.title}" returned the evaluated result ${meta.evaluated}.`,
          detail: `probe intent: ${meta.intent}\nbaseline status: ${base.res.status}, test status: ${res.status}`,
          req,
          res,
          baseline: base.res,
          guidance: "Confirm the evaluation happens server-side and is not echoed from a client template.",
        }),
      );
      continue;
    }

    if (isServerError(res.status) && !isServerError(base.res.status)) {
      out.push(
        observation(ctx, `5xx-${meta.probeId}`, {
          title: "Probe triggered a server error",
          state: "Potential Issue",
          confidence: "medium",
          summary: `A controlled "${meta.intent}" probe changed the status from ${base.res.status} to ${res.status}.`,
          detail: `value: ${meta.value.slice(0, 80)}\nbaseline: ${describeResponse(base.res)}\ntest: ${describeResponse(res)}`,
          req,
          res,
          baseline: base.res,
          guidance: "Confirm the input is validated and that errors do not leak internals.",
        }),
      );
      continue;
    }

    const signature = hasErrorSignature(res.body);
    if (signature && signature !== baselineError) {
      out.push(
        observation(ctx, `error-${meta.probeId}`, {
          title: "Error signature in response",
          state: "Needs Verification",
          confidence: "medium",
          summary: `Response contained the error signature "${signature}" for the "${meta.intent}" probe.`,
          detail: `value: ${meta.value.slice(0, 80)}\nbaseline signature: ${baselineError ?? "(none)"}`,
          req,
          res,
          baseline: base.res,
        }),
      );
      continue;
    }

    if (isHtml(res) && reflectsUnescaped(res.body, meta.value)) {
      out.push(
        observation(ctx, `reflect-${meta.probeId}`, {
          title: "Input reflected without encoding",
          state: "Needs Verification",
          confidence: "low",
          summary: `The ${meta.intent} probe was reflected into HTML unencoded. Reflection alone is not XSS; it needs a context breakout to be exploitable.`,
          detail: `value: ${meta.value.slice(0, 80)}\nreflection is raw in an HTML response`,
          req,
          res,
          baseline: base.res,
          guidance:
            "Inspect the reflection context before concluding; verify output encoding rather than assuming exploitability.",
        }),
      );
    }
  }

  return out.slice(0, 8);
};

/* ------------------------------------------------------------------ */
/* File upload                                                         */
/* ------------------------------------------------------------------ */

const uploadStatic: Analyzer = (ctx) => {
  const base = pair(ctx, 0);
  if (!base) return [];
  const form = ctx.testCase.metadata?.form as { action: string } | undefined;
  if (!form) return [];
  return [
    observation(ctx, "detected", {
      title: "File upload form detected",
      state: "Observation",
      confidence: "medium",
      summary: `A multipart upload form posts to ${form.action}. Enable active tests to probe extension/MIME handling.`,
      detail: `action: ${form.action}`,
      req: base.req,
      res: base.res,
    }),
  ];
};

const ACTIVE_TYPES = [
  "text/html",
  "image/svg+xml",
  "application/xhtml+xml",
  "application/xml",
];

const uploadActive: Analyzer = (ctx) => {
  const out: TestObservation[] = [];
  const files = (ctx.testCase.metadata?.files as { name: string; type: string }[] | undefined) ?? [];

  for (let index = 0; index < files.length; index += 1) {
    const req = ctx.testCase.requests[index];
    if (!req) continue;
    const res = ctx.results[req.id];
    if (!res || !res.ok) continue;
    const file = files[index]!;

    const markerPresent = res.body.includes("wsprobe-upload-marker");
    const ct = contentType(res);

    if (markerPresent && ACTIVE_TYPES.some((t) => ct.includes(t))) {
      out.push(
        observation(ctx, `stored-${index}`, {
          title: "Uploaded file returned as active content",
          state: "Potential Issue",
          confidence: "medium",
          summary: `Uploading ${file.name} (${file.type}) resulted in a response served as ${ct || "an unknown type"} containing the uploaded marker. If the file is later served from a web-accessible path without Content-Disposition: attachment, stored XSS may be possible.`,
          detail: `status: ${res.status}; content-type: ${ct}\nmarker echoed: yes`,
          req,
          res,
          guidance:
            "Serve user uploads from a separate origin, with Content-Disposition: attachment and a restrictive Content-Type.",
        }),
      );
      continue;
    }

    if (isSuccess(res.status) || isRedirect(res.status)) {
      out.push(
        observation(ctx, `accepted-${index}`, {
          title: `Upload accepted: ${file.name}`,
          state: "Observation",
          confidence: "low",
          summary: `The server accepted ${file.name} (${file.type}) with status ${res.status}. Confirm stored files cannot be retrieved as executable content.`,
          detail: `content-type: ${ct || "(none)"}; body preview: ${previewBody(res.body, 200)}`,
          req,
          res,
        }),
      );
    }
  }

  return out;
};

/* ------------------------------------------------------------------ */
/* Registry                                                            */
/* ------------------------------------------------------------------ */

const registry: Record<string, Analyzer> = {
  "security-headers": securityHeaders,
  cors,
  "csrf-static": csrfStatic,
  "csrf-active": csrfActive,
  "auth-anon": authAnon,
  "authz-compare": authzCompare,
  "input-validation": inputValidation,
  "upload-static": uploadStatic,
  "upload-active": uploadActive,
};

export function getAnalyzer(name: string): Analyzer | undefined {
  return registry[name];
}

export function registerAnalyzer(name: string, analyzer: Analyzer): void {
  registry[name] = analyzer;
}

export type { AnalyzeContext };
