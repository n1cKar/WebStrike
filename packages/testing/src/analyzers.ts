import type { ScopedHttpResult } from "@webstrike/types";
import { analyzeCookies } from "@webstrike/security";
import {
  appearsEvaluated,
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
import { diffResponses, hasSubstantiveData, jsonShape } from "./diff";
import { isAuthFlow, isResourceAccess } from "./classify";
import { identityMarkers, isPrivileged, markersPresent } from "./identity";
import type {
  AnalyzeContext,
  Analyzer,
  AutomatedRequest,
  Confidence,
  EndpointClassification,
  ResultState,
  ResultTier,
  Severity,
  TestObservation,
  VerificationStatus,
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
    severity?: Severity;
    tier?: ResultTier;
    endpoint?: string;
    identityId?: string;
    expected?: string;
    observed?: string;
    impact?: string;
    reasoning?: string;
    nextTest?: string;
    remediation?: string;
    verification?: VerificationStatus;
  },
): TestObservation {
  return {
    id: `${ctx.testCase.id}-${suffix}`,
    category: ctx.testCase.category,
    caseId: ctx.testCase.id,
    title: fields.title,
    state: fields.state,
    confidence: fields.confidence,
    summary: fields.summary,
    guidance: fields.guidance,
    severity: fields.severity,
    tier: fields.tier,
    endpoint: fields.endpoint ?? fields.req.url,
    identityId: fields.identityId ?? fields.req.identityId,
    expected: fields.expected,
    observed: fields.observed,
    impact: fields.impact,
    reasoning: fields.reasoning,
    nextTest: fields.nextTest ?? fields.guidance,
    remediation: fields.remediation,
    verification: fields.verification,
    evidence: makeEvidence(fields.req, fields.res, fields.detail, fields.baseline),
  };
}

function classificationsOf(ctx: AnalyzeContext): EndpointClassification[] | undefined {
  return ctx.testCase.metadata?.classifications as EndpointClassification[] | undefined;
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
        severity: "info",
        tier: 3,
        summary: `Not observed: ${missing.map((m) => m.name).join(", ")}. Security hardening observation, not a vulnerability; each gap is reported for manual review.`,
        detail: missing.map((m) => `${m.name}: not present — ${m.why}`).join("\n"),
        expected: "Responses define the security headers the baseline policy requires.",
        observed: `Header(s) absent: ${missing.map((m) => m.name).join(", ")}.`,
        impact:
          "Absent hardening headers widen browser-side attack surface but do not by themselves demonstrate an exploitable weakness.",
        req: base.req,
        res: base.res,
        nextTest:
          "Confirm whether a compensating proxy/CDN sets these headers and whether any consequence is demonstrable.",
      }),
    );
  }

  const server = base.res.headers["server"];
  const poweredBy = base.res.headers["x-powered-by"];
  if ((server && /\d/.test(server)) || (poweredBy && /\d/.test(poweredBy))) {
    out.push(
      observation(ctx, "banner", {
        title: "Technology banner exposed",
        state: "Informational",
        confidence: "medium",
        severity: "info",
        tier: 3,
        summary: `Banner reveals a component version: ${[server, poweredBy].filter(Boolean).join(", ")}. Informational only — version disclosure is not a vulnerability without demonstrated impact.`,
        detail:
          "Version disclosure can help an attacker target known issues in that release; confirm the release is still supported.",
        expected: "Responses avoid advertising precise component versions.",
        observed: `Banner: ${[server, poweredBy].filter(Boolean).join(", ")}.`,
        impact: "Reconnaissance aid only.",
        req: base.req,
        res: base.res,
        nextTest: "Check the disclosed version against the vendor's support lifecycle.",
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

  const classes = classificationsOf(ctx);
  /* Login/registration/reset flows and public pages are expected to answer
     anonymous callers; comparing them here only creates noise. */
  if (isAuthFlow(classes)) return [];

  const sensitiveContext = classes?.some((c) =>
    ["API", "RESOURCE_ACCESS", "PRIVILEGED", "ADMIN", "AUTHENTICATED"].includes(c),
  );
  if (!sensitiveContext) return [];

  if (isDenied(authed.res.status)) return [];

  const diff = diffResponses(anon.res, authed.res);
  const anonSubstantive = hasSubstantiveData(anon.res);

  if (isDenied(anon.res.status)) {
    return [
      observation(ctx, "boundary", {
        title: "Authentication boundary enforced",
        state: "Not Reproducible",
        confidence: "medium",
        severity: "info",
        tier: 3,
        summary: `Anonymous access was refused (${anon.res.status}) while the authenticated request succeeded (${authed.res.status}).`,
        detail: `anonymous: ${describeResponse(anon.res)}\nauthenticated: ${describeResponse(authed.res)}`,
        expected: "Protected endpoint denies unauthenticated access.",
        observed: `Anonymous request answered ${anon.res.status}.`,
        req: anon.req,
        res: anon.res,
        baseline: authed.res,
      }),
    ];
  }

  if (!isSuccess(anon.res.status)) return [];

  const substantive = hasSubstantiveData(authed.res);
  const structuredGain =
    diff.keysAdded.length > 0 || diff.sensitiveKeysAdded.length > 0;

  if (substantive && (structuredGain || !anonSubstantive)) {
    return [
      observation(ctx, "anon-gap", {
        title: "Authenticated response exposes data absent anonymously",
        state: "Needs Verification",
        confidence: "medium",
        severity: "medium",
        tier: 2,
        summary: `The authenticated response to ${authed.req.url} contains substantive data${
          structuredGain ? ` (new keys: ${[...diff.keysAdded, ...diff.sensitiveKeysAdded].slice(0, 6).join(", ")})` : ""
        } that the anonymous response did not, without a clear denial. If this endpoint is not intentionally public, authentication may not be enforced.`,
        detail: `anonymous: ${describeResponse(anon.res)}\nauthenticated: ${describeResponse(authed.res)}\nstructured gain: ${structuredGain}`,
        expected: "An endpoint that returns private data should refuse anonymous callers.",
        observed: `Anonymous request returned ${anon.res.status} with ${anonSubstantive ? "non-substantive" : "no"} private data.`,
        impact:
          "If the data is private, an unauthenticated caller can read it. Public endpoints make this expected.",
        reasoning: "Compared the anonymous and authenticated responses structurally.",
        req: anon.req,
        res: anon.res,
        baseline: authed.res,
        guidance:
          "Confirm the endpoint is meant to be private before treating this as a finding.",
        nextTest:
          "Request the same endpoint with no credentials in a fresh client and confirm whether private data is returned.",
        remediation: "Enforce authentication server-side before returning private data.",
      }),
    ];
  }

  if (diff.similarity > 0.95) {
    return [
      observation(ctx, "public-equiv", {
        title: "Authenticated and anonymous responses match",
        state: "Observation",
        confidence: "low",
        severity: "info",
        tier: 3,
        summary: `Anonymous and authenticated responses to ${anon.req.url} are ${(diff.similarity * 100).toFixed(0)}% similar. Expected for public content; only review if this endpoint should be private.`,
        detail: `similarity: ${(diff.similarity * 100).toFixed(0)}%\nanonymous: ${describeResponse(anon.res)}\nauthenticated: ${describeResponse(authed.res)}`,
        expected: "Matching public content is normal.",
        observed: "Both responses returned substantially the same content.",
        impact: "None demonstrated.",
        req: anon.req,
        res: anon.res,
        baseline: authed.res,
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

  const classes = classificationsOf(ctx);
  if (isAuthFlow(classes)) return [];

  const diff = diffResponses(a.res, b.res);

  if (isDenied(a.res.status) && isSuccess(b.res.status)) {
    return [
      observation(ctx, "b-broader", {
        title: "Identity B reaches a resource denied to A",
        state: "Needs Verification",
        confidence: "medium",
        severity: "medium",
        tier: 2,
        summary: `Identity A was denied (${a.res.status}) while identity B succeeded (${b.res.status}) for ${b.req.url}. Confirm whether B legitimately has broader access (role, ownership, or share).`,
        detail: `identity A: ${describeResponse(a.res)}\nidentity B: ${describeResponse(b.res)}`,
        expected: "Access decisions should be consistent with each identity's permissions.",
        observed: `A received ${a.res.status}; B received ${b.res.status}.`,
        impact: "A privilege boundary may be inconsistent, but B may legitimately have broader rights.",
        req: b.req,
        res: b.res,
        baseline: a.res,
        identityId: b.req.identityId,
      }),
    ];
  }

  if (isSuccess(a.res.status) && isSuccess(b.res.status) && diff.structured && diff.similarity > 0.98) {
    return [
      observation(ctx, "same-content", {
        title: "Two identities receive identical structured content",
        state: "Needs Verification",
        confidence: "medium",
        severity: "medium",
        tier: 2,
        summary: `Identity A and identity B both received ${a.res.status} for ${a.req.url} with ${(diff.similarity * 100).toFixed(0)}% identical structured bodies. If this record is owned by A, B may be able to reach it.`,
        detail: `identity A: ${describeResponse(a.res)}\nidentity B: ${describeResponse(b.res)}\nsimilarity: ${(diff.similarity * 100).toFixed(0)}%`,
        expected: "Each identity should only see the records it is authorised to read.",
        observed: "Both identities received materially identical structured records.",
        impact:
          "If the record is private, this is a horizontal authorization gap. Identical public records are expected.",
        req: b.req,
        res: b.res,
        baseline: a.res,
        identityId: b.req.identityId,
        guidance:
          "Confirm which account owns the object. Only identical private records imply a boundary gap.",
        nextTest: "Confirm object ownership in the application, then repeat the cross-identity read.",
      }),
    ];
  }

  if (isDenied(b.res.status) && isSuccess(a.res.status)) {
    return [
      observation(ctx, "b-denied", {
        title: "Identity B was refused the resource",
        state: "Not Reproducible",
        confidence: "medium",
        severity: "info",
        tier: 3,
        summary: `Identity B received ${b.res.status} while identity A succeeded, which is consistent with object-level authorization.`,
        detail: `identity A: ${describeResponse(a.res)}\nidentity B: ${describeResponse(b.res)}`,
        expected: "Non-owning identities are refused.",
        observed: `B received ${b.res.status}.`,
        req: b.req,
        res: b.res,
        baseline: a.res,
      }),
    ];
  }

  return [];
};

/* ------------------------------------------------------------------ */
/* BOLA / IDOR: does identity B receive identity A's data?             */
/* ------------------------------------------------------------------ */

const authzBola: Analyzer = (ctx) => {
  const classes = classificationsOf(ctx);
  if (!isResourceAccess(classes)) return [];

  const a = pair(ctx, 0);
  const b = pair(ctx, 1);
  const anon = pair(ctx, 2);
  if (!a || !b || !a.res.ok || !b.res.ok) return [];

  const markersA = (ctx.testCase.metadata?.markersA as string[] | undefined) ?? [];
  const leaked = markersPresent(b.res.body, markersA);
  if (leaked.length === 0) return [];

  if (!isSuccess(b.res.status) || !hasSubstantiveData(b.res)) return [];

  const anonLeaksMarker = anon ? markersPresent(anon.res.body, markersA).length > 0 : false;
  const anonProtected = anon
    ? isDenied(anon.res.status) || !hasSubstantiveData(anon.res) || !anonLeaksMarker
    : true;

  if (!anonProtected) {
    return [
      observation(ctx, "bola-public", {
        title: "Identity data appears in a publicly reachable response",
        state: "Needs Verification",
        confidence: "low",
        severity: "low",
        tier: 3,
        summary: `Identity A's marker (${leaked.join(", ")}) appeared in identity B's response, but the same data was reachable anonymously. This is more likely intentional public data than an authorization gap.`,
        detail: `markers: ${leaked.join(", ")}\nanonymous reachable: yes`,
        expected: "Private records should not be reachable anonymously.",
        observed: "The data is public.",
        impact: "None demonstrated.",
        req: b.req,
        res: b.res,
        baseline: a.res,
        identityId: b.req.identityId,
      }),
    ];
  }

  const bShape = jsonShape(b.res.body);
  return [
    observation(ctx, "bola", {
      title: "Potential broken object-level authorization",
      state: "Potential Issue",
      confidence: "high",
      severity: "high",
      tier: 1,
      summary: `Identity B's request for ${b.req.url} returned identity A's data (${leaked.join(", ")}), while anonymous access to the same resource was refused. This is the observable shape of a horizontal authorization gap (IDOR/BOLA).`,
      detail: `markers of A found in B's response: ${leaked.join(", ")}\nsensitive keys in B's response: ${bShape.sensitiveKeys.slice(0, 8).join(", ") || "(none)"}\nA: ${describeResponse(a.res)}\nB: ${describeResponse(b.res)}${anon ? `\nanonymous: ${describeResponse(anon.res)}` : ""}`,
      expected: `Identity B should be refused (401/403) for a resource owned by identity A.`,
      observed: `Identity B received ${b.res.status} containing identity A's data.`,
      impact:
        "Horizontal privilege escalation: one user can read another user's protected records through object-reference manipulation.",
      reasoning:
        "Identity markers owned by A appeared in B's response while anonymous access was refused, isolating the exposure to an authenticated cross-account read.",
      req: b.req,
      res: b.res,
      baseline: a.res,
      identityId: b.req.identityId,
      guidance:
        "Reproduce with a stable resource identifier and confirm the record belongs to A.",
      nextTest:
        "Repeat the cross-identity request; confirm the returned object's owner matches identity A.",
      remediation:
        "Enforce object-level authorization server-side on every record access, keyed to the authenticated subject.",
    }),
  ];
};

/* ------------------------------------------------------------------ */
/* Vertical: can a lower-privileged identity reach admin functionality?*/
/* ------------------------------------------------------------------ */

const authzVertical: Analyzer = (ctx) => {
  const classes = classificationsOf(ctx);
  if (!classes?.some((c) => c === "ADMIN")) return [];

  const privileged = pair(ctx, 0);
  const lower = pair(ctx, 1);
  if (!privileged || !lower) return [];
  if (!privileged.res.ok || !lower.res.ok) return [];

  const privilegedIdentity = ctx.identities.find((i) => i.id === privileged.req.identityId);
  const lowerIdentity = ctx.identities.find((i) => i.id === lower.req.identityId);
  if (!isPrivileged(privilegedIdentity) || isPrivileged(lowerIdentity)) return [];

  const markersA = identityMarkers(privilegedIdentity);
  const leaked = markersPresent(lower.res.body, markersA);

  if (isDenied(lower.res.status)) {
    return [
      observation(ctx, "vertical-denied", {
        title: "Administrative endpoint refused a lower-privileged identity",
        state: "Not Reproducible",
        confidence: "medium",
        severity: "info",
        tier: 3,
        summary: `The lower-privileged identity received ${lower.res.status} for the administrative endpoint while the privileged identity succeeded.`,
        detail: `privileged: ${describeResponse(privileged.res)}\nlower: ${describeResponse(lower.res)}`,
        expected: "Administrative functionality is refused to non-privileged identities.",
        observed: `Second identity received ${lower.res.status}.`,
        req: lower.req,
        res: lower.res,
        baseline: privileged.res,
        identityId: lower.req.identityId,
      }),
    ];
  }

  if (!isSuccess(lower.res.status) || !hasSubstantiveData(lower.res)) return [];

  const strong = leaked.length > 0;
  return [
    observation(ctx, "vertical", {
      title: "Non-privileged identity reached administrative functionality",
      state: strong ? "Potential Issue" : "Needs Verification",
      confidence: strong ? "high" : "medium",
      severity: strong ? "high" : "medium",
      tier: 1,
      summary: `A non-privileged identity received ${lower.res.status} from the administrative endpoint ${lower.req.url}${strong ? ` including privileged data (${leaked.join(", ")})` : ""}.`,
      detail: `privileged: ${describeResponse(privileged.res)}\nlower: ${describeResponse(lower.res)}\nprivileged markers in lower response: ${leaked.join(", ") || "(none)"}`,
      expected: "Administrative functionality should require an elevated role.",
      observed: `Lower-privileged identity received substantive administrative content.`,
      impact:
        "Vertical privilege escalation: a normal user can invoke functionality reserved for administrators.",
      reasoning: strong
        ? "The lower-privileged response contained data attributable to the privileged identity."
        : "The lower-privileged identity reached an administrative endpoint with substantive content; role enforcement is unconfirmed.",
      req: lower.req,
      res: lower.res,
      baseline: privileged.res,
      identityId: lower.req.identityId,
      guidance:
        "Confirm the endpoint is genuinely administrative and that no role check is missing.",
      nextTest:
        "Attempt a state-changing administrative action with the lower-privileged identity (only where safe and authorised).",
      remediation: "Enforce function-level (role) authorization server-side.",
    }),
  ];
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
          severity: "high",
          tier: 2,
          summary: `Sending ${meta.value} to "${ctx.testCase.title}" returned the evaluated result ${meta.evaluated}.`,
          detail: `probe intent: ${meta.intent}\nbaseline status: ${base.res.status}, test status: ${res.status}`,
          expected: "User input is treated as data, not evaluated as an expression.",
          observed: `The probe ${meta.value} produced the evaluated output ${meta.evaluated}.`,
          impact:
            "Server-side evaluation of user input can lead to code/template injection depending on the engine.",
          req,
          res,
          baseline: base.res,
          guidance: "Confirm the evaluation happens server-side and is not echoed from a client template.",
          nextTest: "Vary the expression (e.g. a second arithmetic probe) and confirm the result changes accordingly.",
          remediation: "Never evaluate user input; use safe templating and strict allowlists.",
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
          severity: "medium",
          tier: 2,
          summary: `A controlled "${meta.intent}" probe changed the status from ${base.res.status} to ${res.status}.`,
          detail: `value: ${meta.value.slice(0, 80)}\nbaseline: ${describeResponse(base.res)}\ntest: ${describeResponse(res)}`,
          expected: "Malformed input is rejected cleanly (4xx) without a server fault.",
          observed: `The probe produced ${res.status}.`,
          impact:
            "Unhandled input reaching a fault path can expose error internals or indicate missing validation.",
          reasoning: "A single controlled input changed a healthy endpoint into a server error.",
          req,
          res,
          baseline: base.res,
          guidance: "Confirm the input is validated and that errors do not leak internals.",
          nextTest: "Reproduce with a minimally different value and inspect the error body for internals.",
          remediation: "Validate and normalise input server-side; return 4xx for rejected input.",
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
          severity: "low",
          tier: 3,
          summary: `Response contained the error signature "${signature}" for the "${meta.intent}" probe.`,
          detail: `value: ${meta.value.slice(0, 80)}\nbaseline signature: ${baselineError ?? "(none)"}`,
          expected: "Errors are handled without exposing internal diagnostics.",
          observed: `Diagnostic signature "${signature}" appeared in the response.`,
          impact: "Information disclosure only if the signature reveals internals of security value.",
          req,
          res,
          baseline: base.res,
          guidance: "Inspect the error body; a generic error page is not a finding.",
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
  "authz-bola": authzBola,
  "authz-vertical": authzVertical,
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
