import type {
  CookieObservation,
  HeaderObservation,
  ScopedHttpResult,
} from "@webstrike/types";

const KNOWN_HEADERS: Record<
  string,
  { significance: HeaderObservation["significance"]; why: string }
> = {
  "content-security-policy": {
    significance: "good",
    why: "helps contain XSS and data injection",
  },
  "strict-transport-security": {
    significance: "good",
    why: "forces HTTPS and defeats protocol downgrade",
  },
  "x-content-type-options": {
    significance: "good",
    why: "prevents MIME sniffing",
  },
  "referrer-policy": {
    significance: "good",
    why: "limits referrer leakage to third parties",
  },
  "permissions-policy": {
    significance: "good",
    why: "restricts browser feature access",
  },
  "cache-control": {
    significance: "info",
    why: "controls response caching; sensitive data should be no-store",
  },
  "access-control-allow-origin": {
    significance: "warning",
    why: "CORS reflection deserves review against the configured origin",
  },
  "x-frame-options": {
    significance: "good",
    why: "prevents clickjacking",
  },
};

const SIGNIFICANCE_LABEL: Record<HeaderObservation["significance"], string> = {
  info: "info",
  warning: "review",
  good: "present",
};

export function analyzeHeaders(result: ScopedHttpResult): HeaderObservation[] {
  const out: HeaderObservation[] = [];
  for (const [name, meta] of Object.entries(KNOWN_HEADERS)) {
    const value = result.headers[name.toLowerCase()] ?? result.headers[name];
    if (value !== undefined) {
      out.push({
        header: name,
        present: true,
        value,
        significance: meta.significance,
        message: `present — ${meta.why}. Evidence: ${value.slice(0, 200)}. Confidence: high (observed in the response).`,
      });
    } else {
      out.push({
        header: name,
        present: false,
        significance: "info",
        message: `not observed in this response. Missing security headers are contextual — absence alone is not a vulnerability. Confidence: low (response-specific).`,
      });
    }
  }

  const acao = result.headers["access-control-allow-origin"];
  if (acao !== undefined) {
    // Mirroring detection (e.g. reflecting the Origin) is an observation.
    out.push({
      header: "access-control-allow-origin",
      present: true,
      value: acao,
      significance: acao === "*" ? "warning" : "info",
      message: `reflects feasible CORS review for the authorised target. Confidence: medium.`,
    });
  }

  return out;
}

export function analyzeCookies(result: ScopedHttpResult): CookieObservation[] {
  return result.cookies.map((c) => {
    const observations: string[] = [];
    if (!c.secure) observations.push("not marked Secure (may transit over HTTP)");
    if (!c.httpOnly) observations.push("not marked HttpOnly (readable by scripts)");
    if (!c.sameSite) observations.push("no SameSite attribute set (browser default applies)");
    if (c.maxAge !== undefined) {
      if (c.maxAge > 365 * 24 * 3600) observations.push("unusually long Max-Age");
      if (c.maxAge <= 0) observations.push("session cookie deletion signal");
    }
    return {
      cookie: c.name,
      secure: c.secure ?? false,
      httpOnly: c.httpOnly ?? false,
      sameSite: c.sameSite ?? null,
      domain: c.domain,
      path: c.path,
      expires: c.expires ? new Date(c.expires).toISOString() : undefined,
      observations,
    };
  });
}

export function summarize(result: ScopedHttpResult): string[] {
  const lines: string[] = [];
  if (result.status >= 500) {
    lines.push(
      "server-error status observed — worth verifying whether errors leak stack traces on out-of-scope input",
    );
  }
  if (result.status === 401 || result.status === 403) {
    lines.push("authentication/authorisation boundary enforced for this resource");
  }
  for (const c of result.cookies) {
    if (!c.secure || !c.httpOnly) {
      lines.push(
        `cookie ${c.name} lacks ${c.secure ? "" : "Secure "}${c.httpOnly ? "" : "HttpOnly"} attributes`,
      );
    }
  }
  return lines;
}

export function significanceLabel(s: HeaderObservation["significance"]): string {
  return SIGNIFICANCE_LABEL[s];
}