import type { TestingScope } from "@webstrike/types";
import type { Confidence, ResultState, TestObservation } from "../types";
import { extractForms } from "../surface";
import type { BrowserSnapshot } from "./types";

const SECRET_KEY_PATTERN = /(pass(word|wd)?|secret|token|jwt|api[_-]?key|apikey|auth|session|credential)/i;
const JWT_PATTERN = /^eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}$/;
const SENSITIVE_CONSOLE_PATTERN = /(token|secret|api[_-]?key|password|authorization)\s*[:=]\s*\S+/i;

type ObservationDraft = Omit<TestObservation, "id">;

export function analyzeSnapshot(
  snapshot: BrowserSnapshot,
  scope: TestingScope,
  nextId: () => string,
): TestObservation[] {
  const drafts: ObservationDraft[] = [];

  collectConsole(snapshot, drafts);
  collectMixedContent(snapshot, drafts);
  collectCookieFlags(snapshot, drafts);
  collectForms(snapshot, scope, drafts);
  collectStorage(snapshot, drafts);
  collectFrameProtection(snapshot, drafts);
  collectSourceMaps(snapshot, drafts);

  return drafts.map((draft) => ({ id: nextId(), ...draft }));
}

function pageEvidence(snapshot: BrowserSnapshot, detail: string, bodyPreview: string) {
  return {
    detail,
    request: { label: "GET document", method: "GET" as const, url: snapshot.url, headers: [] },
    response: {
      status: snapshot.documentStatus || 200,
      statusText: "",
      bodyBytes: snapshot.html.length,
      bodyPreview: bodyPreview.slice(0, 2000),
      headers: snapshot.documentHeaders,
    },
  };
}

function draft(
  category: TestObservation["category"],
  title: string,
  state: ResultState,
  confidence: Confidence,
  summary: string,
  snapshot: BrowserSnapshot,
  detail: string,
  bodyPreview: string,
  guidance?: string,
): ObservationDraft {
  return {
    category,
    title,
    state,
    confidence,
    summary,
    guidance,
    evidence: pageEvidence(snapshot, detail, bodyPreview),
  };
}

function collectConsole(snapshot: BrowserSnapshot, drafts: ObservationDraft[]) {
  const errors = snapshot.console.filter((message) => message.level === "error");
  if (errors.length === 0) return;

  const sensitive = errors.filter((message) => SENSITIVE_CONSOLE_PATTERN.test(message.text));
  const joined = errors.map((message) => message.text).join("\n");

  if (sensitive.length > 0) {
    drafts.push(
      draft(
        "browser",
        "Client-side errors reference credentials",
        "Needs Verification",
        "medium",
        `${sensitive.length} console error(s) mention token/secret/key-like values. Confirm nothing sensitive is logged to the browser console.`,
        snapshot,
        "console error output",
        joined,
        "Reproduce with a clean console, then remove or redact the logging.",
      ),
    );
    return;
  }

  drafts.push(
    draft(
      "browser",
      "Client-side errors observed",
      "Observation",
      "low",
      `${errors.length} console error(s) were logged while the page loaded.`,
      snapshot,
      "console error output",
      joined,
    ),
  );
}

function collectMixedContent(snapshot: BrowserSnapshot, drafts: ObservationDraft[]) {
  if (!snapshot.url.startsWith("https:")) return;
  const insecure = snapshot.requests.filter((request) => request.url.startsWith("http://"));
  if (insecure.length === 0) return;

  drafts.push(
    draft(
      "security-headers",
      "Mixed content requested over http",
      "Potential Issue",
      "medium",
      `${insecure.length} resource(s) were requested over plain http from an https page.`,
      snapshot,
      "insecure subresource requests",
      insecure.map((request) => `${request.method} ${request.url}`).join("\n"),
      "Serve all subresources over https to avoid injection and downgrade exposure.",
    ),
  );
}

function cookieApplies(domain: string, hostname: string): boolean {
  const normalized = domain.replace(/^\./, "").toLowerCase();
  const host = hostname.toLowerCase();
  return host === normalized || host.endsWith(`.${normalized}`);
}

function collectCookieFlags(snapshot: BrowserSnapshot, drafts: ObservationDraft[]) {
  let hostname = "";
  try {
    hostname = new URL(snapshot.url).hostname;
  } catch {
    return;
  }

  const relevant = snapshot.cookies.filter((cookie) => cookieApplies(cookie.domain, hostname));
  const readable = relevant.filter(
    (cookie) => !cookie.httpOnly && SECRET_KEY_PATTERN.test(cookie.name),
  );
  const noneInsecure = relevant.filter(
    (cookie) => cookie.sameSite === "None" && !cookie.secure,
  );
  const missingSameSite = relevant.filter((cookie) => !cookie.sameSite);

  if (readable.length > 0) {
    drafts.push(
      draft(
        "authentication",
        "Session-like cookie readable from JavaScript",
        "Potential Issue",
        "medium",
        `${readable.length} cookie(s) with session-like names are missing HttpOnly.`,
        snapshot,
        "cookie flags",
        readable.map((cookie) => `${cookie.name} (HttpOnly=false, SameSite=${cookie.sameSite ?? "unset"})`).join("\n"),
        "Set HttpOnly (and Secure) on session cookies so scripts cannot read them.",
      ),
    );
  }

  if (noneInsecure.length > 0) {
    drafts.push(
      draft(
        "authentication",
        "SameSite=None cookie without Secure",
        "Potential Issue",
        "medium",
        `${noneInsecure.length} cookie(s) use SameSite=None without the Secure attribute.`,
        snapshot,
        "cookie flags",
        noneInsecure.map((cookie) => cookie.name).join("\n"),
        "Add Secure to SameSite=None cookies or use SameSite=Lax/Strict where possible.",
      ),
    );
  }

  if (missingSameSite.length > 0 && missingSameSite.length < relevant.length + 1) {
    drafts.push(
      draft(
        "authentication",
        "Cookies without an explicit SameSite policy",
        "Observation",
        "low",
        `${missingSameSite.length} cookie(s) do not declare SameSite.`,
        snapshot,
        "cookie flags",
        missingSameSite.map((cookie) => `${cookie.name} (domain=${cookie.domain})`).join("\n"),
      ),
    );
  }
}

function collectForms(snapshot: BrowserSnapshot, scope: TestingScope, drafts: ObservationDraft[]) {
  let forms: ReturnType<typeof extractForms>;
  try {
    forms = extractForms(snapshot.html, snapshot.url);
  } catch {
    return;
  }
  if (forms.length === 0) return;

  let pageOrigin = "";
  try {
    pageOrigin = new URL(snapshot.url).origin;
  } catch {
    pageOrigin = "";
  }

  const crossOrigin = forms.filter((form) => {
    try {
      return new URL(form.action).origin !== pageOrigin;
    } catch {
      return false;
    }
  });
  const noToken = crossOrigin.filter((form) => !form.hasCsrfToken);

  if (noToken.length > 0) {
    drafts.push(
      draft(
        "csrf",
        "Cross-origin form without an anti-CSRF token",
        "Needs Verification",
        "low",
        `${noToken.length} form(s) post to a different origin and carry no recognised anti-CSRF token.`,
        snapshot,
        "cross-origin forms",
        noToken.map((form) => `${form.method} ${form.action}`).join("\n"),
        `Confirm these actions are intentional and protected. Authorised origin: ${scope.allowedDomains.join(", ")}.`,
      ),
    );
  }
}

function collectStorage(snapshot: BrowserSnapshot, drafts: ObservationDraft[]) {
  const persistent = Object.entries(snapshot.localStorage).filter(
    ([key, value]) => SECRET_KEY_PATTERN.test(key) || JWT_PATTERN.test(value),
  );
  const transient = Object.entries(snapshot.sessionStorage).filter(
    ([key, value]) => SECRET_KEY_PATTERN.test(key) || JWT_PATTERN.test(value),
  );

  if (persistent.length > 0) {
    drafts.push(
      draft(
        "browser",
        "Credential-like data in localStorage",
        "Potential Issue",
        "medium",
        `${persistent.length} localStorage key(s) look secret or token-like and persist across sessions.`,
        snapshot,
        "localStorage keys",
        persistent.map(([key, value]) => `${key} = ${value.slice(0, 40)}`).join("\n"),
        "Prefer HttpOnly cookies for session material; localStorage is readable by any script.",
      ),
    );
  }

  if (transient.length > 0) {
    drafts.push(
      draft(
        "browser",
        "Credential-like data in sessionStorage",
        "Needs Verification",
        "low",
        `${transient.length} sessionStorage key(s) look token-like.`,
        snapshot,
        "sessionStorage keys",
        transient.map(([key, value]) => `${key} = ${value.slice(0, 40)}`).join("\n"),
      ),
    );
  }
}

function collectFrameProtection(snapshot: BrowserSnapshot, drafts: ObservationDraft[]) {
  const headers = snapshot.documentHeaders;
  const xfo = headers["x-frame-options"];
  const csp = headers["content-security-policy"];
  if (xfo || (csp && csp.toLowerCase().includes("frame-ancestors"))) return;

  drafts.push(
    draft(
      "security-headers",
      "No frame-embedding protection observed",
      "Observation",
      "low",
      "Neither X-Frame-Options nor a CSP frame-ancestors directive was present on the document.",
      snapshot,
      "document response headers",
      "X-Frame-Options: (absent)\nContent-Security-Policy frame-ancestors: (absent)",
    ),
  );
}

function collectSourceMaps(snapshot: BrowserSnapshot, drafts: ObservationDraft[]) {
  const maps = snapshot.requests.filter((request) => {
    const path = request.url.split(/[?#]/)[0] ?? "";
    return path.endsWith(".map") && request.status === 200;
  });
  if (maps.length === 0) return;

  drafts.push(
    draft(
      "browser",
      "Source maps served to the browser",
      "Observation",
      "low",
      `${maps.length} JavaScript source map(s) were publicly retrievable.`,
      snapshot,
      "source map requests",
      maps.map((request) => request.url).join("\n"),
    ),
  );
}
