import type { RequestMethod, TestingScope } from "@webstrike/types";
import { validateScopedUrl } from "@webstrike/security";
import type { DiscoveredEndpoint, DiscoveredForm, DiscoveredParam, Surface } from "./types";

const METHODS = new Set<RequestMethod>([
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
  "OPTIONS",
]);

const CSRF_FIELD = /csrf|xsrf|authenticity|anti[-_]?forgery|__requestverification|token/i;
const FILE_INPUT_TYPES = new Set(["file"]);

function decodeEntities(value: string): string {
  return value
    .replace(/&amp;/gi, "&")
    .replace(/&#38;/g, "&")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">");
}

function parseAttributes(tag: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  const re = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s"'>]+))|([a-zA-Z_:][-a-zA-Z0-9_:.]*)/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(tag)) !== null) {
    const name = (match[1] ?? match[6] ?? "").toLowerCase();
    if (!name) continue;
    const value = match[3] ?? match[4] ?? match[5] ?? "";
    attrs[name] = decodeEntities(value);
  }
  return attrs;
}

export function extractLinks(html: string, baseUrl: string): string[] {
  const links: string[] = [];
  const re = /<a\b[^>]*>/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(html)) !== null) {
    const attrs = parseAttributes(match[0]);
    const href = attrs.href;
    if (!href) continue;
    const resolved = resolveUrl(href, baseUrl);
    if (resolved) links.push(resolved);
  }
  return links;
}

function resolveUrl(href: string, baseUrl: string): string | null {
  const trimmed = href.trim();
  if (!trimmed || trimmed.startsWith("#") || /^(javascript|mailto|tel|data):/i.test(trimmed)) {
    return null;
  }
  try {
    const url = new URL(trimmed, baseUrl);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    url.hash = "";
    return url.toString();
  } catch {
    return null;
  }
}

export function extractForms(html: string, baseUrl: string): DiscoveredForm[] {
  const forms: DiscoveredForm[] = [];
  const formRe = /<form\b[^>]*>([\s\S]*?)<\/form>/gi;
  let match: RegExpExecArray | null;
  while ((match = formRe.exec(html)) !== null) {
    const openTag = match[0].slice(0, match[0].indexOf(">") + 1);
    const attrs = parseAttributes(openTag);
    const action = attrs.action ? resolveUrl(attrs.action, baseUrl) ?? baseUrl : baseUrl;
    const rawMethod = (attrs.method ?? "get").toUpperCase();
    const method: RequestMethod = METHODS.has(rawMethod as RequestMethod)
      ? (rawMethod as RequestMethod)
      : "GET";

    const fields = extractFormFields(match[1] ?? "");
    const fileInput = fields.some((f) => FILE_INPUT_TYPES.has(f.type));
    const csrfField = fields.find(
      (f) => CSRF_FIELD.test(f.name) && (f.type === "hidden" || f.type === "text"),
    );

    forms.push({
      action,
      method,
      fields,
      hasFileInput: fileInput,
      hasCsrfToken: Boolean(csrfField),
      csrfFieldName: csrfField?.name,
    });
  }
  return forms;
}

function extractFormFields(inner: string): DiscoveredForm["fields"] {
  const fields: DiscoveredForm["fields"] = [];
  const re = /<(input|textarea|select)\b[^>]*>/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(inner)) !== null) {
    const attrs = parseAttributes(match[0]);
    const name = attrs.name;
    if (!name) continue;
    const type = (attrs.type ?? match[1] ?? "text").toLowerCase();
    fields.push({
      name,
      type,
      required: "required" in attrs,
      value: attrs.value,
    });
  }
  return fields;
}

function queryParams(url: string): DiscoveredParam[] {
  try {
    const parsed = new URL(url);
    const params: DiscoveredParam[] = [];
    parsed.searchParams.forEach((value, name) => {
      params.push({ name, location: "query", example: value });
    });
    return params;
  } catch {
    return [];
  }
}

function inScope(url: string, scope: TestingScope): boolean {
  return validateScopedUrl(url, scope).ok;
}

export interface DiscoveryPage {
  url: string;
  html: string;
}

export function buildSurface(input: {
  targetUrl: string;
  scope: TestingScope;
  pages: DiscoveryPage[];
  seedPaths?: string[];
  maxEndpoints?: number;
  maxForms?: number;
}): Surface {
  const { targetUrl, scope, pages } = input;
  const maxEndpoints = input.maxEndpoints ?? 30;
  const maxForms = input.maxForms ?? 15;

  let origin = "";
  try {
    origin = new URL(targetUrl).origin;
  } catch {
    origin = targetUrl;
  }

  const notes: string[] = [];
  const endpoints: DiscoveredEndpoint[] = [];
  const forms: DiscoveredForm[] = [];
  const seenEndpoint = new Set<string>();
  const seenForm = new Set<string>();

  const addEndpoint = (endpoint: DiscoveredEndpoint) => {
    const key = `${endpoint.method} ${endpoint.url}`;
    if (seenEndpoint.has(key)) return;
    if (endpoints.length >= maxEndpoints) return;
    seenEndpoint.add(key);
    endpoints.push(endpoint);
  };

  addEndpoint({
    url: targetUrl,
    method: "GET",
    params: queryParams(targetUrl),
    source: "start-url",
  });

  for (const seed of input.seedPaths ?? []) {
    const resolved = resolveUrl(seed, origin);
    if (resolved && inScope(resolved, scope)) {
      addEndpoint({ url: resolved, method: "GET", params: queryParams(resolved), source: "seed" });
    }
  }

  for (const page of pages) {
    for (const link of extractLinks(page.html, page.url)) {
      if (inScope(link, scope)) {
        addEndpoint({ url: link, method: "GET", params: queryParams(link), source: "link" });
      }
    }
    for (const form of extractForms(page.html, page.url)) {
      if (!inScope(form.action, scope)) continue;
      const key = `${form.method} ${form.action} ${form.fields.map((f) => f.name).join(",")}`;
      if (seenForm.has(key)) continue;
      seenForm.add(key);
      if (forms.length < maxForms) forms.push(form);

      addEndpoint({
        url: form.action,
        method: form.method,
        source: "form",
        form,
        params: form.fields.map((f) => ({
          name: f.name,
          location: "form" as const,
          example: f.value,
        })),
      });
    }
  }

  if (forms.some((f) => f.hasFileInput)) {
    notes.push("one or more forms accept file uploads");
  }
  if (endpoints.some((e) => e.method !== "GET")) {
    notes.push("non-GET endpoints discovered; state-changing tests stay off unless enabled");
  }

  return { baseUrl: targetUrl, origin, endpoints, forms, notes };
}
