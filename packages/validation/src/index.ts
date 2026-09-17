import { z } from "zod";
import type { RequestMethod } from "@webstrike/types";

export const MAX_REQUEST_BODY = 512 * 1024;

export const SESSION_NAME_MAX = 120;
export const SESSION_DURATION_MIN_H = 1;
export const SESSION_DURATION_MAX_H = 24;
export const IDENTITY_MIN = 3;
export const IDENTITY_MAX = 300;
export const MAX_ALLOWED_DOMAINS = 20;
export const MAX_ALLOWED_PATHS = 20;
export const MAX_BLOCKED_DOMAINS = 20;

export const maxBytesString = (bytes: number) =>
  z
    .string()
    .max(bytes)
    .refine((s) => new TextEncoder().encode(s).byteLength <= bytes, {
      message: `must not exceed ${bytes} bytes`,
    });

export const httpUrlSchema = z
  .string()
  .refine((s) => {
    if (s.length > 8000) return false;
    try {
      const u = new URL(s);
      return u.protocol === "http:" || u.protocol === "https:";
    } catch {
      return false;
    }
  }, "must be an absolute http(s) URL");

export const hostnameLikeSchema = z
  .string()
  .min(1)
  .max(253)
  .refine((s) => !/[\\/?#@\s]/.test(s), "not a valid host pattern");

export const domainPatternSchema = z
  .string()
  .min(2)
  .max(253)
  .refine((s) => {
    const withoutDot = s.endsWith(".") ? s.slice(0, -1) : s;
    const core = withoutDot.startsWith("*.") ? withoutDot.slice(2) : withoutDot;
    if (!core) return false;
    if (/\s/.test(core)) return false;
    if (core.includes("*")) return false;
    return true;
  }, "must be a hostname or *.pattern with no scheme, path or port");

export const pathPrefixSchema = z
  .string()
  .min(1)
  .max(2048)
  .refine((s) => s.startsWith("/"), "path prefixes must start with /")
  .refine((s) => !/\s/.test(s) && !/\?/.test(s) && !/#/.test(s), "no query or fragment allowed");

export const createSessionSchema = z.object({
  name: z.string().min(1).max(SESSION_NAME_MAX),
  targetUrl: httpUrlSchema,
  allowedDomains: z.array(domainPatternSchema).max(MAX_ALLOWED_DOMAINS),
  allowedPaths: z.array(pathPrefixSchema).max(MAX_ALLOWED_PATHS).default(["/"]),
  blockedDomains: z.array(domainPatternSchema).max(MAX_BLOCKED_DOMAINS).default([]),
  testingIdentity: z.string().min(IDENTITY_MIN).max(IDENTITY_MAX),
  authorizationConfirmation: z.literal(true, {
    error: "authorization confirmation is required",
  }),
  durationHours: z
    .number()
    .int()
    .min(SESSION_DURATION_MIN_H)
    .max(SESSION_DURATION_MAX_H)
    .default(8),
});

export type CreateSessionInput = z.infer<typeof createSessionSchema>;

const methods = [
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
  "OPTIONS",
] as const satisfies readonly RequestMethod[];

export const requestMethodSchema = z.enum(methods);

export const requestCookieSchema = z.object({
  name: z.string().trim().min(1).max(1024),
  value: z.string().max(4096).default(""),
});

export const requestSpecSchema = z.object({
  id: z.string().min(4).max(64),
  method: requestMethodSchema,
  url: httpUrlSchema,
  query: z.record(z.string(), z.string().max(2048)).default({}),
  headers: z
    .array(
      z.object({
        name: z
          .string()
          .trim()
          .min(1)
          .max(256)
          .regex(/^[A-Za-z0-9-]+$/, "invalid header name"),
        value: z
          .string()
          .max(8192)
          .refine((v) => !/[\r\n]/.test(v), "header values must be single-line"),
      }),
    )
    .max(48)
    .default([]),
  cookies: z.array(requestCookieSchema).max(32).default([]),
  body: z.union([z.string().max(MAX_REQUEST_BODY), z.null()]).default(null),
  contentType: z.string().max(256).nullable().default(null),
});

export type RequestSpecInput = z.infer<typeof requestSpecSchema>;

export const loginSchema = z.object({
  email: z.string().trim().toLowerCase().email().max(254),
  password: z.string().min(8).max(512),
});

export const registerSchema = z.object({
  email: z.string().trim().toLowerCase().email().max(254),
  password: z.string().min(8).max(512),
  consent: z.literal(true, { error: "you must confirm access to use WebStrike" }),
});

export type LoginInput = z.infer<typeof loginSchema>;
export type RegisterInput = z.infer<typeof registerSchema>;

/* -------------------------------------------------------------------------- */
/* Automated testing                                                          */
/* -------------------------------------------------------------------------- */

export const runProfileSchema = z.enum(["quick", "standard", "deep"]);
export type RunProfile = z.infer<typeof runProfileSchema>;

export const testCategorySchema = z.enum([
  "security-headers",
  "cors",
  "csrf",
  "authentication",
  "authorization",
  "input-validation",
  "business-logic",
  "file-upload",
  "openapi",
]);

const headerRowSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1)
    .max(256)
    .regex(/^[A-Za-z0-9-]+$/, "invalid header name"),
  value: z
    .string()
    .max(8192)
    .refine((v) => !/[\r\n]/.test(v), "header values must be single-line"),
});

export const testingIdentitySchema = z.object({
  id: z.string().trim().min(1).max(40),
  label: z.string().trim().min(1).max(80),
  role: z.string().trim().max(40).optional(),
  privileged: z.boolean().optional(),
  headers: z.array(headerRowSchema).max(24).default([]),
  cookies: z.array(requestCookieSchema).max(24).default([]),
});

export const workflowStepSchema = z.object({
  id: z.string().trim().min(1).max(60),
  label: z.string().trim().min(1).max(120),
  method: requestMethodSchema.default("GET"),
  url: httpUrlSchema,
  headers: z.array(headerRowSchema).max(24).default([]),
  cookies: z.array(requestCookieSchema).max(24).default([]),
  body: z.union([maxBytesString(MAX_REQUEST_BODY), z.null()]).default(null),
  contentType: z.string().max(256).nullable().default(null),
  identityId: z.string().max(40).optional(),
  extract: z
    .object({
      pattern: z.string().min(1).max(500),
      as: z.string().trim().min(1).max(60),
    })
    .optional(),
  expect: z
    .object({
      status: z.number().int().min(100).max(599).optional(),
      statusIn: z.array(z.number().int().min(100).max(599)).min(1).max(20).optional(),
      bodyContains: z.string().max(1000).optional(),
      bodyAbsent: z.string().max(1000).optional(),
    })
    .optional(),
});

export const automatedRunSchema = z.object({
  categories: z.array(testCategorySchema).min(1).max(9),
  profile: runProfileSchema.default("quick"),
  activeTests: z.boolean().default(false),
  identities: z.array(testingIdentitySchema).max(3).default([]),
  workflow: z.array(workflowStepSchema).max(25).optional(),
  openapi: z.unknown().optional(),
  seedPaths: z.array(httpUrlSchema).max(30).default([]),
});

export type TestingIdentityInput = z.infer<typeof testingIdentitySchema>;
export type WorkflowStepInput = z.infer<typeof workflowStepSchema>;
export type AutomatedRunInput = z.infer<typeof automatedRunSchema>;

/* -------------------------------------------------------------------------- */
/* Browser testing (gated behind a configured remote browser endpoint)        */
/* -------------------------------------------------------------------------- */

export const browserRunSchema = z.object({
  maxPages: z.number().int().min(1).max(5).default(1),
  timeoutMs: z.number().int().min(2_000).max(20_000).default(12_000),
  screenshot: z.boolean().default(true),
});

export type BrowserRunRequest = z.infer<typeof browserRunSchema>;