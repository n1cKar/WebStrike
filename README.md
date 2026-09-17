# WebStrike

WebStrike is a Vercel-only web application security testing platform for **authorized** testing. It performs non-destructive, evidence-backed checks against an explicitly scoped target and reports observed behaviour — it never claims to have found a "vulnerability".

> **Authorized use only.** Only test systems you own or have written permission to test. WebStrike enforces a testing scope (allowed domains, allowed paths, blocked domains), blocks server-side request forgery, and rate-limits every identity. You are responsible for staying within your authorization.

## What it does

- **Automated checks** — a bounded, budgeted engine that discovers surface (links, forms, query parameters, OpenAPI documents) and runs conservative checks across security headers, CORS, CSRF, authentication, authorization, input handling, and file uploads.
- **Browser checks** — optional snapshot checks over the Chrome DevTools Protocol: console errors, mixed content, cookie flags, cross-origin forms, storage, framing controls, and source maps.
- **Evidence, not verdicts** — every observation carries the exact request/response it came from, a state (`Observation`, `Informational`, `Needs Verification`, `Potential Issue`, `Verified Security Issue`, `Not Reproducible`), a confidence level and a severity/tier.
- **Ephemeral by design** — test results, request/response evidence and automated findings are held in memory for the current session only. Only account/identity records are persisted.

## Architecture

```
apps/web            Next.js 16 (Turbopack) UI + API routes + session/scope enforcement
packages/types      Shared domain types (scope, HTTP result, request methods)
packages/security   SSRF guard, scope validation, IP classification, cookie analysis
packages/testing    Automated test engine + browser (CDP) checks
packages/validation Zod schemas shared by the web layer
```

The web app is the only component that performs outbound traffic, through a single sanctioned path (`apps/web/lib/http`). The `@webstrike/security` package is split so browser code can import scope helpers without pulling in Node-only modules.

## Getting started

Requirements: Node.js 22+ and npm (workspaces).

```bash
npm install
cp apps/web/.env.example apps/web/.env   # then edit
npm run dev                              # http://localhost:3000
```

### Environment

| Variable | Required | Purpose |
| --- | --- | --- |
| `AUTH_SECRET` | production | 32+ character signing secret for auth and testing-session cookies. Production fails closed without it. |
| `DATABASE_URL` | no | Neon/PostgreSQL connection string. When absent, an in-memory identity store is used. |
| `REQUIRE_AUTH` | no | Set to `true` to require sign-in. Unset/false enables guest mode. |
| `BROWSER_WS_ENDPOINT` | no | Chrome DevTools Protocol WebSocket endpoint. Browser checks return `503` when unset. |
| `BROWSER_API_TOKEN` | no | Token sent to the browser endpoint when configured. |
| `GROQ_API_KEY` | no | Enables the advisory AI analysis layer. The deterministic engine remains authoritative. |
| `GROQ_MODEL` | no | Overrides the AI model (default `openai/gpt-oss-120b`). |

See `apps/web/.env.example` for the full annotated list.

## Commands

```bash
npm run dev         # start the web app
npm run build       # production build
npm run start       # serve the production build
npm run test        # run the vitest suite (security + testing packages)
npm run typecheck   # typecheck every workspace
npm run lint        # lint the web app
npm run db:migrate  # apply identity-store migrations (requires DATABASE_URL)
```

## Accuracy philosophy

WebStrike is deliberately conservative. A missing header, a reflected parameter or two matching responses is **evidence**, not proof. The engine:

- only escalates to `Potential Issue` for strong, low-false-positive signals (for example, an arbitrary origin reflected **with credentials on an authenticated request**);
- downgrades ambiguous signals such as raw reflection or identical public content to `Needs Verification` / `Observation`;
- records the baseline response alongside every probe so a human can confirm the delta;
- is covered by regression tests that assert a well-configured benign site produces **no** `Potential Issue` observations (`packages/testing/test/accuracy.test.ts`).

A `Potential Issue` only becomes a `Verified Security Issue` when the engine independently re-runs the same non-mutating request and reproduces the condition. Duplicate results are collapsed and ordered by real impact (tier 1 = access control, BOLA/IDOR, auth bypass, data exposure; tier 3 = hardening). Credential material is redacted from all evidence before it is displayed or sent to the optional AI layer.

### Optional AI analysis

When `GROQ_API_KEY` is set, serious results receive an advisory `aiNote` (explanation, plausible false-positive explanations, suggested verification). The model is given only redacted evidence, its response is schema-validated, failures are ignored, and it can never change a result's state or severity.

## Deployment

WebStrike targets Vercel. Import the repository as a monorepo and set the project **Root Directory** to `apps/web`, keeping "Include files outside the root directory" enabled so workspace packages resolve. Add the environment variables above in the project settings; `AUTH_SECRET` is mandatory in production. Persist identities with `npm run db:migrate` against your `DATABASE_URL`.

## Legal

WebStrike is provided for lawful, authorized security testing. Do not use it against systems without explicit permission.
