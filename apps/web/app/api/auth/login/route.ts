import { cookies } from "next/headers";
import { loginSchema } from "@webstrike/validation";
import { checkCsrf } from "@/lib/api/csrf";
import { jsonError, jsonOk, readJson, zodErrorResponse } from "@/lib/api/responses";
import { hashPassword, verifyPassword } from "@/lib/auth/password";
import { createAuthToken, AUTH_COOKIE, authCookieOptions } from "@/lib/auth/session";
import { getUserRepository } from "@/lib/auth/user-repository";
import { audit } from "@/lib/logging/audit";

export const runtime = "nodejs";

let dummyHashPromise: Promise<string> | null = null;
function dummyHash(): Promise<string> {
  dummyHashPromise ??= hashPassword("webstrike-dummy-password");
  return dummyHashPromise;
}

export async function POST(request: Request) {
  const csrf = checkCsrf(request);
  if (!csrf.ok) return jsonError(403, "CSRF", csrf.reason ?? "request refused");

  const body = await readJson(request);
  const parsed = loginSchema.safeParse(body);
  if (!parsed.success) return zodErrorResponse(parsed.error);

  const repo = getUserRepository();
  const user = await repo.findByEmail(parsed.data.email);

  // Always perform a hash comparison to keep timing consistent for unknown users.
  const valid = user
    ? await verifyPassword(parsed.data.password, user.passwordHash)
    : await verifyPassword(parsed.data.password, await dummyHash());

  if (!user || !valid) {
    audit({ event: "auth.login", actor: parsed.data.email, outcome: "deny", reason: "invalid credentials" });
    return jsonError(401, "INVALID_CREDENTIALS", "invalid email or password");
  }

  const token = await createAuthToken({ sub: user.id, email: user.email });
  const store = await cookies();
  store.set(AUTH_COOKIE, token, authCookieOptions());

  audit({ event: "auth.login", actor: user.email, outcome: "allow" });
  return jsonOk({ user: { id: user.id, email: user.email } });
}