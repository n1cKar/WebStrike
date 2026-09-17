import { cookies } from "next/headers";
import { registerSchema } from "@webstrike/validation";
import { checkCsrf } from "@/lib/api/csrf";
import { jsonError, jsonOk, readJson, zodErrorResponse } from "@/lib/api/responses";
import { hashPassword } from "@/lib/auth/password";
import { createAuthToken, AUTH_COOKIE, authCookieOptions } from "@/lib/auth/session";
import { getUserRepository } from "@/lib/auth/user-repository";
import { audit } from "@/lib/logging/audit";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const csrf = checkCsrf(request);
  if (!csrf.ok) return jsonError(403, "CSRF", csrf.reason ?? "request refused");

  const body = await readJson(request);
  const parsed = registerSchema.safeParse(body);
  if (!parsed.success) return zodErrorResponse(parsed.error);

  const repo = getUserRepository();
  const existing = await repo.findByEmail(parsed.data.email);
  if (existing) {
    audit({ event: "auth.register", actor: parsed.data.email, outcome: "deny", reason: "email taken" });
    return jsonError(409, "EMAIL_TAKEN", "an account with that email already exists");
  }

  const passwordHash = await hashPassword(parsed.data.password);

  let user;
  try {
    user = await repo.create(parsed.data.email, passwordHash);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "DUPLICATE") {
      return jsonError(409, "EMAIL_TAKEN", "an account with that email already exists");
    }
    return jsonError(500, "ACCOUNT_CREATE_FAILED", "could not create the account");
  }

  const token = await createAuthToken({ sub: user.id, email: user.email });
  const store = await cookies();
  store.set(AUTH_COOKIE, token, authCookieOptions());

  audit({ event: "auth.register", actor: user.email, outcome: "allow" });
  return jsonOk({ user: { id: user.id, email: user.email } }, 201);
}