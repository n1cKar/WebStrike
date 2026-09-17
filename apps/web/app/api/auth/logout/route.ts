import { cookies } from "next/headers";
import { checkCsrf } from "@/lib/api/csrf";
import { jsonError, jsonOk } from "@/lib/api/responses";
import { AUTH_COOKIE } from "@/lib/auth/session";
import { getCurrentUser } from "@/lib/auth/current-user";
import { TESTING_SESSION_COOKIE } from "@/lib/session/testing-session";
import { audit } from "@/lib/logging/audit";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const csrf = checkCsrf(request);
  if (!csrf.ok) return jsonError(403, "CSRF", csrf.reason ?? "request refused");

  const user = await getCurrentUser();
  const store = await cookies();
  store.delete(AUTH_COOKIE);
  store.delete(TESTING_SESSION_COOKIE);

  if (user) audit({ event: "auth.logout", actor: user.email, outcome: "allow" });
  return jsonOk({ ok: true });
}