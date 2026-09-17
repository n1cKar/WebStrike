import { cookies } from "next/headers";
import { AUTH_COOKIE, verifyAuthToken, type AuthTokenPayload } from "./session";

export type { AuthTokenPayload };

/** Read and verify the signed auth cookie. Returns null when unauthenticated. */
export async function getCurrentUser(): Promise<AuthTokenPayload | null> {
  const store = await cookies();
  const token = store.get(AUTH_COOKIE)?.value;
  if (!token) return null;
  return verifyAuthToken(token);
}