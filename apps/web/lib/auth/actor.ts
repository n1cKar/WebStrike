import { getCurrentUser } from "./current-user";

/**
 * An actor is whoever is driving the app. With REQUIRE_AUTH unset, guests are
 * allowed and receive a shared guest identity; testing data stays ephemeral and
 * every request is still scope-validated, SSRF-filtered and rate-limited.
 * Set REQUIRE_AUTH=true to require a signed-in account again.
 */
export interface Actor {
  id: string;
  email: string;
  guest: boolean;
}

export const GUEST_ACTOR_ID = "guest";

export function authRequired(): boolean {
  return process.env.REQUIRE_AUTH === "true";
}

export async function getActor(): Promise<Actor | null> {
  const user = await getCurrentUser();
  if (user) return { id: user.sub, email: user.email, guest: false };
  if (authRequired()) return null;
  return { id: GUEST_ACTOR_ID, email: "Guest session", guest: true };
}
