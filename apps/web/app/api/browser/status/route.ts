import { jsonError, jsonOk } from "@/lib/api/responses";
import { getActor } from "@/lib/auth/actor";
import { browserConfigured } from "@/lib/browser/config";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const actor = await getActor();
  if (!actor) return jsonError(401, "UNAUTHENTICATED", "sign in required");
  return jsonOk({ configured: browserConfigured() });
}
