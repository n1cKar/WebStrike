import { jsonError, jsonOk } from "@/lib/api/responses";
import { getCurrentUser } from "@/lib/auth/current-user";
import { browserConfigured } from "@/lib/browser/config";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const user = await getCurrentUser();
  if (!user) return jsonError(401, "UNAUTHENTICATED", "sign in required");
  return jsonOk({ configured: browserConfigured() });
}
