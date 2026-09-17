import type { Metadata } from "next";
import { cookies } from "next/headers";
import { notFound } from "next/navigation";
import {
  TESTING_SESSION_COOKIE,
  readTestingSessionToken,
} from "@/lib/session/testing-session";
import { SessionDetail } from "@/components/session/session-detail";

export const metadata: Metadata = { title: "Testing session" };

export default async function SessionPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const store = await cookies();
  const token = store.get(TESTING_SESSION_COOKIE)?.value;
  const session = token ? await readTestingSessionToken(token) : null;

  if (!session || session.id !== id) notFound();

  return <SessionDetail session={session} />;
}