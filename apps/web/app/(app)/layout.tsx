import { redirect } from "next/navigation";
import { AppShell } from "@/components/shell/app-shell";
import { getActor } from "@/lib/auth/actor";

export default async function AuthenticatedLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const actor = await getActor();
  if (!actor) redirect("/login");

  return (
    <AppShell user={{ email: actor.email, guest: actor.guest }}>{children}</AppShell>
  );
}
