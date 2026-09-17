import { redirect } from "next/navigation";
import { ShieldCheck } from "lucide-react";
import { getCurrentUser } from "@/lib/auth/current-user";

export default async function AuthLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const user = await getCurrentUser();
  if (user) redirect("/dashboard");

  return (
    <div className="grid-backdrop flex min-h-screen items-center justify-center px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center justify-center gap-2">
          <ShieldCheck className="size-6 text-primary" />
          <div className="leading-tight">
            <p className="text-lg font-semibold tracking-tight">WebStrike</p>
            <p className="text-[10px] uppercase tracking-widest text-muted-foreground">
              authorised security testing
            </p>
          </div>
        </div>
        <div className="scanline rounded-xl border border-border bg-panel/90 p-6 shadow-2xl shadow-black/40">
          {children}
        </div>
        <p className="mt-4 text-center text-[11px] leading-relaxed text-muted-foreground">
          Testing data is ephemeral. Requests, responses and evidence are never
          persisted.
        </p>
      </div>
    </div>
  );
}