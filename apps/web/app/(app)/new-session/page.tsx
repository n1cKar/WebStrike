import type { Metadata } from "next";
import { NewSessionForm } from "@/components/session/new-session-form";

export const metadata: Metadata = { title: "New testing session" };

export default function NewSessionPage() {
  return (
    <div className="mx-auto max-w-3xl space-y-4 p-4 sm:p-6">
      <div>
        <h1 className="text-lg font-semibold tracking-tight">
          New testing session
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Declare the authorised target and scope. Every server-side request is
          validated against this scope and the SSRF allowlist.
        </p>
      </div>
      <NewSessionForm />
    </div>
  );
}