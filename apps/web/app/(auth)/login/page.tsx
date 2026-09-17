import type { Metadata } from "next";
import { AuthForm } from "@/components/auth/auth-form";

export const metadata: Metadata = { title: "Sign in" };

export default function LoginPage() {
  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-base font-semibold">Sign in</h1>
        <p className="text-xs text-muted-foreground">
          Continue to your testing workspace.
        </p>
      </div>
      <AuthForm mode="login" />
    </div>
  );
}