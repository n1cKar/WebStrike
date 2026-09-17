import type { Metadata } from "next";
import { AuthForm } from "@/components/auth/auth-form";

export const metadata: Metadata = { title: "Create account" };

export default function RegisterPage() {
  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-base font-semibold">Create account</h1>
        <p className="text-xs text-muted-foreground">
          For authorised penetration testing and security research only.
        </p>
      </div>
      <AuthForm mode="register" />
    </div>
  );
}