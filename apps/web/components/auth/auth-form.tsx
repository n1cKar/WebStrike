"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { AlertTriangle, Loader2 } from "lucide-react";
import { loginSchema, registerSchema } from "@webstrike/validation";
import { apiFetch, ApiClientError } from "@/lib/api/client";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";

interface AuthFormProps {
  mode: "login" | "register";
}

export function AuthForm({ mode }: AuthFormProps) {
  const router = useRouter();
  const isRegister = mode === "register";
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [consent, setConsent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [pending, setPending] = useState(false);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setFieldErrors({});

    const schema = isRegister ? registerSchema : loginSchema;
    const parsed = schema.safeParse(
      isRegister
        ? { email, password, consent: consent ? true : false }
        : { email, password },
    );

    if (!parsed.success) {
      const next: Record<string, string> = {};
      for (const issue of parsed.error.issues) {
        const key = issue.path.join(".") || "form";
        next[key] ??= issue.message;
      }
      setFieldErrors(next);
      return;
    }

    setPending(true);
    try {
      await apiFetch(isRegister ? "/api/auth/register" : "/api/auth/login", {
        method: "POST",
        body: JSON.stringify(parsed.data),
      });
      router.push("/dashboard");
      router.refresh();
    } catch (err) {
      if (err instanceof ApiClientError) setError(err.message);
      else setError("unexpected error — please retry");
      setPending(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <div className="space-y-1.5">
        <Label htmlFor="email">Email</Label>
        <Input
          id="email"
          type="email"
          autoComplete="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="operator@example.com"
          required
        />
        {fieldErrors.email && (
          <p className="text-xs text-danger">{fieldErrors.email}</p>
        )}
      </div>

      <div className="space-y-1.5">
        <Label htmlFor="password">Password</Label>
        <Input
          id="password"
          type="password"
          autoComplete={isRegister ? "new-password" : "current-password"}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder={isRegister ? "at least 8 characters" : "••••••••"}
          required
        />
        {fieldErrors.password && (
          <p className="text-xs text-danger">{fieldErrors.password}</p>
        )}
      </div>

      {isRegister && (
        <label className="flex items-start gap-2 rounded-md border border-border bg-panel p-3 text-xs text-muted-foreground">
          <input
            type="checkbox"
            checked={consent}
            onChange={(e) => setConsent(e.target.checked)}
            className="mt-0.5 size-3.5 accent-[var(--primary)]"
          />
          <span>
            I will only use WebStrike against systems I own or have explicit
            written authorisation to test.
          </span>
        </label>
      )}
      {fieldErrors.consent && (
        <p className="text-xs text-danger">{fieldErrors.consent}</p>
      )}

      {error && (
        <div className="flex items-center gap-2 rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-xs text-danger">
          <AlertTriangle className="size-3.5" />
          {error}
        </div>
      )}

      <Button type="submit" className="w-full" disabled={pending}>
        {pending && <Loader2 className="size-4 animate-spin" />}
        {isRegister ? "Create account" : "Sign in"}
      </Button>

      <p className="text-center text-xs text-muted-foreground">
        {isRegister ? "Already have an account? " : "No account yet? "}
        <Link
          href={isRegister ? "/login" : "/register"}
          className="text-primary hover:underline"
        >
          {isRegister ? "Sign in" : "Create one"}
        </Link>
      </p>
    </form>
  );
}