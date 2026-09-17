import type { Metadata } from "next";
import { Database, HardDrive, KeyRound, ShieldCheck, Trash2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SignOutButton } from "@/components/auth/sign-out-button";
import { getCurrentUser } from "@/lib/auth/current-user";
import { getUserRepository } from "@/lib/auth/user-repository";

export const metadata: Metadata = { title: "Settings" };

export default async function SettingsPage() {
  const user = await getCurrentUser();
  const repo = getUserRepository();
  const secretConfigured = Boolean(
    process.env.AUTH_SECRET && process.env.AUTH_SECRET.length >= 32,
  );

  return (
    <div className="mx-auto max-w-3xl space-y-4 p-4 sm:p-6">
      <h1 className="text-lg font-semibold tracking-tight">Settings</h1>

      <Card>
        <CardHeader>
          <CardTitle>Account</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div className="flex items-center justify-between">
            <span className="text-muted-foreground">Email</span>
            <span className="mono">{user?.email ?? "—"}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-muted-foreground">Sign out everywhere</span>
            <SignOutButton />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Storage</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-2 text-muted-foreground">
              <Database className="size-4" /> Account storage
            </span>
            <Badge variant={repo.driver === "postgres" ? "success" : "warning"}>
              {repo.driver === "postgres" ? "PostgreSQL (Neon + Drizzle)" : "In-memory (dev)"}
            </Badge>
          </div>
          {repo.driver === "memory" && (
            <p className="rounded-md border border-warning/30 bg-warning/5 p-3 text-xs text-warning">
              DATABASE_URL is not set. Accounts live in process memory and reset
              on restart. Set DATABASE_URL to a Neon Postgres instance to persist
              accounts. Testing data is never stored in either mode.
            </p>
          )}
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-2 text-muted-foreground">
              <Trash2 className="size-4" /> Testing data
            </span>
            <Badge variant="primary">ephemeral — never persisted</Badge>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Security posture</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-2 text-muted-foreground">
              <KeyRound className="size-4" /> AUTH_SECRET
            </span>
            <Badge variant={secretConfigured ? "success" : "warning"}>
              {secretConfigured ? "configured" : "development fallback"}
            </Badge>
          </div>
          {!secretConfigured && (
            <p className="rounded-md border border-warning/30 bg-warning/5 p-3 text-xs text-warning">
              Set a 32+ character AUTH_SECRET. In production WebStrike refuses to
              start without one.
            </p>
          )}
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-2 text-muted-foreground">
              <ShieldCheck className="size-4" /> Scope &amp; SSRF enforcement
            </span>
            <Badge variant="success">always on</Badge>
          </div>
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-2 text-muted-foreground">
              <HardDrive className="size-4" /> Findings database
            </span>
            <Badge variant="muted">none by design</Badge>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}