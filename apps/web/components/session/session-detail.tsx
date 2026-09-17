"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  Activity,
  Bot,
  Fingerprint,
  Globe2,
  Radio,
  RotateCcw,
  ShieldCheck,
  Square,
} from "lucide-react";
import type { TestingSession } from "@webstrike/types";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useEndSession } from "@/lib/hooks/use-session";
import { useEphemeralResults } from "@/lib/results/store";
import { useNow } from "@/lib/hooks/use-now";
import { formatCountdown } from "@/lib/utils";

export function SessionDetail({ session }: { session: TestingSession }) {
  const router = useRouter();
  const now = useNow();
  const endSession = useEndSession();
  const { requestCount, testCount, entries, clearAll } = useEphemeralResults();

  const expired = now >= session.expiresAt;
  const inactive = expired || session.status === "ended";

  return (
    <div className="mx-auto max-w-4xl space-y-4 p-4 sm:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-semibold tracking-tight">{session.name}</h1>
            <Badge variant={inactive ? "danger" : "success"}>
              {session.status}
            </Badge>
          </div>
          <p className="mono mt-1 text-xs text-muted-foreground">
            {session.targetUrl}
          </p>
        </div>
        <div className="flex gap-2">
          <Button asChild variant="secondary" size="sm" disabled={inactive}>
            <Link href="/repeater">
              <Radio className="size-3.5" /> Repeater
            </Link>
          </Button>
          <Button
            variant="danger"
            size="sm"
            disabled={inactive || endSession.isPending}
            onClick={() => {
              endSession.mutate();
              clearAll();
              router.push("/dashboard");
            }}
          >
            <Square className="size-3.5" /> End session
          </Button>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        <Card>
          <CardContent className="flex items-center gap-3 py-3">
            <Activity className="size-4 text-info" />
            <div>
              <p className="text-[10px] uppercase tracking-widest text-muted-foreground">
                Requests
              </p>
              <p className="mono text-sm font-semibold">{requestCount}</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 py-3">
            <ShieldCheck className="size-4 text-warning" />
            <div>
              <p className="text-[10px] uppercase tracking-widest text-muted-foreground">
                Tests
              </p>
              <p className="mono text-sm font-semibold">{testCount}</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 py-3">
            <RotateCcw className="size-4 text-primary" />
            <div>
              <p className="text-[10px] uppercase tracking-widest text-muted-foreground">
                Expires in
              </p>
              <p className="mono text-sm font-semibold">
                {inactive ? "—" : formatCountdown(session.expiresAt, now)}
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Globe2 className="size-4 text-primary" /> Authorised scope
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <ScopeRow label="Domains" items={session.allowedDomains} variant="primary" />
            <ScopeRow label="Paths" items={session.allowedPaths} variant="muted" />
            <ScopeRow
              label="Blocked"
              items={session.blockedDomains.length ? session.blockedDomains : ["none"]}
              variant="danger"
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Fingerprint className="size-4 text-accent" /> Identity
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="rounded-md border border-border bg-panel-2/60 p-3 text-xs leading-relaxed text-muted-foreground">
              {session.testingIdentity}
            </p>
            <div className="flex items-center gap-2 text-xs text-success">
              <ShieldCheck className="size-3.5" /> Authorisation confirmed
            </div>
            <div className="flex gap-2 pt-1">
              <Button asChild variant="ghost" size="sm" disabled={inactive}>
                <Link href="/automated">
                  <Bot className="size-3.5" /> Automated checks
                </Link>
              </Button>
              <Button asChild variant="ghost" size="sm" disabled={inactive}>
                <Link href={`/results`}>
                  View {entries.length} result{entries.length === 1 ? "" : "s"}
                </Link>
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function ScopeRow({
  label,
  items,
  variant,
}: {
  label: string;
  items: string[];
  variant: "primary" | "muted" | "danger";
}) {
  return (
    <div>
      <p className="text-[10px] uppercase tracking-widest text-muted-foreground">
        {label}
      </p>
      <div className="mt-1.5 flex flex-wrap gap-1.5">
        {items.map((item) => (
          <Badge key={item} variant={variant} className="mono">
            {item}
          </Badge>
        ))}
      </div>
    </div>
  );
}