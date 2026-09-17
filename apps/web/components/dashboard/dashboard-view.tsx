"use client";

import Link from "next/link";
import {
  Activity,
  ArrowRight,
  Clock,
  FileWarning,
  Fingerprint,
  Globe2,
  PlusCircle,
  Radio,
  ShieldAlert,
  ShieldCheck,
  Square,
  Trash2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useEndSession, useTestingSession } from "@/lib/hooks/use-session";
import { useNow } from "@/lib/hooks/use-now";
import { useEphemeralResults } from "@/lib/results/store";
import { formatCountdown, relativeTime } from "@/lib/utils";

function Stat({
  label,
  value,
  icon: Icon,
  tone = "text-foreground",
}: {
  label: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  tone?: string;
}) {
  return (
    <Card>
      <CardContent className="flex items-center gap-3 py-3">
        <Icon className={`size-4 ${tone}`} />
        <div className="min-w-0">
          <p className="text-[10px] uppercase tracking-widest text-muted-foreground">
            {label}
          </p>
          <p className="mono truncate text-sm font-semibold">{value}</p>
        </div>
      </CardContent>
    </Card>
  );
}

export function DashboardView() {
  const { data, isLoading } = useTestingSession();
  const now = useNow();
  const endSession = useEndSession();
  const { requestCount, testCount, entries, clearAll } = useEphemeralResults();
  const session = data?.session ?? null;

  if (isLoading) {
    return (
      <div className="p-6">
        <div className="h-24 animate-pulse rounded-lg border border-border bg-panel/60" />
      </div>
    );
  }

  if (!session) {
    return (
      <div className="mx-auto max-w-3xl p-6">
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center gap-4 py-14 text-center">
            <ShieldCheck className="size-8 text-primary" />
            <div>
              <h2 className="text-base font-semibold">No active testing session</h2>
              <p className="mt-1 max-w-md text-sm text-muted-foreground">
                Every request in WebStrike needs an authorised target. Create a
                temporary session that declares the target, scope, identity and
                expiry.
              </p>
            </div>
            <Button asChild>
              <Link href="/new-session">
                <PlusCircle className="size-4" /> Create testing session
              </Link>
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const expired = now >= session.expiresAt;
  const ended = session.status === "ended";
  const inactive = expired || ended;

  return (
    <div className="mx-auto max-w-5xl space-y-4 p-4 sm:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight">{session.name}</h1>
          <p className="mono text-xs text-muted-foreground">{session.targetUrl}</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={inactive ? "danger" : "success"} className="gap-1.5">
            <span
              className={`size-1.5 rounded-full ${inactive ? "bg-danger" : "bg-success ws-pulse"}`}
            />
            {ended ? "ended" : expired ? "expired" : "active"}
          </Badge>
          <Button asChild variant="secondary" size="sm" disabled={inactive}>
            <Link href="/repeater">
              <Radio className="size-3.5" /> Open repeater
            </Link>
          </Button>
          <Button
            variant="danger"
            size="sm"
            disabled={inactive || endSession.isPending}
            onClick={() => {
              endSession.mutate();
              clearAll();
            }}
          >
            <Square className="size-3.5" /> Stop testing
          </Button>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Requests" value={requestCount} icon={Activity} tone="text-info" />
        <Stat label="Tests executed" value={testCount} icon={ShieldAlert} tone="text-warning" />
        <Stat
          label="Results in memory"
          value={entries.length}
          icon={FileWarning}
          tone="text-accent"
        />
        <Stat
          label="Expires in"
          value={inactive ? "—" : formatCountdown(session.expiresAt, now)}
          icon={Clock}
          tone={expired ? "text-danger" : "text-primary"}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Globe2 className="size-4 text-primary" /> Scope
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-sm">
            <div>
              <p className="text-[10px] uppercase tracking-widest text-muted-foreground">
                Allowed domains
              </p>
              <div className="mt-1.5 flex flex-wrap gap-1.5">
                {session.allowedDomains.map((d) => (
                  <Badge key={d} variant="primary" className="mono">
                    {d}
                  </Badge>
                ))}
              </div>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-widest text-muted-foreground">
                Allowed paths
              </p>
              <div className="mt-1.5 flex flex-wrap gap-1.5">
                {session.allowedPaths.map((p) => (
                  <Badge key={p} variant="muted" className="mono">
                    {p}
                  </Badge>
                ))}
              </div>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-widest text-muted-foreground">
                Blocked domains
              </p>
              <div className="mt-1.5 flex flex-wrap gap-1.5">
                {session.blockedDomains.length === 0 ? (
                  <span className="text-xs text-muted-foreground">
                    none configured — the system denylist still applies
                  </span>
                ) : (
                  session.blockedDomains.map((d) => (
                    <Badge key={d} variant="danger" className="mono">
                      {d}
                    </Badge>
                  ))
                )}
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Fingerprint className="size-4 text-accent" /> Testing identity
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-sm">
            <p className="rounded-md border border-border bg-panel-2/60 p-3 text-xs leading-relaxed text-muted-foreground">
              {session.testingIdentity}
            </p>
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div>
                <p className="text-[10px] uppercase tracking-widest text-muted-foreground">
                  Started
                </p>
                <p className="mono mt-0.5">{relativeTime(session.startTime, now)}</p>
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-widest text-muted-foreground">
                  Expires
                </p>
                <p className="mono mt-0.5">
                  {new Date(session.expiresAt).toLocaleTimeString()}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 rounded-md border border-success/30 bg-success/5 p-2.5 text-xs text-success">
              <ShieldCheck className="size-3.5" />
              Authorisation confirmed at session creation
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Ephemeral results</CardTitle>
          <Link
            href="/results"
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
          >
            view all <ArrowRight className="size-3" />
          </Link>
        </CardHeader>
        <CardContent>
          {entries.length === 0 ? (
            <p className="py-6 text-center text-xs text-muted-foreground">
              No results yet. Send a request from the repeater to populate this
              in-memory list.
            </p>
          ) : (
            <ul className="divide-y divide-border">
              {entries.slice(0, 4).map((entry) => (
                <li
                  key={entry.id}
                  className="flex items-center gap-3 py-2 text-xs"
                >
                  <Badge variant="muted" className="mono">
                    {entry.request.method}
                  </Badge>
                  <span className="mono min-w-0 flex-1 truncate text-muted-foreground">
                    {entry.result?.finalUrl ?? entry.request.url}
                  </span>
                  <Badge
                    variant={
                      entry.status === "error"
                        ? "danger"
                        : entry.result && entry.result.status >= 400
                          ? "warning"
                          : "success"
                    }
                  >
                    {entry.status === "error"
                      ? "refused"
                      : (entry.result?.status ?? "…")}
                  </Badge>
                </li>
              ))}
            </ul>
          )}
          {entries.length > 0 && (
            <Button
              variant="ghost"
              size="sm"
              className="mt-2"
              onClick={clearAll}
            >
              <Trash2 className="size-3.5" /> Discard in-memory results
            </Button>
          )}
        </CardContent>
      </Card>
    </div>
  );
}